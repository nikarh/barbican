//! How much blocking a choice of countries and continents takes, from a summary of the country database made in
//! one pass when it is opened: each country's and continent's extent, and the database as runs of addresses of one
//! place (a country and its continent) for counting any choice together.
//!
//! Addresses add up: the database's networks don't overlap. Prefixes don't: networks of two chosen countries next
//! to each other may merge into fewer, larger prefixes. So a choice's prefixes are counted from the runs: chosen
//! runs next to each other join, and each joined run counts the fewest prefixes that cover it. That is one pass
//! over a few hundred thousand runs, about a millisecond.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use barbican_common::net::{Family, Net, Range};

use crate::geo::{Coverage, Extent};

/// A country and its continent.
pub(crate) type Place = (Option<String>, Option<String>);

/// The place of addresses outside the database.
const NOWHERE: u16 = u16::MAX;

/// The extent of address ranges given in address order, counted as they come: adjacent ones are joined, and each
/// joined run counts the fewest prefixes that cover it, as merging them would give. Nothing is kept but the run in
/// progress.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    extent: Extent,
    v6: u128,
    /// The family, first and last address of the run in progress.
    run: Option<(Family, u128, u128)>,
}

impl Tally {
    pub(crate) fn add(&mut self, net: &Net) {
        let (first, last) = Range::of(net).bounds();
        self.add_range(net.family(), first, last);
    }

    fn add_range(&mut self, family: Family, first: u128, last: u128) {
        if let Some((f, start, end)) = self.run
            && f == family
            && first <= end.saturating_add(1)
            && first >= start
        {
            self.run = Some((f, start, end.max(last)));
            return;
        }
        self.close();
        self.run = Some((family, first, last));
    }

    fn close(&mut self) {
        let Some((family, first, last)) = self.run.take() else {
            return;
        };
        let prefixes = prefixes_between(family, first, last);
        self.extent.prefixes += prefixes;
        let size = (last - first).saturating_add(1);
        match family {
            Family::V4 => self.extent.v4_addresses += u64::try_from(size).unwrap_or(u64::MAX),
            Family::V6 => {
                self.extent.v6_prefixes += prefixes;
                self.v6 = self.v6.saturating_add(size);
            }
        }
    }

    pub(crate) fn finish(mut self) -> Extent {
        self.close();
        self.extent.v6_networks = u64::try_from(self.v6 >> 80).unwrap_or(u64::MAX);
        self.extent
    }
}

/// The fewest prefixes that cover the addresses from `first` to `last` (both included).
pub(crate) fn prefixes_between(family: Family, mut first: u128, last: u128) -> u64 {
    let mut n = 0;
    loop {
        n += 1;
        let Some(left) = (last - first).checked_add(1) else {
            // The whole space: one prefix.
            return n;
        };
        // The largest block that starts at `first`, aligned to its size, and ends by `last`.
        let aligned = if first == 0 {
            family.bits()
        } else {
            first.trailing_zeros().min(family.bits())
        };
        let fits = left.ilog2();
        let k = aligned.min(fits);
        match first.checked_add(1u128 << k) {
            Some(next) if next <= last => first = next,
            _ => return n,
        }
    }
}

/// One family's addresses as runs of one place: each run from its start to the next one's, the last to `last`.
/// IPv4 starts take 4 bytes; IPv6 starts are kept as their upper 64 bits, with the lower ones of the few that have
/// any apart: the database's IPv6 networks are rarely longer than /64.
#[derive(Debug)]
struct Runs {
    family: Family,
    v4: Vec<u32>,
    upper: Vec<u64>,
    /// (index, lower 64 bits) of the starts that have any, by index.
    lower: Vec<(u32, u64)>,
    places: Vec<u16>,
    last: u128,
}

impl Runs {
    fn new(family: Family) -> Self {
        Self {
            family,
            v4: Vec::new(),
            upper: Vec::new(),
            lower: Vec::new(),
            places: Vec::new(),
            last: 0,
        }
    }

    fn start(&self, i: usize) -> u128 {
        match self.family {
            Family::V4 => u128::from(self.v4.get(i).copied().unwrap_or(0)),
            Family::V6 => {
                let upper = u128::from(self.upper.get(i).copied().unwrap_or(0));
                let lower = u32::try_from(i)
                    .ok()
                    .and_then(|i| self.lower.binary_search_by_key(&i, |(j, _)| *j).ok())
                    .and_then(|at| self.lower.get(at))
                    .map_or(0, |(_, lower)| *lower);
                upper << 64 | u128::from(lower)
            }
        }
    }

    /// Adds a network of a place; networks come in address order.
    fn push(&mut self, first: u128, last: u128, place: u16) {
        if let Some(&previous) = self.places.last() {
            if first > self.last.saturating_add(1) {
                self.push_start(self.last + 1, NOWHERE);
            } else if previous == place {
                self.last = self.last.max(last);
                return;
            }
        }
        self.push_start(first, place);
        self.last = last;
    }

    fn push_start(&mut self, start: u128, place: u16) {
        let i = u32::try_from(self.places.len()).unwrap_or(u32::MAX);
        match self.family {
            Family::V4 => self.v4.push(u32::try_from(start).unwrap_or(u32::MAX)),
            Family::V6 => {
                self.upper
                    .push(u64::try_from(start >> 64).unwrap_or(u64::MAX));
                let lower = u64::try_from(start & u128::from(u64::MAX)).unwrap_or(0);
                if lower != 0 {
                    self.lower.push((i, lower));
                }
            }
        }
        self.places.push(place);
    }

    fn shrink(mut self) -> Self {
        self.v4.shrink_to_fit();
        self.upper.shrink_to_fit();
        self.lower.shrink_to_fit();
        self.places.shrink_to_fit();
        self
    }

    /// Counts the runs of the chosen places into `tally`.
    fn count(&self, chosen: &[bool], tally: &mut Tally) {
        let is_chosen = |i: usize| {
            self.places
                .get(i)
                .is_some_and(|p| chosen.get(usize::from(*p)).copied().unwrap_or(false))
        };
        let n = self.places.len();
        let mut i = 0;
        while i < n {
            if !is_chosen(i) {
                i += 1;
                continue;
            }
            // Chosen runs next to each other join.
            let first = self.start(i);
            while i < n && is_chosen(i) {
                i += 1;
            }
            let last = if i < n { self.start(i) - 1 } else { self.last };
            tally.add_range(self.family, first, last);
        }
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.v4.capacity() * 4
            + self.upper.capacity() * 8
            + self.lower.capacity() * 16
            + self.places.capacity() * 2
    }
}

#[derive(Debug)]
pub struct Summary {
    /// Each place, by number.
    places: Vec<Place>,
    /// By country code (upper case): the continent of its first network, and its extent.
    countries: HashMap<String, (Option<String>, Extent)>,
    /// By continent code (upper case).
    continents: HashMap<String, Extent>,
    known: Extent,
    v4: Runs,
    /// Made the first time IPv6 is counted.
    v6: OnceLock<Runs>,
}

impl Summary {
    /// From the database's networks and their place, in address order within each family. The IPv6 runs are made
    /// only with `ipv6`; [`Summary::add_ipv6`] makes them later.
    pub fn new(networks: impl IntoIterator<Item = (Net, Arc<Place>)>, ipv6: bool) -> Self {
        let mut places: Vec<Place> = Vec::new();
        let mut numbers: HashMap<Place, u16> = HashMap::new();
        // Tallies of countries and continents by code (upper case), and each place's.
        let mut countries: Vec<(String, Option<String>, Tally)> = Vec::new();
        let mut continents: Vec<(String, Tally)> = Vec::new();
        let mut tallies_of: Vec<(Option<usize>, Option<usize>)> = Vec::new();
        let mut known = Tally::default();
        let (mut v4, mut v6) = (Runs::new(Family::V4), Runs::new(Family::V6));
        for (net, place) in networks {
            let place = if let Some(n) = numbers.get(&*place) {
                *n
            } else {
                let (country, continent) = &*place;
                let Ok(n) = u16::try_from(places.len()) else {
                    continue;
                };
                if n == NOWHERE {
                    // More places than numbers: no real database has.
                    continue;
                }
                let country_tally = country.as_ref().map(|code| {
                    let code = code.to_ascii_uppercase();
                    countries
                        .iter()
                        .position(|(c, ..)| *c == code)
                        .unwrap_or_else(|| {
                            countries.push((code, continent.clone(), Tally::default()));
                            countries.len() - 1
                        })
                });
                let continent_tally = continent.as_ref().map(|code| {
                    let code = code.to_ascii_uppercase();
                    continents
                        .iter()
                        .position(|(c, _)| *c == code)
                        .unwrap_or_else(|| {
                            continents.push((code, Tally::default()));
                            continents.len() - 1
                        })
                });
                tallies_of.push((country_tally, continent_tally));
                places.push((*place).clone());
                numbers.insert((*place).clone(), n);
                n
            };
            known.add(&net);
            let (country_tally, continent_tally) = tallies_of
                .get(usize::from(place))
                .copied()
                .unwrap_or_default();
            if let Some((.., tally)) = country_tally.and_then(|i| countries.get_mut(i)) {
                tally.add(&net);
            }
            if let Some((_, tally)) = continent_tally.and_then(|i| continents.get_mut(i)) {
                tally.add(&net);
            }
            let (first, last) = Range::of(&net).bounds();
            match net.family() {
                Family::V4 => v4.push(first, last, place),
                Family::V6 if ipv6 => v6.push(first, last, place),
                Family::V6 => {}
            }
        }
        let summary = Self {
            places,
            countries: countries
                .into_iter()
                .map(|(code, continent, tally)| (code, (continent, tally.finish())))
                .collect(),
            continents: continents
                .into_iter()
                .map(|(code, tally)| (code, tally.finish()))
                .collect(),
            known: known.finish(),
            v4: v4.shrink(),
            v6: OnceLock::new(),
        };
        if ipv6 {
            let _ = summary.v6.set(v6.shrink());
        }
        summary
    }

    /// Whether it has the IPv6 runs.
    pub fn has_ipv6(&self) -> bool {
        self.v6.get().is_some()
    }

    /// Adds the IPv6 runs, from the networks it was made from.
    pub fn add_ipv6(&self, networks: impl IntoIterator<Item = (Net, Arc<Place>)>) {
        let numbers: HashMap<&Place, u16> = self
            .places
            .iter()
            .enumerate()
            .filter_map(|(i, p)| Some((p, u16::try_from(i).ok()?)))
            .collect();
        let mut v6 = Runs::new(Family::V6);
        for (net, place) in networks {
            if net.family() != Family::V6 {
                continue;
            }
            if let Some(place) = numbers.get(&*place) {
                let (first, last) = Range::of(&net).bounds();
                v6.push(first, last, *place);
            }
        }
        let _ = self.v6.set(v6.shrink());
    }

    /// How much these countries and continents take, each and together, and everything the database places. IPv6
    /// counts only with `ipv6`, and then needs the IPv6 runs.
    #[must_use]
    pub fn coverage(&self, countries: &[String], continents: &[String], ipv6: bool) -> Coverage {
        let upper = |codes: &[String]| -> Vec<String> {
            codes.iter().map(|c| c.to_ascii_uppercase()).collect()
        };
        let (wanted_countries, wanted_continents) = (upper(countries), upper(continents));
        let chosen: Vec<bool> = self
            .places
            .iter()
            .map(|(country, continent)| {
                let among = |code: &Option<String>, wanted: &[String]| {
                    code.as_ref()
                        .is_some_and(|c| wanted.contains(&c.to_ascii_uppercase()))
                };
                among(country, &wanted_countries) || among(continent, &wanted_continents)
            })
            .collect();
        let mut tally = Tally::default();
        self.v4.count(&chosen, &mut tally);
        if ipv6 && let Some(v6) = self.v6.get() {
            v6.count(&chosen, &mut tally);
        }
        let family = |mut e: Extent| {
            if !ipv6 {
                e.prefixes -= e.v6_prefixes;
                e.v6_prefixes = 0;
                e.v6_networks = 0;
            }
            e
        };
        Coverage {
            countries: countries
                .iter()
                .zip(&wanted_countries)
                .map(|(code, upper)| {
                    let (continent, extent) =
                        self.countries.get(upper).cloned().unwrap_or_default();
                    (code.clone(), continent, family(extent))
                })
                .collect(),
            continents: continents
                .iter()
                .zip(&wanted_continents)
                .map(|(code, upper)| {
                    let extent = self.continents.get(upper).copied().unwrap_or_default();
                    (code.clone(), family(extent))
                })
                .collect(),
            total: family(tally.finish()),
            known: family(self.known),
        }
    }

    /// Roughly how much memory it takes.
    #[cfg(test)]
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.v4.bytes()
            + self.v6.get().map_or(0, Runs::bytes)
            + (self.places.len() + self.countries.len() + self.continents.len()) * 80
    }
}
