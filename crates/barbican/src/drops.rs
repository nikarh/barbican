//! What the firewalls dropped, in total: this host's and each edge's. The kernel's counters start again from 0
//! whenever a table is made anew (a reboot, an edge's firewall restarting); these totals add up what each reading
//! shows, survive restarts in the database, and are what the UI shows.

use std::sync::Arc;

use barbican_common::nft::{Counter, Counters};

use crate::app::App;

/// This host's place; an edge's is its client name.
pub const HOST: &str = "";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops {
    /// When counting started.
    pub since: i64,
    pub total: Counters,
    /// The last reading of the kernel's counters.
    pub last: Counters,
}

impl Drops {
    #[must_use]
    pub fn first(now: i64, reading: Counters) -> Self {
        Self {
            since: now,
            total: reading,
            last: reading,
        }
    }

    /// Takes in a reading of the kernel's counters. Returns whether the totals changed.
    pub fn add(&mut self, reading: Counters) -> bool {
        fn step(total: &mut Counter, last: &mut Counter, now: Counter) {
            // Below the last reading: the counter started again from 0, and all it shows is new.
            let fresh = now.packets < last.packets || now.bytes < last.bytes;
            let (packets, bytes) = if fresh {
                (now.packets, now.bytes)
            } else {
                (now.packets - last.packets, now.bytes - last.bytes)
            };
            total.packets = total.packets.saturating_add(packets);
            total.bytes = total.bytes.saturating_add(bytes);
            *last = now;
        }
        let before = *self;
        step(
            &mut self.total.blocked,
            &mut self.last.blocked,
            reading.blocked,
        );
        step(
            &mut self.total.listed,
            &mut self.last.listed,
            reading.listed,
        );
        *self != before
    }
}

/// Adds a reading of a place's counters (`HOST`, or an edge's name) and saves the totals when they changed. Returns
/// the totals.
pub fn record(app: &Arc<App>, place: &str, now: i64, reading: Counters) -> Drops {
    let (drops, changed) = {
        let Ok(mut all) = app.drops.lock() else {
            return Drops::first(now, reading);
        };
        if let Some(d) = all.get_mut(place) {
            let changed = d.add(reading);
            (*d, changed)
        } else {
            let d = Drops::first(now, reading);
            all.insert(place.to_owned(), d);
            (d, true)
        }
    };
    if changed {
        let app = Arc::clone(app);
        let place = place.to_owned();
        tokio::spawn(async move {
            if let Err(e) = crate::db::drops_save(&app.db.pool, &place, &drops).await {
                tracing::warn!(error = %e, "Saving the drop counters failed");
            }
        });
    }
    drops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(blocked: u64, listed: u64) -> Counters {
        Counters {
            blocked: Counter {
                packets: blocked,
                bytes: blocked * 60,
            },
            listed: Counter {
                packets: listed,
                bytes: listed * 60,
            },
        }
    }

    #[test]
    fn totals_go_on_across_counter_resets() {
        let mut d = Drops::first(100, reading(5, 7));
        assert!(!d.add(reading(5, 7)));
        assert!(d.add(reading(8, 7)));
        assert_eq!(d.total.blocked.packets, 8);
        // A reboot or a table made anew: the kernel counts from 0 again.
        assert!(d.add(reading(2, 1)));
        assert_eq!((d.total.blocked.packets, d.total.listed.packets), (10, 8));
        assert_eq!(d.total.blocked.bytes, 600);
        assert!(d.add(reading(3, 1)));
        assert_eq!((d.total.blocked.packets, d.total.listed.packets), (11, 8));
        assert_eq!(d.since, 100);
    }
}
