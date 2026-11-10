//! The firewall an edge agent keeps equal to what its upstreams block.

use barbican_common::nft::{Counters, Desired, Firewall, NftCommand, Runner};

use crate::daemon::Config;

pub trait Backend: Send {
    /// What it changes, for the status: `nftables table inet barbican`.
    fn describe(&self) -> String;
    /// Creates (or repairs) its rules and sets, keeping what they hold.
    fn setup(&mut self) -> Result<(), String>;
    /// Changes the sets to hold what `desired` says. `now` is the current unix time.
    fn reconcile(&mut self, desired: &Desired, now: u64) -> Result<(), String>;
    /// What the drop rules matched.
    fn counters(&self) -> Option<Counters>;
    /// Removes its rules and sets.
    fn remove(&mut self) -> Result<(), String>;
}

/// nftables: the table of `barbican_common::nft`, as on the agent.
pub struct Nft<R: Runner + Send>(pub Firewall<R>);

impl<R: Runner + Send> Backend for Nft<R> {
    fn describe(&self) -> String {
        format!("nftables table inet {}", self.0.table())
    }

    fn setup(&mut self) -> Result<(), String> {
        self.0.setup().map_err(|e| e.to_string())
    }

    fn reconcile(&mut self, desired: &Desired, now: u64) -> Result<(), String> {
        self.0
            .reconcile(desired, now)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn counters(&self) -> Option<Counters> {
        self.0.counters().ok()
    }

    fn remove(&mut self) -> Result<(), String> {
        self.0.remove().map_err(|e| e.to_string())
    }
}

/// A name for nftables tables, ipset sets and iptables chains: letters, digits, `_` and `-`.
pub fn name(config: &Config, key: &str, default: &str) -> Result<String, String> {
    let value = config.main.option(key).unwrap_or(default).to_owned();
    if value.is_empty()
        || value.len() > 24
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("{key}: up to 24 letters, digits, '_' and '-'"));
    }
    Ok(value)
}

/// The nftables backend, from the `table`, `priority` and `nft` options.
pub fn nft(config: &Config) -> Result<Box<dyn Backend>, String> {
    let table = name(config, "table", "barbican")?;
    let priority = match config.main.option("priority") {
        Some(p) => p
            .parse()
            .map_err(|_| format!("priority: not a number: {p:?}"))?,
        None => -190,
    };
    let program = config.main.option("nft").unwrap_or("nft").to_owned();
    Ok(Box::new(Nft(Firewall::new(
        NftCommand { program },
        &table,
        priority,
    ))))
}
