//! The edge agents: they follow barbican agents' edge APIs and apply what they block on a router.
//! `barbican-edge` does it with nftables (OpenWrt), `barbican-edge-ipset` with iptables and ipset (older kernels,
//! such as Asuswrt-Merlin's).

pub mod backend;
pub mod daemon;
pub mod ipset;
pub mod link;
pub mod saved;
pub mod uci;
