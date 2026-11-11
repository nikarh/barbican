//! barbican-edge: applies the blocks of barbican agents on a router with nftables (OpenWrt).

use std::process::ExitCode;

use barbican_edge::{backend, daemon};

fn main() -> ExitCode {
    daemon::main(
        &daemon::Defaults {
            name: "barbican-edge",
            about: "applies the blocks of barbican agents on a router, with nftables",
            config: "/etc/config/barbican",
            state: "/etc/barbican/state",
            status: "/var/run/barbican-edge.json",
        },
        backend::nft,
    )
}
