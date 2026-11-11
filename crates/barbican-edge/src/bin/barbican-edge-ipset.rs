//! barbican-edge-ipset: applies the blocks of barbican agents on a router with iptables and ipset, for kernels
//! without nftables (Asuswrt-Merlin).

use std::process::ExitCode;

use barbican_edge::{daemon, ipset};

fn main() -> ExitCode {
    daemon::main(
        &daemon::Defaults {
            name: "barbican-edge-ipset",
            about: "applies the blocks of barbican agents on a router, with iptables and ipset",
            config: "/jffs/barbican/barbican.conf",
            state: "/jffs/barbican/state",
            status: "/tmp/barbican-edge.json",
        },
        ipset::backend,
    )
}
