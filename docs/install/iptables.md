# Routers without nftables

Some router firmware runs kernels without nftables: Asuswrt-Merlin, and firmware based on older Linux kernels.
`barbican-edge-ipset` does what [barbican-edge](openwrt.md) does with iptables and ipset instead: a chain in the
mangle table, jumped to first in PREROUTING (before NAT), and ipsets with what is blocked. It needs `iptables` with the
`conntrack` and `set` matches, and `ipset`.

`barbican-edge-ipset-armv7.tar.gz` runs on 32-bit ARM CPUs with or without an FPU, and on 64-bit ARM routers whose
firmware runs 32-bit programs.

ipset times elements out after at most 24.8 days: longer bans get that, and are renewed while the agent runs.

## Asuswrt-Merlin

Turn on **Enable JFFS custom scripts and configs** (Administration → System), then, from another machine:

```sh
curl -fLO https://github.com/nikarh/barbican/releases/latest/download/barbican-edge-ipset-armv7.tar.gz
scp barbican-edge-ipset-armv7.tar.gz admin@router:/tmp/
ssh admin@router 'cd /tmp && tar -xzf barbican-edge-ipset-armv7.tar.gz && barbican-edge-ipset/install.sh'
```

Everything goes to `/jffs/barbican`: the binary, its configuration `barbican.conf` (the same format as on
[OpenWrt](openwrt.md#configuring)), its saved state, and `barbican.sh` (`start`, `stop`, `restart`, `status`). The
installer adds `barbican.sh start` to `/jffs/scripts/services-start`, which runs at boot, and `barbican.sh restore` to
`/jffs/scripts/firewall-start`, which runs whenever the router restarts its firewall (which drops custom rules).

Add the agents to follow to `/jffs/barbican/barbican.conf` (see
[Connecting an edge to an agent](README.md#connecting-an-edge-to-an-agent)), then `/jffs/barbican/barbican.sh restart`.
Its log is in the router's syslog (`barbican-edge`). `/jffs/barbican/uninstall.sh` removes its rules and sets, its
files, and its lines in `/jffs/scripts`.

## Other firmware

Run `barbican-edge-ipset --config <file>` at boot and keep it running (it saves its state on SIGTERM), and
`barbican-edge-ipset --config <file> restore` whenever the firewall's rules are rebuilt. Its options are those of
[`barbican.conf`](../../dist/merlin/barbican.conf), plus `iptables`, `ipset`, `ip6tables` (with `ipv6 '1'`),
`prefix` (of the sets' names) and `chain`.
