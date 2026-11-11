---
title: Routers without nftables
description: barbican-edge-ipset, for Asuswrt-Merlin and other firmware with iptables and ipset instead of nftables.
sidebar:
  order: 6
---

Some router firmware runs kernels without nftables: Asuswrt-Merlin, and firmware based on older Linux kernels. `barbican-edge-ipset` does what [barbican-edge](/install/openwrt/) does with iptables and ipset instead: a chain in the mangle table, jumped to first in PREROUTING (before NAT), and ipsets with what is blocked. It needs `iptables` with the `conntrack` and `set` matches, and `ipset`.

`barbican-edge-ipset-armv7.tar.gz` runs on 32-bit ARM CPUs with or without an FPU, and on 64-bit ARM routers whose firmware runs 32-bit programs; `barbican-edge-ipset-x86_64.tar.gz` on x86_64.

ipset times elements out after at most 24.8 days: longer bans get that, and are renewed while the agent runs.

## Asuswrt-Merlin

Turn on **Enable JFFS custom scripts and configs** (Administration → System), then, from another machine:

```bash
curl -fLO https://github.com/nikarh/barbican/releases/latest/download/barbican-edge-ipset-armv7.tar.gz
scp barbican-edge-ipset-armv7.tar.gz admin@router.example.net:/tmp/
ssh admin@router.example.net 'cd /tmp && tar -xzf barbican-edge-ipset-armv7.tar.gz && barbican-edge-ipset/install.sh'
```

Everything goes to `/jffs/barbican`: the binary, its configuration `barbican.conf` (the same format as on OpenWrt, see [Configuring an edge](/edge/configuration/)), its saved state, and `barbican.sh` (`start`, `stop`, `restart`, `restore`, `status`), which restarts the agent when it stops and logs to the router's syslog as `barbican-edge`. The installer adds `barbican.sh start` to `/jffs/scripts/services-start`, which runs at boot, and `barbican.sh restore` to `/jffs/scripts/firewall-start`, which runs whenever the router restarts its firewall (which drops custom rules). It keeps an existing configuration.

Add the agents to follow to `/jffs/barbican/barbican.conf` (see [Connecting an edge to an agent](/edge/overview/#connecting-an-edge-to-an-agent)), then `/jffs/barbican/barbican.sh restart`. `/jffs/barbican/uninstall.sh` removes its rules and sets, its files, and its lines in `/jffs/scripts`.

## Other firmware

Run `barbican-edge-ipset --config <file>` at boot and keep it running (it saves its state on SIGTERM), and `barbican-edge-ipset --config <file> restore` whenever the firewall's rules are rebuilt. Its options are those of [an edge's configuration](/edge/configuration/), plus `iptables`, `ipset`, `ip6tables` (with `ipv6 '1'`), `prefix` (of the sets' names) and `chain`.
