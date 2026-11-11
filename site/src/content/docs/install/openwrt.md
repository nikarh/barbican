---
title: OpenWrt
description: Installing barbican-edge and its LuCI pages on an OpenWrt router, with apk or opkg, or by hand.
sidebar:
  order: 5
---

`barbican-edge` blocks what barbican agents ban, for everything the router forwards and for the router itself. It needs nftables with JSON support (`nftables-json`, which OpenWrt's images have).

Pick the build for the router's CPU: `x86_64`, `aarch64`, or `armv7` (32-bit ARM with an FPU: Cortex-A7, A9, A15; `cat /proc/cpuinfo` lists `vfp` among its features). The packages are the same for every OpenWrt target of that CPU. The examples below use `armv7`.

## OpenWrt 25.12 and later (apk)

```bash
cd /tmp
wget https://github.com/nikarh/barbican/releases/latest/download/barbican-edge-armv7.apk
wget https://github.com/nikarh/barbican/releases/latest/download/luci-app-barbican.apk
apk add --allow-untrusted ./barbican-edge-armv7.apk ./luci-app-barbican.apk
```

## OpenWrt 24.10 and earlier (opkg)

```bash
cd /tmp
wget https://github.com/nikarh/barbican/releases/latest/download/barbican-edge-armv7.ipk
wget https://github.com/nikarh/barbican/releases/latest/download/luci-app-barbican.ipk
opkg install ./barbican-edge-armv7.ipk ./luci-app-barbican.ipk
```

When the router's `wget` can't do HTTPS, download on another machine and copy the files over. The packages aren't signed for OpenWrt's package managers (hence `--allow-untrusted`); check them against the release's signed checksums first: [Verifying downloads](/install/verifying/).

## Configuring

The package enables and starts the agent. Add the agents it follows in LuCI (**Services → Barbican → Settings**) or in `/etc/config/barbican`, which upgrades keep:

```text title="/etc/config/barbican"
config barbican 'main'
	option enabled '1'
	option dry_run '0'             # 1: follow and save, but change nothing in the firewall
	option lists '1'               # also the agents' country blocks and blocking lists
	option persist_interval '0'    # also save every N seconds (0: only on a clean stop)

config upstream 'server'
	option url 'https://192.0.2.10:7380'
	option fingerprint '3F:A1:...'        # barbican edge-fingerprint, on the agent
	option token_file '/etc/barbican/server.token'
```

then `/etc/init.d/barbican-edge restart`. Every option is in [Configuring an edge](/edge/configuration/), and the steps on the agent's side in [Connecting an edge to an agent](/edge/overview/#connecting-an-edge-to-an-agent).

**Services → Barbican → Status** (or `barbican-edge status`) shows whether it follows its agents and what it blocks: [LuCI pages](/edge/luci/). The edge stays connected to each agent and reports to it, so each agent's UI shows it too (**Settings → Edges**).

Without IPv6 on the router, `option ipv6 '0'` leaves it out: see [IPv6](/edge/configuration/#ipv6).

## By hand

`barbican-edge-<arch>.tar.gz` has the same files and an `install.sh` that puts them in place, adds them to `/etc/sysupgrade.conf` so that a firmware upgrade keeps them, and starts the agent:

```bash
tar -xzf barbican-edge-armv7.tar.gz && cd barbican-edge && ./install.sh
```

It keeps an existing `/etc/config/barbican`.

## Removing

`apk del barbican-edge luci-app-barbican` (or `opkg remove`) stops it and removes its table; the configuration stays.
