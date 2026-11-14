---
title: Configuring an edge
description: Every option of an edge agent's UCI file, dry run, IPv6, the saved state, and routers without a clock.
sidebar:
  order: 2
---

Both edge agents read a file in UCI syntax: `/etc/config/barbican` for `barbican-edge` on OpenWrt (edited in LuCI too, see [LuCI pages](/edge/luci/)), `/jffs/barbican/barbican.conf` for `barbican-edge-ipset` on Asuswrt-Merlin, or any file with `--config <path>`. It has one `barbican` section and one `upstream` section per agent to follow. After a change, restart the agent (`/etc/init.d/barbican-edge restart`; on OpenWrt a change made in LuCI restarts it).

```text title="/etc/config/barbican"
config barbican 'main'
	option enabled '1'
	option dry_run '0'
	option lists '1'
	option ipv6 '1'
	option state '/etc/barbican/state'
	option persist_interval '0'

config upstream 'server'
	option url 'https://192.0.2.10:7380'
	option fingerprint '3F:A1:...'
	option token_file '/etc/barbican/server.token'

config upstream 'office'
	option url 'https://198.51.100.20:7380'
	option fingerprint 'SHA256:9C0E...'
	option token 'a-token-of-at-least-16-characters'
```

## The `barbican` section

| Option | Default | |
| --- | --- | --- |
| `enabled` | `1` | `0`: on OpenWrt the service doesn't start; when run anyway, the same as `dry_run '1'` |
| `dry_run` | `0` | `1`: follow the agents and save their state, but change nothing in the firewall. See [Dry run](#dry-run) |
| `lists` | `1` | Also apply the agents' blocked countries and blocking feeds, not only their bans and deny lists |
| `ipv6` | `1` with nftables, `0` with ipset | Block IPv6 too. See [IPv6](#ipv6) |
| `state` | `/etc/barbican/state` (`/jffs/barbican/state` for ipset) | Where the state is saved; the lists go next to it, as `<state>.lists` |
| `persist_interval` | `0` | Also save the state every this many seconds; `0`: only when the agent stops cleanly |
| `check_interval` | `60` | Seconds between checks whether another program changed the firewall, and writes of the status (with the drop counters) |
| `status` | `/var/run/barbican-edge.json` (`/tmp/barbican-edge.json` for ipset) | The status file, which `status` and the LuCI pages read |

With nftables (`barbican-edge`):

| Option | Default | |
| --- | --- | --- |
| `table` | `barbican` | The `inet` table it owns: up to 24 letters, digits, `_` and `-` |
| `priority` | `-190` | Of its prerouting chain: after connection tracking (-200), before NAT (-100) |
| `nft` | `nft` | The nft program (it needs JSON support, `nftables-json`) |

With iptables and ipset (`barbican-edge-ipset`):

| Option | Default | |
| --- | --- | --- |
| `prefix` | `barbican` | Of its sets' names |
| `chain` | `BARBICAN` | Its chain in the mangle table |
| `iptables`, `ipset` | `iptables`, `ipset` | The programs |
| `ip6tables` | `ip6tables` | With `ipv6 '1'` only |

## `upstream` sections

One per agent to follow; the section's name (`server` above) is how the edge calls the agent in its status.

| Option | |
| --- | --- |
| `url` | The agent's edge API, `https://<address>:<port>` (its `edge.listen`); only `https://` |
| `fingerprint` | SHA-256 of the agent's certificate, as `barbican edge-fingerprint` prints it: 64 hex digits, colons and a `SHA256:` prefix optional. Only that certificate is accepted |
| `token` or `token_file` | The token of an `[[edge.client]]` of the agent, or a file holding it |
| `enabled` | `0` leaves the agent out |

## Dry run

With `option dry_run '1'` the edge follows its agents, keeps and saves their state, and reports what it would block, but changes nothing in the firewall: no table, no sets. Its status (and LuCI's status page, and the agent's **Settings → Edges**) says **dry run** and counts what would be blocked. To try an edge first, and to see what holding the lists costs the router in memory before they go into the kernel.

## IPv6

With `option ipv6 '0'` the edge tells its agents that it doesn't load IPv6, and they send it none: neither bans of IPv6 addresses nor IPv6 list prefixes. On a router without IPv6, the country and blocklist ranges of IPv6 would take about as much kernel memory as IPv4's (about 250 bytes each on a 32-bit router; roughly 14 MB for Africa, Asia and South America), for nothing. See [Resource use](/reference/resources/).

An agent whose own firewall has `ipv6 = false` doesn't compute IPv6 list prefixes until an edge that loads IPv6 connects: that edge gets its lists a moment later than the others after the agent starts, and from then on the agent keeps them up to date.

`barbican-edge` blocks IPv6 unless told not to; `barbican-edge-ipset` only with `option ipv6 '1'` (and `ip6tables`).

## Saved state

The edge saves what its agents sent when it stops cleanly (a reboot, an upgrade, `stop`), in two compact binary files:

- `state`: each agent's bans and allows, 13 bytes a ban for IPv4 (about 320 KB for 25 000 bans);
- `state.lists`: the agents' country and blocklist prefixes, 5 bytes each for IPv4 and 17 for IPv6, only the families it loads (about 500 KB for 100 000 IPv4 prefixes). Rewritten only when a list changed.

At boot the init script runs `barbican-edge restore` before the firewall and the network start: the saved blocks are in place while no agent is reachable yet. Once one is, it sends whatever changed since.

Nothing else is written to flash, which wears with every write. After a power cut the router starts from the last clean stop; `option persist_interval` (seconds) also saves that often, at the cost of writes.

## Routers without a clock

A router without a battery-backed clock boots in the past, until NTP sets the time. The edge counts the remaining time of bans from the agents' clock (each change says what the agent's clock was when it was sent), and the saved state from when it was saved: bans don't end early or late because the router's clock is wrong.

## Commands

```text
barbican-edge [--config <path>]   run
barbican-edge restore             put the saved blocks in place, then exit (at boot, before the network)
barbican-edge status              print the running agent's status (JSON)
barbican-edge remove              remove its firewall rules and sets, and with them every block
barbican-edge --version
```

The same for `barbican-edge-ipset`. On SIGTERM or SIGINT the agent saves its state and exits. Its log goes to standard error: the system log on OpenWrt (`logread -e barbican`), syslog as `barbican-edge` on Asuswrt-Merlin.
