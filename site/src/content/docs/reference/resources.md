---
title: Resource use
description: Memory and CPU of the agent, the UI container and the edge agent, and what the kernel's sets take.
sidebar:
  order: 3
---

Measured with 25 000 bans, Africa, Asia and South America blocked (about 100 000 IPv4 and 87 000 IPv6 prefixes) and three blocklists:

| | Memory | Notes |
| --- | --- | --- |
| Agent (`barbican`) | about 70 MB resident | Much of it the geolocation databases (mapped) and SQLite's cache; idle CPU near zero |
| UI container (`barbican ui-proxy`) | about 4 MB | |
| Edge agent (`barbican-edge`) | 6–10 MB resident, about 20 MB at a full resync | Idle: about 10 ms of CPU per 100 s |
| Kernel: list sets | about 140 B an element on x86-64, about 250 B on 32-bit ARM | The prefixes are loaded merged into ranges: the IPv4 list above is 55 000 elements instead of 102 000, about 8 MB on x86-64, 14 MB on ARM (IPv6 another 57 000 elements, unless off) |
| Kernel: bans | about 140 B a ban | 25 000 bans: 3.4 MB |

The kernel's sets don't slow packets down with their size: a lookup costs about the same with 1 000 elements or 300 000. Loading 100 000 elements takes about a second on a router.

## Keeping it small

- **Leave out IPv6 where there is none**: `firewall.ipv6 = false` on the agent, `option ipv6 '0'` on an edge. Its country and blocklist list is as large as IPv4's.
- **Country blocks** are what takes the most kernel memory. Settings shows, as you add countries and continents, how many prefixes and addresses they are.
- **Lists on an edge**: `option lists '0'` gives a router only the bans and the deny list, not the countries and blocking feeds.
- **Events** are counted per address, rule, source and hour, not stored line by line, and deleted after **Keep events** (a year by default). Addresses are stored as 4 or 16 bytes, and every distinct "what it tried" once.

## Work done

- Only lines that match a rule, or are logins, reach the engine: parsing and matching happen in each source without allocating.
- Firewall changes go straight over netlink, one small transaction each whatever the sets hold; only what changed is written. Once a minute (`firewall.check_interval`) the agent asks the kernel for the ruleset's generation, one small request, to notice changes made by other programs.
- An edge's full state (25 000 bans and 100 000 list prefixes) is 2.4 MB on the wire and decodes in under a millisecond.
