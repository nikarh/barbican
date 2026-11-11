---
title: How it works
description: From a log line to a ban - sources, parsers, the rule set, the engine, storage, trust, and what happens at boot.
sidebar:
  order: 1
---

barbican is one process (tokio, with a few blocking threads) and one SQLite database.

```text
 logs ─► parser ─► rules ─► engine ─► SQLite
 (docker, file,     │          │
  journald,     (in each   bans, trust
  VictoriaLogs)  source)       │
                               ▼
                    nftables (this host) ── edge API ──► barbican-edge ─► nftables (router)
```

## Sources: parse and match where the lines are

Each [source](/guides/sources/) runs on its own and reconnects when its input goes away. It parses each line and matches it against the rule set right there, reusing its buffers: parsers borrow from the line instead of copying it, and the result of matching is a 64-bit mask of the rules that matched (so at most 64 rules). Only lines that matched a rule, or are logins, go on to the engine as hits; the rest cost a parse and a few regular expression matches.

Each source saves a cursor (a file's inode and offset, the journal's cursor, the time of the last line) every few seconds and when the agent stops, and continues from it after a restart.

## The engine: record, trust, count, ban

The engine takes hits in batches (up to 512, one transaction each). For each hit, judged at the time of its line:

1. An allowed address (the allow list, an allowing feed, the exempt networks) is ignored.
2. The address is recorded with its country and network (from the geolocation databases, cached), and the event counted under the first rule it matched, per address, rule, source and hour, with "what it tried" (`GET example.com/x → 404`, a user name, a probe) stored once and referred to by id.
3. A successful login, or a signed-in user's request, trusts the address for the policy's trust time.
4. Unless the address is trusted or already banned, every banning rule that matched counts the hit in its window, per address; a rule whose threshold is reached bans. The ban's length comes from [the policy](/guides/rules/#the-policy), counting the address's earlier bans.

New events, bans and edge reports are pushed to the UIs that are open (the **Live** panel, the overview's counters).

## Storage

Everything is in SQLite: addresses (4 or 16 bytes), the distinct texts of what they tried, events counted per hour, bans with their history, trust, rules, the policy, feeds and their contents, the allow and deny lists, and the sources' cursors. Events older than the retention (a year by default) are deleted; bans and their addresses stay.

## The state and the firewall

What should be blocked is kept in memory: bans in force, the allow and deny lists, the exempt networks, blocked countries' prefixes (from the country database) and feeds' prefixes. When it changes, the [firewall](/internals/firewall/) gets only the difference, and the [edge API](/edge/protocol/) pushes the change to every connected edge.

Countries and feeds are combined into one list of prefixes, merged, with a version: edges get it again only when its version changes.

## At boot

The unit starts before `network-pre.target` and Docker, and is of `Type=notify`: the agent reports itself ready only once its table is back with every block. No packet reaches a service before the blocks are in place. Bans that ran out while the host was down are left out; the kernel lifts the others on time.

When the agent stops, the table stays: blocks hold while it restarts or is upgraded, and the kernel lifts bans on time. Removing the package removes the table.

## Dry run

With `firewall.enabled = false` (or `--dry-run`) everything above happens except the firewall: no table is made or changed. The UI says **dry run**, and edges still get the bans (and block them, unless they run dry themselves).
