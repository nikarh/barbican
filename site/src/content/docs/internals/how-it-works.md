---
title: How a log line becomes a ban
description: Sources and cursors, parsing and matching, counting windows, trust, ban lengths, storage, what is kept in memory, boot, and importing history.
sidebar:
  order: 1
---

```text
 source ─► parser ─► rule match ─► engine ─► database
                                     │
                                     ├─► kernel sets on this host
                                     └─► edge agents
```

## Reading

Each [source](/guides/sources/) runs on its own. It reads lines from its input and keeps a cursor: a file's identity and offset, the journal's cursor, or the time of the last line read from Docker or VictoriaLogs. The cursor is saved every few seconds and when the agent stops, so after a restart reading continues where it stopped, without reading lines twice or skipping a gap (within what the input still has). When an input goes away (a container restarts, a file rotates, a log store is unreachable) the source reconnects with a growing pause.

The source parses each line and matches it against the rules right there. Most lines match nothing, and those cost one parse and a few pattern matches and go no further. Only lines that matched a rule, and logins, are passed on to the engine.

## Deciding

The engine handles those events in order of their time, in batches written to the database in one transaction each. For each event:

1. If the address is allowed (allow list, allowing feed, exempt networks), it stops here.
2. The address is recorded with its country and network, and the event is counted under the first rule it matched, per address, rule, source and hour. What it tried (`GET example.com/x → 404`, a user name, a probe's description) is stored once and referred to after that.
3. A successful login, or a request of a signed-in Authelia user, makes the address trusted for the policy's trust time.
4. Unless the address is trusted or already banned, every banning rule it matched counts the event in that rule's time window for the address. A rule that reaches its threshold bans.

A ban's length is decided when it starts: the rule's length or the default, then the shortest length that applies for the address's country, network or the feeds that list it, multiplied for each earlier ban of the address (repeat offenders), up to the policy's maximum. Lifting a ban by hand or letting it expire keeps it in the history, where it counts as an earlier ban next time.

Counting per hour keeps the database small: a scanner that sends the same request a thousand times in an hour is one row with a count of a thousand.

## What should be blocked

The agent keeps the current picture in memory: bans in force, allow and deny lists, exempt networks, the prefixes of blocked countries (from the geolocation database) and of blocking feeds. Countries and feeds are merged into one list with a version. When anything changes, only the difference goes to the [kernel](/internals/firewall/) and to the [edge agents](/internals/edge-link/).

Open UIs get new events, bans and edge reports as they happen.

## Storage

Everything lives in one SQLite database: addresses (4 or 16 bytes each), the texts of what they tried, hourly event counts, bans with their history, trust, rules, the policy, feeds and their contents, allow and deny lists, drop counters, and the sources' cursors. Events older than the retention (a year by default) are deleted; bans and their addresses stay.

## Boot and stop

The systemd unit starts before the network and Docker, and the agent reports itself ready only once its table holds every block. No packet reaches a service before the blocks are in place. Bans that expired while the host was down are left out.

When the agent stops, its table stays. Blocks hold while it restarts or is upgraded, and the kernel keeps lifting bans on time. Removing the package removes the table.

## Dry run

With `[firewall] enabled = false` (or `--dry-run`) the agent does everything above except touch the kernel. Edge agents still receive the bans and enforce them, unless they run dry themselves.

## Importing history

`barbican import` feeds old log lines through the same engine, at the times they were written. Events land in their hours, trust and bans are judged as they would have been, and bans end when they would have ended. A year-long ban from a month ago is still in force after the import; most short ones are long over. See [Importing old logs](/guides/import/).
