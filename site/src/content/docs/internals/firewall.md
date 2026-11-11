---
title: The firewall
description: barbican's nftables table, its chain and sets, how they are kept up to date over netlink, and what happens when something else changes them.
sidebar:
  order: 2
---

barbican owns one table, `inet barbican` (`firewall.table`); nothing else on the host is changed. Its one chain hooks prerouting at priority -190 (`firewall.priority`): after connection tracking (-200) and before destination NAT (-100), so it sees what arrives for the host itself, for its containers (before Docker's DNAT), and, on a router, everything forwarded.

## What the chain does

1. Packets of connections the host (or a LAN client of a router) opened are accepted: replies are never blocked, so blocking a country doesn't stop the host downloading from it.
2. Sources in the allow sets are accepted: the allow list, allowing feeds and the exempt networks.
3. Sources in the block sets are dropped: bans and the deny list. Single addresses are in hash sets (`host4`, `host6`), prefixes in interval sets (`net4`, `net6`), each element with its remaining time, so the kernel lifts bans on time even when barbican isn't running.
4. Sources in the list sets are dropped: blocked countries and blocking feeds.

Drops are counted per kind (bans, lists), which the overview shows.

```bash
sudo nft list table inet barbican
```

## List sets hold ranges

Countries and feeds are lists of prefixes, but the list sets hold address ranges: an interval set keeps any range as one element, as much memory as one prefix, and a run of adjacent prefixes that is no prefix itself is one range. A country's prefixes make about half as many ranges: the 101 761 IPv4 prefixes of Africa, Asia and South America are 55 339 ranges. The same addresses are dropped either way.

A small set (`lists_version`) holds the version of the lists loaded, written in the same transaction: after a restart the agent knows whether the kernel has the lists already, and doesn't load unchanged lists again.

## Changes over netlink

The table and its chain are made with `nft` (`firewall.nft`). Elements are changed straight over netlink, in the kernel's `nf_tables`: each change is one small transaction, whatever the sets hold. (`nft` itself reads every element of every set before it changes anything: seconds once a blocklist with hundreds of thousands of prefixes is loaded.)

Only what changed is written: a ban, a lift, an edit of the allow or deny list, new lists (only the ranges that changed). The kernel times bans out by itself.

## When something else changes nftables

What the kernel has is read back at the start, and again only when another program changed nftables. The kernel counts every commit in the ruleset's generation (what `nft` checks its own cache with), and barbican asks for it every minute (`firewall.check_interval`), one small request. So a flushed ruleset, a restarted firewall service or a hand-edited set is put right within a minute, and an idle agent costs next to nothing.

It doesn't subscribe to nftables' notifications: while anyone listens, the kernel makes a notification of every element of every commit and holds them until the commit ends, gigabytes for another program's large set load.

If netlink fails (an unexpected kernel), everything goes through `nft` instead: changes as `nft -f` scripts, and the sets read back with `nft -j list set` every minute.

## Boot and stop

The unit runs before `network-pre.target` and Docker, and reports ready only once the table is back: no packet reaches a service before the blocks are in place. Stopping barbican leaves the table in place, with the kernel lifting bans on time; removing the package removes it.

A table with another layout (from another version) is replaced.

## On routers

The [nftables edge agent](/edge/overview/) keeps the same table on an OpenWrt router, from the union of what its agents send. `barbican-edge-ipset` does the same with an iptables chain in the mangle table, jumped to first in PREROUTING, and ipsets: hash sets for addresses and prefixes, with timeouts (at most 24.8 days, renewed while an agent runs).
