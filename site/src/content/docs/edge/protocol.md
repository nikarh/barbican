---
title: The edge protocol
description: How an edge agent follows an agent - one TLS connection, binary frames, a journal of changes, lists in chunks, status reports and heartbeats.
sidebar:
  order: 4
---

One long-lived TLS connection per edge and agent, the edge connecting. On it, length-prefixed binary frames with fixed-width little-endian fields, read in place: a received frame is validated once and its records are then used without copying. The frames are described in [`crates/barbican-common/src/edge/wire.rs`](https://github.com/nikarh/barbican/blob/main/crates/barbican-common/src/edge/wire.rs); this page is an overview.

## The conversation

1. The edge says **hello**: the protocol version, its token, where its copy of the agent's state is (an epoch and a sequence number), the version of the list it has, its own version and backend, and whether it enforces, wants the lists, and loads IPv6.
2. The agent checks the token and the protocol version. A wrong one is **refused** with the reason (and, for the version, the one the agent speaks), and the connection closed.
3. Otherwise it answers **welcome** (with the client's name and its own version) and sends what the edge misses: the changes since its sequence number from its journal, or the whole state when it can't (the agent restarted, which changes the epoch, or the changes are too old to still be in the journal). When the edge's list version differs, the combined list of blocked countries and blocking feeds follows, in chunks the edge applies once all arrived.
4. From then on the agent pushes each change as it happens (bans, lifts, allows, the deny list), and the list when it changes.
5. The edge sends **status** reports: on connecting, when something changed, and at least every minute: what it applied and when, how many blocks and listed prefixes it holds, its drop counters (blocked and listed packets and bytes), whether it enforces, its version, backend, error, memory and uptime, and the other agents it follows. Reports can carry extensions an older agent skips, so more can be added without a new protocol version.
6. Either side **pings** after 20 seconds without sending anything else and drops the connection after 60 seconds without hearing anything. The edge then connects again, 2 to 60 seconds apart while it fails, and carries on from where it was.

## Frames

Every frame is a `u32` length, then a type byte and its payload; at most 4 MiB and 65 536 records a frame, so large changes and lists span several frames.

| Frame | Type | Direction | |
| --- | --- | --- | --- |
| HELLO | `0x01` | edge → agent | protocol, flags, sequence, epoch, list version, token, edge version, backend |
| WELCOME | `0x02` | agent → edge | protocol, client name, agent version |
| REFUSE | `0x03` | agent → edge | the reason |
| PING | `0x04` | both | |
| CHANGES | `0x10` | agent → edge | full or not, more follow or not, sequence, the agent's time, epoch, blocks, unblocks, allows, unallows |
| LIST | `0x11` | agent → edge | last chunk or not, total, offset, version, prefixes |
| STATUS | `0x20` | edge → agent | the report, then extensions |

Records are fixed-size: a net (an address or prefix) is 18 bytes (family, prefix length, 16 address bytes), a block 26 (a net and its end time, `0` for never). Times are unix seconds of the sender's clock; changes carry the agent's time when they were sent, so an edge with a wrong clock still counts the remaining time of bans right.

## Costs

A full state of 25 000 bans and 100 000 list prefixes is 2.4 MB and decodes in under a millisecond. A ban reaches a router's firewall in about half a second, most of it the edge gathering changes that come together.

## Versions

The protocol has a version (currently 2). Agents refuse edges of another version and say which one they speak: update agents and edges together. A change to the protocol either keeps older edges working, or bumps the version.

## Security

The connection is TLS only. The edge accepts exactly the certificate whose SHA-256 fingerprint it is configured with, not a certificate authority's word, so it works with bare LAN addresses, and nobody between an edge and its agent can read the token or feed the edge bans or allow lists. Each edge has its own token (at least 16 characters); what an agent sends is only ever what that agent blocks and allows, and what an edge reports only reaches the agent's UI. See [Security](/internals/security/#the-edge-api).
