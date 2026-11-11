---
title: How agents and edges talk
description: The connection between the agent and edge agents, why it is safe on an untrusted network, what an edge can and cannot learn or do, resync after restarts, offline behaviour, and the cost on a router.
sidebar:
  order: 3
---

An edge agent keeps one connection open to the agent it follows. The agent pushes every change down it the moment it happens, and the edge reports back what it applied and what its firewall dropped.

## Who connects to whom

Edges connect out to the agent's edge API. Nothing ever connects to an edge, so a router running one opens no port. The agent listens on the address you give it (`edge.listen`), usually on the LAN.

## Why the connection is safe

- **TLS with a pinned certificate.** The agent makes a self-signed certificate on its first start (or uses one you give it). Each edge is configured with that certificate's SHA-256 fingerprint and accepts that certificate and no other. No certificate authority is involved, so it works with bare LAN addresses, and nobody between the edge and the agent can impersonate the agent, read the traffic or inject bans or allows.
- **A token per edge.** Each edge has its own client entry on the agent with a token of at least 16 characters. A wrong token is refused before anything else is sent. Removing an edge's client entry (and restarting the agent) cuts that edge off without touching the others.
- **Narrow content.** The agent sends an edge only what it blocks and allows: addresses, prefixes, end times and a list version. No logs, events, rules, user names or configuration ever cross the link. An edge reports counters and its own state, which only appear in the agent's UI.

So the worst a compromised edge can do is lie about its own counters, or stop blocking at the place it runs. It can't change the agent's decisions or see anything beyond the block list. Someone who steals an edge's token can read the block list, and you revoke it by removing that client.

## The conversation

1. The edge sends a hello: its token, the protocol version, where its copy of the agent's state is (an epoch and a sequence number), the version of the lists it holds, whether it enforces or runs dry, and whether it wants the lists and IPv6.
2. The agent checks the token and version, or refuses with the reason.
3. It then sends what the edge is missing: only the changes since the edge's sequence number, or the whole state when that's not possible (the agent restarted, or the edge was away too long). If the edge's lists are outdated, the merged country and blocklist list follows, in chunks the edge applies only once all of them arrived.
4. After that, each ban, lift and allow is pushed as it happens, and the lists whenever their version changes.
5. The edge sends status reports when it connects, when something changes, and at least once a minute: what it holds, its drop counters, whether it enforces, errors, memory and uptime, and the other agents it follows.
6. Each side pings after 20 seconds of silence and drops the connection after 60. The edge reconnects with a growing pause (2 to 60 seconds) and resumes from where it was.

An edge that doesn't load IPv6, or doesn't want the lists, gets none of them, which saves both bandwidth and the router's memory.

## Offline behaviour

An edge that can't reach its agent keeps what it has. Its blocks stay in the kernel, and the kernel lifts bans as they expire. When the agent comes back, the edge receives only what changed.

At boot, the edge restores its saved state before the network comes up, so a router that restarts while the agent is down still blocks. The state is written to flash only on a clean stop (reboot or upgrade), as two compact files: about 320 KB for 25 000 bans and 500 KB for 100 000 list prefixes. Nothing else is written during normal operation, which matters for a router's flash.

Routers without a battery-backed clock boot with the wrong time until NTP fixes it. Every change carries the agent's clock, and the saved state carries the time it was saved, so ban lengths come out right either way.

## The format and its cost

The link uses a compact binary format of length-prefixed messages with fixed-size records: 18 bytes for an address or prefix, 26 for a ban with its end time. A full state of 25 000 bans and 100 000 list prefixes is 2.4 MB and takes under a millisecond to decode. A new ban reaches a router's firewall in about half a second, most of which is the edge waiting briefly to apply changes that arrive together in one go.

| Message | Direction | Carries |
| --- | --- | --- |
| hello | edge → agent | protocol version, token, epoch and sequence, list version, edge version and firewall backend, flags |
| welcome | agent → edge | the client's name, the agent's version |
| refuse | agent → edge | the reason, and the protocol version the agent speaks |
| ping | both | nothing |
| changes | agent → edge | bans, lifts, allows and their removal, the sequence and the agent's time; full state or a difference |
| list | agent → edge | a chunk of the merged list with its version |
| status | edge → agent | the report, with room for additions older agents skip |

Messages are at most 4 MiB, so a large state spans several. Agents and edges of one release speak the same protocol version. An agent refuses an edge of another version and tells it which one it speaks, so update them together.
