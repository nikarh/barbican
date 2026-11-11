---
title: Introduction
description: What barbican does, its parts, and how a log line becomes a block in the firewall.
sidebar:
  order: 1
---

barbican bans addresses that abuse your services. It reads the logs of a reverse proxy, an SSH or SFTP server and an authentication portal; rules decide what counts as abuse; offenders are blocked with nftables, on the server and, through a small edge agent, on a router for the whole network. Countries and continents can be blocked as a whole, and public blocklists used, as blocks, as allow lists, or as data for rules. A web UI shows what every address tried and what was decided, and is where rules, ban lengths, countries, lists and blocklists are edited.

It does what fail2ban, a log pipeline and a dashboard do together, in one process with a SQLite database.

## The parts

- **The agent** (`barbican`) runs on a server whose logs it reads. It parses them, matches the events against its rules, records what matched, bans, and keeps one nftables table of its own equal to what it blocks. It runs as a systemd service with one capability, `CAP_NET_ADMIN`.
- **The UI** is served by the agent on a unix socket only its group may use, and to browsers by a container next to your other ones (`barbican ui-proxy`, the image `ghcr.io/nikarh/barbican`) that answers only your reverse proxy. It has no login of its own: it goes behind the reverse proxy's authentication. See [the web UI](/guides/ui/).
- **Edge agents** (`barbican-edge` with nftables on OpenWrt, `barbican-edge-ipset` with iptables and ipset on firmware without nftables) follow one or more agents and block what they block on a router, for everything it forwards. See [edge agents](/edge/overview/).

```text
 logs ─► parser ─► rules ─► engine ─► SQLite
 (docker, file,     │          │
  journald,     (in each   bans, trust
  VictoriaLogs)  source)       │
                               ▼
                    nftables (this host) ── edge API ──► barbican-edge ─► nftables (router)
```

## From a log line to a block

1. A **source** reads a log: a container's log through the Docker API, a file, the systemd journal, or a VictoriaLogs query. Each continues where it stopped after a restart. See [sources and parsers](/guides/sources/).
2. Its **parser** turns a line into an event: an HTTP request, a failed or successful login, a login as an unknown user, or a protocol probe. Lines that are none of these are skipped.
3. **Rules** match events by their path, method, status, user agent, user name, source, whether the proxy had a route for the request, or whether a blocklist lists the address. A rule bans once its threshold is reached within its time window, or only records. See [rules and policy](/guides/rules/).
4. The **engine** records what matched, counted per address, rule, source and hour, keeps addresses people logged in from trusted, and bans. The ban's length comes from the rule or the policy, per country, network or blocklist if you set one, and grows for repeat offenders.
5. The **firewall** gets the ban as an element of an nftables set with a timeout: the kernel lifts it on time, whether barbican runs or not. Edge agents get it pushed within a fraction of a second. See [the firewall](/internals/firewall/).

Addresses on the allow list, in an allowing feed, in the exempt networks (private ranges by default), or trusted after a login are recorded but never banned.

## What it isn't

- It doesn't look at traffic, only at what services log. An attack that leaves no log line, or a line no parser understands, goes unnoticed; a [regular expression source](/guides/sources/#a-log-without-a-parser) covers other logs.
- It isn't a general firewall: it owns one table (`inet barbican`) that drops packets from what it blocks, and changes nothing else on the host.
- It doesn't protect a link from floods: packets are dropped when they reach the host (or the router), after they used the bandwidth. Replies to connections the host opened always pass, whoever sends them.
- It has no users or login: whoever reaches its UI can change everything. Put the UI behind authentication.

Next: the [quick start](/start/quick-start/).
