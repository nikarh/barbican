---
title: Introduction
description: What barbican does, what it is made of, what it works with today, and what it doesn't do.
sidebar:
  order: 1
---

barbican watches the logs of the services you expose to the internet and blocks the addresses that abuse them. Someone scanning for `.env` files, guessing SSH passwords or hammering your login portal gets banned in the firewall within a second, on the server and, if you want, on your router for the whole network. You see what every address tried and why it was banned in a web UI, which is also where you change the rules.

It is one program with one configuration. Reading logs, deciding, blocking, country and blocklist filtering, the UI and the router side all come together, so there are no jails, bouncers, dashboards or cron scripts to wire up yourself.

## How it fits together

```text
 log sources ──► parsers ──► rules ──► decisions ──► firewall on this host
                                          │
                                          └──► edge agents ──► firewall on routers
```

The **agent** reads logs, keeps the database, makes every decision and serves the UI. You run one agent: it is the single place where rules, lists, trust and counters live. If services run on several machines, ship their logs to the agent (see [Planning a deployment](/guides/deployment/)).

**Edge agents** run where packets enter your network, typically a router or the box that terminates TLS for your sites. They follow the agent, hold a copy of what it blocks and drop those packets in their own kernel. They read no logs and make no decisions.

The **UI** is served by the agent on a local socket and reached by browsers through a small container that only answers your reverse proxy, after it authenticated the user.

## Pluggable parts and what exists today

Each stage has a small interface, and the pieces below are the implementations that exist today. Adding a new log format, log store or firewall means adding one more of them; the rest of barbican doesn't change.

| Part | What it does | Available today |
| --- | --- | --- |
| Log sources | Read lines and remember where they stopped | Docker containers (through the Docker API), files (followed across rotation), the systemd journal, VictoriaLogs queries |
| Parsers | Turn a line into an event: an HTTP request, a login, an unknown user, a protocol probe | Traefik access logs, OpenSSH (and SFTP servers built on it), Authelia, and a regular expression for any other log |
| Feeds | Lists of addresses fetched on a schedule, used to block, to allow, or as data for rules | Any URL with addresses or prefixes, one per line, CSV or JSON lines. Presets: Spamhaus DROP, FireHOL level 1, blocklist.de, Tor exit nodes, Cloudflare's ranges |
| Geolocation | Country and network of each address, for display, rules and country blocking | DB-IP Lite (downloaded monthly) or MaxMind GeoLite2 |
| Firewall backends | Keep the kernel's sets equal to what should be blocked | nftables (servers and OpenWrt), iptables with ipset (routers whose kernel has no nftables) |
| Edge platforms | Packaging and service integration on routers | OpenWrt packages with LuCI pages, a tarball with an init script for Asuswrt-Merlin and similar firmware |
| History import | Run old logs through the rules as if read live | Timestamped log files, and a VictoriaLogs exporter |

Packages exist for Debian and Ubuntu (`.deb`, plus an apt repository), Arch Linux (`.pkg.tar.zst`, plus a pacman repository) and OpenWrt (`.apk` and `.ipk`), with static binaries for any other Linux. Architectures are x86-64 and aarch64 for the agent, and x86-64, aarch64 and 32-bit ARM for edge agents. The UI container is published for amd64 and arm64.

## From a log line to a block

1. A source reads a line, and its parser turns it into an event, or skips it.
2. Rules match the event: by path, method, status, host, user agent, user name, whether a blocklist lists the address, and so on. A rule bans when an address reaches its threshold within its time window.
3. The agent records the event, keeps addresses people logged in from trusted, and picks a ban length from the rule and the policy (by country, network or blocklist, longer for repeat offenders).
4. The ban becomes an element of a kernel set with a timeout, on the agent's host and on every edge. The kernel lifts it when it expires, whether barbican is running or not.

Allowed addresses (your allow list, allowing feeds, your LAN and container networks) are never banned, and logins keep their address trusted for a while, so you don't lock yourself out.

[How a log line becomes a ban](/internals/how-it-works/) goes through this in detail.

## What it doesn't do

- It doesn't inspect traffic. It only sees what services log, so an attack that leaves no log line goes unnoticed. A [regular expression source](/guides/sources/#a-log-without-a-parser) covers logs it has no parser for.
- It isn't a general firewall. It owns one table that drops packets from what it blocks and leaves the rest of your rules alone.
- It doesn't protect your bandwidth from floods. Packets are dropped when they reach the host or router, after they crossed your uplink.
- It has no user accounts. Whoever reaches the UI controls it, which is why the UI is only reachable through your reverse proxy's authentication.
- It runs on Linux only, and it is a young project with one maintainer and no shared threat intelligence of its own. [Compared with other tools](/start/comparison/) covers where other tools are a better fit.

Next: the [quick start](/start/quick-start/).
