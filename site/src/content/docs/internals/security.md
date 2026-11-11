---
title: Security
description: What Barbican trusts, how the agent's service is sandboxed, and how to report a vulnerability.
sidebar:
  order: 5
---

Barbican decides who may reach a server, so what matters is who can change its decisions: users of the UI, whoever writes the logs it reads, and the edge API.

## The UI

The UI has no login of its own and full control over Barbican, so it is reachable only through a unix socket guarded by the kernel's peer credentials, and from browsers only through a proxy in a container behind your authenticating reverse proxy. [How the UI is protected](/internals/control-surface/) explains each layer and what an attacker in each position can do.

## Logs

Barbican believes the logs it reads. Whoever can write lines into them can get addresses banned, and only addresses that aren't allowed: no rule bans an allowed or exempt address, and every ban can be lifted in the UI. Read logs that only the services write. A reverse proxy should log the address it received the connection from (or, behind a CDN, an address it trusts the CDN for), not one from a header any client can set.

Trust works the other way: a successful login keeps an address from being banned for a while. Logins come from the services' own logs (sshd, Authelia).

## The edge API

Edges connect out to the agent over TLS, accept only the certificate whose fingerprint they are configured with, and present a token of their own. See [How agents and edges talk](/internals/edge-link/#why-the-connection-is-safe).

The self-signed certificate and its key are made on the first start next to the database, readable only by the agent. To change them, delete them (or set `edge.cert` and `edge.key`), restart, and give the edges the new fingerprint.

## The service

The systemd unit runs Barbican with as little as it needs:

- `DynamicUser=yes`: a user of its own, made up by systemd; its state (`/var/lib/barbican`) is private (mode 0700), files it makes are its own only (`UMask=0077`).
- One capability, `CAP_NET_ADMIN`, for nftables (`AmbientCapabilities` and `CapabilityBoundingSet`), and `NoNewPrivileges`.
- Groups: `systemd-journal` for journald sources, `barbican-ui` for the UI's socket. Docker sources need the Docker API: give it a read-only socket proxy rather than the `docker` group, which is root on the host.
- `ProtectSystem=strict` (the file system is read-only but for its state directory and `/run/barbican-ui`), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, protected kernel tunables, modules, logs, control groups, clock and host name, `ProtectProc=invisible`, no namespaces, realtime or SUID, `MemoryDenyWriteExecute`, native system calls of `@system-service` only, and the address families `AF_UNIX`, `AF_NETLINK`, `AF_INET` and `AF_INET6`.

The edge agents run as root on their routers, as router services do.

## Reporting a vulnerability

A way to get an address past Barbican's bans, to get someone else's address banned, or to change its decisions without access to its UI or edge API is a security issue. Please report it privately, through [GitHub's vulnerability reporting](https://github.com/nikarh/barbican/security/advisories/new), not in a public issue, with the log lines or requests involved and how to reproduce it.
