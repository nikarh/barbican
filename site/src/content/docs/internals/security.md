---
title: Security
description: Who can reach what - the UI without a login and its Origin check, the edge API's pinned TLS and tokens, the service's sandbox, and reporting vulnerabilities.
sidebar:
  order: 3
---

barbican decides who may reach a server. What matters is who can change its decisions: the UI, whoever writes the logs it reads, and the edge API.

## The UI

The UI has **no login**: anyone who reaches it can ban, lift, allow, and change every rule. Keep `ui.listen` on localhost, a private address or a Docker bridge's address, and put it behind a reverse proxy with authentication, or a VPN. See [Behind a reverse proxy](/guides/reverse-proxy/).

A proxy that authenticates by a cookie would let any site the user visits open the UI's WebSocket with that cookie. So the agent refuses a WebSocket whose `Origin` header doesn't match its `Host` (or `X-Forwarded-Host`): only pages of the UI's own origin can connect. Clients that send no `Origin` (scripts, not browsers) aren't checked; they still have to get past the proxy.

With the UI in a container, the agent serves the API on a unix socket that only members of the `barbican-ui` group may use (mode 0660, in a directory of mode 2770), and the image runs read-only, without capabilities, as an unprivileged user. Nothing listens on a port of the host.

## Logs

barbican believes the logs it reads. Whoever can write lines into them can get addresses banned, and only addresses that aren't allowed: no rule bans an allowed or exempt address, and every ban can be lifted in the UI. Read logs that only the services write. A reverse proxy should log the address it received the connection from (or, behind a CDN, an address it trusts the CDN for), not one from a header any client can set.

Trust works the other way: a successful login keeps an address from being banned for a while. Logins come from the services' own logs (sshd, Authelia).

## The edge API

- TLS only. An edge accepts exactly the certificate whose SHA-256 fingerprint it is configured with (no certificate authority, so it works with bare LAN addresses): nobody between an edge and its agent can read the token, or feed the edge bans or allow lists.
- Each edge has its own token, at least 16 characters, checked when it connects; a wrong token is refused.
- Edges connect out; nothing connects to them.
- What an agent sends an edge is only ever what that agent blocks and allows; what an edge reports only reaches the agent's UI.

The self-signed certificate and its key are made on the first start next to the database, readable only by the agent. To change them, delete them (or set `edge.cert` and `edge.key`), restart, and give the edges the new fingerprint.

## The service

The systemd unit runs barbican with as little as it needs:

- `DynamicUser=yes`: a user of its own, made up by systemd; its state (`/var/lib/barbican`) is private (mode 0700), files it makes are its own only (`UMask=0077`).
- One capability, `CAP_NET_ADMIN`, for nftables (`AmbientCapabilities` and `CapabilityBoundingSet`), and `NoNewPrivileges`.
- Groups: `systemd-journal` for journald sources, `barbican-ui` for the UI's socket. Docker sources need the Docker API: give it a read-only socket proxy rather than the `docker` group, which is root on the host.
- `ProtectSystem=strict` (the file system is read-only but for its state directory and `/run/barbican-ui`), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, protected kernel tunables, modules, logs, control groups, clock and host name, `ProtectProc=invisible`, no namespaces, realtime or SUID, `MemoryDenyWriteExecute`, native system calls of `@system-service` only, and the address families `AF_UNIX`, `AF_NETLINK`, `AF_INET` and `AF_INET6`.

The edge agents run as root on their routers, as router services do.

## Reporting a vulnerability

A way to get an address past barbican's bans, to get someone else's address banned, or to change its decisions without access to its UI or edge API is a security issue. Please report it privately, through [GitHub's vulnerability reporting](https://github.com/nikarh/barbican/security/advisories/new), not in a public issue, with the log lines or requests involved and how to reproduce it.
