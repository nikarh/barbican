---
title: How the UI is protected
description: Why the UI has no network listener, who may use the agent's socket, why the UI proxy only runs in a container behind a trusted reverse proxy, and what local processes, LAN hosts and internet attackers can and cannot do.
sidebar:
  order: 4
---

The UI is full control over barbican: whoever can use it can ban anyone, lift any ban, allow any address and rewrite every rule. It has no login of its own, because your reverse proxy already authenticates users better than a second password prompt would. So the work goes into making sure nothing but an authenticated user, through your reverse proxy, can reach it.

## No network listener

The agent serves the UI and its API only on a unix socket. There is no option for a TCP port, not even on localhost, because a port is open to every process on the host: a compromised container with host networking, a script, anything.

The socket is guarded twice:

- File permissions: the socket and its directory belong to a dedicated group (`barbican-ui`), modes 0660 and 2770.
- Peer credentials: for every connection, the agent asks the kernel which user and groups the connecting process has. It accepts root, its own user and members of the socket's group, primary or supplementary, and refuses and logs everyone else. A mistake in file permissions doesn't open the UI.

From your machine you can reach it through SSH, which forwards a local port to the remote socket as your user (who must be in the group).

## The UI proxy runs in a container

Browsers reach the UI through `barbican ui-proxy`, which serves the page and passes the API to the socket. It is published as a container image, and that is the only supported way to run it:

- The container gets the socket's group and nothing else: no capabilities, a read-only file system, no published port, no host network and no shared IPC.
- It sits on a network of its own that only your reverse proxy joins.
- It answers only requests that come from the reverse proxy's address (`--trusted-proxy`) and, with `--user-header`, only those carrying the user name your reverse proxy authenticated. Without a trusted proxy it refuses to start.

Run on the host instead, anything that reaches its port, local processes included, would get the UI. The proxy warns when it doesn't look like it runs in a container.

Trust the reverse proxy's own address (a `/32`), never the whole container network: that network's gateway is the host, so anything on the host could otherwise reach the proxy through it and send any header it likes.

## Cross-site requests

A reverse proxy that authenticates with a cookie would let any website the user visits open a WebSocket to the UI with that cookie. The agent refuses WebSockets whose `Origin` doesn't match the UI's own host, so only the UI's own page can connect.

## No way around it in release builds

Development needs shortcuts, such as a proxy without a trusted proxy. Those exist only in debug builds, and the released binaries and images don't contain them: no configuration or flag can turn them on.

## What an attacker can and can't do

| Who | Can | Can't |
| --- | --- | --- |
| Anyone on the internet | Get their own address banned. Use a CDN or open proxy to send requests from addresses you don't ban | Reach the UI or the agent's socket. Get an allowed or exempt address banned. Talk to an edge |
| A host on your LAN | Reach the reverse proxy's login page. Connect to the edge API port | Use the edge API without a token, or impersonate the agent to an edge (pinned certificate). Reach the UI proxy directly |
| A process on the agent's host, not root and not in the group | Write to logs it may write to, and so get addresses banned (never allowed ones) | Connect to the socket (peer credentials), reach the UI proxy, change the firewall |
| Another container on the same host | Nothing through barbican | Reach the UI proxy, which sits on a network of its own and answers only the reverse proxy's address |
| Root on the agent's host | Everything | |

Everything an attacker can achieve through logs is limited to banning addresses that aren't allowed, and every ban can be lifted in the UI. See [Security](/internals/security/) for logs, the service's sandbox and reporting vulnerabilities.
