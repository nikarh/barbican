---
title: Planning a deployment
description: Where to run the agent and edge agents so that blocks actually stop traffic, reverse proxies and CDNs, several servers, exempt networks, routers, and the mistakes that make a setup look like it works when it doesn't.
sidebar:
  order: 0
---

Barbican can only drop a packet on a machine that receives it from the attacker's own address. Most setups that "don't block anything" break that rule somewhere: a proxy in front of the server, NAT on the router, a CDN. This page goes through where each part should run and the details that decide whether a ban actually stops anyone.

## Block where the connection arrives

Draw the path a connection from the internet takes to your service, and look at the first machine that receives it with the client's real address as the source. That machine is where blocking works.

| Your setup | The server sees | Block on |
| --- | --- | --- |
| The router forwards a port straight to the server (SSH, SFTP, a game server) | the client's address | the server (the agent's own firewall), or the router |
| A reverse proxy on the same server as the services (Traefik, nginx in Docker) | the client's address | the server |
| A separate box terminates TLS and proxies to the server (HAProxy on a router or access point, a load balancer) | the proxy's address | the proxy box, with an edge agent there |
| A CDN or tunnel in front (Cloudflare proxy, Cloudflare Tunnel) | the CDN's addresses | nowhere by address: see [CDNs](#behind-a-cdn) |

In the third case the agent still learns the client's address, because the proxy passes it on (`X-Forwarded-For` or the PROXY protocol) and your reverse proxy logs it. The agent can ban it, but a ban in the server's own firewall does nothing, because no packet from that address ever reaches the server. Run an edge agent on the proxy box and the ban takes effect there.

An edge agent on the router covers every port the router forwards, for every server behind it, which also catches services whose logs Barbican doesn't read.

## One agent, many hosts

Run one agent. It holds the rules, the policy, the lists, the trusted logins and the counters, and it is the only UI. If your services run on several machines, ship their logs to the agent's host and read them there, for example with a log collector into VictoriaLogs and a [VictoriaLogs source](/guides/sources/#inputs) on the agent. Every machine that needs to block runs an edge agent following that one agent.

Several independent agents work, but each counts only what it sees. A scanner that tries three paths on one server and three on another reaches no threshold anywhere. Each has its own allow list, countries and feeds, and an edge following several agents merges what they block, so a conflict between two allow lists ends up decided by whichever applies first.

## Behind a CDN

With a CDN proxying your site, every request reaches you from the CDN's addresses. Banning those would block your own visitors, and geolocation databases place some of Cloudflare's addresses in whatever country, so blocking a continent can drop your visitors at random.

- Set up the **Cloudflare** source of the feed catalog (both lists, IPv4 and IPv6, allow). Cloudflare's ranges are then never banned and always let through.
- Configure your reverse proxy to log the visitor's address from the header the CDN sets, trusting that header only from the CDN's ranges. Barbican then records and bans the visitor, which helps for anything that reaches you without the CDN, and keeps your data meaningful.
- Blocking visitors behind a CDN by address has to happen at the CDN itself (its firewall rules), not on your network.

## Addresses that are never banned

Write out the networks that must never be blocked under `[exempt]`, even if they match the defaults:

```toml title="/etc/barbican/config.toml"
[exempt]
# The LAN, container networks, carrier-grade NAT (VPN overlays often live there).
nets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]
```

- Make sure every Docker network on the host falls inside these. Docker's default address pools are inside `172.16.0.0/12` and `192.168.0.0/16`; a custom pool elsewhere needs adding.
- Exempt addresses are accepted before any drop rule, so even a public blocklist that lists private ranges (some do, as "bogons") can't block your LAN.
- Your own devices reach your services through NAT loopback when they use the public name from inside: the server then sees the router's LAN address, which is exempt. That's the reason a test from inside your network is never banned. Test from a phone on mobile data, or another outside address.

## Try it in dry run first

Start the agent with `[firewall] enabled = false` and each edge with `option dry_run '1'`. Everything works except the firewall: rules count, bans are recorded with their reasons, edges receive and report what they would block. Leave it for a day or two, read **Bans**, and check nothing you care about is there. Logins make addresses trusted during that time too, so your own addresses are known before you enforce.

## IPv6

Turn IPv6 off where you don't have it: `firewall.ipv6 = false` on the agent, `option ipv6 '0'` on an edge. Country and blocklist lists are about as large for IPv6 as for IPv4, so on a host without IPv6 that is kernel memory spent for nothing. An edge without IPv6 tells the agent, which then sends it no IPv6 at all.

## Routers

Before turning blocking on at a router, run its edge agent in dry run and look at its memory: the status shows the agent's own use, and [Resource use](/reference/resources/) has measured numbers for the kernel's sets. As a guide, an edge agent uses 6 to 10 MB, 25 000 bans take about 3.4 MB of kernel memory, and three continents of IPv4 country ranges about 14 MB on a 32-bit ARM router. If that is too much, `option lists '0'` gives the router only the bans, and the agent's host keeps blocking countries.

The edge writes to flash only when it stops cleanly (a reboot, an upgrade). After a power cut the router starts from the last clean stop, and catches up as soon as the agent is reachable.

## The kernel

- Barbican needs the nftables modules for sets and connection tracking (`nft_ct` among them). After a kernel upgrade without a reboot, the running kernel's modules may be gone from disk, and the agent fails to set up its table. Reboot into the new kernel.
- The chain hooks prerouting at priority -190: after connection tracking (-200) and before Docker's port forwarding (-100). Blocks apply to the host, to published container ports, and to everything a router forwards.
- Replies to connections the host opened always pass. Blocking a country doesn't stop the host downloading updates from it.

## Check that blocking works

The overview counts packets dropped, for the host and for each edge separately, with totals that survive restarts. If a banned scanner keeps appearing in the logs while the drop counter stays at zero, its packets reach the machine some other way than the one doing the blocking: go back to [the first section](#block-where-the-connection-arrives).

`sudo nft list table inet barbican` shows the table, its sets and the counters on a host or an OpenWrt edge.
