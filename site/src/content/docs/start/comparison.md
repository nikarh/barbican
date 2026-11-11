---
title: Compared with other tools
description: How Barbican relates to fail2ban, CrowdSec, sshguard, reaction, blocklist scripts and router packages such as banIP and pfBlockerNG.
sidebar:
  order: 3
---

Most of what Barbican does exists elsewhere in pieces. The reason to use it is that the pieces come in one program with one configuration and a UI: log parsing, rules, bans, country and blocklist filtering, and the same blocks pushed to routers. If you already run one of the tools below and it does what you need, there may be no reason to switch. This page tries to say where each one fits.

The descriptions of other tools come from their own documentation, linked at the bottom of the page.

## At a glance

| | Barbican | fail2ban | CrowdSec | sshguard | reaction | banIP (OpenWrt) | pfBlockerNG (pfSense) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bans from logs | yes | yes | yes | yes | yes | for logins on the router itself | no |
| Detection | rules over parsed events (HTTP, logins, probes) | regex filters per jail | parsers and scenarios from a hub | its own patterns for SSH and other services | regex patterns over command output | a monitor of the router's log | none |
| Country blocking | yes | no | not covered here | no | no | yes | yes |
| Blocklist feeds | yes, also as allow lists or rule data | no | community blocklist and more in its console | no | no | yes, many presets | yes |
| Where it blocks | the host, and routers through edge agents | the host | wherever a remediation component runs | the host | wherever its actions run | the router | the firewall |
| Several hosts | one agent, logs shipped to it, edges follow it | each host on its own | a local API that machines report to | each host on its own | each host on its own | the router on its own | the firewall on its own |
| Web UI | built in, self-hosted | no | a hosted console | no | no | LuCI | pfSense's UI |
| Shared threat intelligence | no | no | yes | no | no | public feeds only | public feeds only |

## fail2ban

fail2ban is the classic: jails pair a regular expression filter with a log file and an action, usually firewall rules that reject the address for a while. It ships filters for a long list of services and runs almost anywhere Python does. Repeat offenders can get longer bans (`bantime.increment`).

Barbican covers fewer services out of the box (Traefik, OpenSSH, Authelia, plus regular expressions), and in exchange it understands what it reads. A rule says "40 responses 401, 403 or 404 within 10 minutes from one address" or "any request for a path only vulnerability scanners ask for", instead of a regular expression per message. Successful logins make an address trusted, so a user who mistypes their password isn't banned. It also blocks countries and blocklists, shows what every address did, and pushes bans to routers.

## CrowdSec

CrowdSec separates detection from blocking: a security engine parses logs and runs scenarios, decisions go to a local API, and remediation components ("bouncers") enforce them, for example the firewall bouncer, which keeps nftables, iptables, ipset or pf sets in sync. Reported attacks feed a community blocklist that every participant receives, which is something Barbican doesn't have. CrowdSec also offers an application firewall component and a hosted console.

Barbican has the same split between detection (the agent) and enforcement (the edge agents), on a smaller scale and fully self-hosted: one binary with a built-in UI, no hub and no account. You can still use CrowdSec's blocklists in Barbican, through a blocklist integration URL from a CrowdSec console account.

Pick CrowdSec if you want community intelligence, its large library of scenarios, or a WAF. Pick Barbican if you want one self-contained program you can read and configure in an afternoon, with router enforcement and country blocking included.

## sshguard

sshguard aggregates system logs, recognizes attacks on SSH and other services, and blocks repeat offenders through a firewall backend. It is small and needs little configuration. It has no blocklists, no countries, no UI, and each host works on its own.

## reaction

reaction runs commands such as `journalctl -f`, matches their output with regular expressions, and runs actions (any command) when a pattern repeats. Its configuration is YAML or Jsonnet, and its author describes it as simpler and faster than fail2ban. It is a flexible engine: you write the patterns and the firewall commands yourself.

Barbican is more opinionated. It has parsers, default rules, kernel sets it manages itself, and a UI, at the cost of being less of a general "watch output, run command" tool.

## Blocklist scripts and router packages

A script that downloads blocklists into an ipset or nftables set, run from cron, blocks known-bad networks and nothing else. Router packages do the same with more care:

- **banIP** on OpenWrt keeps blocklist feeds and country or ASN lists in nftables sets on the router, backs them up for the next boot, and can also ban failed logins found in the router's own log (LuCI, SSH, Asterisk). Its documentation warns that enabling too many feeds leads to out-of-memory conditions on small devices, and doesn't support devices with less than 256 MB of RAM.
- **pfBlockerNG** on pfSense turns blocklist URLs and country lists into firewall aliases you use in rules.

Barbican's edge agent sits in the same place on the router, with a different source of truth: it doesn't download feeds itself, it receives everything (bans from your servers' logs, countries, blocklists) from your agent, already merged into address ranges, which takes less memory than the same prefixes one by one.

## How Barbican handles the hard parts

These are problems every tool in this space runs into, and what Barbican does about them.

- **Large lists cost time and memory.** Countries and blocklists are merged into address ranges before they reach the kernel: Africa, Asia and South America are about 55 000 IPv4 ranges instead of 102 000 prefixes. Sets are changed over netlink, one small transaction per change, so a ban costs milliseconds even with hundreds of thousands of elements loaded. Lookups cost about the same at any set size. See [the firewall](/internals/firewall/).
- **Routers have little memory and flash that wears out.** The edge agent is a static binary of a few megabytes that uses 6 to 10 MB of memory. It writes its state to flash only when it stops cleanly, in compact binary files, and puts the blocks back at boot before the network comes up. It can leave out IPv6 and the lists entirely. See [Resource use](/reference/resources/).
- **Reverse proxies hide the client.** Bans are only useful where the attacker's connection arrives. Barbican's edge agent can run on the box that terminates TLS, and rules see the client address the proxy logged, not its own. See [Planning a deployment](/guides/deployment/).
- **Several servers, one attacker.** With one agent and logs shipped to it, an address that probes two servers is counted once, against one set of rules, lists and trusted logins.
- **Locking yourself out.** Logins make an address trusted, private networks are exempt by default, and everything can run in dry run first, on the agent and on each edge.
- **Something else flushes the firewall.** The agent notices within a minute, from the ruleset's generation counter, and puts its table back.

## What Barbican doesn't have

- Shared threat intelligence. You get what your own logs show, plus public feeds.
- A large library of parsers. Today: Traefik, OpenSSH, Authelia, and regular expressions.
- Other operating systems. It needs Linux with nftables, or a router with iptables and ipset.
- A long track record. It is a new project with one maintainer.

## Sources

- fail2ban: [README](https://github.com/fail2ban/fail2ban/blob/master/README.md), [jail.conf](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)
- CrowdSec: [README](https://github.com/crowdsecurity/crowdsec/blob/master/README.md), [firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer)
- sshguard: [README](https://bitbucket.org/sshguard/sshguard/)
- reaction: [README](https://framagit.org/ppom/reaction)
- banIP: [README in OpenWrt's packages](https://github.com/openwrt/packages/blob/master/net/banip/README.md)
- pfBlockerNG: [Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
