---
title: Configuration
description: Every setting of /etc/barbican/config.toml, with its default.
sidebar:
  order: 1
---

`/etc/barbican/config.toml` (or `--config <path>`, or `$BARBICAN_CONFIG`) says where logs come from, where the UI and the edge API listen, and how the firewall is set up. Rules, ban lengths, countries, the allow and deny lists and feeds are not here: they are edited in the UI and kept in the database.

Every table is optional, and unknown settings are an error. A change takes effect when the agent restarts (`systemctl restart barbican`). The packages install an example, [`dist/config.toml`](https://github.com/nikarh/barbican/blob/main/dist/config.toml), and keep your edits on upgrades.

```toml title="/etc/barbican/config.toml"
[database]
path = "/var/lib/barbican/barbican.db"

[ui]
socket = "/run/barbican-ui/ui.sock"
socket_group = "barbican-ui"

[edge]
listen = "0.0.0.0:7380"
[[edge.client]]
name = "router"
token_file = "/etc/barbican/edge-router.token"

[firewall]
enabled = true

[geoip]
download = true

[[source]]
name = "traefik"
parser = "traefik"
docker = { container = "traefik" }
```

## database

| Setting | Default | |
| --- | --- | --- |
| `path` | `/var/lib/barbican/barbican.db` | The SQLite database. The edge API's self-signed certificate goes next to it |

## ui

Without `[ui]` there is no UI. The UI is full control over the agent, so it is served only on a unix socket, which [`barbican ui-proxy` in a container](/guides/reverse-proxy/) serves to browsers behind your reverse proxy's authentication.

| Setting | Default | |
| --- | --- | --- |
| `socket` | | The unix socket the UI and its API are served on, such as `/run/barbican-ui/ui.sock`. Required |
| `socket_group` | the agent's | The group that owns the socket (mode 0660): besides root and the agent's own user, only its members (as primary or supplementary group) may connect, which the agent checks on every connection. The packages make `barbican-ui` |

`listen`, a TCP address for the UI, is no longer supported: any program on the host could have used it. A configuration that still has it is refused at start, with where to go instead.

## edge

Without `[edge]` no edge can follow this agent. See [Edge agents](/edge/overview/).

| Setting | Default | |
| --- | --- | --- |
| `listen` | | The address of the edge API, TLS only, such as `0.0.0.0:7380` |
| `cert`, `key` | made on the first start | Its TLS certificate and key (PEM), both or neither. Without them, a self-signed pair is made next to the database (`edge-cert.pem`, `edge-key.pem`); edges pin it by its fingerprint (`barbican edge-fingerprint`) |
| `client` | | `[[edge.client]]` tables, one per edge |

Each `[[edge.client]]`:

| Setting | |
| --- | --- |
| `name` | What the UI calls the edge |
| `token` or `token_file` | Its token, at least 16 characters, or a file holding it (trimmed) |

## firewall

| Setting | Default | |
| --- | --- | --- |
| `enabled` | `true` | `false`: decide and record everything, change nothing (as `--dry-run`) |
| `table` | `barbican` | The `inet` table Barbican owns: letters, digits, `_` and `-` |
| `priority` | `-190` | Of its prerouting chain: after connection tracking (-200), before NAT (-100) |
| `nft` | `nft` | The nft program, for making the table (elements are changed over netlink) |
| `ipv6` | `true` | `false`: nothing of IPv6 goes into nftables. Its country and blocklist ranges take about as much kernel memory as IPv4's (roughly 140 bytes each on x86-64, about 8 MB for Africa, Asia and South America), for nothing on a host without IPv6 |
| `check_interval` | `60` | Seconds between checks whether another program changed nftables, and readings of the drop counters; at least 1 |

## geoip

| Setting | Default | |
| --- | --- | --- |
| `country` | `/var/lib/barbican/dbip-country-lite.mmdb` | A country database in the MaxMind DB format: DB-IP's IP to Country Lite, or MaxMind's GeoLite2 Country |
| `asn` | `/var/lib/barbican/dbip-asn-lite.mmdb` | A network (ASN) database: DB-IP's IP to ASN Lite, or GeoLite2 ASN |
| `download` | `true` | Download DB-IP's free databases to these paths when missing, and again once a month. `false`: use the files as they are |

DB-IP's databases are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); the UI credits them.

## docker

| Setting | Default | |
| --- | --- | --- |
| `socket` | `/run/docker.sock` | The Docker API's unix socket, for docker sources, or a read-only proxy of it (see [Permissions](/guides/sources/#permissions)) |

## exempt

| Setting | Default | |
| --- | --- | --- |
| `nets` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]` | Addresses and prefixes no rule acts on and that are never blocked. The UI's allow list adds to these |

Setting `nets` replaces the default list: keep the private ranges in it.

## source

`[[source]]` tables, one per log. See [Sources and parsers](/guides/sources/).

| Setting | |
| --- | --- |
| `name` | Shown in the UI; rules can be limited to sources. Unique |
| `parser` | `traefik`, `sshd`, `authelia` or `regex` |
| `pattern` | With `parser = "regex"` only: the regular expression, with the named group `ip` and others |
| `kind` | With `parser = "regex"` only: `http`, `auth_failure`, `auth_success`, `invalid_user` or `probe` |
| one input | `docker = { container = "..." }`, `file = { path = "..." }`, `journald = { unit = "..." }` (or `identifier = "..."`), or `victorialogs = { url = "...", query = "..." }` |
