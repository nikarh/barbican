# barbican

Bans addresses that abuse your services. barbican reads the logs of a reverse proxy, an SSH or SFTP server and an
authentication portal; rules decide what counts as abuse; offenders are blocked with nftables, on the server and,
through a small edge agent, on an OpenWrt router for the whole network. Countries and continents can be blocked as a
whole, and public blocklists used, as blocks or as data for rules. A web UI shows what every address tried and what
was decided, and is where rules, ban lengths, countries, lists and blocklists are edited.

It is what fail2ban, a log pipeline and a dashboard do together, in one process with a SQLite database.

```text
 logs ─► parser ─► rules ─► engine ─► SQLite
 (docker, file,     │          │
  journald,     (in each   bans, trust
  VictoriaLogs)  source)       │
                               ▼
                    nftables (this host) ── edge API ──► barbican-edge ─► nftables (router)
```

- **Sources**: a container's log (through the Docker API), a file (followed across rotation), the systemd journal,
  or a VictoriaLogs query. Each continues where it stopped after a restart.
- **Parsers**: Traefik's access log (common log format or JSON), OpenSSH's sshd, Authelia (text or JSON), or a
  regular expression of your own. A parser turns a line into an event: an HTTP request, a failed or successful
  login, a login as an unknown user, or a protocol probe.
- **Rules** match events (path, method, status, whether the proxy had a route, user agent, user name, the source,
  membership of a blocklist) and ban once a threshold is reached in a time window, or only record.
- **Trust**: an address someone logged in from (a successful Authelia or SSH login, and every request of a signed-in
  Authelia user) is trusted for a while: no rule acts on it.
- **Ban lengths** come from the rule or the default, per country if you set one (shorter for your own country, where
  people you know share addresses), and grow for repeat offenders.
- **Storage** is compact: addresses are 4 or 16 bytes, every distinct "what it tried" is stored once, and events are
  counted per address, rule, source and hour.

## Install

| Where | Guide |
| --- | --- |
| Debian, Ubuntu | [docs/install/debian.md](docs/install/debian.md) |
| Arch Linux | [docs/install/arch.md](docs/install/arch.md) |
| Any other Linux (static binaries for x86_64 and aarch64) | [docs/install/linux.md](docs/install/linux.md) |
| OpenWrt routers (`.apk`, `.ipk` and LuCI pages) | [docs/install/openwrt.md](docs/install/openwrt.md) |
| Routers without nftables, such as Asuswrt-Merlin | [docs/install/iptables.md](docs/install/iptables.md) |
| Connecting a router to an agent | [docs/install/README.md](docs/install/README.md#connecting-an-edge-to-an-agent) |

Release files are signed: `SHA256SUMS.asc`, with the key [`docs/signing-key.asc`](docs/signing-key.asc)
(`2DED94B14E12F49939656D6611E3B0A85A53607A`); [docs/releasing.md](docs/releasing.md) shows how to check them.

Try it first without touching the firewall: `barbican --dry-run` (or `[firewall] enabled = false`) decides and
records everything, and changes nothing.

## Configuration

`/etc/barbican/config.toml` (or `--config`, or `$BARBICAN_CONFIG`) says where logs come from and where things
listen. Rules, ban lengths, countries, the allow and deny lists and blocklists are edited in the UI and kept in the
database. A full example is [`dist/config.toml`](dist/config.toml).

| Setting | Default | |
|---|---|---|
| `database.path` | `/var/lib/barbican/barbican.db` | |
| `ui.listen` | (no UI) | The web UI and its WebSocket API. It has no login: listen on localhost or a private address, behind a proxy with authentication. |
| `ui.socket` | | Instead of `listen`: a unix socket, for [the UI in a container](#the-ui-in-a-container). |
| `ui.socket_group` | the agent's | The group that owns the socket (mode 0660): its members may use the UI. The unit is in `barbican-ui`. |
| `edge.listen` | (no edge API) | The API edge agents follow, over TLS only. |
| `edge.cert`, `edge.key` | made on the first start | Its TLS certificate and key (PEM). Without them, a self-signed pair is made next to the database; edges pin it by its fingerprint (`barbican edge-fingerprint`). |
| `edge.client` | | `[[edge.client]]` tables: `name`, and `token` or `token_file` (at least 16 characters). |
| `firewall.enabled` | `true` | `false`: decide and record, change nothing (as `--dry-run`). |
| `firewall.table` | `barbican` | The `inet` table barbican owns. |
| `firewall.priority` | `-190` | Of its prerouting chain: after connection tracking (-200), before NAT (-100). |
| `firewall.nft` | `nft` | |
| `firewall.ipv6` | `true` | `false`: nothing of IPv6 goes into nftables. Its country and blocklist ranges take about as much kernel memory as IPv4's (roughly 140 bytes each on x86-64, ~8 MB for Africa, Asia and South America), for nothing on a host without IPv6. |
| `firewall.check_interval` | `60` | Seconds between checks whether another program changed nftables, and readings of the drop counters. |
| `geoip.country`, `geoip.asn` | `/var/lib/barbican/dbip-*-lite.mmdb` | Databases in the MaxMind DB format (DB-IP Lite, or MaxMind's GeoLite2). |
| `geoip.download` | `true` | Download DB-IP's free databases when missing, and again once a month. |
| `docker.socket` | `/run/docker.sock` | The Docker API, for docker sources. |
| `exempt.nets` | private ranges | Never acted on, never blocked. |
| `source` | | `[[source]]` tables, below. |

### Sources

```toml
[[source]]
name = "traefik"          # shown in the UI; rules can be limited to sources
parser = "traefik"        # traefik, sshd, authelia, or regex
docker = { container = "traefik" }
# or: file = { path = "/var/log/nginx/access.log" }
# or: journald = { unit = "sshd.service" }        (or identifier = "sshd")
# or: victorialogs = { url = "http://127.0.0.1:9428", query = "container_name:traefik" }
```

A log barbican has no parser for takes a regular expression: the group `ip` is the address, and the others depend on
`kind`: `method`, `path`, `status`, `host`, `agent` for `http`; `user` for `auth_failure`, `auth_success` and
`invalid_user`; `what` for `probe`.

```toml
[[source]]
name = "app"
parser = "regex"
kind = "auth_failure"
pattern = 'Failed login for (?P<user>\S+) from (?P<ip>[0-9a-f.:]+)'
file = { path = "/var/log/app/app.log" }
```

**Traefik**: the default access log has no request host and no user agent. With `accessLog.format: json` (and
`fields.headers.names.User-Agent: keep`) rules can use both. Requests without a route (`RouterName` empty, or `-`
in the common log format) are the bare address or hosts you don't serve: only internet-wide scanners send them.

**Authelia**: failed and successful logins are logged at the `info` level; signed-in users' requests, which keep
their addresses trusted, only at `debug`.

**Permissions**: the unit runs barbican as its own user (`DynamicUser`) with `CAP_NET_ADMIN` only, in the
`systemd-journal` group for journald sources. A docker source needs the Docker API: rather than the `docker` group
(which is root on the host), give it a read-only socket proxy that allows container inspection and logs, and point
`docker.socket` at it.

### Old logs

```sh
barbican parse traefik access.log                 # what the parser makes of each line
barbican replay --list --geoip /var/lib/barbican \
  traefik:access.log sshd:sftp.log authelia:authelia.log
```

`replay` runs logs (each line starting with an RFC 3339 time, as `docker logs --timestamps` writes them) through the
default rules in memory and says what would have been banned.

To start with history, `import` puts old logs into the agent's database, through its rules, as though they had been
read live at their times: events count in their hours, and bans start when their lines happened and end as they
would have (most are long over; a year-long one from a month ago is still on). Each file is `<source>:<file>`, a
source of the configuration, in the same timestamped format. Stop the agent first; a docker source the agent hasn't
read yet then goes on from the end of the import, not an hour back.

`barbican-vlogs` (in the same packages) streams a VictoriaLogs query's history in that format, oldest first: the
time range in windows, several fetched at a time, each parsed as it arrives (about 400 000 lines a second on a small
server). As the agent's user, so the database stays its own:

```sh
systemctl stop barbican
systemd-run --wait --pipe -p DynamicUser=yes -p User=barbican -p StateDirectory=barbican bash -c '
  vlogs() { barbican-vlogs --url http://127.0.0.1:9428 --since 2026-02-12 "$1"; }
  barbican import traefik:<(vlogs container_name:traefik) sftp:<(vlogs container_name:sftpd)'
systemctl start barbican
```

`barbican-vlogs --help` has its options (`--since`/`--until` as a time, a date or an age like `30d`, `--parallel`).

## Rules and policy

New databases start with these rules; all of them can be changed, turned off, or deleted in the UI.

| Rule | Bans |
|---|---|
| Exploit probes | at once, for a year: `.env`, `.git`, PHP and CGI scripts, admin panels of software that isn't there, path traversal, injection |
| No known host | at once, for a year: requests the proxy had no route for |
| Unusual methods | at once: HTTP methods no browser or app sends |
| Many errors | 40 responses 401, 403 or 404 within 10 minutes |
| Failed logins | 5 within 10 minutes |
| Root logins | at once, for a year: logins as `root`, `admin`, `administrator` |
| Unknown users | 2 logins as unknown users within an hour, for a year |
| Protocol probes | at once, for a year: garbage instead of SSH, ancient algorithms |

Patterns in conditions are regular expressions that match anywhere unless anchored; one that starts with `!` matches
what the rest doesn't (`!^(GET|POST)$`). A rule can ban a prefix (`/24`, `/64`) instead of the address.

Events are recorded under the first rule (in order) that matches; every banning rule that matches counts them. An
address on the allow list, exempt, or trusted, is recorded but never banned.

The policy (**Settings** in the UI): the default ban length (90 days), lengths per country, per network (ASN) and per
blocklist (the shortest that applies counts), the repeat multiplier
(each earlier ban of an address doubles the length) up to a maximum (a year), how long a login keeps an address
trusted (30 days), countries and continents blocked as a whole, and how long events are kept (a year).

**Shared addresses**: VPN and relay services (Cloudflare WARP, iCloud Private Relay, Tor) hand the same addresses to
many people, scanners among them. Allowing them would let anyone through; banning them for a year shuts out
everyone else using them. Give them short bans instead: a length for AS13335 (Cloudflare) and one for the "iCloud
Private Relay" blocklist preset (Apple's published egress ranges), as data rather than a block.

**Feeds** (lists fetched from the internet): Spamhaus DROP, FireHOL level 1, blocklist.de, Tor's exit list and
Cloudflare's address ranges can be added in one click, any list of addresses by URL (with basic authentication:
CrowdSec's blocklists through a "blocklist integration" of a console account). A list either blocks as a whole,
allows as a whole (never banned, let through before any block, here and on the edges, like the allow list), or is
data: rules can ask for "listed in", and address pages show it.

**Behind Cloudflare's proxy**, a site's visitors arrive from Cloudflare's addresses, and geolocation databases place
some of those in Asia, Africa or South America whatever data centre uses them: blocking those continents would then
drop your own visits now and then. Allow Cloudflare's ranges (the "Allow Cloudflare" feeds, refreshed daily).

## The firewall

barbican owns one table (`inet barbican`); nothing else on the host is changed. Its chain hooks prerouting at -190,
so it sees what arrives for the host, for its containers (before Docker's DNAT), and, on a router, everything
forwarded:

1. packets of connections the host (or a LAN client of a router) opened are accepted: replies are never blocked, so
   blocking a country doesn't stop the host downloading from it;
2. the allow sets accept;
3. bans drop: single addresses in hash sets, prefixes in interval sets, each element with its remaining time, so the
   kernel lifts bans on time even when barbican isn't running;
4. country and blocklist addresses drop. Their prefixes go into interval sets merged into ranges: the kernel keeps
   any range as one element, as much memory as one prefix, and a country's adjacent prefixes make about half as
   many ranges (101 761 IPv4 prefixes of Africa, Asia and South America are 55 339 ranges).

The table and its chain are made with `nft`; elements are changed straight over netlink, each change one small
transaction whatever the lists hold (`nft` itself reads every element of every set before it changes anything,
seconds with a large blocklist loaded). Only what changed is written: a ban, a lift, an edit of the allow or deny
list, new lists (only the ranges that changed; a restart doesn't load unchanged lists again). The kernel times bans
out by itself. What the kernel has is read back at the start and when another program changed nftables: the kernel
counts every commit in the ruleset's generation (what `nft` checks its own cache with), and barbican asks for it once
a minute, one small request. So a flushed ruleset or a hand-edited set is put right within a minute, and an idle
agent costs next to nothing. (It doesn't subscribe to nftables' notifications: while anyone listens, the kernel makes
a notification of every element of every commit and holds them until the commit ends, gigabytes for another
program's large set load.) Should netlink fail, everything goes through `nft` instead, reading the sets back every
minute. Stopping barbican leaves the table in place.

**At boot** the unit runs before `network-pre.target` and Docker, and reports ready only once the table is back: no
packet reaches a service before the blocks are in place.

## The edge agents

An edge agent follows one or more agents' edge APIs and keeps its router's firewall equal to the union of what they
block (with their allow lists): `barbican-edge` with nftables on OpenWrt, `barbican-edge-ipset` with iptables and ipset
where there is no nftables. It stays connected to each agent, which pushes every ban and lift as it happens, so they
reach the router within a fraction of a second; the edge reports back what it applied and what its firewall dropped,
which the agent's UI shows (**Settings → Edges**, and the overview's **Edges** panel, each edge's drops apart from the
host's own). Installing and configuring: [OpenWrt](docs/install/openwrt.md), [without nftables](docs/install/iptables.md).

- **Dry run** (`option dry_run '1'`): the edge follows the agents and keeps their state, and reports what it would
  block, but changes nothing in the firewall. To try an edge first, and to see what it costs.
- **IPv6** (`option ipv6`, on by default with nftables, off with ipset): without it the agents send the edge no IPv6
  at all, neither bans nor list prefixes.
- **Saved state**: the edge saves what its agents sent when it stops cleanly (a reboot, an upgrade), in two compact
  binary files: `state` (bans and allows, 13 bytes a ban, about 320 KB for 25 000 bans) and `state.lists` (the
  country and blocklist prefixes, 5 bytes each for IPv4, only the families it loads: about 500 KB for 100 000). At
  boot they are put back before the network comes up, so blocks hold while no agent is reachable yet; once one is,
  it sends whatever changed. Nothing else is written to flash, which wears; `option persist_interval` (seconds) also
  saves that often, against power cuts. A router without a clock that keeps time boots in the past: lengths are
  counted from when the state was saved.
- **LuCI** (OpenWrt, **Services → Barbican**): the status page shows the mode (enforcing or dry run), what is blocked,
  each agent's connection, and what the firewall dropped; the settings page edits `/etc/config/barbican`.

**Security**: edges connect out, nothing connects to them; what an agent sends them is only ever what that agent
blocks and allows. The edge API is TLS only, and an edge accepts exactly the
certificate whose fingerprint it is configured with (no CA, so it works with bare LAN addresses): nobody between an
edge and its agent can read the tokens or feed the edge bans or allow lists. Each edge has its own token (at least
16 characters), and what an edge reports only reaches the agent's UI.

### The edge protocol

One long-lived TLS connection per edge and agent, the edge connecting. On it, length-prefixed binary frames
(`u32` length, a type byte, then fixed-width little-endian fields; at most 4 MiB and 65 536 records a frame), read in
place: a ban is a 26-byte record (family, prefix length, 16 address bytes, end time), a list prefix 18 bytes, and a
received frame is validated and used without copying its records.

- The edge says **hello**: protocol version, its token, where its copy of the agent's state is (an epoch and a
  sequence number, the list's version), whether it enforces, wants the lists, and loads IPv6.
- The agent answers **welcome** and sends what the edge misses: the changes since its sequence number, or the whole
  state after the agent restarted; the list when its version differs, in chunks the edge applies once complete.
  After that it pushes each change as it happens. A wrong token or protocol version is refused with the reason.
- The edge sends **status** reports: on connecting, when something changed, and at least every minute (what it
  applied, its drop counters, errors, memory, uptime, and the other agents it follows). Reports can carry extensions
  an older agent skips, so more can be added without a new protocol version.
- Either side **pings** after 20 seconds without sending and drops the connection after 60 seconds without hearing
  anything; the edge then reconnects (2 to 60 seconds apart) and carries on from where it was.

A full state of 25 000 bans and 100 000 list prefixes is 2.4 MB and decodes in under a millisecond; a ban reaches a
router's firewall in about half a second (most of it the edge gathering changes that come together). Both sides must
speak the same protocol version: update agents and edges together. The frames are described in
[`crates/barbican-common/src/edge/wire.rs`](crates/barbican-common/src/edge/wire.rs).

## Resource use

Measured with 25 000 bans, Africa, Asia and South America blocked (about 100 000 IPv4 and 87 000 IPv6 prefixes) and
three blocklists:

| | Memory | Notes |
|---|---|---|
| Agent (`barbican`) | about 70 MB resident | Much of it the geolocation databases (mapped) and SQLite's cache; idle CPU near zero |
| UI container (`barbican ui-proxy`) | about 4 MB | |
| Edge agent (`barbican-edge`) | 6–10 MB resident, about 20 MB at a full resync | Idle: about 10 ms of CPU per 100 s |
| Kernel: list sets | about 140 B an element on x86-64, about 250 B on 32-bit ARM | The prefixes are loaded merged into ranges: the IPv4 list above is 55 000 elements instead of 102 000, about 8 MB on x86-64, 14 MB on ARM (IPv6 another 57 000 elements, unless off) |
| Kernel: bans | about 140 B a ban | 25 000 bans: 3.4 MB |

The kernel sets don't slow packets down with their size: a lookup costs about the same with 1 000 elements or
300 000. Loading 100 000 elements takes about a second on a router. Leave out IPv6 where there is none
(`firewall.ipv6 = false`, the edge's `option ipv6 '0'`): its list is as large as IPv4's.

## Behind a reverse proxy

The UI is a single page and one WebSocket (`/api/ws`), and works under a path prefix. It has no login: put it behind
your proxy's authentication (forward auth, basic auth, a VPN). The WebSocket is refused when its `Origin` doesn't
match `Host` (or `X-Forwarded-Host`), so another site can't use a signed-in browser's cookies to reach it.

With Traefik in Docker and barbican on the host, a file provider route does it:

```yaml
http:
  routers:
    barbican:
      rule: Host(`barbican.example.com`)
      service: barbican
      middlewares: [auth]
  services:
    barbican:
      loadBalancer:
        servers:
          - url: http://172.17.0.1:7381   # ui.listen on the docker0 address
```

### The UI in a container

The agent has to run on the host (it changes the host's firewall, early in boot), but the UI can be a container next
to your other ones, routed and authenticated like them. The agent then serves the UI's API on a unix socket instead
of a port, and the image `ghcr.io/nikarh/barbican` (amd64, arm64) runs `barbican ui-proxy`: it serves the UI and
passes `/api` (the WebSocket included) to the socket. The socket's directory, `/run/barbican-ui`, and the socket
belong to the group `barbican-ui` (both made by the packages; modes 2770 and 0660), so only containers given that
group can use it, and nothing listens on a port of the host.

```toml
# /etc/barbican/config.toml
[ui]
socket = "/run/barbican-ui/ui.sock"
socket_group = "barbican-ui"
```

```yaml
services:
  barbican:
    image: ghcr.io/nikarh/barbican:latest
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    user: "65534:65534"
    # The gid of barbican-ui on the host (getent group barbican-ui): the container knows no group names.
    group_add: ["${BARBICAN_UI_GID}"]
    volumes:
      # The directory, not the socket: the agent makes a new socket each time it starts.
      - /run/barbican-ui:/run/barbican-ui:ro
    labels:
      traefik.enable: "true"
      traefik.http.routers.barbican.rule: Host(`barbican.example.com`)
      traefik.http.routers.barbican.middlewares: auth
      traefik.http.services.barbican.loadbalancer.server.port: "8080"
```

- `read_only`, `cap_drop: [ALL]`, `no-new-privileges`: the image is one static binary (`FROM scratch`) that writes
  nothing and needs no privileges.
- `user`: any uid works; `group_add` is what grants the UI. Connecting to a socket on a read-only mount works.
- It listens on 8080 (`barbican ui-proxy --listen <address>`), for the agent's socket at
  `/run/barbican-ui/ui.sock` (`--socket <path>`); `/healthz` answers while the proxy runs, and the image's healthcheck (`barbican healthcheck`)
  asks it. While the agent can't be reached (stopped, restarting, a missing socket or one the container may not use)
  the API answers 502, the UI says so and why, and it reconnects on its own. The reason is what the proxy answers on
  `/api/proxy` (JSON: the socket, and the error with what to check), which works with `curl` too.
- The `Origin` check is the agent's, on the headers the browser sent: the proxy passes them through unchanged.

## Development

[mise](https://mise.jdx.dev) installs the tools and runs the tasks (`mise tasks`):

- `mise run dev`: the agent (dry run, `dev/config.toml`) and the UI's dev server at http://localhost:5173
- `mise run check`: formatting, clippy, oxlint, the type check, tests, generated files, cargo-deny
- `mise run build`: release builds, the UI embedded; `mise run build:edge [x86_64|aarch64|armv7]`: edge archives
- `mise run e2e`: the end-to-end suites, in throwaway VMs ([`e2e/README.md`](e2e/README.md))
- `mise run db:prepare` after changing a query or a migration; `mise run bindings` after changing the UI's API

The workspace has three crates: `barbican` (the agent, and the UI proxy of the image), `barbican-edge` (the router
agents: plain threads, blocking I/O over its own small TLS client, about a megabyte) and `barbican-common` (addresses, the edge protocol, nftables). The UI is React with Mantine
and ag-grid in `web/`; the LuCI pages are in `luci/`.

## Attribution and license

IP geolocation by [DB-IP](https://db-ip.com), under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/), when
barbican downloads its databases.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
