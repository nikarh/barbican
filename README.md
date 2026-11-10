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

### The agent

Release files are on the [releases page](https://github.com/nikarh/barbican/releases) (static binaries, so any Linux
with nftables): `barbican_amd64.deb` / `barbican_arm64.deb`, `barbican-x86_64.pkg.tar.zst` /
`barbican-aarch64.pkg.tar.zst` for Arch Linux, and `barbican-<arch>-linux-musl.tar.gz` with the binary, the unit
and an example configuration. `SHA256SUMS` is signed (`SHA256SUMS.asc`). The `latest` pre-release is built from
`main`.

The packages install `/usr/bin/barbican`, the systemd unit and `/etc/barbican/config.toml`, and don't start
anything. Edit the configuration (at least its sources), then:

```sh
systemctl enable --now barbican
```

Try it first without touching the firewall: `barbican --dry-run` (or `[firewall] enabled = false`) decides and
records everything, and changes nothing.

### The edge agent (OpenWrt)

`barbican-edge-<arch>.tar.gz` (x86_64, aarch64, armv7) has the static binary, its init script and UCI configuration,
the LuCI pages, and an installer to run on the router:

```sh
scp -O barbican-edge-armv7.tar.gz root@router:/tmp/   # or: ssh root@router 'cat > /tmp/x.tar.gz' < ...
ssh root@router 'cd /tmp && tar -xzf barbican-edge-armv7.tar.gz && barbican-edge/install.sh'
```

Then add the agents it follows in LuCI (**Services → Barbican → Settings**) or in `/etc/config/barbican`. It needs
nftables with JSON support (`nftables-json`, the default in OpenWrt's images). The files are added to
`/etc/sysupgrade.conf`, so they survive an upgrade.

## Configuration

`/etc/barbican/config.toml` (or `--config`, or `$BARBICAN_CONFIG`) says where logs come from and where things
listen. Rules, ban lengths, countries, the allow and deny lists and blocklists are edited in the UI and kept in the
database. A full example is [`dist/config.toml`](dist/config.toml).

| Setting | Default | |
|---|---|---|
| `database.path` | `/var/lib/barbican/barbican.db` | |
| `ui.listen` | (no UI) | The web UI and its WebSocket API. It has no login: listen on localhost or a private address, behind a proxy with authentication. |
| `edge.listen` | (no edge API) | The API edge agents follow, over TLS only. |
| `edge.cert`, `edge.key` | made on the first start | Its TLS certificate and key (PEM). Without them, a self-signed pair is made next to the database; edges pin it by its fingerprint (`barbican edge-fingerprint`). |
| `edge.client` | | `[[edge.client]]` tables: `name`, and `token` or `token_file` (at least 16 characters). |
| `firewall.enabled` | `true` | `false`: decide and record, change nothing (as `--dry-run`). |
| `firewall.table` | `barbican` | The `inet` table barbican owns. |
| `firewall.priority` | `-190` | Of its prerouting chain: after connection tracking (-200), before NAT (-100). |
| `firewall.nft` | `nft` | |
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

### Trying it on old logs

```sh
barbican parse traefik access.log                 # what the parser makes of each line
barbican replay --list --geoip /var/lib/barbican \
  traefik:access.log sshd:sftp.log authelia:authelia.log
```

`replay` runs logs (each line starting with an RFC 3339 time, as `docker logs --timestamps` writes them) through the
default rules in memory and says what would have been banned.

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

**Blocklists**: Spamhaus DROP, FireHOL level 1, blocklist.de and Tor's exit list can be added in one click, any list
of addresses by URL (with basic authentication: CrowdSec's blocklists through a "blocklist integration" of a console
account). A list either blocks as a whole, or is data: rules can ask for "listed in", and address pages show it.

## The firewall

barbican owns one table (`inet barbican`); nothing else on the host is changed. Its chain hooks prerouting at -190,
so it sees what arrives for the host, for its containers (before Docker's DNAT), and, on a router, everything
forwarded:

1. packets of connections the host (or a LAN client of a router) opened are accepted: replies are never blocked, so
   blocking a country doesn't stop the host downloading from it;
2. the allow sets accept;
3. bans drop: single addresses in hash sets, prefixes in interval sets, each element with its remaining time, so the
   kernel lifts bans on time even when barbican isn't running;
4. country and blocklist prefixes drop.

The sets are reconciled with the state (what the kernel has is read back, and only the difference applied) whenever
something changes, and every minute. Stopping barbican leaves the table in place.

**At boot** the unit runs before `network-pre.target` and Docker, and reports ready only once the table is back: no
packet reaches a service before the blocks are in place.

## The edge agent

`barbican-edge` follows one or more agents' edge APIs and keeps its own table on the router equal to the union of
what they block (with each agent's allow list). It polls with long polling, so a ban or a lift reaches the router
within a second. Its configuration is `/etc/config/barbican`:

```text
config barbican 'main'
	option enabled '1'
	option lists '1'               # also the agents' country blocks and blocking lists
	option persist_interval '3600'

config upstream 'server'
	option url 'https://192.168.1.10:7380'
	option fingerprint '3F:A1:...'        # barbican edge-fingerprint, on the agent
	option token_file '/etc/barbican/server.token'
```

The state is saved to `/etc/barbican/state.json` when it changed, at most once an hour (flash wears), and put back
at boot by the init script before the firewall and the network start (`START=11`), so blocks hold across reboots and
while agents are unreachable. A router without a clock that keeps time boots in the past: lengths are counted from
when the state was saved.

`barbican-edge status` prints its status; LuCI shows it (**Services → Barbican**).

**Security**: edges only pull, nothing can push to them. The edge API is TLS only, and an edge accepts exactly the
certificate whose fingerprint it is configured with (no CA, so it works with bare LAN addresses): nobody between an
edge and its agent can read the tokens or feed the edge bans or allow lists. Each edge has its own token (at least
16 characters), and the API only reads.

The edge API (`GET /api/edge/v1/changes?epoch=&since=&wait=`, `GET /api/edge/v1/list`, both with
`Authorization: Bearer <token>`) is described in [`crates/barbican-common/src/edge.rs`](crates/barbican-common/src/edge.rs).

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

## Development

[mise](https://mise.jdx.dev) installs the tools and runs the tasks (`mise tasks`):

- `mise run dev`: the agent (dry run, `dev/config.toml`) and the UI's dev server at http://localhost:5173
- `mise run check`: formatting, clippy, oxlint, the type check, tests, generated files, cargo-deny
- `mise run build`: release builds, the UI embedded; `mise run build:edge [x86_64|aarch64|armv7]`: edge archives
- `mise run e2e`: the end-to-end suites, in throwaway VMs ([`e2e/README.md`](e2e/README.md))
- `mise run db:prepare` after changing a query or a migration; `mise run bindings` after changing the UI's API

The workspace has three crates: `barbican` (the agent), `barbican-edge` (the router agent: plain threads, no TLS, a
few hundred kilobytes) and `barbican-common` (addresses, the edge protocol, nftables). The UI is React with Mantine
and ag-grid in `web/`; the LuCI pages are in `luci/`.

## Attribution and license

IP geolocation by [DB-IP](https://db-ip.com), under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/), when
barbican downloads its databases.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
