# barbican

[![CI](https://github.com/nikarh/barbican/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/barbican/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-barbican.arhipov.net-b5832a)](https://barbican.arhipov.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Bans addresses that abuse your services. barbican reads the logs of a reverse proxy, an SSH or SFTP server and an
authentication portal; rules decide what counts as abuse; offenders are blocked with nftables, on the server and,
through a small edge agent, on a router for the whole network. Countries and continents can be blocked as a whole,
and public blocklists used, as blocks, allow lists or data for rules. A web UI shows what every address tried and
what was decided, and is where rules, ban lengths, countries, lists and blocklists are edited.

**Documentation: <https://barbican.arhipov.net/>**

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="site/src/assets/screenshots/overview-dark.webp">
  <img alt="barbican's overview: bans and events of the last 30 days, recent bans, the firewall, geolocation and feeds." src="site/src/assets/screenshots/overview-light.webp">
</picture>

It is what fail2ban, a log pipeline and a dashboard do together, in one process with a SQLite database.

```text
 logs ─► parser ─► rules ─► engine ─► SQLite
 (docker, file,     │          │
  journald,     (in each   bans, trust
  VictoriaLogs)  source)       │
                               ▼
                    nftables (this host) ── edge API ──► barbican-edge ─► nftables (router)
```

- **Sources**: a container's log (through the Docker API), a file, the systemd journal, or a VictoriaLogs query.
  **Parsers** for Traefik, OpenSSH's sshd and Authelia, or a regular expression of your own.
- **Rules** match HTTP requests, logins and protocol probes, and ban once a threshold is reached in a time window.
  Addresses someone logged in from are trusted; ban lengths can depend on the country, the network or a blocklist,
  and grow for repeat offenders.
- **The firewall**: one nftables table of its own, changed over netlink, element by element; the kernel lifts bans on
  time. At boot the blocks are back before the network and Docker start.
- **Edge agents** for OpenWrt (nftables, with LuCI pages) and for routers with iptables and ipset (Asuswrt-Merlin)
  follow one or more agents over a pinned TLS connection; bans reach them within a fraction of a second.

## Install

Packages for Debian, Ubuntu and Arch Linux, static binaries for any Linux (x86_64 and aarch64), and edge agents for
OpenWrt and Asuswrt-Merlin are in each [release](https://github.com/nikarh/barbican/releases), with signed checksums
(key [`docs/signing-key.asc`](docs/signing-key.asc), `2DED94B14E12F49939656D6611E3B0A85A53607A`). See
[Installation](https://barbican.arhipov.net/install/overview/), then the
[Quick start](https://barbican.arhipov.net/start/quick-start/).

Try it first without touching the firewall: `barbican --dry-run` (or `[firewall] enabled = false` in
`/etc/barbican/config.toml`) decides and records everything, and changes nothing.

## Documentation

The documentation is the site at <https://barbican.arhipov.net/>, built from [`site/`](site/), with a version for
every release and one for `main`:

- [Introduction](https://barbican.arhipov.net/start/introduction/) and [Quick start](https://barbican.arhipov.net/start/quick-start/)
- [Sources and parsers](https://barbican.arhipov.net/guides/sources/), [Rules and policy](https://barbican.arhipov.net/guides/rules/), and [Countries, blocklists and allow lists](https://barbican.arhipov.net/guides/feeds/)
- [The web UI](https://barbican.arhipov.net/guides/ui/), [Behind a reverse proxy](https://barbican.arhipov.net/guides/reverse-proxy/), and [Importing old logs](https://barbican.arhipov.net/guides/import/)
- [Edge agents](https://barbican.arhipov.net/edge/overview/) and [the edge protocol](https://barbican.arhipov.net/edge/protocol/)
- [Configuration](https://barbican.arhipov.net/reference/configuration/), [command line](https://barbican.arhipov.net/reference/cli/) and [resource use](https://barbican.arhipov.net/reference/resources/)
- [The firewall](https://barbican.arhipov.net/internals/firewall/) and [Security](https://barbican.arhipov.net/internals/security/)

To preview it locally, run `mise run docs`. [Writing the docs](https://barbican.arhipov.net/project/docs/) explains
how it is organized and published.

## Development

[mise](https://mise.jdx.dev) installs the tools and runs the tasks (`mise tasks`): `mise run dev` (the agent in dry
run and the UI's dev server), `mise run check` (everything CI checks), `mise run build`, and `mise run e2e` (the
end-to-end suites, in throwaway VMs: [`e2e/README.md`](e2e/README.md)). See
[Development](https://barbican.arhipov.net/project/development/).

## Attribution and license

IP geolocation by [DB-IP](https://db-ip.com), under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/), when
barbican downloads its databases.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
