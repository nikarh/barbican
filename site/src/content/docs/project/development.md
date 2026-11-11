---
title: Development
description: The repository's layout, the tools and tasks, the checks to run before committing, and the end-to-end tests in VMs.
sidebar:
  order: 1
---

[mise](https://mise.jdx.dev) installs the tools (Node, zig, cargo-zigbuild, nfpm, git-cliff, cargo-deny) and runs the tasks; Rust comes from `rust-toolchain.toml`. `mise tasks` lists them.

| Task | |
| --- | --- |
| `mise run dev` | The agent (in dry run, with `dev/config.toml`) and the UI's dev server at <http://localhost:5173> |
| `mise run check` | Everything CI checks: formatting, clippy, oxlint, the type check, tests, generated files, action pins, cargo-deny |
| `mise run fmt` | Format Rust and the frontend |
| `mise run build` | Release builds, the UI embedded |
| `mise run build:edge [x86_64\|aarch64\|armv7]` | Small static builds of the edge agent for routers |
| `mise run e2e [server\|router]` | The end-to-end suites, in throwaway VMs |
| `mise run bindings` | Regenerate the UI's API types after changing `api.rs` |
| `mise run db:prepare` | Refresh `.sqlx/` after changing a query or a migration |
| `mise run docs`, `docs:build`, `docs:screenshots` | The documentation: see [Writing the docs](/project/docs/) |

`mise run dev` needs `dev/config.toml` first: a configuration with `database.path = "dev/barbican.db"`, `ui.socket = "dev/ui.sock"` (a socket path must be short: under about 100 characters), and file sources pointing at logs you can read. It never changes the firewall. The agent serves the UI only on that socket, as in production; the Vite dev server (http://localhost:5173) proxies `/api` straight to it (`$BARBICAN_UI_SOCKET` for another path), so development needs no TCP listener in the agent.

To try `barbican ui-proxy` itself outside a container, a debug build (`cargo run -- ui-proxy ...`) accepts `--insecure-no-trusted-proxy`, which answers every request. Release builds don't have it: they always require `--trusted-proxy`.

## Layout

- `crates/barbican-common`: what both agents share: addresses (`net`), the edge protocol (`edge`) and nftables (`nft`: the table, its sets, reconciling them). No async, few dependencies: it is built for routers too.
- `crates/barbican`: the agent: log sources (`source/`), parsers (`parse/`), the rule engine (`engine`), storage (`db`), geolocation (`geo`), blocklists (`feeds`), the firewall (`firewall`), the edge API (`edge_api`), the WebSocket RPC for the UI (`api.rs` holds every type of it, `rpc.rs` runs it), the embedded UI (`web.rs`) and the UI proxy of the image (`proxy`).
- `crates/barbican-edge`: the router agents: plain threads, blocking I/O over its own small TLS client, configured from a UCI file.
- `crates/barbican-vlogs`: VictoriaLogs history for `barbican import`.
- `web/`: the React UI (Mantine, ag-grid). `web/src/api/generated/` is generated from `api.rs`; never edit it by hand.
- `luci/luci-app-barbican`: the LuCI pages of the edge agent.
- `crates/barbican/migrations/`: SQLite migrations.
- `dist/`: the systemd unit, example configuration, packaging, the OpenWrt init script and UCI config, the Merlin scripts.
- `site/`: this documentation.

## Rules of the code

- Commits follow [Conventional Commits](https://www.conventionalcommits.org): the changelog is made from them.
- A change to the UI's protocol changes `api.rs`, then the bindings, then the frontend, in the same commit.
- A change to the edge protocol keeps older edge agents working, or bumps the protocol version.
- A change to the configuration updates `dist/config.toml` and the [configuration reference](/reference/configuration/) in the same commit.
- Never ban what can't be unbanned from the UI, and never let a rule ban an allow-listed address.
- Tests, commit messages and docs use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and example domains.

## End-to-end tests

Nothing that changes nftables runs on the development machine: the agents without `--dry-run`, `nft`, or the suites' scripts. `mise run e2e` boots throwaway VMs under QEMU (a Debian server and an OpenWrt router, joined by a tunnel between their QEMUs), copies static builds in and runs the suites there: real traffic from network namespaces, bans and lifts, country blocks with large lists, reboots, the UI container, and an edge following the server. The host needs `qemu-system-x86_64`, `qemu-img`, `genisoimage`, and access to `/dev/kvm`; [`e2e/README.md`](https://github.com/nikarh/barbican/blob/main/e2e/README.md) has the details. CI runs the same.
