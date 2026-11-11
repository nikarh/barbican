When adding dependencies don't edit manifests by hand - use the package managers (`cargo add`, `npm install <pkg>@latest`)
so the latest versions are used.
Commit your changes. Use conventional commits. Split logical changes into individual commits.
Before committing run `mise run check` (formatting, clippy, oxlint, type check, tests, cargo-deny, and that the
generated files are up to date).

Commit messages, code, tests and docs describe bugs and their fixes in general terms: what goes wrong, under which
conditions, and what changed. Never frame them around a particular deployment, server, run or data set, and don't
carry over its details: its addresses, domains, host names, user names or what runs where. Test data uses
documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and example domains.

## Firewall changes run in VMs only

Never run anything that changes nftables (the agents without `--dry-run`, `nft`, the e2e suite's scripts) on the
development machine. `mise run e2e` boots throwaway VMs and runs everything there; see `e2e/README.md`.

## Layout

- `crates/barbican-common` - what both agents share: addresses (`net`), the edge protocol (`edge`) and nftables
  (`nft`: the table, its sets, reconciling them). No async, few dependencies: it is built for routers too.
- `crates/barbican` - the agent: log sources (`source/`), parsers (`parse/`), the rule engine (`engine`), storage
  (`db`), geolocation (`geo`), blocklists (`feeds`), the firewall (`firewall`), the edge API (`edge_api`), the
  WebSocket RPC for the UI (`api.rs` holds every type of it, `rpc.rs` runs it) and the embedded UI (`web.rs`).
- `crates/barbican-edge` - the router agent: follows agents' edge APIs and applies the result. Plain threads and
  blocking I/O, no tokio, configured from a UCI file.
- `web/` - the React UI. `web/src/api/generated/` is generated from `crates/barbican/src/api.rs` by
  `mise run bindings` (`cargo test` does it too); never edit it by hand.
- `luci/luci-app-barbican` - the LuCI pages of the edge agent (JavaScript views, menu, ACL).
- `crates/barbican/migrations/` - SQLite migrations. After changing a migration or a `query!`, run
  `mise run db:prepare` and commit `.sqlx/`.
- `dist/` - the systemd unit, example configuration, the OpenWrt init script and UCI config.

## Rules

- A change to the protocol changes `api.rs`, then the bindings, then the frontend, in the same commit.
- A change to the edge protocol keeps older edge agents working, or bumps `edge::PROTOCOL_VERSION`.
- A change to the configuration updates `README.md` and `dist/` in the same commit.
- Never ban what can't be unbanned from the UI, and never let a rule ban an allow-listed address.
- `web/package.json` `overrides` force fixed versions of vulnerable transitive dev dependencies whose dependents
  haven't caught up yet. Drop an override once the dependent requires a fixed version itself.
