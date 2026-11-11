#!/usr/bin/env bash
# Runs the agent (with dev/config.toml, in dry run: the firewall is never changed) and the Vite dev server at
# http://localhost:5173, which proxies /api to the agent's unix socket (dev/ui.sock, or $BARBICAN_UI_SOCKET). Rust
# changes need a restart.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

config=${BARBICAN_CONFIG:-dev/config.toml}
if [[ ! -f $config ]]; then
  echo "Create $config first (see dist/config.toml): database.path = \"dev/barbican.db\", ui.socket = \"dev/ui.sock\"," >&2
  echo "and file sources pointing at logs you can read." >&2
  exit 1
fi

trap 'kill 0' EXIT
cargo run -p barbican -- --dry-run --config "$config" &
(cd web && npm run dev) &
wait -n
