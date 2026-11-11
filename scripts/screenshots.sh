#!/usr/bin/env bash
# Screenshots of the UI for the docs (site/src/assets/screenshots/), from synthetic data, in a throwaway VM.
#
#   scripts/screenshots.sh              (mise run docs:screenshots)
#   KEEP_VM=1 scripts/screenshots.sh    leave the VM running afterwards
#
# Builds the agent and the edge agent with the UI as it is now, boots the end-to-end suites' server VM (e2e/vm.sh, see
# e2e/README.md), and runs scripts/screenshots-vm.sh there: the agent in dry run with a history made up from a fixed
# seed (site/scripts/history.mjs), two edges in dry run, and live lines trickling in. Through an SSH port forward,
# site/scripts/screenshots.mjs drives the system's Chromium with playwright-core, in dark and light, on a desktop and
# a phone screen, and fails, writing nothing, if a page shows an address, domain or name the history didn't make up.
#
# Nothing of this machine goes in: no logs, configuration or addresses; the VM reaches the internet only for the
# blocklists of its feeds. Needs what the e2e suites need (e2e/README.md) and Chromium (or $CHROMIUM).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

STATE_DIR="${BARBICAN_VM_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/barbican-e2e}"
TARGET=x86_64-unknown-linux-musl
PORT="${BARBICAN_SCREENSHOTS_PORT:-17381}"
vm=e2e/vm.sh
work=$(mktemp -d)
forward=

log() { printf '[screenshots] %s\n' "$*" >&2; }
cleanup() { # <status> <the last command>
  ((${1} == 0)) || log "exited with status $1 after: $2"
  [[ -z "${forward}" ]] || kill "${forward}" 2>/dev/null || true
  jobs -p | xargs -r kill 2>/dev/null || true
  [[ -n "${KEEP_VM:-}" ]] || "${vm}" server down || true
  rm -rf "${work}"
}
trap 'cleanup "$?" "${BASH_COMMAND}"' EXIT

chromium=${CHROMIUM:-$(command -v chromium || command -v chromium-browser || command -v google-chrome-stable || command -v google-chrome || true)}
[[ -n "${chromium}" ]] || { log "no Chromium found: set CHROMIUM"; exit 1; }

"${vm}" server up &
server_up=$!

log "building the UI and static binaries"
mise run web:build
mise x -- cargo zigbuild --locked --release --target "${TARGET}" -p barbican -p barbican-edge
bin="target/${TARGET}/release"

# DB-IP's free databases (CC BY 4.0), refreshed once a month: the country one is the e2e suites'.
mkdir -p "${STATE_DIR}"
for db in country asn; do
  file="${STATE_DIR}/dbip-${db}-lite.mmdb"
  if [[ ! -f "${file}" ]] || [[ -n $(find "${file}" -mtime +31) ]]; then
    log "downloading the ${db} database"
    curl -fsSL "https://download.db-ip.com/free/dbip-${db}-lite-$(date -u +%Y-%m).mmdb.gz" | gzip -dc >"${file}.part" ||
      curl -fsSL "https://download.db-ip.com/free/dbip-${db}-lite-$(date -u -d '-1 month' +%Y-%m).mmdb.gz" |
      gzip -dc >"${file}.part"
    mv "${file}.part" "${file}"
  fi
done

log "installing the site's dependencies"
(cd site && mise x -- npm install --no-audit --no-fund --silent)
mise x -- node site/scripts/history.mjs --now "$(date +%s)" --out "${work}/data"

wait "${server_up}"
log "copying into the VM"
# In one stream, flat (each file under its own name).
tar -c --transform 's#.*/##' "${bin}/barbican" "${bin}/barbican-edge" e2e/rpc.py scripts/screenshots-vm.sh \
  -C "${STATE_DIR}" dbip-country-lite.mmdb dbip-asn-lite.mmdb |
  "${vm}" server ssh 'sudo rm -rf /opt/barbican && sudo mkdir -p /opt/barbican && sudo chown debian /opt/barbican && tar -x --warning=no-timestamp -C /opt/barbican'
tar -c -C "${work}" data | "${vm}" server ssh 'tar -x --warning=no-timestamp -C /opt/barbican'
"${vm}" server ssh 'sudo /opt/barbican/screenshots-vm.sh'

"${vm}" server forward "${PORT}" 7381 &
forward=$!
for _ in $(seq 50); do curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null && break; sleep 0.2; done

log "taking the screenshots"
mise x -- node site/scripts/screenshots.mjs --url "http://127.0.0.1:${PORT}/" --chromium "${chromium}" \
  --allow "${work}/data/allow.json" --out site/src/assets/screenshots
