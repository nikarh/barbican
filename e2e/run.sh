#!/usr/bin/env bash
# Runs the end-to-end suites in throwaway VMs (see e2e/README.md): builds static binaries, boots the server and
# router VMs, copies everything in and runs the suites there. Nothing touches this machine's firewall.
#
#   e2e/run.sh              both suites
#   e2e/run.sh server       one of them
#   KEEP_VM=1 e2e/run.sh    leave the VMs running afterwards
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

STATE_DIR="${BARBICAN_VM_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/barbican-e2e}"
TARGET=x86_64-unknown-linux-musl
suites=("${@:-server router}")
read -r -a suites <<<"${suites[*]}"
vm=e2e/vm.sh

log() { printf '[e2e] %s\n' "$*" >&2; }

cleanup() {
  if [[ -z "${KEEP_VM:-}" ]]; then
    "${vm}" router down || true
    "${vm}" server down || true
  fi
}
trap cleanup EXIT

log "building static binaries"
mise x -- cargo zigbuild --locked --release --target "${TARGET}" -p barbican -p barbican-edge
bin="target/${TARGET}/release"

# The country database, refreshed once a month (DB-IP's free database, CC BY 4.0).
geo="${STATE_DIR}/dbip-country-lite.mmdb"
mkdir -p "${STATE_DIR}"
if [[ ! -f "${geo}" ]] || [[ -n $(find "${geo}" -mtime +31) ]]; then
  log "downloading the country database"
  month=$(date -u +%Y-%m)
  curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz" | gzip -dc >"${geo}.part" ||
    curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$(date -u -d '-1 month' +%Y-%m).mmdb.gz" | gzip -dc >"${geo}.part"
  mv "${geo}.part" "${geo}"
fi

"${vm}" server up &
server_up=$!
if [[ " ${suites[*]} " == *" router "* ]]; then
  "${vm}" router up
fi
wait "${server_up}"
"${vm}" server ssh 'sudo ip addr replace 10.99.0.1/24 dev enp0s3 && sudo ip link set enp0s3 up'

log "copying into the server VM"
"${vm}" server ssh 'sudo mkdir -p /opt/barbican && sudo chown debian /opt/barbican'
for f in "${bin}/barbican" "${bin}/barbican-edge-ipset" e2e/rpc.py e2e/server.sh dist/barbican.service "${geo}"; do
  "${vm}" server put "${f}" "/opt/barbican/$(basename "${f}")"
done
"${vm}" server ssh 'chmod +x /opt/barbican/barbican /opt/barbican/barbican-edge-ipset /opt/barbican/server.sh'

status=0
for suite in "${suites[@]}"; do
  case "${suite}" in
    server)
      log "server suite"
      "${vm}" server ssh 'sudo /opt/barbican/server.sh' || status=1
      ;;
    router)
      log "router suite"
      scripts/package-openwrt.sh x86_64 "${bin}/barbican-edge" target/e2e-packages >/dev/null
      e2e/router.sh target/e2e-packages || status=1
      ;;
    *)
      log "unknown suite ${suite}"
      status=1
      ;;
  esac
done
exit "${status}"
