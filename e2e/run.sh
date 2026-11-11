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

started=$(date +%s%3N)
log() { LC_ALL=C printf '[e2e %6.1fs] %s\n' "$(($(date +%s%3N) - started))e-3" "$*" >&2; }
cleanup() { # <status> <the last command>
  local status=$1
  if ((status != 0)); then
    # Exiting on a failed command (`set -e`) says which one, rather than silently.
    log "exited with status ${status} after: $2"
    # What the VMs printed, before they are gone (CI also keeps the console logs as an artifact).
    for name in server router; do
      if [[ -s "${STATE_DIR}/${name}/console.log" ]]; then
        log "the end of the ${name} VM's console:"
        tail -n 40 "${STATE_DIR}/${name}/console.log" >&2 || true
      fi
    done
  fi
  # The boots, if the build failed.
  jobs -p | xargs -r kill 2>/dev/null || true
  if [[ -z "${KEEP_VM:-}" ]]; then
    "${vm}" router down || true
    "${vm}" server down || true
  fi
}
trap 'cleanup "$?" "${BASH_COMMAND}"' EXIT

# The VMs boot while the binaries build.
"${vm}" server up &
server_up=$!
router_up=
if [[ " ${suites[*]} " == *" router "* ]]; then
  "${vm}" router up &
  router_up=$!
fi

log "building static binaries"
# The e2e profile: release builds' settings, the workspace's crates unoptimised (they compile twice as fast).
mise x -- cargo zigbuild --locked --profile e2e --target "${TARGET}" -p barbican -p barbican-edge
bin="target/${TARGET}/e2e"

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

# The OpenWrt packages (apk's mkpkg runs in a container, seconds) are made while the server suite runs: only the
# router suite needs them.
packaged=
if [[ -n "${router_up}" ]]; then
  log "packaging the edge agent for OpenWrt (meanwhile)"
  scripts/package-openwrt.sh x86_64 "${bin}/barbican-edge" target/e2e-packages >/dev/null &
  packaged=$!
fi

wait "${server_up}"
[[ -z "${router_up}" ]] || wait "${router_up}"
"${vm}" server ssh 'sudo ip addr replace 10.99.0.1/24 dev enp0s3 && sudo ip link set enp0s3 up'

log "copying into the server VM"
# In one stream, flat (each file under its own name).
tar -c --transform 's#.*/##' "${bin}/barbican" "${bin}/barbican-edge-ipset" e2e/rpc.py e2e/server.sh \
  dist/barbican.service dist/barbican.sysusers dist/barbican.tmpfiles Dockerfile.ci -C "$(dirname "${geo}")" "$(basename "${geo}")" |
  "${vm}" server ssh 'sudo mkdir -p /opt/barbican && sudo chown debian /opt/barbican && tar -x -C /opt/barbican'

status=0
for suite in "${suites[@]}"; do
  case "${suite}" in
    server)
      log "server suite"
      "${vm}" server ssh 'sudo /opt/barbican/server.sh' || status=1
      ;;
    router)
      if [[ -n "${packaged}" ]] && ! wait "${packaged}"; then
        log "packaging the edge agent failed"
        status=1
        continue
      fi
      log "router suite"
      e2e/router.sh target/e2e-packages || status=1
      ;;
    *)
      log "unknown suite ${suite}"
      status=1
      ;;
  esac
done
exit "${status}"
