#!/usr/bin/env bash
# The agent of the docs' screenshots: runs inside the e2e server VM as root (scripts/screenshots.sh copies it there,
# with the binaries and a synthetic history from site/scripts/history.mjs).
#
# barbican runs in dry run (the firewall is never changed), reading three empty logs. Before its history is imported
# it gets its policy, feeds and allow and deny lists through the RPC; after the import, a ban made by hand. Two edge
# agents follow it, in dry run too, from the same VM. Then the lines of the live set are appended to its logs, slowly.
set -euo pipefail

DIR=/opt/barbican
RPC="python3 ${DIR}/rpc.py"
CONFIG=/etc/barbican/config.toml

log() { printf '[screenshots vm] %s\n' "$*" >&2; }
wait_until() { # <seconds> <command...>
  local deadline=$((SECONDS + $1))
  shift
  until "$@"; do
    ((SECONDS < deadline)) || return 1
    sleep 0.2
  done
}
ui_up() { curl -fsS -o /dev/null http://127.0.0.1:7381/ 2>/dev/null; }

start_agent() {
  systemctl reset-failed barbican 2>/dev/null || true
  systemd-run --quiet --unit barbican --property Type=exec "${DIR}/barbican" --config "${CONFIG}" --dry-run
  wait_until 60 ui_up || { journalctl -u barbican --no-pager | tail -n 30 >&2; exit 1; }
}
stop_agent() {
  systemctl stop barbican
}
calls() { # <phase of setup.json>
  jq -c ".$1[]" "${DIR}/data/setup.json" | while read -r call; do
    ${RPC} "$(jq -r .method <<<"${call}")" "$(jq -c .params <<<"${call}")" >/dev/null
  done
}

systemctl stop barbican barbican-edge-gateway barbican-edge-branch barbican-live 2>/dev/null || true
rm -rf /var/lib/barbican /var/lib/barbican-edge /var/log/demo /etc/barbican /etc/barbican-edge
mkdir -p /var/lib/barbican /var/log/demo /etc/barbican /etc/barbican-edge
touch /var/log/demo/web.log /var/log/demo/ssh.log /var/log/demo/auth.log

cat >"${CONFIG}" <<'EOF'
[database]
path = "/var/lib/barbican/barbican.db"

[ui]
listen = "127.0.0.1:7381"

[edge]
listen = "127.0.0.1:7380"
[[edge.client]]
name = "gateway"
token = "docs-gateway-token-0123456789"
[[edge.client]]
name = "branch"
token = "docs-branch-token-0123456789"

[firewall]
enabled = false

[geoip]
country = "/opt/barbican/dbip-country-lite.mmdb"
asn = "/opt/barbican/dbip-asn-lite.mmdb"
download = false

[[source]]
name = "traefik"
parser = "traefik"
file = { path = "/var/log/demo/web.log" }

[[source]]
name = "sshd"
parser = "sshd"
file = { path = "/var/log/demo/ssh.log" }

[[source]]
name = "authelia"
parser = "authelia"
file = { path = "/var/log/demo/auth.log" }
EOF

log "setting the agent up"
start_agent
calls before
# Every feed fetched before the import, so that its bans know what the lists list.
for id in $(${RPC} feeds.list | jq '.[].def.id'); do
  ${RPC} feed.refresh "{\"id\": ${id}}" >/dev/null || log "feed ${id} could not be fetched"
done
stop_agent

log "importing the history"
"${DIR}/barbican" import --config "${CONFIG}" \
  "traefik:${DIR}/data/history/web.log" "sshd:${DIR}/data/history/ssh.log" "authelia:${DIR}/data/history/auth.log"

start_agent
calls after

log "starting the edges"
fingerprint=$("${DIR}/barbican" edge-fingerprint --config "${CONFIG}")
for edge in gateway branch; do
  mkdir -p "/var/lib/barbican-edge/${edge}"
  cat >"/etc/barbican-edge/${edge}" <<EOF
config barbican 'main'
	option enabled '1'
	option dry_run '1'
	option state '/var/lib/barbican-edge/${edge}/state'
	option status '/run/barbican-edge-${edge}.json'

config upstream 'server'
	option url 'https://127.0.0.1:7380'
	option fingerprint '${fingerprint}'
	option token 'docs-${edge}-token-0123456789'
EOF
  systemd-run --quiet --unit "barbican-edge-${edge}" --property Type=exec \
    "${DIR}/barbican-edge" --config "/etc/barbican-edge/${edge}"
done
edges_up() { [[ $(${RPC} edges.list | jq '[.[] | select(.connected)] | length') == 2 ]]; }
wait_until 30 edges_up || { log "the edges didn't connect"; ${RPC} edges.list >&2; exit 1; }

# The live set: some of the visitors again, a line every second and a half.
systemd-run --quiet --unit barbican-live --property Type=exec bash -c '
  for log in web auth; do
    while read -r line; do
      printf "%s\n" "$line" >>"/var/log/demo/$log.log"
      sleep 1.5
    done <"/opt/barbican/data/live/$log.log"
  done'
log "ready"
