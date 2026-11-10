#!/usr/bin/env bash
# The server suite: runs inside the server VM as root (e2e/run.sh copies it there with the binaries).
#
# Attackers live in network namespaces routed from the VM: `att` has 203.0.113.10 and 1.0.1.10 (an address the
# geolocation database puts in China), `by` (a bystander) has 198.51.100.10. The VM serves HTTP on 203.0.113.1:8080
# and 198.51.100.1:8080; `att` serves HTTP on 203.0.113.10:9000. barbican runs as the systemd service, reading a
# Traefik access log (a file), the journal and a container's log.
set -euo pipefail

DIR=/opt/barbican
RPC="python3 ${DIR}/rpc.py"
LOG=/var/log/e2e/access.log
failures=0

say() { printf '\n== %s\n' "$*"; }
pass() { printf '  ok   %s\n' "$*"; }
fail() {
  printf '  FAIL %s\n' "$*"
  failures=$((failures + 1))
}

# wait_until <seconds> <command...>: until the command succeeds, or the time is up.
wait_until() {
  local deadline=$((SECONDS + $1))
  shift
  until "$@"; do
    ((SECONDS < deadline)) || return 1
    sleep 0.3
  done
}

reach() { # <netns> <source address> <target>
  ip netns exec "$1" curl -s -o /dev/null -m 2 --interface "$2" "http://$3:8080/"
}
blocked() { ! reach "$@"; }
att() { reach att 203.0.113.10 203.0.113.1; }
att_blocked() { blocked att 203.0.113.10 203.0.113.1; }
cn() { reach att 1.0.1.10 203.0.113.1; }
cn_blocked() { blocked att 1.0.1.10 203.0.113.1; }
by() { reach by 198.51.100.10 198.51.100.1; }

probe() { # <address>: a Traefik access log line of an exploit probe
  printf '%s - - [10/Nov/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 404 19 "-" "-" 1 "-" "-" 0ms\n' "$1" >>"${LOG}"
}

active_ban_id() { # <net>
  ${RPC} bans.list '{"active": true}' | python3 -c "
import json, sys
rows = [b for b in json.load(sys.stdin)['rows'] if b['net'] == sys.argv[1]]
print(rows[0]['id'] if rows else '')" "$1"
}
lift() { # <net>
  local id
  id=$(active_ban_id "$1")
  [[ -n ${id} ]] && ${RPC} ban.lift "{\"id\": ${id}}" >/dev/null
}

setup_network() {
  for ns in att by; do ip netns del "${ns}" 2>/dev/null || true; done
  ip link del veth-att 2>/dev/null || true
  ip link del veth-by 2>/dev/null || true
  ip netns add att
  ip link add veth-att type veth peer name eth0 netns att
  ip addr add 203.0.113.1/24 dev veth-att
  ip link set veth-att up
  ip route replace 1.0.1.10/32 dev veth-att
  ip -n att addr add 203.0.113.10/24 dev eth0
  ip -n att addr add 1.0.1.10/32 dev eth0
  ip -n att link set eth0 up
  ip -n att link set lo up
  ip -n att route add default via 203.0.113.1
  ip netns add by
  ip link add veth-by type veth peer name eth0 netns by
  ip addr add 198.51.100.1/24 dev veth-by
  ip link set veth-by up
  ip -n by addr add 198.51.100.10/24 dev eth0
  ip -n by link set eth0 up
  ip -n by route add default via 198.51.100.1
  pkill -f 'http.server 8080' || true
  pkill -f 'http.server 9000' || true
  # Detached, with no descriptor of this script's: its SSH session ends when it does.
  setsid -f sh -c 'cd /tmp && exec python3 -m http.server 8080' </dev/null >/dev/null 2>&1
  setsid -f sh -c 'cd /tmp && exec ip netns exec att python3 -m http.server 9000 --bind 203.0.113.10' \
    </dev/null >/dev/null 2>&1
  wait_until 10 att
}

setup_barbican() {
  systemctl stop barbican 2>/dev/null || true
  nft delete table inet barbican 2>/dev/null || true
  rm -rf /var/lib/barbican /var/lib/private/barbican /var/log/e2e
  mkdir -p /var/log/e2e /etc/barbican
  touch "${LOG}"
  chmod 0755 /var/log/e2e
  chmod 0644 "${LOG}"
  cat >/etc/barbican/config.toml <<'EOF'
[ui]
listen = "127.0.0.1:7381"

[edge]
listen = "0.0.0.0:7380"
[[edge.client]]
name = "router"
token = "e2e-router-token-0123456789"

[geoip]
country = "/opt/barbican/dbip-country-lite.mmdb"
download = false

[[source]]
name = "web"
parser = "traefik"
file = { path = "/var/log/e2e/access.log" }

[[source]]
name = "ssh"
parser = "sshd"
journald = { identifier = "e2e-sshd" }

[[source]]
name = "container"
parser = "sshd"
docker = { container = "e2e-logger" }
EOF
  sed "s#^ExecStart=.*#ExecStart=${DIR}/barbican#" "${DIR}/barbican.service" >/etc/systemd/system/barbican.service
  mkdir -p /etc/systemd/system/barbican.service.d
  printf '[Service]\nSupplementaryGroups=systemd-journal docker\nEnvironment=RUST_LOG=barbican=debug\n' \
    >/etc/systemd/system/barbican.service.d/e2e.conf
  docker rm -f e2e-logger >/dev/null 2>&1 || true
  docker run -d --name e2e-logger alpine:3 sh -c 'while true; do sleep 1; done' >/dev/null
  systemctl daemon-reload
}

started_at=$(date '+%Y-%m-%d %H:%M:%S')
on_exit() {
  if ((failures > 0)); then
    say "barbican's log"
    journalctl -u barbican --since "${started_at}" --no-pager | tail -n 80
  fi
}
trap on_exit EXIT

say "setup"
setup_network
setup_barbican

say "start"
# Type=notify: systemctl returns once barbican says it is ready, with its table in place.
if systemctl start barbican && nft list table inet barbican >/dev/null; then pass "starts, table in place"; else fail "start"; fi
id_user=$(systemctl show -p User --value barbican)
pid=$(systemctl show -p MainPID --value barbican)
if [[ $(stat -c %U "/proc/${pid}") != root ]]; then pass "runs as its own user (${id_user:-dynamic})"; else fail "runs as root"; fi
if att && by; then pass "everyone reaches the service"; else fail "the service isn't reachable"; fi

say "a probe bans its address"
probe 203.0.113.10
if wait_until 5 att_blocked; then pass "the prober is blocked"; else fail "the prober still gets through"; fi
if by; then pass "others still get through"; else fail "a bystander is blocked"; fi
if [[ -n $(active_ban_id 203.0.113.10) ]]; then pass "the ban is listed"; else fail "the ban isn't listed"; fi
if curl -s -o /dev/null -m 2 http://203.0.113.10:9000/; then pass "replies to the host's own connections pass"; else fail "outbound to a banned address broke"; fi

say "lifting a ban"
lift 203.0.113.10
if wait_until 5 att; then pass "lifted"; else fail "still blocked after lifting"; fi

say "the allow list wins"
entry=$(${RPC} entry.save '{"net": "203.0.113.0/24", "allow": true, "note": "e2e", "secs": null}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
probe 203.0.113.10
sleep 2
if att && [[ -z $(active_ban_id 203.0.113.10) ]]; then pass "an allowed address isn't banned"; else fail "an allowed address was banned"; fi
${RPC} entry.delete "{\"id\": ${entry}}" >/dev/null

say "thresholds, from the journal"
systemd-cat -t e2e-sshd echo "Invalid user admin from 198.51.100.10 port 4242"
sleep 2
if by; then pass "one unknown user isn't enough"; else fail "banned on the first unknown user"; fi
systemd-cat -t e2e-sshd echo "Invalid user oracle from 198.51.100.10 port 4243"
if wait_until 5 blocked by 198.51.100.10 198.51.100.1; then pass "the second one bans"; else fail "not banned after two unknown users"; fi
lift 198.51.100.10

say "a container's log"
docker exec e2e-logger sh -c 'echo "banner exchange: Connection from 203.0.113.10 port 5: invalid format" > /proc/1/fd/1'
if wait_until 15 att_blocked; then pass "a probe in a container's log bans"; else fail "the container's log isn't read"; fi
lift 203.0.113.10
wait_until 5 att || true

say "countries"
policy=$(${RPC} policy.get | python3 -c 'import json,sys; p=json.load(sys.stdin); p["blockedCountries"]=["CN"]; print(json.dumps(p))')
${RPC} policy.update "${policy}" >/dev/null
if wait_until 30 cn_blocked; then pass "a blocked country's address is dropped"; else fail "a blocked country gets through"; fi
if att; then pass "other countries get through"; else fail "an address of another country is blocked"; fi
count=$(nft -j list set inet barbican list4 | python3 -c 'import json,sys; print(sum(len(i["set"].get("elem",[])) for i in json.load(sys.stdin)["nftables"] if "set" in i))')
if ((count > 1000)); then pass "the country's ${count} prefixes are in the set"; else fail "only ${count} prefixes"; fi
policy=$(${RPC} policy.get | python3 -c 'import json,sys; p=json.load(sys.stdin); p["blockedCountries"]=[]; print(json.dumps(p))')
${RPC} policy.update "${policy}" >/dev/null
if wait_until 30 cn; then pass "unblocked"; else fail "still blocked after unblocking the country"; fi

say "bans run out in the kernel"
${RPC} ban.create '{"net": "203.0.113.10", "secs": 4, "reason": "e2e"}' >/dev/null
if wait_until 5 att_blocked; then pass "a ban by hand blocks"; else fail "a ban by hand doesn't block"; fi
systemctl stop barbican
if nft list table inet barbican >/dev/null && att_blocked; then pass "stopping leaves the blocks in place"; else fail "stopping removed the blocks"; fi
if wait_until 8 att; then pass "the kernel lifted the ban on time, without the agent"; else fail "the ban outlived its time"; fi

say "a reboot"
systemctl start barbican
${RPC} ban.create '{"net": "203.0.113.10", "secs": null, "reason": "e2e forever"}' >/dev/null
wait_until 5 att_blocked || true
systemctl stop barbican
# A reboot loses the table.
nft delete table inet barbican
if att; then pass "without the table, traffic passes"; else fail "blocked without the table"; fi
systemctl start barbican
if att_blocked; then pass "blocks are back by the time the agent reports ready"; else fail "blocks came back late"; fi

say "the edge API"
curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:7380/api/edge/v1/changes | grep -q 401 &&
  pass "refuses without a token" || fail "answers without a token"
if ! curl -s -m 3 -o /dev/null -H 'Authorization: Bearer e2e-router-token-0123456789' http://127.0.0.1:7380/api/edge/v1/changes; then
  pass "plain HTTP is refused (TLS only)"
else
  fail "answers plain HTTP"
fi
command -v openssl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl >/dev/null
FINGERPRINT=$(${DIR}/barbican edge-fingerprint --config /etc/barbican/config.toml)
served=$(openssl s_client -connect 127.0.0.1:7380 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
if [[ ${served} == "${FINGERPRINT}" ]]; then pass "edge-fingerprint prints the served certificate's fingerprint"; else fail "fingerprint ${FINGERPRINT} != ${served}"; fi
changes=$(curl -sk -H 'Authorization: Bearer e2e-router-token-0123456789' 'https://127.0.0.1:7380/api/edge/v1/changes?since=0')
if python3 -c 'import json,sys; c=json.loads(sys.argv[1]); assert c["full"] and any(b["net"]=="203.0.113.10" for b in c["block"])' "${changes}"; then
  pass "gives an edge the whole state"
else
  fail "the edge's state is wrong: ${changes}"
fi
lift 203.0.113.10

say "downloads and blocklists (internet)"
# The ASN database is downloaded from DB-IP when missing.
sed -i 's#^download = false#asn = "/var/lib/barbican/dbip-asn-lite.mmdb"\ndownload = true#' /etc/barbican/config.toml
systemctl restart barbican
asn_known() { ${RPC} ip.get '{"ip": "1.1.1.1"}' | python3 -c 'import json,sys; sys.exit(json.load(sys.stdin)["asn"] != 13335)'; }
if wait_until 180 asn_known; then pass "the ASN database is downloaded (1.1.1.1 is AS13335)"; else fail "no ASN database after downloading"; fi
# A real public list.
${RPC} feed.save '{"id": 0, "name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop_v4.json", "enabled": true, "block": false, "refreshSecs": 43200, "username": null, "password": null}' >/dev/null
drop_fetched() { ${RPC} feeds.list | python3 -c 'import json,sys; f=[x for x in json.load(sys.stdin) if x["def"]["name"]=="Spamhaus DROP"][0]; sys.exit(not (f["count"] > 100 and f["error"] is None))'; }
if wait_until 120 drop_fetched; then pass "Spamhaus DROP is fetched"; else fail "Spamhaus DROP: $(${RPC} feeds.list)"; fi
# A list served here, blocking: its prefix is dropped as a whole.
mkdir -p /tmp/feed && printf '# e2e\n198.51.100.0/24 ; bystanders\n' >/tmp/feed/list.txt
setsid -f sh -c 'cd /tmp/feed && exec python3 -m http.server 8099 --bind 127.0.0.1' </dev/null >/dev/null 2>&1
sleep 1
feed=$(${RPC} feed.save '{"id": 0, "name": "e2e", "url": "http://127.0.0.1:8099/list.txt", "enabled": true, "block": true, "refreshSecs": 3600, "username": null, "password": null}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["def"]["id"])')
if wait_until 30 blocked by 198.51.100.10 198.51.100.1; then pass "a blocking list drops what it lists"; else fail "the blocking list doesn't block"; fi
if att; then pass "others still get through"; else fail "a blocking list blocked more than it lists"; fi
${RPC} feed.delete "{\"id\": ${feed}}" >/dev/null
if wait_until 10 by; then pass "removing the list unblocks"; else fail "still blocked after removing the list"; fi
pkill -f 'http.server 8099' || true

say "an ipset edge (iptables, as on Asuswrt-Merlin)"
# The agent only decides (dry run): what blocks now is barbican-edge-ipset, through iptables-legacy and ipset.
command -v ipset >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ipset >/dev/null
mkdir -p /etc/systemd/system/barbican.service.d
printf '[Service]\nExecStart=\nExecStart=%s/barbican --dry-run\n' "${DIR}" >/etc/systemd/system/barbican.service.d/dry-run.conf
systemctl daemon-reload
systemctl restart barbican
nft delete table inet barbican 2>/dev/null || true
cat >/tmp/edge-ipset.conf <<'EOF2'
config barbican 'main'
	option iptables 'iptables-legacy'
	option state '/tmp/edge-ipset-state.json'
	option status '/tmp/edge-ipset-status.json'
	option persist_interval '1'

config upstream 'server'
	option url 'https://127.0.0.1:7380'
	option fingerprint 'FINGERPRINT'
	option token 'e2e-router-token-0123456789'
EOF2
sed -i "s/FINGERPRINT/${FINGERPRINT}/" /tmp/edge-ipset.conf
rm -f /tmp/edge-ipset-state.json
EDGE="${DIR}/barbican-edge-ipset --config /tmp/edge-ipset.conf"
setsid -f sh -c "exec ${EDGE} >/tmp/edge-ipset.log 2>&1" </dev/null
in_ipset() { ipset list barbican-host4 2>/dev/null | grep -q '^203.0.113.10'; }
# An edge configured with another fingerprint refuses the agent.
sed "s/option fingerprint .*/option fingerprint '$(printf '00%.0s' $(seq 32))'/; s#/tmp/edge-ipset-#/tmp/edge-wrong-#;
  s/^config barbican 'main'$/config barbican 'main'\n\toption enabled '0'/" /tmp/edge-ipset.conf >/tmp/edge-wrong.conf
setsid -f sh -c "exec ${DIR}/barbican-edge-ipset --config /tmp/edge-wrong.conf >/tmp/edge-wrong.log 2>&1" </dev/null
wrong() { grep -q "not the configured fingerprint" /tmp/edge-wrong.log; }
if wait_until 10 wrong; then pass "an edge refuses an agent whose certificate isn't the pinned one"; else fail "the wrong fingerprint: $(cat /tmp/edge-wrong.log)"; fi
pkill -f "edge-wrong.conf" || true
if wait_until 10 att; then pass "nothing blocked yet"; else fail "blocked before anything was banned"; fi
${RPC} ban.create '{"net": "203.0.113.10", "secs": 3600, "reason": "e2e ipset"}' >/dev/null
if wait_until 10 in_ipset && wait_until 5 att_blocked; then pass "a ban reaches the ipset and iptables drop it"; else fail "the ipset edge doesn't block"; fi
if by; then pass "others still get through"; else fail "a bystander is blocked by the ipset edge"; fi
if curl -s -o /dev/null -m 2 http://203.0.113.10:9000/; then pass "replies to the host's own connections pass"; else fail "outbound to a banned address broke"; fi
timeout=$(ipset list barbican-host4 | awk '/^203.0.113.10/ {print $3}')
if ((timeout > 3000 && timeout <= 3600)); then pass "the element times out in the kernel (${timeout} s left)"; else fail "timeout ${timeout}"; fi
lift 203.0.113.10
if wait_until 10 att; then pass "a lift reaches it"; else fail "still blocked by the ipset edge"; fi
${RPC} ban.create '{"net": "203.0.113.10", "secs": null, "reason": "e2e ipset"}' >/dev/null
wait_until 10 att_blocked || true
sleep 2
pkill -TERM -f "barbican-edge-ipset --config /tmp/edge-ipset.conf" || true
sleep 1
# A router's firewall restart drops the rules; restore puts them back from the saved state.
iptables-legacy -t mangle -D PREROUTING -j BARBICAN
if att; then pass "without the jump, traffic passes"; else fail "blocked without the jump"; fi
${DIR}/barbican-edge-ipset --config /tmp/edge-ipset.conf restore
if att_blocked; then pass "restore puts the blocks back"; else fail "restore didn't block"; fi
${DIR}/barbican-edge-ipset --config /tmp/edge-ipset.conf remove
if att && ! ipset list -n | grep -q barbican && ! iptables-legacy -t mangle -S | grep -q BARBICAN; then
  pass "remove takes its rules and sets away"
else
  fail "remove left something"
fi
lift 203.0.113.10
rm -f /etc/systemd/system/barbican.service.d/dry-run.conf
systemctl daemon-reload
systemctl restart barbican

say "done"
if ((failures > 0)); then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "all checks passed"
