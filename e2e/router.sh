#!/usr/bin/env bash
# The router suite: barbican-edge in the OpenWrt VM following the agent in the server VM (run after the server
# suite, which leaves the agent running with an edge client "router"). Run from the host by e2e/run.sh.
#
# The "attacker" is the address 203.0.113.77 on the server VM's link to the router; the router routes it back
# there. Probes are pings to the router's WAN address (OpenWrt's firewall allows them), from 203.0.113.77 and,
# as a bystander, from the server's own 10.99.0.1.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The packages of scripts/package-openwrt.sh.
PACKAGES="$1"
vm=e2e/vm.sh
failures=0

say() { printf '\n== %s\n' "$*"; }
pass() { printf '  ok   %s\n' "$*"; }
fail() {
  printf '  FAIL %s\n' "$*"
  failures=$((failures + 1))
}
wait_until() {
  local deadline=$((SECONDS + $1))
  shift
  until "$@"; do
    ((SECONDS < deadline)) || return 1
    sleep 0.5
  done
}

router() { "${vm}" router ssh "$@"; }
server() { "${vm}" server ssh "$@"; }
rpc() { server "python3 /opt/barbican/rpc.py $*"; }
ping_from() { server "ping -c 1 -W 1 -I $1 10.99.0.2 >/dev/null 2>&1"; }
attacker_through() { ping_from 203.0.113.77; }
attacker_blocked() { ! ping_from 203.0.113.77; }
in_set() { router "nft list set inet barbican host4 2>/dev/null | grep -q '203.0.113.77'"; }
not_in_set() { ! in_set; }
lift_all() { # every active ban of the attacker's address
  local id
  for id in $(rpc bans.list "'{\"active\": true}'" | python3 -c 'import json,sys; print(" ".join(str(b["id"]) for b in json.load(sys.stdin)["rows"] if b["net"] == "203.0.113.77"))'); do
    rpc ban.lift "'{\"id\": ${id}}'" >/dev/null
  done
}

say "setup"
router '[ -x /etc/init.d/barbican-edge ] && /etc/init.d/barbican-edge stop; true'
server 'sudo ip link set enp0s3 up && sudo ip addr replace 10.99.0.1/24 dev enp0s3 && sudo ip addr replace 203.0.113.77/32 dev enp0s3'
router 'ip route replace 203.0.113.77/32 dev eth1'
router 'apk del barbican-edge luci-app-barbican >/dev/null 2>&1; rm -f /etc/barbican/state.json; nft delete table inet barbican 2>/dev/null; mkdir -p /etc/barbican; true'
cat >"${TMPDIR:-/tmp}/barbican-e2e-uci" <<'EOF'
config barbican 'main'
	option enabled '1'
	option persist_interval '1'

config upstream 'server'
	option url 'http://10.99.0.1:7380'
	option token 'e2e-router-token-0123456789'
EOF
"${vm}" router put "${TMPDIR:-/tmp}/barbican-e2e-uci" /etc/config/barbican
"${vm}" router put "${PACKAGES}/barbican-edge-x86_64.apk" /tmp/barbican-edge.apk
"${vm}" router put "${PACKAGES}/luci-app-barbican.apk" /tmp/luci-app-barbican.apk
if wait_until 10 attacker_through; then pass "the attacker reaches the router"; else fail "no ping through before anything is blocked"; fi

say "following the agent"
rpc ban.create "'{\"net\": \"203.0.113.77\", \"secs\": null, \"reason\": \"e2e edge\"}'" >/dev/null
# Installed as a package, which enables and starts it.
router 'apk add --allow-untrusted /tmp/barbican-edge.apk /tmp/luci-app-barbican.apk >/dev/null 2>&1'
if router '[ -e /etc/rc.d/S11barbican-edge ] && pidof barbican-edge >/dev/null'; then pass "the package installs, enables and starts it"; else fail "the package didn't start it"; fi
if wait_until 15 in_set; then pass "the agent's ban reached the router"; else fail "the ban isn't in the router's set"; fi
if attacker_blocked; then pass "the router drops the banned address"; else fail "the banned address still gets through the router"; fi
if ping_from 10.99.0.1; then pass "others still get through"; else fail "a bystander is blocked on the router"; fi
status=$(router 'barbican-edge status')
if python3 -c 'import json,sys; s=json.loads(sys.argv[1]); assert s["upstreams"][0]["connected"] and s["blocks"] >= 1' "${status}"; then
  pass "barbican-edge status reports the upstream and the block"
else
  fail "status: ${status}"
fi

say "lifting on the agent"
start=${SECONDS}
lift_all
if wait_until 10 not_in_set; then pass "a lift reaches the router in $((SECONDS - start)) s (long poll)"; else fail "the lift didn't reach the router"; fi
if wait_until 5 attacker_through; then pass "lifted on the router"; else fail "still blocked on the router"; fi

say "a reboot without the agent"
rpc ban.create "'{\"net\": \"203.0.113.77\", \"secs\": null, \"reason\": \"e2e edge reboot\"}'" >/dev/null
wait_until 15 in_set || true
# The state is saved when it changed, at most every persist_interval (1 s here).
sleep 3
server 'sudo systemctl stop barbican'
router 'reboot' || true
# Until the old system is gone (SSH answers for a while during the shutdown), then until the new one is up.
down() { ! router true 2>/dev/null; }
wait_until 120 down || true
"${vm}" router up >/dev/null 2>&1
router 'ip route replace 203.0.113.77/32 dev eth1'
if in_set && attacker_blocked; then pass "blocks are back after a reboot, with the agent down"; else fail "the router forgot its blocks"; fi
status=$(router 'barbican-edge status')
if python3 -c 'import json,sys; s=json.loads(sys.argv[1]); assert not s["upstreams"][0]["connected"]' "${status}"; then
  pass "the upstream is reported down"
else
  fail "status after the reboot: ${status}"
fi
server 'sudo systemctl start barbican'
connected() { router 'barbican-edge status' | grep -q '"connected":true'; }
if wait_until 30 connected; then
  pass "it follows the agent again once it is back"
else
  fail "didn't reconnect"
fi

say "LuCI"
if router 'wget -qO- http://127.0.0.1/luci-static/resources/view/barbican/status.js | grep -q barbican-edge'; then
  pass "the views are served"
else
  fail "the views aren't served"
fi
if router 'ubus call luci getMenu "{}" 2>/dev/null | grep -q "barbican" || jsonfilter -i /usr/share/luci/menu.d/luci-app-barbican.json -e "@" >/dev/null'; then
  pass "the menu is valid"
else
  fail "the menu"
fi

say "cleanup"
lift_all
router 'apk del barbican-edge luci-app-barbican >/dev/null 2>&1; barbican-edge remove 2>/dev/null; true'
if router '! pidof barbican-edge >/dev/null && [ ! -e /etc/rc.d/S11barbican-edge ] && [ -f /etc/config/barbican ]'; then
  pass "removing the package stops it and keeps the configuration"
else
  fail "removing the package"
fi

if ((failures > 0)); then
  say "barbican-edge's log"
  router 'logread -e barbican | tail -n 40' || true
  echo "${failures} check(s) failed"
  exit 1
fi
echo "all checks passed"
