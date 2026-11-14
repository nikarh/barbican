#!/usr/bin/env bash
# The server suite: runs inside the server VM as root (e2e/run.sh copies it there with the binaries).
#
# Attackers live in network namespaces routed from the VM: `att` has 203.0.113.10 and 1.0.1.10 (an address the
# geolocation database puts in China), `by` (a bystander) has 198.51.100.10. The VM serves HTTP on 203.0.113.1:8080
# and 198.51.100.1:8080; `att` serves HTTP on 203.0.113.10:9000. barbican runs as the systemd service, reading a
# Traefik access log (a file), the journal and a container's log; at the end its UI moves to a unix socket, for the
# image's UI proxy in a container.
set -euo pipefail

DIR=/opt/barbican
RPC="python3 ${DIR}/rpc.py"
LOG=/var/log/e2e/access.log
failures=0

# Each section says how long it took, so that the slow ones stand out.
section_start=
say() {
  local now
  now=$(date +%s%3N)
  [[ -z "${section_start}" ]] || printf '  (%d ms)\n' $((now - section_start))
  section_start=${now}
  printf '\n== %s\n' "$*"
}
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
    sleep 0.1
  done
}

# Dropped packets show as a connection that doesn't happen. Over a veth the kernel answers a SYN in well under a
# millisecond, busy or not, so 150 ms without an answer means dropped (each check that finds a block waits that long).
reach() { # <netns> <source address> <target>
  ip netns exec "$1" curl -s -o /dev/null --connect-timeout 0.15 -m 3 --interface "$2" "http://$3:8080/"
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
banned() { [[ -n $(active_ban_id "$1") ]]; }
# Whether the agent has handled an event of this address: what it did about it is in the database by then.
seen() { # <ip>
  ${RPC} events.list "{\"ip\": \"$1\", \"offset\": 0}" | python3 -c "import json, sys; sys.exit(not json.load(sys.stdin)['rows'])"
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
socket = "/run/barbican-ui/ui.sock"
socket_group = "barbican-ui"

[edge]
listen = "0.0.0.0:7380"
[[edge.client]]
name = "router"
token = "e2e-router-token-0123456789"

[firewall]
# Whether another program changed nftables: every minute by default.
check_interval = 1

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
  install -D -m 0644 "${DIR}/barbican.sysusers" /etc/sysusers.d/barbican.conf
  systemd-sysusers
  install -D -m 0644 "${DIR}/barbican.tmpfiles" /etc/tmpfiles.d/barbican.conf
  systemd-tmpfiles --create barbican.conf
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
# An allowed address leaves no trace; a probe after it, from elsewhere, is handled after it.
probe 192.0.2.10
wait_until 5 banned 192.0.2.10 || true
if att && ! banned 203.0.113.10; then pass "an allowed address isn't banned"; else fail "an allowed address was banned"; fi
${RPC} entry.delete "{\"id\": ${entry}}" >/dev/null
lift 192.0.2.10

say "thresholds, from the journal"
systemd-cat -t e2e-sshd echo "Invalid user admin from 198.51.100.10 port 4242"
wait_until 5 seen 198.51.100.10 || true
if by && ! banned 198.51.100.10; then pass "one unknown user isn't enough"; else fail "banned on the first unknown user"; fi
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
# Its prefixes merged into ranges: runs of adjacent prefixes that are no prefix together are one element each.
read -r count ranges < <(nft -j list set inet barbican list4 | python3 -c '
import json, sys
elems = [e for i in json.load(sys.stdin)["nftables"] if "set" in i for e in i["set"].get("elem", [])]
print(len(elems), sum(1 for e in elems if isinstance(e, dict) and "range" in e))')
if ((count > 1000 && ranges > 0)); then pass "the country is in the set as ${count} elements, ${ranges} of them ranges"; else fail "${count} elements, ${ranges} ranges"; fi
policy=$(${RPC} policy.get | python3 -c 'import json,sys; p=json.load(sys.stdin); p["blockedCountries"]=[]; print(json.dumps(p))')
${RPC} policy.update "${policy}" >/dev/null
if wait_until 30 cn; then pass "unblocked"; else fail "still blocked after unblocking the country"; fi

say "a large list loaded"
# 300 000 prefixes, 1.0.1.0/24 among them: changing a set must not cost more for it (nft alone reads every set's
# elements before any change, seconds with a list this size).
mkdir -p /tmp/biglist
python3 -c '
print("1.0.1.0/24")
for i in range(299999):
    n = (11 << 16) + 2 * i
    print(f"{n >> 16}.{(n >> 8) & 255}.{n & 255}.0/24")' >/tmp/biglist/list.txt
setsid -f sh -c 'cd /tmp/biglist && exec python3 -m http.server 8098 --bind 127.0.0.1' </dev/null >/dev/null 2>&1
wait_until 5 curl -fs -o /dev/null http://127.0.0.1:8098/list.txt
big=$(${RPC} feed.save '{"id": 0, "name": "e2e large", "url": "http://127.0.0.1:8098/list.txt", "enabled": true, "block": true, "refreshSecs": 86400, "username": null, "password": null}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["def"]["id"])')
if wait_until 60 cn_blocked; then pass "a list of 300000 prefixes is loaded"; else fail "the large list isn't loaded"; fi
# How long from asking until packets are dropped (or pass again): each probe that gets through takes a moment, the
# first one dropped is when the change was in place.
time_until() { # <check>
  local start now
  start=$(date +%s%N)
  while :; do
    now=$(date +%s%N)
    "$@" && break
    ((now - start < 10000000000)) || break
  done
  echo $(((now - start) / 1000000))
}
${RPC} ban.create '{"net": "203.0.113.10", "secs": 600, "reason": "e2e"}' >/dev/null &
ms=$(time_until att_blocked)
wait
if ((ms < 500)); then pass "a ban is in place within ${ms} ms"; else fail "a ban took ${ms} ms with the large list loaded"; fi
# Whether it passes, at once: over a veth an answer takes well under a millisecond.
att_now() { ip netns exec att curl -s -o /dev/null --connect-timeout 0.05 -m 1 --interface 203.0.113.10 http://203.0.113.1:8080/; }
id=$(active_ban_id 203.0.113.10)
${RPC} ban.lift "{\"id\": ${id}}" >/dev/null &
ms=$(time_until att_now)
wait
if ((ms < 500)); then pass "lifted within ${ms} ms"; else fail "lifting took ${ms} ms with the large list loaded"; fi
# Another program changing the table while the agent runs: the next check of the ruleset's generation (every second
# here) notices, and it is put right.
${RPC} ban.create '{"net": "203.0.113.10", "secs": 600, "reason": "e2e"}' >/dev/null
wait_until 5 att_blocked || true
nft delete element inet barbican host4 '{ 203.0.113.10 }'
if wait_until 5 att_blocked; then pass "a ban removed by hand is put back"; else fail "a ban removed by hand stays removed"; fi
nft delete table inet barbican
if wait_until 10 att_blocked && cn_blocked; then pass "a deleted table comes back, bans and lists in it"; else fail "not repaired after deleting the table"; fi
lift 203.0.113.10
${RPC} feed.delete "{\"id\": ${big}}" >/dev/null
if wait_until 30 cn; then pass "removing the list unblocks"; else fail "still blocked after removing the large list"; fi
pkill -f 'http.server 8098' || true
if journalctl -u barbican --since "${started_at}" | grep -q "using the nft program instead"; then
  fail "netlink failed: $(journalctl -u barbican --since "${started_at}" | grep "using the nft program instead" | head -1)"
else
  pass "elements changed over netlink throughout"
fi

say "bans run out in the kernel"
${RPC} ban.create '{"net": "203.0.113.10", "secs": 5, "reason": "e2e"}' >/dev/null
if wait_until 5 att_blocked; then pass "a ban by hand blocks"; else fail "a ban by hand doesn't block"; fi
systemctl stop barbican
if nft list table inet barbican >/dev/null && att_blocked; then pass "stopping leaves the blocks in place"; else fail "stopping removed the blocks"; fi
if wait_until 8 att; then pass "the kernel lifted the ban on time, without the agent"; else fail "the ban outlived its time"; fi

say "a reboot"
systemctl start barbican
${RPC} ban.create '{"net": "203.0.113.10", "secs": null, "reason": "e2e forever"}' >/dev/null
wait_until 5 att_blocked || true
# What was dropped: the kernel's counter of the ban rules, and the agent's total (the counters are read every second
# here: check_interval).
kernel_dropped() { nft -j list chain inet barbican prerouting | python3 -c 'import json,sys; print(sum(e["counter"]["packets"] for i in json.load(sys.stdin)["nftables"] if "rule" in i and i["rule"].get("comment") == "blocked" for e in i["rule"]["expr"] if "counter" in e))'; }
total_dropped() { ${RPC} overview.get | python3 -c 'import json,sys; print(json.load(sys.stdin)["firewall"]["droppedBlocked"])'; }
att_blocked || true
before=$(kernel_dropped)
total_seen() { (($(total_dropped) >= before)); }
wait_until 5 total_seen || true
total_before=$(total_dropped)
systemctl restart barbican
if ((before > 0)) && (($(kernel_dropped) >= before)); then
  pass "a restart keeps the kernel's drop counters (${before} packets)"
else
  fail "the drop counters started again after a restart: ${before}, then $(kernel_dropped)"
fi
if (($(total_dropped) >= total_before)); then pass "and the total"; else fail "the total dropped: ${total_before}, then $(total_dropped)"; fi
systemctl stop barbican
# A reboot loses the table.
nft delete table inet barbican
if att; then pass "without the table, traffic passes"; else fail "blocked without the table"; fi
systemctl start barbican
if att_blocked; then pass "blocks are back by the time the agent reports ready"; else fail "blocks came back late"; fi
# The table is new and its counters start from 0; the total goes on from where it was.
total_kept() { (($(total_dropped) > total_before)); }
if wait_until 5 total_kept; then
  pass "the drop total survives the table being made anew ($(total_dropped) packets, kernel $(kernel_dropped))"
else
  fail "the total after the table was made anew: $(total_dropped), before ${total_before}"
fi

say "the edge API"
if ! curl -s -m 3 -o /dev/null http://127.0.0.1:7380/; then
  pass "plain HTTP is refused (TLS only)"
else
  fail "answers plain HTTP"
fi
command -v openssl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl >/dev/null
FINGERPRINT=$(${DIR}/barbican edge-fingerprint --config /etc/barbican/config.toml)
served=$(openssl s_client -connect 127.0.0.1:7380 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
if [[ ${served} == "${FINGERPRINT}" ]]; then pass "edge-fingerprint prints the served certificate's fingerprint"; else fail "fingerprint ${FINGERPRINT} != ${served}"; fi
# Edges that only follow (dry run): one with a token the agent doesn't know, one with the right one.
edge_conf() { # <name> <token>
  cat <<EOF2
config barbican 'main'
	option dry_run '1'
	option state '/tmp/edge-$1-state.json'
	option status '/tmp/edge-$1-status.json'

config upstream 'server'
	option url 'https://127.0.0.1:7380'
	option fingerprint '${FINGERPRINT}'
	option token '$2'
EOF2
}
edge_conf stranger 'not-a-known-token-0123456789' >/tmp/edge-stranger.conf
edge_conf follower 'e2e-router-token-0123456789' >/tmp/edge-follower.conf
rm -f /tmp/edge-stranger-* /tmp/edge-follower-*
for name in stranger follower; do
  setsid -f sh -c "exec ${DIR}/barbican-edge-ipset --config /tmp/edge-${name}.conf >/tmp/edge-${name}.log 2>&1" </dev/null
done
refused() { grep -q "refused this edge: unknown token" /tmp/edge-stranger.log 2>/dev/null; }
if wait_until 10 refused; then pass "refuses an edge without a known token"; else fail "the stranger: $(cat /tmp/edge-stranger.log)"; fi
followed() { grep -q '"203.0.113.10"' /tmp/edge-follower-status.json 2>/dev/null; }
if wait_until 10 followed; then pass "gives an edge the whole state"; else fail "the follower: $(cat /tmp/edge-follower.log)"; fi
edge_seen() {
  ${RPC} edges.list | python3 -c 'import json,sys
e = {x["name"]: x for x in json.load(sys.stdin)}["router"]
assert e["connected"] and e["enforcing"] is False and e["report"]["blocks"] >= 1, e'
}
if wait_until 10 edge_seen; then pass "the agent sees the edge connected, in dry run, with its blocks"; else fail "edges: $(${RPC} edges.list)"; fi
pkill -f "edge-stranger.conf" || true
pkill -f "edge-follower.conf" || true
edge_gone() { ${RPC} edges.list | python3 -c 'import json,sys; sys.exit({x["name"]: x for x in json.load(sys.stdin)}["router"]["connected"])'; }
if wait_until 10 edge_gone; then pass "and sees it go"; else fail "the edge still shows as connected"; fi
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
wait_until 5 curl -fs -o /dev/null http://127.0.0.1:8099/list.txt
feed=$(${RPC} feed.save '{"id": 0, "name": "e2e", "url": "http://127.0.0.1:8099/list.txt", "enabled": true, "block": true, "refreshSecs": 3600, "username": null, "password": null}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["def"]["id"])')
if wait_until 30 blocked by 198.51.100.10 198.51.100.1; then pass "a blocking list drops what it lists"; else fail "the blocking list doesn't block"; fi
if att; then pass "others still get through"; else fail "a blocking list blocked more than it lists"; fi
${RPC} feed.delete "{\"id\": ${feed}}" >/dev/null
if wait_until 10 by; then pass "removing the list unblocks"; else fail "still blocked after removing the list"; fi
# Lists of one JSON document (fetched together), of networks and of user agents, added at once as the catalog does.
cat >/tmp/feed/bots.json <<'EOF2'
{"services": {"A": {"ipv4": ["198.51.100.0/25"], "ipv6": []}, "B (b)": {"ipv4": ["203.0.113.7"], "ipv6": ["2001:db8::/48"]}}}
EOF2
printf 'ASN,Entity\n13335,"Cloudflare, Inc."\n' >/tmp/feed/asns.csv
printf 'User-agent: GPTBot\nUser-agent: CCBot\nDisallow: /\n' >/tmp/feed/robots.txt
feed_def() { # <name> <file> <content> <select or null>
  printf '{"id": 0, "name": "%s", "url": "http://127.0.0.1:8099/%s", "enabled": true, "block": false, "refreshSecs": 3600, "username": null, "password": null, "content": "%s", "select": %s, "catalog": null}' "$@"
}
${RPC} feeds.apply "{\"delete\": [], \"save\": [$(feed_def bots-a bots.json addresses '"/services/A"'), $(feed_def bots-b bots.json addresses '"/services/B (b)"'), $(feed_def asns asns.csv networks null), $(feed_def agents robots.txt agents null)]}" >/dev/null
feeds_are() { # <python condition on f, the feeds by name>
  ${RPC} feeds.list | python3 -c 'import json,sys; f={x["def"]["name"]: x for x in json.load(sys.stdin)}; sys.exit(not eval(sys.argv[1]))' "$1"
}
if wait_until 60 feeds_are 'f["bots-a"]["count"] == 1 and f["bots-b"]["count"] == 2 and f["agents"]["count"] == 2'; then
  pass "services of one JSON document and a list of user agents are read"
else
  fail "lists: $(${RPC} feeds.list)"
fi
listed_in() { ${RPC} ip.get "{\"ip\": \"$1\"}" | python3 -c 'import json,sys; sys.exit(sys.argv[1] not in json.load(sys.stdin)["listed"])' "$2"; }
if listed_in 203.0.113.7 bots-b && ! listed_in 203.0.113.7 bots-a; then pass "an address is listed in its service's list only"; else fail "listed: $(${RPC} ip.get '{"ip": "203.0.113.7"}')"; fi
if wait_until 30 feeds_are 'f["asns"]["count"] == 1 and f["asns"]["extent"]["prefixes"] > 10' && listed_in 1.1.1.1 asns; then
  pass "a list of networks stands for their prefixes in the ASN database"
else
  fail "networks: $(${RPC} ip.get '{"ip": "1.1.1.1"}')"
fi
for id in $(${RPC} feeds.list | python3 -c 'import json,sys; print(" ".join(str(f["def"]["id"]) for f in json.load(sys.stdin) if f["def"]["url"].startswith("http://127.0.0.1:8099/")))'); do
  ${RPC} feed.delete "{\"id\": ${id}}" >/dev/null
done
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
rm -f /tmp/edge-ipset-state.json /tmp/edge-ipset-state.lists
EDGE="${DIR}/barbican-edge-ipset --config /tmp/edge-ipset.conf"
setsid -f sh -c "exec ${EDGE} >/tmp/edge-ipset.log 2>&1" </dev/null
in_ipset() { ipset list barbican-host4 2>/dev/null | grep -q '^203.0.113.10'; }
# An edge configured with another fingerprint refuses the agent.
sed "s/option fingerprint .*/option fingerprint '$(printf '00%.0s' $(seq 32))'/; s#/tmp/edge-ipset-#/tmp/edge-wrong-#;
  s/^config barbican 'main'$/config barbican 'main'\n\toption enabled '0'/" /tmp/edge-ipset.conf >/tmp/edge-wrong.conf
setsid -f sh -c "exec ${DIR}/barbican-edge-ipset --config /tmp/edge-wrong.conf >/tmp/edge-wrong.log 2>&1" </dev/null
wrong() { grep -q "not the configured fingerprint" /tmp/edge-wrong.log 2>/dev/null; }
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
# It saves its state as it stops.
pkill -TERM -f "barbican-edge-ipset --config /tmp/edge-ipset.conf" || true
edge_gone() { ! pgrep -f "barbican-edge-ipset --config /tmp/edge-ipset.conf" >/dev/null; }
wait_until 5 edge_gone || true
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

say "the UI's socket"
# Ready (sd_notify) comes before the UI's socket is bound.
socket_ready() { [[ $(stat -c '%a %G' /run/barbican-ui/ui.sock 2>/dev/null) == "660 barbican-ui" ]]; }
if wait_until 10 socket_ready; then
  pass "the UI's socket is barbican-ui's alone (0660)"
else
  fail "the socket: $(ls -la /run/barbican-ui 2>&1)"
fi
if ! sudo -u nobody test -x /run/barbican-ui; then pass "others can't enter its directory"; else fail "/run/barbican-ui is open to others"; fi
if ! ss -Hltn | grep -q ':7381 '; then pass "no UI port"; else fail "the UI listens on a TCP port"; fi
# A member through a supplementary group (as a container with group_add): let in.
id e2e-ui-member >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin -G barbican-ui e2e-ui-member
if sudo -u e2e-ui-member python3 "${DIR}/rpc.py" meta.get >/dev/null 2>&1; then
  pass "a member of barbican-ui (supplementary group) may use the socket"
else
  fail "a member of barbican-ui was refused"
fi
# Someone else, even when the file's mode would let them: the agent checks the peer's credentials itself.
since=$(date '+%F %T')
chmod 0711 /run/barbican-ui
chmod 0666 /run/barbican-ui/ui.sock
if ! sudo -u nobody python3 "${DIR}/rpc.py" meta.get >/dev/null 2>&1 \
  && journalctl -u barbican --since "${since}" | grep -q "Refused a connection to the UI socket"; then
  pass "anyone else is refused on their credentials, whatever the socket's mode"
else
  fail "a stranger got through the socket ($(journalctl -u barbican --since "${since}" | tail -3))"
fi
chmod 2770 /run/barbican-ui
chmod 0660 /run/barbican-ui/ui.sock
if ${RPC} meta.get >/dev/null; then pass "root may use it"; else fail "root was refused"; fi
printf '[ui]\nlisten = "127.0.0.1:7381"\n' >/tmp/ui-listen.toml
# It exits with an error: the output first, then what it says (pipefail would fail a pipeline on that exit).
refused=$(timeout 10 "${DIR}/barbican" --dry-run --config /tmp/ui-listen.toml 2>&1 || true)
if grep -q 'ui.listen is no longer supported' <<<"${refused}"; then
  pass "a configuration with ui.listen is refused, and says why"
else
  fail "ui.listen wasn't refused"
fi
rm -f /tmp/ui-listen.toml

say "the UI in a container"
mkdir -p /tmp/ui-image/ci-rootfs/amd64
install -m 0755 "${DIR}/barbican" /tmp/ui-image/ci-rootfs/amd64/barbican
docker build -q -f "${DIR}/Dockerfile.ci" -t barbican-e2e-ui /tmp/ui-image >/dev/null
gid=$(getent group barbican-ui | cut -d: -f3)
ui_container() { # <name> <port> [docker run options]
  local name=$1 port=$2
  shift 2
  docker rm -f "${name}" >/dev/null 2>&1 || true
  docker run -d --name "${name}" --read-only --cap-drop=ALL --security-opt no-new-privileges --user 65534:65534 \
    -v /run/barbican-ui:/run/barbican-ui:ro -p "127.0.0.1:${port}:8080" "$@" barbican-e2e-ui >/dev/null
}
# A trusted proxy is required; here every address is one (the tests reach the containers through published ports).
any_proxy=(-e BARBICAN_TRUSTED_PROXIES=0.0.0.0/0,::/0)
ui_container e2e-ui 7382 --group-add "${gid}" "${any_proxy[@]}"
ui_container e2e-ui-stranger 7383 "${any_proxy[@]}"
# Only what an authenticating proxy forwarded: from its address, with the user it authenticated.
ui_container e2e-ui-gated 7384 --group-add "${gid}" "${any_proxy[@]}" -e BARBICAN_USER_HEADER=Remote-User
ui_container e2e-ui-elsewhere 7385 --group-add "${gid}" -e BARBICAN_TRUSTED_PROXIES=192.0.2.1/32 -e BARBICAN_USER_HEADER=Remote-User
UI="python3 ${DIR}/rpc.py --url ws://127.0.0.1:7382/api/ws"
healthy() { docker exec e2e-ui /barbican healthcheck; }
if wait_until 10 healthy; then pass "the container is healthy (read-only, no capabilities, nobody)"; else fail "unhealthy: $(docker logs e2e-ui 2>&1 | tail -5)"; fi
if [[ $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7382/) == 200 ]]; then pass "it serves the UI"; else fail "no UI page"; fi
${UI} ban.create '{"net": "203.0.113.10", "secs": 3600, "reason": "e2e ui container"}' >/dev/null || true
if wait_until 5 att_blocked; then pass "a ban made through the container blocks"; else fail "the container's API doesn't reach the agent"; fi
ws() { # <port> [curl options]: the status of a WebSocket handshake
  local port=$1
  shift
  curl -s -o /dev/null -w '%{http_code}' -m 3 "$@" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "http://127.0.0.1:${port}/api/ws" || true
}
if [[ $(ws 7382 -H 'Origin: https://elsewhere.example') == 403 ]]; then pass "the agent still refuses another site's WebSocket"; else fail "a cross-site WebSocket got through the proxy"; fi
if [[ $(ws 7383) == 502 ]]; then pass "a container without the group can't use the socket"; else fail "a container without barbican-ui reached the agent"; fi
code() { curl -s -o /dev/null -w '%{http_code}' -m 3 "$@" || true; }
gated_up() { [[ $(code http://127.0.0.1:7384/healthz) == 200 ]]; }
wait_until 10 gated_up || true
if [[ $(code http://127.0.0.1:7384/) == 403 && $(ws 7384) == 403 && $(code http://127.0.0.1:7384/api/proxy) == 403 ]]; then
  pass "with a trusted proxy set, a request without a user is refused (page, WebSocket, status)"
else
  fail "the gated proxy let a request without a user through"
fi
if [[ $(code -H 'Remote-User: alice' http://127.0.0.1:7384/) == 200 ]] \
  && python3 "${DIR}/rpc.py" --url ws://127.0.0.1:7384/api/ws -H 'Remote-User: alice' meta.get >/dev/null; then
  pass "a request a trusted proxy forwarded with its user passes, the WebSocket too"
else
  fail "the gated proxy refused a forwarded request"
fi
if [[ $(code -H 'Remote-User: alice' http://127.0.0.1:7385/) == 403 && $(code http://127.0.0.1:7385/healthz) == 200 ]]; then
  pass "from an address that isn't the trusted proxy: refused, but the healthcheck answers"
else
  fail "an untrusted address got through the gated proxy"
fi
docker rm -f e2e-ui-unguarded >/dev/null 2>&1 || true
unguarded=$(timeout 10 docker run --rm --name e2e-ui-unguarded --read-only --cap-drop=ALL --user 65534:65534 barbican-e2e-ui 2>&1 || true)
if grep -q -- '--trusted-proxy is required' <<<"${unguarded}"; then
  pass "without a trusted proxy the UI proxy refuses to start"
else
  fail "the UI proxy started without a trusted proxy"
fi
systemctl restart barbican
reconnects() { ${UI} bans.list '{"active": true}' >/dev/null 2>&1; }
if wait_until 10 reconnects; then pass "the container reaches the agent again after it restarted"; else fail "lost the agent after its restart"; fi
id=$(${UI} bans.list '{"active": true}' | python3 -c 'import json,sys; print([b["id"] for b in json.load(sys.stdin)["rows"] if b["net"]=="203.0.113.10"][0])')
${UI} ban.lift "{\"id\": ${id}}" >/dev/null
if wait_until 5 att; then pass "a lift through the container"; else fail "still blocked after lifting through the container"; fi
start=${SECONDS}
docker stop e2e-ui >/dev/null
if ((SECONDS - start < 5)); then pass "it stops at once"; else fail "docker stop took $((SECONDS - start)) s"; fi
docker rm -f e2e-ui e2e-ui-stranger e2e-ui-gated e2e-ui-elsewhere >/dev/null
docker rmi barbican-e2e-ui >/dev/null
userdel e2e-ui-member 2>/dev/null || true

say "done"
if ((failures > 0)); then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "all checks passed"
