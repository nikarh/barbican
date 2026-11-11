# OpenWrt

`barbican-edge` blocks what barbican agents ban, for everything the router forwards and for the router itself. It
needs nftables with JSON support (`nftables-json`, which OpenWrt's images have).

Pick the build for the router's CPU: `x86_64`, `aarch64`, or `armv7` (32-bit ARM with an FPU: Cortex-A7, A9, A15;
`cat /proc/cpuinfo` lists `vfp` among its features). The packages are the same for every OpenWrt target of that CPU.

## OpenWrt 25.12 and later (apk)

```sh
cd /tmp
wget https://github.com/nikarh/barbican/releases/latest/download/barbican-edge-armv7.apk
wget https://github.com/nikarh/barbican/releases/latest/download/luci-app-barbican.apk
apk add --allow-untrusted ./barbican-edge-armv7.apk ./luci-app-barbican.apk
```

## OpenWrt 24.10 and earlier (opkg)

```sh
cd /tmp
wget https://github.com/nikarh/barbican/releases/latest/download/barbican-edge-armv7.ipk
wget https://github.com/nikarh/barbican/releases/latest/download/luci-app-barbican.ipk
opkg install ./barbican-edge-armv7.ipk ./luci-app-barbican.ipk
```

(When the router's `wget` can't do HTTPS, download on another machine and copy the files over.)

## Configuring

The package enables and starts the agent. Add the agents it follows in LuCI (**Services → Barbican → Settings**) or in
`/etc/config/barbican`, which upgrades keep:

```text
config barbican 'main'
	option enabled '1'
	option dry_run '0'             # 1: follow and save, but change nothing in the firewall
	option lists '1'               # also the agents' country blocks and blocking lists
	option persist_interval '3600'

config upstream 'server'
	option url 'https://192.168.1.10:7380'
	option fingerprint '3F:A1:...'        # barbican edge-fingerprint, on the agent
	option token_file '/etc/barbican/server.token'
```

then `/etc/init.d/barbican-edge restart`. **Services → Barbican → Status** (or `barbican-edge status`) shows whether
it follows its agents and what it blocks. The edge stays connected to each agent and reports to it, so each agent's UI
shows it too (**Settings → Edges**): whether it is connected, what it applied, and what its firewall dropped. See
[Connecting an edge to an agent](README.md#connecting-an-edge-to-an-agent).

Without IPv6 on the router, `option ipv6 '0'` leaves it out: its country and blocklist prefixes would otherwise take
about as much memory as IPv4's (roughly 140 bytes each; ~12 MB for Africa, Asia and South America).

Every minute (`option check_interval`, in seconds) the edge asks nftables for the ruleset's generation, one small
request: when another program changed the ruleset (a firewall restart flushes it), the table is put right.

The state is saved to `/etc/barbican/state.json` when it changed, at most once an hour (flash wears), and on a clean
stop; at boot it is put back before the firewall and the network start, so blocks hold across reboots and while the
agents are unreachable.

## By hand

`barbican-edge-<arch>.tar.gz` has the same files and an `install.sh` that puts them in place (and in
`/etc/sysupgrade.conf`). Removing the package (`apk del barbican-edge luci-app-barbican`, or `opkg remove`) stops it
and removes its table; the configuration stays.
