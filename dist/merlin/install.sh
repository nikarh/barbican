#!/bin/sh
# Installs (or upgrades) barbican-edge-ipset on Asuswrt-Merlin. Run it on the router, from the unpacked archive:
#
#   tar -xzf barbican-edge-ipset-<arch>.tar.gz && cd barbican-edge-ipset && ./install.sh
#
# Needs JFFS custom scripts (Administration, System: "Enable JFFS custom scripts and configs"). Everything goes to
# /jffs/barbican; marked blocks are added to /jffs/scripts/services-start and firewall-start. Keeps an existing
# configuration.
set -eu
cd "$(dirname "$0")"
DIR=/jffs/barbican

if [ "$(nvram get jffs2_scripts 2>/dev/null)" != 1 ]; then
	echo "JFFS custom scripts are off: turn them on first (nvram set jffs2_scripts=1; nvram commit)" >&2
	exit 1
fi
for tool in ipset iptables; do
	command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done

mkdir -p "$DIR" /jffs/scripts
[ -x "$DIR/barbican.sh" ] && "$DIR/barbican.sh" stop || true
cp barbican-edge-ipset "$DIR/barbican-edge-ipset"
cp barbican.sh "$DIR/barbican.sh"
chmod 0755 "$DIR/barbican-edge-ipset" "$DIR/barbican.sh"
[ -f "$DIR/barbican.conf" ] || { cp barbican.conf "$DIR/barbican.conf"; chmod 0600 "$DIR/barbican.conf"; }

# add_block <script> <line>: the line between marks, once.
add_block() {
	[ -f "$1" ] || printf '#!/bin/sh\n' >"$1"
	chmod 0755 "$1"
	if ! grep -q '^# BEGIN barbican' "$1"; then
		printf '# BEGIN barbican\n%s\n# END barbican\n' "$2" >>"$1"
	fi
}
add_block /jffs/scripts/services-start "$DIR/barbican.sh start"
add_block /jffs/scripts/firewall-start "$DIR/barbican.sh restore"

"$DIR/barbican.sh" start
echo "barbican-edge-ipset $("$DIR/barbican-edge-ipset" --version | cut -d' ' -f2) installed: add agents to $DIR/barbican.conf, then $DIR/barbican.sh restart"
