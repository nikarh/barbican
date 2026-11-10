#!/bin/sh
# Removes barbican-edge-ipset from Asuswrt-Merlin: its rules and sets, its files and its blocks in /jffs/scripts.
DIR=/jffs/barbican
[ -x "$DIR/barbican.sh" ] && "$DIR/barbican.sh" stop
[ -x "$DIR/barbican-edge-ipset" ] && "$DIR/barbican-edge-ipset" --config "$DIR/barbican.conf" remove
for f in /jffs/scripts/services-start /jffs/scripts/firewall-start; do
	[ -f "$f" ] && sed -i '/^# BEGIN barbican$/,/^# END barbican$/d' "$f"
done
rm -rf "$DIR"
echo "barbican-edge-ipset removed"
