#!/bin/sh
# Installs (or upgrades) barbican-edge on an OpenWrt router. Run it on the router, from the unpacked archive:
#
#   tar -xzf barbican-edge-<arch>.tar.gz && cd barbican-edge && ./install.sh
#
# Keeps an existing /etc/config/barbican. Needs nftables with JSON support (nftables-json, OpenWrt's default).
set -eu
cd "$(dirname "$0")"

if ! nft -j list tables >/dev/null 2>&1; then
	echo "nft can't output JSON: install nftables-json (apk add nftables-json, or opkg install nftables-json)" >&2
	exit 1
fi

[ -x /etc/init.d/barbican-edge ] && /etc/init.d/barbican-edge stop || true
install -m 0755 barbican-edge /usr/sbin/barbican-edge
install -m 0755 barbican-edge.init /etc/init.d/barbican-edge
[ -f /etc/config/barbican ] || install -m 0600 barbican.config /etc/config/barbican
mkdir -p /etc/barbican /www/luci-static/resources/view/barbican /usr/share/luci/menu.d /usr/share/rpcd/acl.d
cp luci/htdocs/luci-static/resources/view/barbican/*.js /www/luci-static/resources/view/barbican/
cp luci/root/usr/share/luci/menu.d/luci-app-barbican.json /usr/share/luci/menu.d/
cp luci/root/usr/share/rpcd/acl.d/luci-app-barbican.json /usr/share/rpcd/acl.d/
# Kept across sysupgrade.
for f in /etc/config/barbican /etc/barbican/ /usr/sbin/barbican-edge /etc/init.d/barbican-edge \
	/www/luci-static/resources/view/barbican/ /usr/share/luci/menu.d/luci-app-barbican.json \
	/usr/share/rpcd/acl.d/luci-app-barbican.json; do
	grep -qxF "$f" /etc/sysupgrade.conf 2>/dev/null || echo "$f" >>/etc/sysupgrade.conf
done
/etc/init.d/rpcd restart
rm -f /tmp/luci-indexcache* 2>/dev/null || true
/etc/init.d/barbican-edge enable
/etc/init.d/barbican-edge start
echo "barbican-edge $(/usr/sbin/barbican-edge --version | cut -d' ' -f2) installed: add agents in LuCI (Services, Barbican) or /etc/config/barbican"
