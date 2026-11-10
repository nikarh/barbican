#!/usr/bin/env bash
# Builds an edge agent's archive for a router.
#
#   scripts/package-edge.sh nft <name> <binary> <output dir>     barbican-edge-<name>.tar.gz, for OpenWrt: the binary,
#                                                                 its init script and UCI configuration, the LuCI pages
#                                                                 and install.sh
#   scripts/package-edge.sh ipset <name> <binary> <output dir>   barbican-edge-ipset-<name>.tar.gz, for
#                                                                 Asuswrt-Merlin: the binary, its supervisor, a
#                                                                 configuration, install.sh and uninstall.sh
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <nft|ipset> <name> <binary> <output dir>" >&2
  exit 2
fi
flavor=$1 name=$2 binary=$3 out=$4
cd "$(dirname "$0")/.."
mkdir -p "${out}"
case "${flavor}" in
  nft)
    stage="target/package-edge/barbican-edge"
    rm -rf "${stage}"
    mkdir -p "${stage}/luci"
    install -m 0755 "${binary}" "${stage}/barbican-edge"
    install -m 0755 dist/openwrt/barbican-edge.init "${stage}/barbican-edge.init"
    install -m 0644 dist/openwrt/barbican.config "${stage}/barbican.config"
    install -m 0755 dist/openwrt/install.sh "${stage}/install.sh"
    cp -r luci/luci-app-barbican/htdocs luci/luci-app-barbican/root "${stage}/luci/"
    archive="${out}/barbican-edge-${name}.tar.gz"
    ;;
  ipset)
    stage="target/package-edge/barbican-edge-ipset"
    rm -rf "${stage}"
    mkdir -p "${stage}"
    install -m 0755 "${binary}" "${stage}/barbican-edge-ipset"
    install -m 0755 dist/merlin/barbican.sh dist/merlin/install.sh dist/merlin/uninstall.sh "${stage}/"
    install -m 0644 dist/merlin/barbican.conf "${stage}/barbican.conf"
    archive="${out}/barbican-edge-ipset-${name}.tar.gz"
    ;;
  *)
    echo "unknown flavor ${flavor} (nft, ipset)" >&2
    exit 2
    ;;
esac
cp README.md LICENSE-MIT LICENSE-APACHE "${stage}/"
tar -C "$(dirname "${stage}")" -czf "${archive}" "$(basename "${stage}")"
echo "${archive}"
