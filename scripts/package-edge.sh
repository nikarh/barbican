#!/usr/bin/env bash
# Builds the edge agent's archive for a router: the static binary, its init script and UCI configuration, the LuCI
# pages, and install.sh, which puts them in place when run on the router.
#
#   scripts/package-edge.sh <name> <binary> <output dir>     e.g. armv7 target/armv7-.../barbican-edge out
#
# Outputs barbican-edge-<name>.tar.gz.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <name> <binary> <output dir>" >&2
  exit 2
fi
name=$1 binary=$2 out=$3
cd "$(dirname "$0")/.."
stage="target/package-edge/barbican-edge"
rm -rf "${stage}"
mkdir -p "${stage}/luci" "${out}"
install -m 0755 "${binary}" "${stage}/barbican-edge"
install -m 0755 dist/openwrt/barbican-edge.init "${stage}/barbican-edge.init"
install -m 0644 dist/openwrt/barbican.config "${stage}/barbican.config"
install -m 0755 dist/openwrt/install.sh "${stage}/install.sh"
cp -r luci/luci-app-barbican/htdocs luci/luci-app-barbican/root "${stage}/luci/"
cp README.md LICENSE-MIT LICENSE-APACHE "${stage}/"
tar -C "$(dirname "${stage}")" -czf "${out}/barbican-edge-${name}.tar.gz" barbican-edge
echo "${out}/barbican-edge-${name}.tar.gz"
