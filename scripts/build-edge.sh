#!/usr/bin/env bash
# Small static builds of the edge agents for routers, with cargo-zigbuild (see mise.toml), packaged as for a release
# into out/:
#
#   barbican-edge-{x86_64,aarch64,armv7}.tar.gz   nftables, for OpenWrt (armv7: Cortex-A7/A9/A15 with an FPU)
#   barbican-edge-ipset-armv7.tar.gz              iptables and ipset, for Asuswrt-Merlin (armv7 without an FPU,
#                                                 which also runs on the newer, 64-bit routers' 32-bit userspace)
#   barbican-edge-ipset-x86_64.tar.gz             the same, for tests
#
#   scripts/build-edge.sh                         all of them
#   scripts/build-edge.sh armv7 ipset-armv7       some
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A TARGETS=(
  [x86_64]=x86_64-unknown-linux-musl
  [aarch64]=aarch64-unknown-linux-musl
  [armv7]=armv7-unknown-linux-musleabihf
  [ipset-armv7]=armv7-unknown-linux-musleabi
  [ipset-x86_64]=x86_64-unknown-linux-musl
)
names=("$@")
[[ ${#names[@]} -gt 0 ]] || names=(x86_64 aarch64 armv7 ipset-armv7 ipset-x86_64)
for name in "${names[@]}"; do
  target=${TARGETS[${name}]:?"unknown build ${name} (${!TARGETS[*]})"}
  rustup target add "${target}" >/dev/null
  cargo zigbuild --locked --profile release-small --target "${target}" -p barbican-edge
  dir="target/${target}/release-small"
  case "${name}" in
    ipset-*) scripts/package-edge.sh ipset "${name#ipset-}" "${dir}/barbican-edge-ipset" out ;;
    *) scripts/package-edge.sh nft "${name}" "${dir}/barbican-edge" out ;;
  esac
done
