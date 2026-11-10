#!/usr/bin/env bash
# Small static builds of the edge agents for routers, with cargo-zigbuild (see mise.toml), packaged as for a release
# into out/:
#
#   barbican-edge-{x86_64,aarch64,armv7}.tar.gz   nftables, for OpenWrt (armv7: Cortex-A7/A9/A15 with an FPU),
#   barbican-edge-<arch>.{apk,ipk}                 and its OpenWrt packages, with luci-app-barbican.{apk,ipk}
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
# All in one build: with codegen-units = 1, each target's last step uses a single core.
declare -A targets=()
for name in "${names[@]}"; do
  targets[${TARGETS[${name}]:?"unknown build ${name} (${!TARGETS[*]})"}]=1
done
rustup target add "${!targets[@]}" >/dev/null
args=()
for target in "${!targets[@]}"; do args+=(--target "${target}"); done
cargo zigbuild --locked --profile release-small "${args[@]}" -p barbican-edge
for name in "${names[@]}"; do
  target=${TARGETS[${name}]}
  dir="target/${target}/release-small"
  case "${name}" in
    ipset-*) scripts/package-edge.sh ipset "${name#ipset-}" "${dir}/barbican-edge-ipset" out ;;
    *)
      scripts/package-edge.sh nft "${name}" "${dir}/barbican-edge" out
      scripts/package-openwrt.sh "${name}" "${dir}/barbican-edge" out
      ;;
  esac
done
