#!/usr/bin/env bash
# Small static builds of the edge agent for routers, with cargo-zigbuild (see mise.toml), packaged as for a
# release into out/: barbican-edge-<arch>.tar.gz.
#
#   scripts/build-edge.sh                 x86_64, aarch64 and armv7 (Cortex-A7/A9/A15 routers)
#   scripts/build-edge.sh armv7           one of them
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A TARGETS=(
  [x86_64]=x86_64-unknown-linux-musl
  [aarch64]=aarch64-unknown-linux-musl
  [armv7]=armv7-unknown-linux-musleabihf
)
names=("$@")
[[ ${#names[@]} -gt 0 ]] || names=(x86_64 aarch64 armv7)
for name in "${names[@]}"; do
  target=${TARGETS[${name}]:?"unknown architecture ${name} (x86_64, aarch64, armv7)"}
  rustup target add "${target}" >/dev/null
  cargo zigbuild --locked --profile release-small --target "${target}" -p barbican-edge
  scripts/package-edge.sh "${name}" "target/${target}/release-small/barbican-edge" out
done
