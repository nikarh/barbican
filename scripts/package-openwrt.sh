#!/usr/bin/env bash
# Builds OpenWrt packages: barbican-edge for one CPU, and luci-app-barbican, as .apk (OpenWrt 25.12 and later, with
# apk-tools 3's mkpkg, run in an Alpine container when this system has none) and .ipk (24.10 and earlier).
#
#   scripts/package-openwrt.sh <name> <binary> <output dir>   e.g. armv7 target/armv7-.../barbican-edge out
#
# Outputs barbican-edge-<name>.apk, barbican-edge-<name>.ipk, luci-app-barbican.apk and luci-app-barbican.ipk. The
# binary is static, so the packages are "noarch": the file name says which CPU it is for. The configuration isn't part
# of the package (an upgrade keeps it): its post-install script writes the default when there is none.
#
# The version is the binary's own. A build of main (0.1.0-dev+abc1234) is numbered by the commits up to it: before
# the release of its base version 0.1.0_pre205 (apk) and 0.1.0~dev205 (ipk), after it 0.1.0_p205 and 0.1.0+dev205.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <name> <binary> <output dir>" >&2
  exit 2
fi
name=$1 binary=$2 out=$3
cd "$(dirname "$0")/.."
root=$(pwd)
mkdir -p "${out}"
out=$(cd "${out}" && pwd)

version=$("${binary}" --version 2>/dev/null | awk '{print $2}') || true
if [[ -z "${version}" ]]; then
  # A binary for another CPU can't run here: the version of the sources.
  version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)${BARBICAN_VERSION_SUFFIX:-}
fi
if [[ "${version}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-dev\+([0-9a-f]+)$ ]]; then
  base=${BASH_REMATCH[1]} commit=${BASH_REMATCH[2]}
  count=$(git rev-list --count "${commit}")
  if git ls-remote --exit-code --tags origin "refs/tags/v${base}" >/dev/null 2>&1; then
    apk_version="${base}_p${count}-r1" ipk_version="${base}+dev${count}-1"
  else
    apk_version="${base}_pre${count}-r1" ipk_version="${base}~dev${count}-1"
  fi
elif [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  apk_version="${version}-r1" ipk_version="${version}-1"
else
  echo "can't package version ${version}" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "${stage}"' EXIT

# The files of both packages.
edge="${stage}/barbican-edge"
install -D -m 0755 "${binary}" "${edge}/usr/sbin/barbican-edge"
install -D -m 0755 dist/openwrt/barbican-edge.init "${edge}/etc/init.d/barbican-edge"
install -D -m 0644 dist/openwrt/barbican.config "${edge}/usr/share/barbican/barbican.config"
install -D -m 0644 LICENSE-MIT "${edge}/usr/share/licenses/barbican-edge/LICENSE-MIT"
install -D -m 0644 LICENSE-APACHE "${edge}/usr/share/licenses/barbican-edge/LICENSE-APACHE"
luci="${stage}/luci-app-barbican"
mkdir -p "${luci}"
cp -r luci/luci-app-barbican/root/. "${luci}/"
mkdir -p "${luci}/www"
cp -r luci/luci-app-barbican/htdocs/. "${luci}/www/"

# .apk, with apk mkpkg (here, or in a container).
mkpkg() { # <package> <version> <description> <depends> <output>
  local pkg=$1
  local args=(mkpkg --files "/stage/${pkg}" --output "/out/$5"
    --info "name:${pkg}" --info "version:$2" --info "description:$3" --info arch:noarch
    --info "license:MIT OR Apache-2.0" --info "origin:${pkg}" --info "url:https://github.com/nikarh/barbican"
    --info "maintainer:Nikolay Arhipov <nikarh@users.noreply.github.com>")
  [[ -n "$4" ]] && args+=(--info "depends:$4")
  # apk runs post-upgrade, not post-install, on an upgrade: both run the postinst (which restarts the service).
  for kind in post-install:postinst post-upgrade:postinst pre-deinstall:prerm post-deinstall:postrm; do
    local script="dist/openwrt/package/${pkg}.${kind#*:}"
    [[ -f "${script}" ]] && cp "${script}" "${stage}/${pkg}.${kind#*:}" && args+=(--script "${kind%%:*}:/stage/${pkg}.${kind#*:}")
  done
  if apk mkpkg --help >/dev/null 2>&1; then
    # The same paths as in the container.
    local link
    link=$(mktemp -d)
    ln -s "${stage}" "${link}/stage"
    ln -s "${out}" "${link}/out"
    (cd "${link}" && apk "${args[@]//\/stage/${link}/stage}")
  else
    "${CONTAINER:-$(command -v docker || command -v podman)}" run --rm -v "${stage}:/stage:ro" -v "${out}:/out" docker.io/library/alpine:edge \
      apk "${args[@]}"
  fi
}
mkpkg barbican-edge "${apk_version}" "Applies the blocks of barbican agents on the router, with nftables" \
  "nftables-json" "barbican-edge-${name}.apk"
mkpkg luci-app-barbican "${apk_version}" "LuCI pages of barbican-edge" "barbican-edge luci-base" \
  "luci-app-barbican.apk"

# .ipk: a gzipped tar of debian-binary, control.tar.gz and data.tar.gz.
ipk() { # <package> <version> <description> <depends> <output>
  local pkg=$1 dir="${stage}/ipk-$1"
  mkdir -p "${dir}/control"
  cat >"${dir}/control/control" <<CONTROL
Package: ${pkg}
Version: $2
Depends: $4
Architecture: all
Maintainer: Nikolay Arhipov <nikarh@users.noreply.github.com>
License: MIT OR Apache-2.0
Section: net
Description: $3
CONTROL
  for script in postinst prerm postrm; do
    [[ -f "dist/openwrt/package/${pkg}.${script}" ]] && install -m 0755 "dist/openwrt/package/${pkg}.${script}" "${dir}/control/${script}"
  done
  echo "2.0" >"${dir}/debian-binary"
  tar --owner=0 --group=0 -C "${dir}/control" -czf "${dir}/control.tar.gz" .
  tar --owner=0 --group=0 -C "${stage}/${pkg}" -czf "${dir}/data.tar.gz" .
  tar --owner=0 --group=0 -C "${dir}" -czf "${out}/$5" ./debian-binary ./data.tar.gz ./control.tar.gz
}
ipk barbican-edge "${ipk_version}" "Applies the blocks of barbican agents on the router, with nftables" \
  "nftables-json" "barbican-edge-${name}.ipk"
ipk luci-app-barbican "${ipk_version}" "LuCI pages of barbican-edge" "barbican-edge, luci-base" "luci-app-barbican.ipk"
ls -1 "${out}"/barbican-edge-"${name}".{apk,ipk} "${out}"/luci-app-barbican.{apk,ipk}
