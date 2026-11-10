#!/usr/bin/env bash
# Builds the agent's .deb and Arch Linux packages from a static release binary, with nfpm (see mise.toml).
#
#   scripts/package.sh <x86_64|aarch64> <binary> <output dir>
#
# The version is the workspace's, with BARBICAN_VERSION_SUFFIX appended as in the build (checked against the binary's
# --version when it runs here). A build of main (0.1.0-dev+abc1234) is packaged with the
# number of commits up to it, so each build of main is newer than the one before, and after the release of its base
# version if that is out already, or before (deb: 0.1.0+dev205.abc1234 or 0.1.0~dev205.abc1234; Arch:
# 0.1.0.dev205.abc1234 or 0.1.0dev205.abc1234). Counting the commits needs the whole history.
# Outputs barbican_<amd64|arm64>.deb and barbican-<arch>.pkg.tar.zst.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <x86_64|aarch64> <binary> <output dir>" >&2
  exit 2
fi
arch=$1 binary=$2 out=$3
case "${arch}" in
  x86_64) goarch=amd64 ;;
  aarch64) goarch=arm64 ;;
  *) echo "unknown architecture: ${arch}" >&2 && exit 2 ;;
esac

cd "$(dirname "$0")/.."
stage=target/package
rm -rf "${stage}"
mkdir -p "${stage}"
install -m 0755 "${binary}" "${stage}/barbican"
grep -q '^ExecStart=/usr/bin/barbican$' dist/barbican.service

version="$(cargo pkgid -p barbican | sed 's/.*[#@]//')${BARBICAN_VERSION_SUFFIX:-}"
if [[ "${arch}" == "$(uname -m)" ]]; then
  reported=$("${stage}/barbican" --version | awk '{print $2}')
  if [[ "${reported}" != "${version}" ]]; then
    echo "the binary is ${reported}, expected ${version}" >&2
    exit 1
  fi
fi
if [[ "${version}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-dev\+([0-9a-f]+)$ ]]; then
  base=${BASH_REMATCH[1]} commit=${BASH_REMATCH[2]}
  if [[ "$(git rev-parse --is-shallow-repository)" == true ]]; then
    echo "can't count the commits of ${commit} in a shallow clone (fetch-depth: 0)" >&2
    exit 1
  fi
  build="dev$(git rev-list --count "${commit}").${commit}"
  if git ls-remote --exit-code --tags origin "refs/tags/v${base}" >/dev/null 2>&1; then
    deb_version="${base}+${build}" arch_version="${base}.${build}"
  else
    deb_version="${base}~${build}" arch_version="${base}${build}"
  fi
elif [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  deb_version=${version} arch_version=${version}
else
  echo "can't package version ${version}" >&2
  exit 1
fi
echo "packaging ${version} as ${deb_version} (deb) and ${arch_version} (Arch)"

export BARBICAN_ARCH=${goarch}
mkdir -p "${out}"
BARBICAN_PKG_VERSION=${deb_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager deb --target "${out}/barbican_${goarch}.deb"
BARBICAN_PKG_VERSION=${arch_version} nfpm package --config dist/packaging/nfpm.yaml \
  --packager archlinux --target "${out}/barbican-${arch}.pkg.tar.zst"
