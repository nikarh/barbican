#!/usr/bin/env bash
# Bumps the workspace version in Cargo.toml (every crate shares it) and prints the new one.
#
#   scripts/bump-version.sh patch|minor|major|current|X.Y.Z   (current: the version as it is, for a first release)
set -euo pipefail
cd "$(dirname "$0")/.."

current=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)
IFS=. read -r major minor patch <<< "$current"
case "${1:?usage: bump-version.sh patch|minor|major|X.Y.Z}" in
  patch) next="$major.$minor.$((patch + 1))" ;;
  minor) next="$major.$((minor + 1)).0" ;;
  major) next="$((major + 1)).0.0" ;;
  current) next=$current ;;
  *.*.*) next=$1 ;;
  *) echo "unknown bump $1" >&2 && exit 1 ;;
esac

sed -i "/^\[workspace.package\]/,/^\[/s/^version\( *\)= *\"$current\"/version\1= \"$next\"/" Cargo.toml
cargo update -q --workspace --offline 2> /dev/null || cargo update -q --workspace
echo "$next"
