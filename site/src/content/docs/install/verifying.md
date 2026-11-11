---
title: Verifying downloads
description: Checking release files against their signed checksums, and what each release file is.
sidebar:
  order: 7
---

Every release (and the `latest` pre-release built from `main`) has `SHA256SUMS`, the checksums of all its files, and `SHA256SUMS.asc`, their detached GPG signature. The signing key is "barbican releases", fingerprint `2DED94B14E12F49939656D6611E3B0A85A53607A` (ed25519), published in the repository as [`docs/signing-key.asc`](https://github.com/nikarh/barbican/blob/main/docs/signing-key.asc).

```bash
curl -fsSLO https://github.com/nikarh/barbican/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/nikarh/barbican/releases/latest/download/SHA256SUMS.asc
curl -fsSL https://raw.githubusercontent.com/nikarh/barbican/main/docs/signing-key.asc | gpg --import
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

`gpg --verify` must report a good signature by the key with the fingerprint above; `sha256sum` then checks the files you downloaded into the same directory.

## Release files

Asset names never change, so `https://github.com/nikarh/barbican/releases/latest/download/<name>` always points at the newest file:

| Asset | Contents |
| --- | --- |
| `barbican-{x86_64,aarch64}-linux-musl` | The agent |
| `barbican-vlogs-{x86_64,aarch64}-linux-musl` | A VictoriaLogs query's history as timestamped lines, for [`barbican import`](/guides/import/) |
| `barbican-{x86_64,aarch64}-linux-musl.tar.gz` | The agent and barbican-vlogs, its systemd unit, the example config, the README and the licenses |
| `barbican_{amd64,arm64}.deb`, `barbican-{x86_64,aarch64}.pkg.tar.zst` | Debian and Arch Linux packages of the agent |
| `barbican-edge-{x86_64,aarch64,armv7}.apk`, `.ipk` | The edge agent for OpenWrt (25.12 and later, 24.10 and earlier) |
| `luci-app-barbican.apk`, `.ipk` | Its LuCI pages |
| `barbican-edge-{x86_64,aarch64,armv7}.tar.gz` | The same, with `install.sh`, for installing by hand |
| `barbican-edge-ipset-{armv7,x86_64}.tar.gz` | The ipset edge agent for Asuswrt-Merlin, with its supervisor and installer |
| `SHA256SUMS`, `SHA256SUMS.asc` | Checksums of all of the above and their detached GPG signature |

The UI's container image, `ghcr.io/nikarh/barbican` (linux/amd64 and linux/arm64), is tagged `X.Y.Z`, `X.Y` and `latest` for releases, and `main` and `sha-<commit>` for builds of main.
