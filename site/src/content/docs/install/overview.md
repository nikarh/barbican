---
title: Overview
description: The two parts of barbican, where each one runs, and the files of a release.
sidebar:
  order: 1
---

barbican has two parts: the **agent**, on a server whose logs it reads, and, optionally, **edge agents** on routers, which block what one or more agents ban for the whole network.

| Where | Guide |
| --- | --- |
| Debian, Ubuntu and their derivatives | [Debian and Ubuntu](/install/debian/) |
| Arch Linux | [Arch Linux](/install/arch/) |
| Any other Linux with systemd and nftables | [Any other Linux](/install/linux/) |
| A router with OpenWrt | [OpenWrt](/install/openwrt/) |
| A router without nftables (Asuswrt-Merlin, other firmware on older kernels) | [Routers without nftables](/install/iptables/) |

Once both run, [connect the edge to the agent](/edge/overview/#connecting-an-edge-to-an-agent).

## Requirements

- The agent: Linux on x86_64 or aarch64 with nftables (the `nft` program), as root or with `CAP_NET_ADMIN`. The binaries are static (musl): no library has to be installed. The packages run it as a systemd service.
- The UI: any current browser. The agent serves it on a unix socket only; browsers reach it through a container (`ghcr.io/nikarh/barbican`, amd64 and arm64) behind your reverse proxy: [The UI container](/guides/reverse-proxy/#the-ui-container).
- An edge agent: OpenWrt with nftables (x86_64, aarch64, or 32-bit ARM with an FPU), or a router with iptables and ipset (32-bit ARM, x86_64).

## Release files

Every file is on the [releases page](https://github.com/nikarh/barbican/releases). Asset names never change between releases, so `https://github.com/nikarh/barbican/releases/latest/download/<name>` always points at the newest one. The full list is in [Verifying downloads](/install/verifying/#release-files), with how to check them against the signed checksums.

The `latest` pre-release is built from `main` on every push, with the same files signed the same way and a version such as `0.1.1-dev+abc1234`. It is never marked as GitHub's latest release, so `releases/latest/download/` keeps pointing at the newest `vX.Y.Z`. To try a build of main, download from `https://github.com/nikarh/barbican/releases/download/latest/<name>` instead.

Agents and edges of one release speak the same [edge protocol](/internals/edge-link/): update them together.
