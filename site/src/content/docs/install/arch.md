---
title: Arch Linux
description: Installing the agent's package on Arch Linux.
sidebar:
  order: 3
---

From the signed pacman repository, set up once: pacman then installs and upgrades Barbican with the rest of the
system, checking its signature.

```bash
# The signing key (fingerprint 2DED94B14E12F49939656D6611E3B0A85A53607A, see Verifying downloads), trusted once.
curl -fsSLo barbican.asc https://raw.githubusercontent.com/nikarh/barbican/main/docs/signing-key.asc
sudo pacman-key --add barbican.asc
sudo pacman-key --lsign-key 2DED94B14E12F49939656D6611E3B0A85A53607A
# The repository: releases (pacman-latest-$arch instead follows the builds of main).
printf '[barbican]\nServer = https://github.com/nikarh/barbican/releases/download/pacman-$arch\n' \
  | sudo tee -a /etc/pacman.conf
sudo pacman -Sy barbican
```

Or a single package, without the repository:

```bash
curl -fLO "https://github.com/nikarh/barbican/releases/latest/download/barbican-$(uname -m).pkg.tar.zst"
sudo pacman -U "barbican-$(uname -m).pkg.tar.zst"
```

The package is built for x86_64 and aarch64. It installs `/usr/bin/barbican`, `/usr/bin/barbican-vlogs`, the systemd unit, the `barbican-ui` group and `/etc/barbican/config.toml` (kept on upgrades), and starts nothing. First say where your logs are (the `[[source]]` tables, see [Sources and parsers](/guides/sources/)), then

```bash
sudo systemctl enable --now barbican
```

To try it without touching the firewall, set `enabled = false` under `[firewall]` first. Removing the package stops it and removes its nftables table; the database in `/var/lib/barbican` stays.
