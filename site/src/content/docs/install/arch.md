---
title: Arch Linux
description: Installing the agent's package on Arch Linux.
sidebar:
  order: 3
---

```bash
curl -fLO "https://github.com/nikarh/barbican/releases/latest/download/barbican-$(uname -m).pkg.tar.zst"
sudo pacman -U "barbican-$(uname -m).pkg.tar.zst"
```

The package is built for x86_64 and aarch64. It installs `/usr/bin/barbican`, `/usr/bin/barbican-vlogs`, the systemd unit, the `barbican-ui` group and `/etc/barbican/config.toml` (kept on upgrades), and starts nothing. First say where your logs are (the `[[source]]` tables, see [Sources and parsers](/guides/sources/)), then

```bash
sudo systemctl enable --now barbican
```

To try it without touching the firewall, set `enabled = false` under `[firewall]` first. Removing the package stops it and removes its nftables table; the database in `/var/lib/barbican` stays.
