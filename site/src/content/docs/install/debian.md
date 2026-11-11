---
title: Debian and Ubuntu
description: Installing the agent's .deb package on Debian, Ubuntu and their derivatives.
sidebar:
  order: 2
---

The agent's package is a static binary with its systemd unit; it depends on nothing but `nftables`.

From the signed apt repository, set up once: apt then installs and upgrades Barbican with the rest of the system.

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://raw.githubusercontent.com/nikarh/barbican/main/docs/signing-key.asc \
  | sudo tee /etc/apt/keyrings/barbican.asc >/dev/null
# Releases (apt-latest instead follows the builds of main).
echo "deb [signed-by=/etc/apt/keyrings/barbican.asc] https://github.com/nikarh/barbican/releases/download/apt/ ./" \
  | sudo tee /etc/apt/sources.list.d/barbican.list
sudo apt update && sudo apt install barbican
```

Or a single package, without the repository:

```bash
arch=$(dpkg --print-architecture)    # amd64 or arm64
curl -fLO "https://github.com/nikarh/barbican/releases/latest/download/barbican_${arch}.deb"
sudo apt install "./barbican_${arch}.deb"
```

It installs `/usr/bin/barbican`, `/usr/bin/barbican-vlogs`, `/usr/lib/systemd/system/barbican.service`, the `barbican-ui` group and the directory of the UI's socket, and `/etc/barbican/config.toml`, and starts nothing. First say where your logs are (the `[[source]]` tables, see [Sources and parsers](/guides/sources/)), then

```bash
sudo systemctl enable --now barbican
```

To try it without touching the firewall, set `enabled = false` under `[firewall]` first: everything is decided and recorded, and nothing blocked.

An upgrade (`apt install` of a newer package) restarts a running agent; its blocks stay in place meanwhile. Removing the package stops it and removes its nftables table; the database in `/var/lib/barbican` stays.

**Logs it reads**: journald sources work as they are (the unit puts the agent in the `systemd-journal` group). Docker sources need the Docker API: see [Permissions](/guides/sources/#permissions).
