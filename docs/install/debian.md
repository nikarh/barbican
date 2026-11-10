# Debian and Ubuntu

The agent's package is a static binary with its systemd unit; it depends on nothing but `nftables`.

```sh
arch=$(dpkg --print-architecture)    # amd64 or arm64
curl -fLO "https://github.com/nikarh/barbican/releases/latest/download/barbican_${arch}.deb"
sudo apt install "./barbican_${arch}.deb"
```

It installs `/usr/bin/barbican`, `/usr/lib/systemd/system/barbican.service` and `/etc/barbican/config.toml`, and
starts nothing: first say where your logs are (the `[[source]]` tables, see the
[configuration](../../README.md#configuration)), then

```sh
sudo systemctl enable --now barbican
```

To try it without touching the firewall, set `[firewall] enabled = false` first: everything is decided and recorded,
and nothing blocked.

An upgrade (`apt install` of a newer package) restarts a running agent; its blocks stay in place meanwhile. Removing
the package stops it and removes its nftables table; the database in `/var/lib/barbican` stays.

**Logs it reads**: journald sources work as is (the unit puts the agent in the `systemd-journal` group). For docker
sources, see [Permissions](../../README.md#sources).
