# Arch Linux

```sh
curl -fLO "https://github.com/nikarh/barbican/releases/latest/download/barbican-$(uname -m).pkg.tar.zst"
sudo pacman -U "barbican-$(uname -m).pkg.tar.zst"
```

It installs `/usr/bin/barbican`, the systemd unit and `/etc/barbican/config.toml` (kept on upgrades), and starts
nothing: first say where your logs are (the `[[source]]` tables, see the [configuration](../../README.md#configuration)),
then

```sh
sudo systemctl enable --now barbican
```

To try it without touching the firewall, set `[firewall] enabled = false` first. Removing the package stops it and
removes its nftables table; the database in `/var/lib/barbican` stays.
