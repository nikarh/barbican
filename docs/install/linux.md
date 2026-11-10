# Any other Linux

The agent is a static binary: any Linux on x86_64 or aarch64 with nftables runs it. The archive has the binary, the
systemd unit (with the `barbican-ui` group it needs and the directory of the UI's socket, as sysusers.d and tmpfiles.d files) and an example configuration.

```sh
curl -fL "https://github.com/nikarh/barbican/releases/latest/download/barbican-$(uname -m)-linux-musl.tar.gz" | tar -xz
sudo install -m 0755 barbican/barbican /usr/bin/barbican
sudo install -m 0644 barbican/barbican.service /etc/systemd/system/barbican.service
sudo install -D -m 0644 barbican/barbican.sysusers /etc/sysusers.d/barbican.conf && sudo systemd-sysusers
sudo install -D -m 0644 barbican/barbican.tmpfiles /etc/tmpfiles.d/barbican.conf && sudo systemd-tmpfiles --create
sudo install -D -m 0644 barbican/config.toml /etc/barbican/config.toml
sudo systemctl daemon-reload
```

Edit `/etc/barbican/config.toml` (at least its `[[source]]` tables), then `sudo systemctl enable --now barbican`.

The unit runs barbican as a user of its own (`DynamicUser`) with `CAP_NET_ADMIN` only, before the network is up and
before Docker: it reports itself ready once its blocks are in place. Without systemd, run `barbican` as root, early
in boot; it needs `nft` in its `PATH`.
