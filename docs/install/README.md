# Installing

barbican has two parts: the **agent**, on a server whose logs it reads, and, optionally, **edge agents** on routers,
which block what one or more agents ban for the whole network.

| Where | Guide |
| --- | --- |
| Debian, Ubuntu and their derivatives | [debian.md](debian.md) |
| Arch Linux | [arch.md](arch.md) |
| Any other Linux with systemd and nftables | [linux.md](linux.md) |
| A router with OpenWrt | [openwrt.md](openwrt.md) |
| A router without nftables (Asuswrt-Merlin, other firmware on older kernels) | [iptables.md](iptables.md) |

Every file is on the [releases page](https://github.com/nikarh/barbican/releases); the `latest` pre-release is
built from `main`. Check what you downloaded against the signed checksums ([releasing.md](../releasing.md#how-a-release-happens)
shows how).

## Connecting an edge to an agent

1. On the agent, turn the edge API on and give the edge a token of its own (at least 16 characters), in
   `/etc/barbican/config.toml`:

   ```toml
   [edge]
   listen = "0.0.0.0:7380"
   [[edge.client]]
   name = "router"
   token_file = "/etc/barbican/edge-router.token"
   ```

   ```sh
   head -c 24 /dev/urandom | base64 > /etc/barbican/edge-router.token
   systemctl restart barbican
   ```

2. The edge API is TLS only, with a certificate the agent made on that start. Edges accept exactly that certificate,
   by its fingerprint:

   ```sh
   barbican edge-fingerprint
   ```

   (The UI's **Settings → About** shows it too.)

3. On the router, add the agent as an upstream: its address, that fingerprint and the token (see the router's guide).
   Agents and edges of one release speak the same protocol: update them together.
