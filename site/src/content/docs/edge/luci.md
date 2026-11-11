---
title: LuCI pages
description: The status and settings pages of barbican-edge in OpenWrt's web interface.
sidebar:
  order: 3
---

`luci-app-barbican` adds **Services → Barbican** to LuCI, OpenWrt's web interface, with two pages. It is a separate package (`luci-app-barbican.apk` or `.ipk`, see [OpenWrt](/install/openwrt/)); the archive for installing by hand has it too.

## Status

What the edge agent last wrote to its status file (`/var/run/barbican-edge.json`), refreshed every 5 seconds:

- **Overview**: the mode (enforcing, or dry run: following the agents with the firewall left alone), how many addresses and prefixes are blocked (or would be), how many country and blocklist prefixes are listed, the packets dropped for each, whether the firewall was applied (and when) or its error, and the version.
- **Agents**: each upstream, whether the edge follows it or why not (its error), how many blocks, allowed and listed prefixes it sent, and when it was last heard from.
- **Blocks**: the first blocks, with how long each lasts and which agent it came from.

Bans and lifts are made on the agents, not here.

When the page can't show a status it says why: the agent isn't running (no status file; check its settings and `logread -e barbican`), or the LuCI session is older than the package, and keeps the permissions it had at login: log out and back in.

## Settings

Edits `/etc/config/barbican` (see [Configuring an edge](/edge/configuration/)); **Save & Apply** restarts the agent.

- **General**: enabled, dry run, IPv6, apply lists, how often to also save the state, the nftables table and the chain's priority.
- **Agents**: one row per upstream: enabled, its URL (`https://` only), its certificate's fingerprint (64 hex digits, colons optional), and its token or a token file.

The package's ACL lets LuCI read the status file and read and write the `barbican` UCI configuration, nothing else.
