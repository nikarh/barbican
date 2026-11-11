---
title: Command line
description: The commands and options of barbican, barbican-vlogs, barbican-edge and barbican-edge-ipset.
sidebar:
  order: 2
---

## barbican

```text
barbican [--config <path>] [--dry-run]     run the agent
barbican parse <parser> [<file>]           print what a parser makes of each line (of stdin without a file)
barbican ui-proxy [--socket <path>] [--listen <address>] --trusted-proxy <cidr>... [--user-header <name>]
                                           serve the UI (in a container) for an agent whose UI is on a unix
                                           socket [default: /run/barbican-ui/ui.sock, 0.0.0.0:8080]. Only
                                           requests from the authenticating reverse proxy's addresses
                                           (required), and with --user-header only those naming a user
                                           ($BARBICAN_TRUSTED_PROXIES, comma-separated, $BARBICAN_USER_HEADER)
barbican healthcheck [--address <address>] exit 0 when the UI (or the proxy) answers [default: 127.0.0.1:8080]
barbican edge-fingerprint [--config <path>]
                                           print the edge API certificate's fingerprint, for edges' configuration
barbican import [--config <path>] <source>:<file>...
                                           old logs of configured sources into the database, judged at their
                                           times (stop the agent first)
barbican replay [--list] [--geoip <dir>] <parser>:<file>...
                                           run logs through the default rules and say what would be banned;
                                           each line starts with an RFC 3339 time (docker logs --timestamps)
barbican --version
```

| Option | |
| --- | --- |
| `-c`, `--config <path>` | The [configuration file](/reference/configuration/); by default `$BARBICAN_CONFIG`, or `/etc/barbican/config.toml` |
| `--dry-run` | Decide and record, but leave the firewall alone (as `firewall.enabled = false`) |
| `-h`, `--help` | The help |

- **Running**: the agent logs to standard error, at the `info` level unless `RUST_LOG` says otherwise (`RUST_LOG=debug`, or per module). Under systemd (`journalctl -u barbican`) it tells systemd it is ready once its firewall table is in place.
- **`parse`**: parsers `traefik`, `sshd`, `authelia`. Prints the address, the kind of event and what happened for each line understood, and how many were. See [Checking a parser](/guides/import/#checking-a-parser).
- **`replay`** and **`import`**: see [Importing old logs](/guides/import/).
- **`edge-fingerprint`**: reads the certificate the agent made on its first start with `[edge]`; it doesn't make one.
- **`ui-proxy`** and **`healthcheck`**: what the container image runs, and only supported in a container; see [The UI container](/guides/reverse-proxy/#the-ui-container). It refuses to start without `--trusted-proxy`, and warns when it doesn't seem to run in a container. `/healthz` answers anyone (the healthcheck asks it); everything else only the trusted proxy.

## barbican-vlogs

```text
barbican-vlogs [options] <LogsQL query>
```

Streams a VictoriaLogs query's history as `<time> <message>` lines, oldest first, on standard output, for `barbican import`.

| Option | Default | |
| --- | --- | --- |
| `--url <url>` | `http://127.0.0.1:9428` | The VictoriaLogs |
| `--since <time>` | `365d` | From: an RFC 3339 time, a date (`2026-02-12`) or an age (`30d`, `12h`) |
| `--until <time>` | now | To, the same way |
| `--window <hours>` | `6` | The time range of one request |
| `--parallel <n>` | `4` | Requests at a time |

## barbican-edge, barbican-edge-ipset

```text
barbican-edge [--config <path>]   run (configuration: a UCI file, by default /etc/config/barbican)
barbican-edge restore             put the saved blocks in place, then exit (at boot, before the network)
barbican-edge status              print the running agent's status (JSON)
barbican-edge remove              remove its firewall rules and sets, and with them every block
barbican-edge --version
```

`barbican-edge-ipset` takes the same commands; its configuration is `/jffs/barbican/barbican.conf` by default. The options of the configuration file are in [Configuring an edge](/edge/configuration/).
