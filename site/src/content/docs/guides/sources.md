---
title: Sources and parsers
description: Where barbican reads logs from (Docker, files, the journal, VictoriaLogs), the parsers for Traefik, sshd and Authelia, and a regular expression for any other log.
sidebar:
  order: 1
---

A source is one log: a name, a parser, and one input. Inputs and parsers are independent of each other, so any parser works with any input, and new ones can be added without touching the rest. Sources are the `[[source]]` tables of `/etc/barbican/config.toml`; each has a name, shown in the UI and used by rules that only look at some sources.

```toml title="/etc/barbican/config.toml"
[[source]]
name = "traefik"          # shown in the UI; rules can be limited to sources
parser = "traefik"        # traefik, sshd, authelia, or regex
docker = { container = "traefik" }
# or: file = { path = "/var/log/nginx/access.log" }
# or: journald = { unit = "sshd.service" }        (or identifier = "sshd")
# or: victorialogs = { url = "http://127.0.0.1:9428", query = "container_name:traefik" }
```

Two sources can't have the same name. After a change to the sources, restart the agent.

## Inputs

| Input | Reads | After a restart | On the first start |
| --- | --- | --- | --- |
| `docker = { container = "..." }` | The container's log through the Docker API (`docker.socket`), with timestamps. A stopped, restarted or recreated container is found again by name. | From the time of the last line read | The last hour |
| `file = { path = "..." }` | A file, followed across rotation (renamed or truncated) | From where it stopped, if it is the same file; otherwise from its end | From its end |
| `journald = { unit = "..." }` or `{ identifier = "..." }` | The systemd journal, through `journalctl --follow`, for one unit or syslog identifier | From the journal's cursor | The last hour |
| `victorialogs = { url = "...", query = "..." }` | A VictoriaLogs query, followed live | The last 15 minutes, skipping lines up to the last one read (a longer gap is lost) | The last hour |

Each source runs on its own and reconnects, with a growing pause, when its input goes away. The overview's **Sources** panel shows each one's input, how many lines it read and matched, when the last came, and its error if it has one.

To read history from before the agent's first start, [import it](/guides/import/).

## Parsers

A parser turns a line into an event, or skips it. The kinds of events are:

| Kind | From | Rules can match |
| --- | --- | --- |
| HTTP request | Traefik, regex | method, path, status, host, user agent, whether the proxy had a route |
| Failed login | sshd, Authelia, regex | user name |
| Successful login | sshd, Authelia, regex | user name; makes the address [trusted](/guides/rules/#trust) |
| Unknown user | sshd, regex | user name |
| Protocol probe | sshd, regex | what it was (`invalid banner`, `no matching algorithms`, ...) |

`barbican parse <parser> [<file>]` prints what a parser makes of each line of a file (or of standard input): a quick way to check that a log is understood.

```bash
docker logs traefik 2>&1 | tail -n 100 | barbican parse traefik
```

### Traefik

Traefik's access log, in the common log format or as JSON. The default (common) format has no request host and no user agent; with JSON rules can use both:

```yaml title="traefik.yml"
accessLog:
  format: json
  fields:
    headers:
      names:
        User-Agent: keep
```

Requests without a route (`RouterName` empty, or `-` in the common log format) were for the server's bare address or for hosts it doesn't serve: only scanners of the whole internet send them. The default rule **No known host** bans them.

### sshd

OpenSSH's messages, as sshd (or `sshd-session`) logs them to the journal or a file, with or without a syslog prefix: failed passwords and keyboard-interactive logins, `Invalid user`, disconnects of authenticating users, too many authentication attempts, PAM failures, accepted logins, and protocol probes (an invalid banner, a bad protocol version, no identification string, no matching algorithms, protocol errors). SFTP servers built on OpenSSH log the same.

### Authelia

Authelia's log, as text (logfmt) or JSON: failed first and second factor logins, and successful ones. Failed and successful logins are logged at the `info` level. At the `debug` level Authelia also logs every request of a signed-in user (its authorization checks): barbican reads those as sessions, which keep the user's address trusted while they use your services.

## A log without a parser

Any other log takes a regular expression. The group `ip` is the address, and the others depend on `kind`:

| `kind` | Groups |
| --- | --- |
| `http` | `method`, `path`, `status`, `host`, `agent` |
| `auth_failure`, `auth_success`, `invalid_user` | `user` |
| `probe` | `what` |

```toml
[[source]]
name = "app"
parser = "regex"
kind = "auth_failure"
pattern = 'Failed login for (?P<user>\S+) from (?P<ip>[0-9a-f.:]+)'
file = { path = "/var/log/app/app.log" }
```

`pattern` and `kind` go with `parser = "regex"`, and only with it. The syntax is the common one without look-around or backreferences ([full reference](https://docs.rs/regex/latest/regex/#syntax)), and matching takes time proportional to the line's length whatever the pattern.

## Permissions

The unit runs barbican as its own user (`DynamicUser`) with `CAP_NET_ADMIN` only:

- **journald** sources work as they are: the unit puts the agent in the `systemd-journal` group.
- **file** sources need the file to be readable by others, or a group the agent is in (`SupplementaryGroups=` in a drop-in for the unit).
- **docker** sources need the Docker API. Membership of the `docker` group is root on the host; rather give barbican a read-only socket proxy that allows container inspection and logs, and point `docker.socket` at it (a unix socket the agent may read).
- **victorialogs** sources need the VictoriaLogs HTTP API to be reachable from the host.
