---
title: Importing old logs
description: Checking what a parser makes of a log, trying the rules on old logs, and importing history into the agent's database, from files or from VictoriaLogs.
sidebar:
  order: 6
---

Three commands work on logs you already have: `barbican parse` shows what a parser makes of each line, `barbican replay` runs logs through the default rules and says what would have been banned, and `barbican import` puts them into the agent's database as though they had been read live.

`replay` and `import` take lines that each start with an RFC 3339 time, as `docker logs --timestamps` writes them:

```text
2026-02-12T08:15:02.123456789Z 203.0.113.7 - - [12/Feb/2026:08:15:02 +0000] "GET /.env HTTP/1.1" 404 19 "-" "-" 1 "-" "-" 0ms
```

```bash
docker logs --timestamps traefik > traefik.log 2>&1
```

Lines without a time are counted and skipped.

## Checking a parser

```bash
barbican parse traefik access.log     # or: ... | barbican parse sshd
```

prints, for each line the parser understood, the address, the kind of event and what happened (tab-separated), and at the end how many lines it understood. Parsers: `traefik`, `sshd`, `authelia`.

## Trying the rules on old logs

```bash
barbican replay --list --geoip /var/lib/barbican \
  traefik:access.log sshd:sftp.log authelia:authelia.log
```

runs the logs, each `<parser>:<file>`, through the [default rules](/guides/rules/#the-default-rules) in an in-memory database, in the order of their times, and says how many lines it read, how many matched a rule, and how many bans each rule would have made (`--list`: every ban too, with its country and reason). `--geoip <dir>` is a directory with the country and network databases (`dbip-country-lite.mmdb`, `dbip-asn-lite.mmdb`), for countries. Nothing is written anywhere.

## Importing history

`barbican import` puts old logs into the agent's database, through its rules, as though they had been read live at their times: events count in their hours, and bans start when their lines happened and end as they would have (most are long over; a year-long one from a month ago is still on). The database's own rules and policy are used, with the trust and bans as they were at each line's time.

Each file is `<source>:<file>`, where `<source>` is a source of the configuration: its parser reads the file and its events are counted under it. Stop the agent first: a running agent wouldn't see the new bans until it restarts. A docker source the agent hasn't read yet then goes on from the end of the import, not an hour back.

The unit runs the agent as a dynamic user with a private state directory: run `import` as that user, so that the database stays its own.

```bash
docker logs --timestamps traefik > /tmp/traefik.log 2>&1
sudo systemctl stop barbican
sudo systemd-run --wait --pipe -p DynamicUser=yes -p User=barbican -p StateDirectory=barbican \
  barbican import traefik:/dev/stdin < /tmp/traefik.log
sudo systemctl start barbican
```

It prints how many lines it read, how many matched, how many bans it made and how many of them are still on.

## From VictoriaLogs

`barbican-vlogs` (in the same packages and archives) streams a VictoriaLogs query's history as timestamped lines, oldest first: the time range in windows, several fetched at a time, each parsed as it arrives (about 400 000 lines a second on a small server). Fed to `import` as the agent's user:

```bash
sudo systemctl stop barbican
sudo systemd-run --wait --pipe -p DynamicUser=yes -p User=barbican -p StateDirectory=barbican bash -c '
  vlogs() { barbican-vlogs --url http://127.0.0.1:9428 --since 2026-02-12 "$1"; }
  barbican import traefik:<(vlogs container_name:traefik) sftp:<(vlogs container_name:sftpd)'
sudo systemctl start barbican
```

Its options:

| Option | Default | |
| --- | --- | --- |
| `--url <url>` | `http://127.0.0.1:9428` | The VictoriaLogs |
| `--since <time>` | `365d` | From: an RFC 3339 time, a date (`2026-02-12`) or an age (`30d`, `12h`) |
| `--until <time>` | now | To, the same way |
| `--window <hours>` | `6` | The time range of one request |
| `--parallel <n>` | `4` | Requests at a time |

A window that fails is tried again, five times at most.
