# barbican

Bans addresses that abuse your services. It reads the logs of a reverse proxy, an SSH or SFTP server and an
authentication portal, decides from rules what counts as abuse, and blocks the addresses with nftables, on the
server and, through a small edge agent, on an OpenWrt router. Countries can be blocked as a whole, and public
blocklists used. A web UI shows what each address tried and what was decided.

Work in progress.
