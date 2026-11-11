# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org).

## [0.1.0] - 2026-11-11

### Features

- The nftables table and its sets, reconciled with what should be blocked by @nikarh
- The edge protocol: a journal of changes for edges, and their mirror of it by @nikarh
- Parsers for Traefik, sshd and Authelia logs, and for any log with a regular expression by @nikarh
- Rules, the ban policy and geolocation, with defaults for common attacks by @nikarh
- Storage, blocklists and the rule set, with parsers that borrow from the line instead of allocating by @nikarh
- The engine: records what rules matched, trusts addresses people log in from, and bans on thresholds by @nikarh
- Run the agent: log sources, the firewall, the edge API and the UI's RPC, with a systemd unit by @nikarh
- Barbican-edge: applies the agents' blocks on an OpenWrt router by @nikarh
- LuCI pages for barbican-edge: its status, and its settings in UCI by @nikarh
- The web UI: overview, addresses and what they did, events, bans, rules, lengths, countries, lists and blocklists by @nikarh
- Ban lengths per network (ASN) and per blocklist, for addresses many people share; an iCloud Private Relay preset by @nikarh
- Barbican-edge-ipset: the edge agent with iptables and ipset, for routers without nftables (Asuswrt-Merlin) by @nikarh
- The edge API over TLS only, with the agent's certificate pinned by the edges by @nikarh
- The UI's API on a unix socket, and barbican ui-proxy to serve the UI from a container by @nikarh
- Barbican import, for the history of logs by @nikarh
- Events of routed requests say which route they went to by @nikarh
- The UI proxy says why the agent can't be reached by @nikarh
- The UI shows that it can't reach the agent, and why by @nikarh
- The settings' lists are edited in place, one way for all of them by @nikarh
- The settings say how much blocking countries and continents takes by @nikarh
- Barbican-vlogs, a VictoriaLogs query's history as timestamped lines by @nikarh
- An address's activity and bans in sortable grids, a page at a time by @nikarh
- Show which geolocation databases are in use, how old, and when they update by @nikarh
- Blocklists show their list's age, the last check, the next fetch and why one fails by @nikarh
- Nftables set elements over netlink, reconciled only when something changed by @nikarh
- **web:** Grids show every column on phones, and scroll sideways to them by @nikarh
- **web:** An address's page leaves the phone's screen to its grid by @nikarh
- IPv6 can be left out of the firewall (`firewall.ipv6`, the edge's `ipv6`) by @nikarh
- **edge:** Dry_run follows the agents and saves their state, but leaves the firewall alone by @nikarh
- **edge:** Agents push to edges over one persistent binary connection by @nikarh
- **web:** An Edges view, and every edge's drops beside this host's by @nikarh
- Feeds that allow what they list (never banned, let through first, here and on the edges), and Cloudflare's ranges as presets by @nikarh
- **edge:** State saved compactly and only on a clean stop; edges without IPv6 get none by @nikarh
- **nft:** The list sets hold merged address ranges instead of prefixes by @nikarh
- **e2e:** Vm.sh forwards a port of this machine into a VM by @nikarh
- The UI only on the agent's unix socket, checked by its peers' credentials; ui-proxy answers only a trusted proxy by @nikarh
- Signed pacman and apt repositories (releases, and the builds of main), as portcullis has by @nikarh
- Drop totals survive restarts and reboots, this host's and each edge's, kept by the agent by @nikarh

### Fixes

- Save the edge agent's state when a save comes due, and when it is stopped by @nikarh
- Index events by what, so pruning doesn't hold the database for hours by @nikarh
- UI calls made while not connected wait for the connection by @nikarh
- Save where each source got to as the agent stops by @nikarh
- Grids fill the page down to its bottom by @nikarh
- Grids are dark in the dark scheme by @nikarh
- Grids show that they load, that nothing matches, or why they failed by @nikarh
- Country pickers offer only countries of today by @nikarh
- The block picker shows continents with their code and a globe, as their rows do by @nikarh
- The image's first healthchecks run every second by @nikarh
- **web:** The browser tab names the screen or the address, and Barbican capitalized by @nikarh
- **web:** Grids keep their layout from the first paint to the rows by @nikarh
- **web:** Switching screens shows their grids' rows in the first frame by @nikarh
- **web:** The phone's tab bar no longer jumps in Firefox for Android by @nikarh
- **web:** Less above the grids on a phone by @nikarh
- **web:** Rule and blocklist cards give their text the full width by @nikarh
- **web:** Inputs take the full width on a phone by @nikarh
- **web:** Time columns are as wide as their longest text, measured in the grid's font by @nikarh
- **packaging:** The Arch package's scripts run, and an upgrade restarts the agent by @nikarh
- **web:** No pinned column on a phone, where the address alone took most of the width by @nikarh
- **web:** Compact columns on a phone, measured from their content, and the address filter's labels in full by @nikarh
- **web:** Event times show the hour they were counted in, as a range by @nikarh
- **web:** Geolocation and blocklists are panels of their own, each with a Details link like the others by @nikarh
- **web:** Panel links (Details, All bans) as small and quiet as the panel's title by @nikarh
- **openwrt:** An upgrade of the .apk restarts barbican-edge (apk runs post-upgrade, not post-install) by @nikarh
- **luci:** The status page says when it may not read the status (log in again) instead of that the agent isn't running by @nikarh
- **luci:** The status page may read the status file where /var/run really is (rpcd checks the resolved path, /tmp/run) by @nikarh
- **luci:** The status page says when the edge runs dry, and the settings have dry run and IPv6 by @nikarh
- **edge:** Its count of listed prefixes leaves IPv6 out when it doesn't load IPv6, as the agent's does by @nikarh
- **traefik:** A client written as a forwarded chain (visitor, proxy) is parsed, and the last hop is blamed by @nikarh
- **nft:** Setup keeps a chain whose rules are already right, and with it what their counters counted by @nikarh

### Performance

- Barbican import streams its files, merged by time by @nikarh
- Events list from an index in its order, overview sums from the index alone by @nikarh
- **edge:** The ipset backend writes only changes and checks only its jump every minute by @nikarh
- **nft:** Tell drift by the ruleset's generation, checked every minute, instead of notifications by @nikarh

### Documentation

- The README: how it works, installing, configuring, rules, the firewall, the edge agent; and the e2e suites by @nikarh
- Changelog by @nikarh
- Installing the OpenWrt packages, and the ipset edge agent on Asuswrt-Merlin by @nikarh
- Releasing, the signing key, and checking downloads by @nikarh
- Installation guides per platform: Debian, Arch, other Linux, OpenWrt, and routers without nftables by @nikarh
- Running the UI in a container next to an agent on the host by @nikarh
- **api:** The listed counts are the lists' prefixes, which the list sets hold merged into fewer ranges by @nikarh
- The edge's dry run, IPv6, saved state and LuCI pages, the edge protocol, and what everything uses by @nikarh
- A documentation site, with screenshots of the UI made from synthetic data in a VM by @nikarh
- The README is an overview that links to the site, which has the install and release guides by @nikarh
- The UI's socket and who may use it, the UI container behind a trusted reverse proxy, and development over the socket by @nikarh
- Trust the reverse proxy's own address, never the network's subnet, whose gateway is the host by @nikarh


<!-- generated by git-cliff -->
