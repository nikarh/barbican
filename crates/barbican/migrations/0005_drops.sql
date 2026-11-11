-- What a firewall dropped, in total: this host's (place '') and each edge's (place = the edge client's name). The
-- kernel's counters start again from 0 when a table is made anew (a reboot, an edge restarting); `last_*` is the last
-- reading, and a lower one means the counter started again: what it shows is then added as a whole.
CREATE TABLE drops (
    place TEXT PRIMARY KEY,
    since INTEGER NOT NULL,
    blocked_packets INTEGER NOT NULL,
    blocked_bytes INTEGER NOT NULL,
    listed_packets INTEGER NOT NULL,
    listed_bytes INTEGER NOT NULL,
    last_blocked_packets INTEGER NOT NULL,
    last_blocked_bytes INTEGER NOT NULL,
    last_listed_packets INTEGER NOT NULL,
    last_listed_bytes INTEGER NOT NULL
) STRICT;
