-- Addresses seen doing something a rule matched, or logging in. `addr` is 4 or 16 bytes.
CREATE TABLE ip (
    id INTEGER PRIMARY KEY,
    addr BLOB NOT NULL UNIQUE,
    country TEXT,
    asn INTEGER,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX ip_last_seen ON ip (last_seen);
CREATE INDEX ip_country ON ip (country);

CREATE TABLE asn (
    number INTEGER PRIMARY KEY,
    name TEXT NOT NULL
) STRICT;

CREATE TABLE source (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
) STRICT;

-- What an address did, each distinct text stored once: `GET /.env → 404`, a user name, a probe.
CREATE TABLE what (
    id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    text TEXT NOT NULL,
    UNIQUE (kind, text)
) STRICT;

-- Events counted per address, hour (unix time / 3600), rule, source and what.
CREATE TABLE event (
    ip INTEGER NOT NULL REFERENCES ip (id) ON DELETE CASCADE,
    hour INTEGER NOT NULL,
    rule INTEGER NOT NULL,
    source INTEGER NOT NULL,
    what INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (ip, hour, rule, source, what)
) STRICT, WITHOUT ROWID;
CREATE INDEX event_hour ON event (hour);

-- Decisions: bans by rules, and the ones made by hand in the UI. `net` is the address bytes and the prefix length.
CREATE TABLE ban (
    id INTEGER PRIMARY KEY,
    net BLOB NOT NULL,
    ip INTEGER REFERENCES ip (id) ON DELETE SET NULL,
    rule INTEGER,
    reason TEXT NOT NULL,
    created INTEGER NOT NULL,
    until INTEGER,
    lifted INTEGER,
    lifted_by TEXT
) STRICT;
CREATE INDEX ban_active ON ban (until) WHERE lifted IS NULL;
CREATE INDEX ban_ip ON ban (ip);
CREATE INDEX ban_created ON ban (created);

-- The allow and deny lists of the UI: they override every decision.
CREATE TABLE entry (
    id INTEGER PRIMARY KEY,
    net BLOB NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('allow', 'deny')),
    note TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL,
    until INTEGER,
    UNIQUE (net, kind)
) STRICT;

-- Addresses someone logged in from recently: no rule acts on them.
CREATE TABLE trust (
    ip INTEGER PRIMARY KEY REFERENCES ip (id) ON DELETE CASCADE,
    user TEXT NOT NULL,
    since INTEGER NOT NULL,
    until INTEGER NOT NULL
) STRICT;

-- Rules, as JSON, in the order they are tried.
CREATE TABLE rule (
    id INTEGER PRIMARY KEY,
    position INTEGER NOT NULL,
    definition TEXT NOT NULL
) STRICT;

-- The ban policy and other settings of the UI, as JSON.
CREATE TABLE setting (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Blocklists fetched from the internet. `data` is the last good copy, one prefix per line.
CREATE TABLE feed (
    id INTEGER PRIMARY KEY,
    definition TEXT NOT NULL,
    fetched INTEGER,
    count INTEGER,
    error TEXT,
    etag TEXT,
    data TEXT
) STRICT;

-- Where each log source stopped reading, so a restart continues there.
CREATE TABLE cursor (
    source TEXT PRIMARY KEY,
    position TEXT NOT NULL
) STRICT;
