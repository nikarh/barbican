//! The SQLite database: addresses, what they did, decisions, lists, rules and settings.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use barbican_common::net::Net;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{SqliteConnection, SqlitePool};

pub type Error = sqlx::Error;

#[derive(Debug, Clone)]
pub struct Db {
    pub pool: SqlitePool,
}

/// A ban in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRow {
    pub id: i64,
    pub net: Net,
    pub ip: Option<i64>,
    pub rule: Option<i64>,
    pub reason: String,
    pub created: i64,
    pub until: Option<i64>,
    pub lifted: Option<i64>,
    pub lifted_by: Option<String>,
}

/// An allow or deny entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRow {
    pub id: i64,
    pub net: Net,
    pub allow: bool,
    pub note: String,
    pub created: i64,
    pub until: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRow {
    pub addr: Net,
    pub user: String,
    pub since: i64,
    pub until: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedRow {
    pub id: i64,
    pub definition: String,
    pub fetched: Option<i64>,
    pub count: Option<i64>,
    pub error: Option<String>,
    pub etag: Option<String>,
    pub data: Option<String>,
}

fn net(bytes: &[u8]) -> Result<Net, Error> {
    Net::from_bytes(bytes).ok_or_else(|| Error::Decode("an address of the wrong length".into()))
}

/// The address bytes the `ip` table stores: 4 or 16, no prefix length.
#[must_use]
pub fn addr_bytes(ip: std::net::IpAddr) -> Vec<u8> {
    match barbican_common::net::canonical(ip) {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// An address from the `ip` table's bytes.
#[must_use]
pub fn addr_from_bytes(bytes: &[u8]) -> Option<std::net::IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(std::net::IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(std::net::IpAddr::from),
        _ => None,
    }
}

impl Db {
    /// Opens (and creates or migrates) the database.
    pub async fn open(path: &Path) -> Result<Self, Error> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir).map_err(Error::Io)?;
        }
        let options = SqliteConnectOptions::from_str("sqlite://")?
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10))
            .pragma("temp_store", "MEMORY");
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { pool })
    }

    /// An in-memory database, for tests.
    #[cfg(test)]
    pub async fn memory() -> Self {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        // One connection: each connection to :memory: is a database of its own.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!().run(&pool).await.unwrap();
        Self { pool }
    }
}

// --- Addresses and events ---------------------------------------------------------------------------------------

/// Adds an address, or counts one more hit of it. Returns its id.
pub async fn ip_seen(
    conn: &mut SqliteConnection,
    addr: &[u8],
    now: i64,
    country: Option<&str>,
    asn: Option<i64>,
) -> Result<i64, Error> {
    let row = sqlx::query!(
        "INSERT INTO ip (addr, country, asn, first_seen, last_seen, hits) VALUES (?, ?, ?, ?, ?, 1)
         ON CONFLICT (addr) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen), hits = hits + 1,
             country = coalesce(excluded.country, country), asn = coalesce(excluded.asn, asn)
         RETURNING id",
        addr,
        country,
        asn,
        now,
        now
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.id)
}

pub async fn asn_name(conn: &mut SqliteConnection, number: i64, name: &str) -> Result<(), Error> {
    sqlx::query!(
        "INSERT INTO asn (number, name) VALUES (?, ?) ON CONFLICT (number) DO UPDATE SET name = excluded.name
         WHERE name != excluded.name",
        number,
        name
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn what_id(conn: &mut SqliteConnection, kind: i64, text: &str) -> Result<i64, Error> {
    let row = sqlx::query!(
        "INSERT INTO what (kind, text) VALUES (?, ?) ON CONFLICT (kind, text) DO UPDATE SET kind = excluded.kind
         RETURNING id",
        kind,
        text
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.id)
}

pub async fn source_id(conn: &mut SqliteConnection, name: &str) -> Result<i64, Error> {
    let row = sqlx::query!(
        "INSERT INTO source (name) VALUES (?) ON CONFLICT (name) DO UPDATE SET name = excluded.name RETURNING id",
        name
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.id)
}

pub async fn event_add(
    conn: &mut SqliteConnection,
    ip: i64,
    hour: i64,
    rule: i64,
    source: i64,
    what: i64,
    count: i64,
) -> Result<(), Error> {
    sqlx::query!(
        "INSERT INTO event (ip, hour, rule, source, what, count) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (ip, hour, rule, source, what) DO UPDATE SET count = count + excluded.count",
        ip,
        hour,
        rule,
        source,
        what,
        count
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Deletes events from before `hour`, and what nothing refers to any more.
pub async fn prune(pool: &SqlitePool, hour: i64) -> Result<u64, Error> {
    let mut tx = pool.begin().await?;
    let events = sqlx::query!("DELETE FROM event WHERE hour < ?", hour)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query!(
        "DELETE FROM ip WHERE NOT EXISTS (SELECT 1 FROM event WHERE event.ip = ip.id)
           AND NOT EXISTS (SELECT 1 FROM ban WHERE ban.ip = ip.id)
           AND NOT EXISTS (SELECT 1 FROM trust WHERE trust.ip = ip.id)"
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "DELETE FROM what WHERE NOT EXISTS (SELECT 1 FROM event WHERE event.what = what.id)"
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(events)
}

// --- Bans -------------------------------------------------------------------------------------------------------

pub async fn ban_insert(
    conn: &mut SqliteConnection,
    net: &Net,
    ip: Option<i64>,
    rule: Option<i64>,
    reason: &str,
    created: i64,
    until: Option<i64>,
) -> Result<i64, Error> {
    let bytes = net.to_bytes();
    let row = sqlx::query!(
        "INSERT INTO ban (net, ip, rule, reason, created, until) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        bytes,
        ip,
        rule,
        reason,
        created,
        until
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.id)
}

/// Bans not lifted and not run out at `now`.
pub async fn bans_active(pool: &SqlitePool, now: i64) -> Result<Vec<BanRow>, Error> {
    let rows = sqlx::query!(
        "SELECT id, net, ip, rule, reason, created, until, lifted, lifted_by FROM ban
         WHERE lifted IS NULL AND (until IS NULL OR until > ?) ORDER BY id",
        now
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(BanRow {
                id: r.id,
                net: net(&r.net)?,
                ip: r.ip,
                rule: r.rule,
                reason: r.reason,
                created: r.created,
                until: r.until,
                lifted: r.lifted,
                lifted_by: r.lifted_by,
            })
        })
        .collect()
}

/// Lifts a ban before its time. Returns whether there was an active one.
pub async fn ban_lift(pool: &SqlitePool, id: i64, now: i64, by: &str) -> Result<bool, Error> {
    let done = sqlx::query!(
        "UPDATE ban SET lifted = ?, lifted_by = ? WHERE id = ? AND lifted IS NULL",
        now,
        by,
        id
    )
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// How many bans an address has had.
pub async fn bans_of(conn: &mut SqliteConnection, ip: i64) -> Result<i64, Error> {
    let row = sqlx::query!("SELECT count(*) AS n FROM ban WHERE ip = ?", ip)
        .fetch_one(&mut *conn)
        .await?;
    Ok(row.n)
}

// --- Allow and deny lists ---------------------------------------------------------------------------------------

pub async fn entries(pool: &SqlitePool) -> Result<Vec<EntryRow>, Error> {
    let rows = sqlx::query!("SELECT id, net, kind, note, created, until FROM entry ORDER BY id")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(EntryRow {
                id: r.id,
                net: net(&r.net)?,
                allow: r.kind == "allow",
                note: r.note,
                created: r.created,
                until: r.until,
            })
        })
        .collect()
}

/// Adds an entry, or replaces the note and time of the same one.
pub async fn entry_upsert(
    pool: &SqlitePool,
    net: &Net,
    allow: bool,
    note: &str,
    created: i64,
    until: Option<i64>,
) -> Result<i64, Error> {
    let bytes = net.to_bytes();
    let kind = if allow { "allow" } else { "deny" };
    let row = sqlx::query!(
        "INSERT INTO entry (net, kind, note, created, until) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (net, kind) DO UPDATE SET note = excluded.note, until = excluded.until RETURNING id",
        bytes,
        kind,
        note,
        created,
        until
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

pub async fn entry_delete(pool: &SqlitePool, id: i64) -> Result<bool, Error> {
    let done = sqlx::query!("DELETE FROM entry WHERE id = ?", id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

// --- Trust ------------------------------------------------------------------------------------------------------

pub async fn trust(
    conn: &mut SqliteConnection,
    ip: i64,
    user: &str,
    now: i64,
    until: i64,
) -> Result<(), Error> {
    sqlx::query!(
        "INSERT INTO trust (ip, user, since, until) VALUES (?, ?, ?, ?)
         ON CONFLICT (ip) DO UPDATE SET user = excluded.user, until = max(until, excluded.until)",
        ip,
        user,
        now,
        until
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn trusted(pool: &SqlitePool, now: i64) -> Result<Vec<TrustRow>, Error> {
    let rows = sqlx::query!(
        "SELECT ip.addr, trust.user, trust.since, trust.until FROM trust JOIN ip ON ip.id = trust.ip
         WHERE trust.until > ?",
        now
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            let addr = addr_from_bytes(&r.addr)
                .ok_or_else(|| Error::Decode("an address of the wrong length".into()))?;
            Ok(TrustRow {
                addr: Net::host(addr),
                user: r.user,
                since: r.since,
                until: r.until,
            })
        })
        .collect()
}

pub async fn untrust(pool: &SqlitePool, addr: &[u8]) -> Result<bool, Error> {
    let done = sqlx::query!(
        "DELETE FROM trust WHERE ip = (SELECT id FROM ip WHERE addr = ?)",
        addr
    )
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

// --- Rules, settings, cursors -----------------------------------------------------------------------------------

/// `(id, definition)` in order.
pub async fn rules(pool: &SqlitePool) -> Result<Vec<(i64, String)>, Error> {
    let rows = sqlx::query!("SELECT id, definition FROM rule ORDER BY position, id")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.definition)).collect())
}

pub async fn rule_insert(pool: &SqlitePool, definition: &str) -> Result<i64, Error> {
    let row = sqlx::query!(
        "INSERT INTO rule (position, definition) VALUES ((SELECT coalesce(max(position), 0) + 1 FROM rule), ?)
         RETURNING id",
        definition
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

pub async fn rule_update(pool: &SqlitePool, id: i64, definition: &str) -> Result<bool, Error> {
    let done = sqlx::query!(
        "UPDATE rule SET definition = ? WHERE id = ?",
        definition,
        id
    )
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn rule_delete(pool: &SqlitePool, id: i64) -> Result<bool, Error> {
    let done = sqlx::query!("DELETE FROM rule WHERE id = ?", id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Puts the rules in this order (ids not listed keep their place after them).
pub async fn rules_order(pool: &SqlitePool, ids: &[i64]) -> Result<(), Error> {
    let mut tx = pool.begin().await?;
    for (position, id) in ids.iter().enumerate() {
        let position = i64::try_from(position).unwrap_or(i64::MAX);
        sqlx::query!("UPDATE rule SET position = ? WHERE id = ?", position, id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

pub async fn setting(pool: &SqlitePool, key: &str) -> Result<Option<String>, Error> {
    let row = sqlx::query!("SELECT value FROM setting WHERE key = ?", key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.value))
}

pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), Error> {
    sqlx::query!(
        "INSERT INTO setting (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        key,
        value
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn cursor(pool: &SqlitePool, source: &str) -> Result<Option<String>, Error> {
    let row = sqlx::query!("SELECT position FROM cursor WHERE source = ?", source)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.position))
}

pub async fn set_cursor(
    conn: &mut SqliteConnection,
    source: &str,
    position: &str,
) -> Result<(), Error> {
    sqlx::query!(
        "INSERT INTO cursor (source, position) VALUES (?, ?) ON CONFLICT (source) DO UPDATE SET position = excluded.position",
        source,
        position
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

// --- Feeds ------------------------------------------------------------------------------------------------------

pub async fn feeds(pool: &SqlitePool) -> Result<Vec<FeedRow>, Error> {
    let rows = sqlx::query_as!(
        FeedRow,
        "SELECT id, definition, fetched, count, error, etag, data FROM feed ORDER BY id"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn feed_insert(pool: &SqlitePool, definition: &str) -> Result<i64, Error> {
    let row = sqlx::query!(
        "INSERT INTO feed (definition) VALUES (?) RETURNING id",
        definition
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Saves a feed's definition; a changed URL forgets the last copy.
pub async fn feed_update(
    pool: &SqlitePool,
    id: i64,
    definition: &str,
    keep_data: bool,
) -> Result<bool, Error> {
    let done = sqlx::query!(
        "UPDATE feed SET definition = ?,
             data = CASE WHEN ? THEN data END, etag = CASE WHEN ? THEN etag END, fetched = CASE WHEN ? THEN fetched END
         WHERE id = ?",
        definition,
        keep_data,
        keep_data,
        keep_data,
        id
    )
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn feed_delete(pool: &SqlitePool, id: i64) -> Result<bool, Error> {
    let done = sqlx::query!("DELETE FROM feed WHERE id = ?", id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Records a fetch: new data (with its count and etag), or only an error that keeps the last good copy.
pub async fn feed_fetched(
    pool: &SqlitePool,
    id: i64,
    now: i64,
    result: Result<(Option<&str>, i64, Option<&str>), &str>,
) -> Result<(), Error> {
    match result {
        Ok((data, count, etag)) => {
            sqlx::query!(
                "UPDATE feed SET fetched = ?, error = NULL, count = ?, etag = ?, data = coalesce(?, data) WHERE id = ?",
                now,
                count,
                etag,
                data,
                id
            )
            .execute(pool)
            .await?;
        }
        Err(error) => {
            sqlx::query!(
                "UPDATE feed SET fetched = ?, error = ? WHERE id = ?",
                now,
                error,
                id
            )
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Net {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn addresses_events_and_pruning() {
        let db = Db::memory().await;
        let mut conn = db.pool.acquire().await.unwrap();
        let a = addr_bytes("192.0.2.1".parse().unwrap());
        let id = ip_seen(&mut conn, &a, 100, Some("DE"), None).await.unwrap();
        assert_eq!(
            ip_seen(&mut conn, &a, 200, None, Some(64_500))
                .await
                .unwrap(),
            id
        );
        let w = what_id(&mut conn, 1, "GET /.env → 404").await.unwrap();
        assert_eq!(what_id(&mut conn, 1, "GET /.env → 404").await.unwrap(), w);
        let s = source_id(&mut conn, "web").await.unwrap();
        event_add(&mut conn, id, 1, 7, s, w, 1).await.unwrap();
        event_add(&mut conn, id, 1, 7, s, w, 2).await.unwrap();
        event_add(&mut conn, id, 9, 7, s, w, 1).await.unwrap();
        let row = sqlx::query!("SELECT sum(count) AS n FROM event")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(row.n, Some(4));
        let ip = sqlx::query!("SELECT country, asn, hits, last_seen FROM ip")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            (ip.country.as_deref(), ip.asn, ip.hits, ip.last_seen),
            (Some("DE"), Some(64_500), 2, 200)
        );
        drop(conn);

        assert_eq!(prune(&db.pool, 5).await.unwrap(), 1);
        // The address still has an event.
        let count = sqlx::query!("SELECT count(*) AS n FROM ip")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count.n, 1);
        assert_eq!(prune(&db.pool, 100).await.unwrap(), 1);
        let count = sqlx::query!(
            "SELECT (SELECT count(*) FROM ip) AS ips, (SELECT count(*) FROM what) AS whats"
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!((count.ips, count.whats), (0, 0));
    }

    #[tokio::test]
    async fn bans() {
        let db = Db::memory().await;
        let mut conn = db.pool.acquire().await.unwrap();
        let ip = ip_seen(
            &mut conn,
            &addr_bytes("203.0.113.9".parse().unwrap()),
            0,
            None,
            None,
        )
        .await
        .unwrap();
        let a = ban_insert(
            &mut conn,
            &n("203.0.113.9"),
            Some(ip),
            Some(1),
            "probe",
            10,
            Some(100),
        )
        .await
        .unwrap();
        let b = ban_insert(
            &mut conn,
            &n("198.51.100.0/24"),
            None,
            None,
            "by hand",
            10,
            None,
        )
        .await
        .unwrap();
        ban_insert(&mut conn, &n("192.0.2.1"), None, None, "old", 1, Some(5))
            .await
            .unwrap();
        assert_eq!(bans_of(&mut conn, ip).await.unwrap(), 1);
        drop(conn);
        let active = bans_active(&db.pool, 50).await.unwrap();
        assert_eq!(active.iter().map(|b| b.id).collect::<Vec<_>>(), vec![a, b]);
        assert_eq!(active[1].net, n("198.51.100.0/24"));
        assert!(ban_lift(&db.pool, a, 60, "ui").await.unwrap());
        assert!(!ban_lift(&db.pool, a, 61, "ui").await.unwrap());
        assert_eq!(bans_active(&db.pool, 60).await.unwrap().len(), 1);
        assert_eq!(bans_active(&db.pool, 200).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn entries_trust_rules_settings() {
        let db = Db::memory().await;
        let id = entry_upsert(&db.pool, &n("192.0.2.0/24"), true, "office", 1, None)
            .await
            .unwrap();
        assert_eq!(
            entry_upsert(&db.pool, &n("192.0.2.0/24"), true, "home", 2, Some(9))
                .await
                .unwrap(),
            id
        );
        entry_upsert(&db.pool, &n("192.0.2.0/24"), false, "", 3, None)
            .await
            .unwrap();
        let all = entries(&db.pool).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].note.as_str(), all[0].until, all[0].allow),
            ("home", Some(9), true)
        );
        assert!(entry_delete(&db.pool, id).await.unwrap());

        let mut conn = db.pool.acquire().await.unwrap();
        let a = addr_bytes("2001:db8::7".parse().unwrap());
        let ip = ip_seen(&mut conn, &a, 0, None, None).await.unwrap();
        trust(&mut conn, ip, "alice", 10, 100).await.unwrap();
        trust(&mut conn, ip, "alice", 20, 50).await.unwrap();
        drop(conn);
        let t = trusted(&db.pool, 60).await.unwrap();
        assert_eq!((t[0].addr, t[0].until), (n("2001:db8::7"), 100));
        assert!(untrust(&db.pool, &a).await.unwrap());
        assert_eq!(trusted(&db.pool, 0).await.unwrap(), Vec::new());

        let r1 = rule_insert(&db.pool, "{\"a\":1}").await.unwrap();
        let r2 = rule_insert(&db.pool, "{\"b\":2}").await.unwrap();
        rules_order(&db.pool, &[r2, r1]).await.unwrap();
        assert_eq!(
            rules(&db.pool)
                .await
                .unwrap()
                .iter()
                .map(|r| r.0)
                .collect::<Vec<_>>(),
            vec![r2, r1]
        );
        assert!(rule_update(&db.pool, r1, "{}").await.unwrap());
        assert!(rule_delete(&db.pool, r1).await.unwrap());

        assert_eq!(setting(&db.pool, "policy").await.unwrap(), None);
        set_setting(&db.pool, "policy", "{}").await.unwrap();
        set_setting(&db.pool, "policy", "{\"x\":1}").await.unwrap();
        assert_eq!(
            setting(&db.pool, "policy").await.unwrap().as_deref(),
            Some("{\"x\":1}")
        );

        let f = feed_insert(&db.pool, "{}").await.unwrap();
        feed_fetched(&db.pool, f, 5, Ok((Some("192.0.2.0/24\n"), 1, Some("e1"))))
            .await
            .unwrap();
        feed_fetched(&db.pool, f, 6, Err("timeout")).await.unwrap();
        let feed = &feeds(&db.pool).await.unwrap()[0];
        assert_eq!(
            (feed.data.as_deref(), feed.error.as_deref(), feed.count),
            (Some("192.0.2.0/24\n"), Some("timeout"), Some(1))
        );
        feed_update(&db.pool, f, "{\"url\":2}", false)
            .await
            .unwrap();
        assert_eq!(feeds(&db.pool).await.unwrap()[0].data, None);
    }
}
