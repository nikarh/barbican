//! What the UI's methods do.

use std::net::IpAddr;
use std::sync::Arc;

use barbican_common::net::Net;
use serde::Serialize;
use serde_json::Value;
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::api::{
    Activity, ActivitySort, BanCreateParams, BansParams, BlockCoverage, Call, Count,
    CoverageParams, DayStat, Entry, EntrySaveParams, ErrorCode, EventRow, EventsParams, Feed,
    IpActivityParams, IpDetail, IpFilter, IpRow, IpSort, IpsParams, Live, Meta, Overview, Page,
    PlaceExtent, RpcError, TrustInfo,
};
use crate::app::{App, now};
use crate::db::{self, BanRow, EntryRow};
use crate::feeds::FeedDef;
use crate::firewall::{rebuild_rules, refresh_lists};
use crate::rules::{Compiled, Policy, Rule};
use crate::signal::Kind;
use crate::state::Feed as StateFeed;

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 1_000;

fn error(code: ErrorCode, message: impl Into<String>) -> RpcError {
    RpcError {
        code,
        message: message.into(),
    }
}

fn bad(message: impl Into<String>) -> RpcError {
    error(ErrorCode::BadRequest, message)
}

fn internal(e: impl std::fmt::Display) -> RpcError {
    tracing::error!(error = %e, "A UI call failed");
    error(ErrorCode::Internal, e.to_string())
}

fn json(value: impl Serialize) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(internal)
}

fn net(s: &str) -> Result<Net, RpcError> {
    let net: Net = s
        .parse()
        .map_err(|_| bad(format!("{s:?} is not an address or a prefix")))?;
    if net.is_never_blocked() {
        return Err(bad(format!(
            "{net} can't be blocked (loopback, link-local, multicast or everything)"
        )));
    }
    Ok(net)
}

fn limit(limit: Option<u32>) -> i64 {
    i64::from(limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT))
}

pub async fn call(app: &Arc<App>, call: Call) -> Result<Value, RpcError> {
    match call {
        Call::MetaGet => json(meta(app)),
        Call::OverviewGet => json(overview(app).await?),
        Call::IpsList(p) => json(ips(app, p).await?),
        Call::IpGet(p) => json(ip(app, &p.ip).await?),
        Call::IpActivity(p) => json(ip_activity(app, &p).await?),
        Call::EventsList(p) => json(events(app, p).await?),
        Call::BansList(p) => json(bans(app, p).await?),
        Call::BanCreate(p) => json(ban_create(app, p).await?),
        Call::BanLift(p) => ban_lift(app, p.id).await.map(|()| Value::Null),
        Call::EntriesList => json(entries(app)),
        Call::EntrySave(p) => json(entry_save(app, p).await?),
        Call::EntryDelete(p) => entry_delete(app, p.id).await.map(|()| Value::Null),
        Call::TrustRemove(p) => trust_remove(app, &p.ip).await.map(|()| Value::Null),
        Call::RulesList => json(
            app.state
                .read()
                .map(|s| s.rules.clone())
                .unwrap_or_default(),
        ),
        Call::RulesDefaults => json(crate::rules::defaults()),
        Call::RuleSave(rule) => json(rule_save(app, rule).await?),
        Call::RuleDelete(p) => rule_delete(app, p.id).await.map(|()| Value::Null),
        Call::RulesOrder(p) => rules_order(app, &p.ids).await.map(|()| Value::Null),
        Call::PolicyGet => json(
            app.state
                .read()
                .map(|s| s.policy.clone())
                .unwrap_or_default(),
        ),
        Call::PolicyUpdate(policy) => json(policy_update(app, policy).await?),
        Call::CountriesCoverage(p) => json(coverage(app, p).await?),
        Call::FeedsList => json(feeds(app)),
        Call::FeedsPresets => json(crate::feeds::presets()),
        Call::FeedSave(def) => json(feed_save(app, def).await?),
        Call::FeedDelete(p) => feed_delete(app, p.id).await.map(|()| Value::Null),
        Call::FeedRefresh(p) => {
            crate::run::fetch_feed(app, p.id).await;
            Ok(Value::Null)
        }
        // Handled by the connection itself.
        Call::LiveSubscribe | Call::Unsubscribe(_) => Err(bad("not a plain call")),
    }
}

fn meta(app: &App) -> Meta {
    let geo = app.geo();
    Meta {
        version: crate::VERSION.to_owned(),
        dry_run: !app.firewall.lock().is_ok_and(|f| f.enabled),
        sources: app.config.sources.iter().map(|s| s.name.clone()).collect(),
        has_countries: geo.has_countries(),
        has_asns: geo.has_asns(),
        edge_api: app.config.edge.is_some(),
        edge_fingerprint: app.edge_fingerprint.get().cloned(),
    }
}

/// Looks up the addresses of ip ids, for showing bans.
fn addr(bytes: Option<&[u8]>) -> Option<IpAddr> {
    bytes.and_then(db::addr_from_bytes)
}

fn ban_of_row(row: &sqlx::sqlite::SqliteRow) -> Result<crate::api::Ban, RpcError> {
    let net_bytes: Vec<u8> = row.try_get("net").map_err(internal)?;
    let ban = BanRow {
        id: row.try_get("id").map_err(internal)?,
        net: Net::from_bytes(&net_bytes)
            .ok_or_else(|| internal("a stored ban's address is broken"))?,
        ip: row.try_get("ip").map_err(internal)?,
        rule: row.try_get("rule").map_err(internal)?,
        reason: row.try_get("reason").map_err(internal)?,
        created: row.try_get("created").map_err(internal)?,
        until: row.try_get("until").map_err(internal)?,
        lifted: row.try_get("lifted").map_err(internal)?,
        lifted_by: row.try_get("lifted_by").map_err(internal)?,
    };
    let bytes: Option<Vec<u8>> = row.try_get("addr").map_err(internal)?;
    let ip = addr(bytes.as_deref());
    let country: Option<String> = row.try_get("country").map_err(internal)?;
    Ok(crate::api::ban(&ban, ip, country))
}

const BAN_COLUMNS: &str = "SELECT ban.id, ban.net, ban.ip, ban.rule, ban.reason, ban.created, ban.until, ban.lifted, \
     ban.lifted_by, ip.addr, ip.country FROM ban LEFT JOIN ip ON ip.id = ban.ip";

/// Events and bans per day of the 30 days from `since`.
async fn days(pool: &sqlx::SqlitePool, since: i64) -> Result<Vec<DayStat>, RpcError> {
    let mut days: Vec<DayStat> = (0..30)
        .map(|i| DayStat {
            day: since + i * 86_400,
            events: 0,
            bans: 0,
        })
        .collect();
    let events_by_day: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT hour / 24 AS day, sum(count) FROM event WHERE hour >= ? GROUP BY day",
    )
    .bind(since / 3_600)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let bans_by_day: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT created / 86400 AS day, count(*) FROM ban WHERE created >= ? GROUP BY day",
    )
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    for (day, n) in events_by_day {
        if let Some(d) = days.iter_mut().find(|d| d.day / 86_400 == day) {
            d.events = n;
        }
    }
    for (day, n) in bans_by_day {
        if let Some(d) = days.iter_mut().find(|d| d.day / 86_400 == day) {
            d.bans = n;
        }
    }
    Ok(days)
}

/// The sources' status, with their counters as they are now.
fn sources(app: &App) -> Vec<crate::api::SourceStatus> {
    use std::sync::atomic::Ordering;
    let counters = app
        .source_counters
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default();
    app.sources
        .lock()
        .map(|s| {
            s.values()
                .map(|status| {
                    let mut status = status.clone();
                    if let Some(c) = counters.get(&status.name) {
                        status.lines = c.lines.load(Ordering::Relaxed);
                        status.parsed = c.parsed.load(Ordering::Relaxed);
                        let last = c.last_line.load(Ordering::Relaxed);
                        status.last_line = (last != 0).then_some(last);
                    }
                    status
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn overview(app: &Arc<App>) -> Result<Overview, RpcError> {
    let pool = &app.db.pool;
    let now = now();
    let today = now - now.rem_euclid(86_400);
    let since = today - 29 * 86_400;
    let scalar = |sql: &'static str, bind: i64| async move {
        sqlx::query_scalar::<_, i64>(sql)
            .bind(bind)
            .fetch_one(pool)
            .await
            .map_err(internal)
    };
    let bans_today = scalar("SELECT count(*) FROM ban WHERE created >= ?", today).await?;
    let events_today = scalar(
        "SELECT coalesce(sum(count), 0) FROM event WHERE hour >= ?",
        today / 3_600,
    )
    .await?;
    let ips = scalar("SELECT count(*) FROM ip WHERE last_seen >= ?", 0).await?;

    let days = days(pool, since).await?;
    let countries: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT ip.country, count(*) AS n FROM ban JOIN ip ON ip.id = ban.ip WHERE ban.created >= ?
         GROUP BY ip.country ORDER BY n DESC LIMIT 12",
    )
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let rules: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT rule, sum(count) AS n FROM event WHERE hour >= ? AND rule != 0 GROUP BY rule ORDER BY n DESC",
    )
    .bind(since / 3_600)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let recent_rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{BAN_COLUMNS} ORDER BY ban.id DESC LIMIT 12"
    )))
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let recent = recent_rows
        .iter()
        .map(ban_of_row)
        .collect::<Result<Vec<_>, _>>()?;

    let (bans_active, trusted, rule_names) = app
        .state
        .read()
        .map(|s| {
            let names: Vec<(i64, String)> =
                s.rules.iter().map(|r| (r.id, r.name.clone())).collect();
            (
                i64::try_from(s.bans.len()).unwrap_or(0),
                i64::try_from(s.trust.len()).unwrap_or(0),
                names,
            )
        })
        .unwrap_or_default();
    Ok(Overview {
        bans_active,
        bans_today,
        events_today,
        ips,
        trusted,
        firewall: app.firewall.lock().map(|f| f.clone()).unwrap_or_default(),
        sources: sources(app),
        edges: app
            .edges
            .lock()
            .map(|e| e.values().cloned().collect())
            .unwrap_or_default(),
        days,
        countries: countries
            .into_iter()
            .map(|(c, n)| Count {
                key: c.unwrap_or_else(|| "?".to_owned()),
                count: n,
            })
            .collect(),
        rules: rules
            .into_iter()
            .map(|(id, n)| Count {
                key: rule_names
                    .iter()
                    .find(|(i, _)| *i == id)
                    .map_or_else(|| format!("#{id}"), |(_, n)| n.clone()),
                count: n,
            })
            .collect(),
        recent,
    })
}

/// The address range a search term means: a whole address or prefix, or the start of an IPv4 address
/// (`203.0.113` is 203.0.113.0/24).
fn search_range(query: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let net = query.parse::<Net>().ok().or_else(|| {
        let parts: Vec<&str> = query.trim_end_matches('.').split('.').collect();
        if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
            return None;
        }
        let mut octets = [0u8; 4];
        for (o, p) in octets.iter_mut().zip(&parts) {
            *o = p.parse().ok()?;
        }
        let len = u8::try_from(parts.len() * 8).ok()?;
        Some(Net::prefix(IpAddr::from(octets), len))
    })?;
    let inner = net.inner();
    let (first, last) = match inner {
        ipnet::IpNet::V4(n) => (
            n.network().octets().to_vec(),
            n.broadcast().octets().to_vec(),
        ),
        ipnet::IpNet::V6(n) => (
            n.network().octets().to_vec(),
            n.broadcast().octets().to_vec(),
        ),
    };
    Some((first, last))
}

fn ips_where(qb: &mut QueryBuilder<Sqlite>, p: &IpsParams, now: i64) {
    qb.push(" WHERE 1 = 1");
    match p.filter {
        IpFilter::All => {}
        IpFilter::Banned => {
            qb.push(" AND EXISTS (SELECT 1 FROM ban WHERE ban.ip = ip.id AND ban.lifted IS NULL AND (ban.until IS NULL OR ban.until > ");
            qb.push_bind(now);
            qb.push("))");
        }
        IpFilter::Trusted => {
            qb.push(" AND EXISTS (SELECT 1 FROM trust WHERE trust.ip = ip.id AND trust.until > ");
            qb.push_bind(now);
            qb.push(")");
        }
    }
    let Some(query) = p.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) else {
        return;
    };
    if let Some((first, last)) = search_range(query) {
        qb.push(" AND length(ip.addr) = ");
        qb.push_bind(i64::try_from(first.len()).unwrap_or(0));
        qb.push(" AND ip.addr BETWEEN ");
        qb.push_bind(first);
        qb.push(" AND ");
        qb.push_bind(last);
    } else if query.len() == 2 && query.chars().all(|c| c.is_ascii_alphabetic()) {
        qb.push(" AND ip.country = ");
        qb.push_bind(query.to_ascii_uppercase());
    } else if let Some(number) = query
        .strip_prefix("AS")
        .or(query.strip_prefix("as"))
        .and_then(|n| n.parse::<i64>().ok())
    {
        qb.push(" AND ip.asn = ");
        qb.push_bind(number);
    } else {
        qb.push(" AND asn.name LIKE ");
        qb.push_bind(format!("%{query}%"));
    }
}

async fn ips(app: &Arc<App>, p: IpsParams) -> Result<Page<IpRow>, RpcError> {
    let now = now();
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT ip.addr, ip.country, ip.asn, asn.name AS as_name, ip.first_seen, ip.last_seen, ip.hits FROM ip \
         LEFT JOIN asn ON asn.number = ip.asn",
    );
    ips_where(&mut qb, &p, now);
    let column = match p.sort {
        IpSort::LastSeen => "ip.last_seen",
        IpSort::FirstSeen => "ip.first_seen",
        IpSort::Hits => "ip.hits",
        IpSort::Country => "ip.country",
    };
    qb.push(format_args!(
        " ORDER BY {column} {}, ip.id DESC",
        if p.ascending { "ASC" } else { "DESC" }
    ));
    qb.push(" LIMIT ");
    qb.push_bind(limit(p.limit));
    qb.push(" OFFSET ");
    qb.push_bind(i64::from(p.offset));
    let rows = qb.build().fetch_all(&app.db.pool).await.map_err(internal)?;

    let mut count =
        QueryBuilder::<Sqlite>::new("SELECT count(*) FROM ip LEFT JOIN asn ON asn.number = ip.asn");
    ips_where(&mut count, &p, now);
    let total: i64 = count
        .build_query_scalar()
        .fetch_one(&app.db.pool)
        .await
        .map_err(internal)?;

    let state = app.state.read().map_err(internal)?;
    let rows = rows
        .iter()
        .filter_map(|row| {
            let bytes: Vec<u8> = row.try_get("addr").ok()?;
            let ip = addr(Some(&bytes))?;
            let ban = state.ban_of(ip, now);
            Some(IpRow {
                ip: ip.to_string(),
                country: row.try_get("country").ok()?,
                asn: row.try_get("asn").ok()?,
                as_name: row.try_get("as_name").ok()?,
                first_seen: row.try_get("first_seen").ok()?,
                last_seen: row.try_get("last_seen").ok()?,
                hits: row.try_get("hits").ok()?,
                banned: ban.is_some() || state.denied(ip, now),
                ban_until: ban.and_then(|b| b.until),
                trusted: state.trusted(ip, now).is_some(),
            })
        })
        .collect();
    Ok(Page { rows, total })
}

async fn ip(app: &Arc<App>, text: &str) -> Result<IpDetail, RpcError> {
    let ip: IpAddr = text
        .trim()
        .parse()
        .map_err(|_| bad(format!("{text:?} is not an address")))?;
    let ip = barbican_common::net::canonical(ip);
    let now = now();
    let pool = &app.db.pool;
    let info = app.geo().lookup(ip);
    let row: Option<(i64, i64, i64, i64)> =
        sqlx::query_as("SELECT id, first_seen, last_seen, hits FROM ip WHERE addr = ?")
            .bind(db::addr_bytes(ip))
            .fetch_optional(pool)
            .await
            .map_err(internal)?;
    let (ban_count, activity_count) = if let Some((id, ..)) = row {
        let bans: i64 = sqlx::query_scalar("SELECT count(*) FROM ban WHERE ip = ?")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(internal)?;
        let activity: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT 1 FROM event WHERE ip = ? GROUP BY what, source, rule)",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(internal)?;
        (bans, activity)
    } else {
        (0, 0)
    };
    let state = app.state.read().map_err(internal)?;
    let active_ban = state
        .ban_of(ip, now)
        .map(|b| crate::api::ban(b, b.ip.map(|_| ip), info.country.clone()));
    let country_blocked = info.country.as_ref().is_some_and(|c| {
        state
            .policy
            .blocked_countries
            .iter()
            .any(|b| b.eq_ignore_ascii_case(c))
    }) || info.continent.as_ref().is_some_and(|c| {
        state
            .policy
            .blocked_continents
            .iter()
            .any(|b| b.eq_ignore_ascii_case(c))
    });
    Ok(IpDetail {
        ip: ip.to_string(),
        country: info.country.clone(),
        continent: info.continent.clone(),
        asn: info.asn.map(i64::from),
        as_name: info.as_name.clone(),
        first_seen: row.map(|r| r.1),
        last_seen: row.map(|r| r.2),
        hits: row.map_or(0, |r| r.3),
        listed: state.listed(ip).into_iter().map(str::to_owned).collect(),
        country_blocked,
        trusted: state.trusted(ip, now).map(|t| TrustInfo {
            user: t.user.clone(),
            until: t.until,
        }),
        allowed: state.allowed(ip, now),
        denied: state.denied(ip, now),
        active_ban,
        ban_count,
        activity_count,
    })
}

/// The id of an address the agent has seen, from its text.
async fn ip_id(pool: &sqlx::SqlitePool, text: &str) -> Result<Option<i64>, RpcError> {
    let ip: IpAddr = text
        .trim()
        .parse()
        .map_err(|_| bad(format!("{text:?} is not an address")))?;
    sqlx::query_scalar("SELECT id FROM ip WHERE addr = ?")
        .bind(db::addr_bytes(barbican_common::net::canonical(ip)))
        .fetch_optional(pool)
        .await
        .map_err(internal)
}

/// What an address did: its events summed by what, source and rule, a page at a time. The address's events are
/// read through the primary key (they are its prefix); only they are grouped and sorted.
async fn ip_activity(app: &Arc<App>, p: &IpActivityParams) -> Result<Page<Activity>, RpcError> {
    let pool = &app.db.pool;
    let Some(id) = ip_id(pool, &p.ip).await? else {
        return Ok(Page {
            rows: Vec::new(),
            total: 0,
        });
    };
    let order = match p.sort {
        ActivitySort::Last => "max(event.hour)",
        ActivitySort::First => "min(event.hour)",
        ActivitySort::Count => "sum(event.count)",
        ActivitySort::What => "what.text",
    };
    let direction = if p.ascending { "ASC" } else { "DESC" };
    let rows: Vec<(i64, String, String, i64, i64, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT what.kind, what.text, source.name, event.rule, sum(event.count), min(event.hour), max(event.hour)
         FROM event JOIN what ON what.id = event.what JOIN source ON source.id = event.source
         WHERE event.ip = ? GROUP BY event.what, event.source, event.rule
         ORDER BY {order} {direction}, event.what, event.source, event.rule LIMIT ? OFFSET ?"
    )))
    .bind(id)
    .bind(limit(p.limit))
    .bind(i64::from(p.offset))
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT 1 FROM event WHERE ip = ? GROUP BY what, source, rule)",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    let rows = rows
        .into_iter()
        .filter_map(|(kind, what, source, rule, count, first, last)| {
            Some(Activity {
                kind: Kind::from_code(kind)?,
                what,
                source,
                rule,
                count,
                first: first * 3_600,
                last: last * 3_600 + 3_599,
            })
        })
        .collect();
    Ok(Page { rows, total })
}

fn events_where(qb: &mut QueryBuilder<Sqlite>, p: &EventsParams) -> Result<(), RpcError> {
    qb.push(" WHERE 1 = 1");
    if let Some(ip) = p.ip.as_deref().filter(|s| !s.is_empty()) {
        let ip: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| bad(format!("{ip:?} is not an address")))?;
        qb.push(" AND event.ip = (SELECT id FROM ip WHERE addr = ");
        qb.push_bind(db::addr_bytes(ip));
        qb.push(")");
    }
    if let Some(rule) = p.rule {
        qb.push(" AND event.rule = ");
        qb.push_bind(rule);
    }
    if let Some(source) = p.source.as_deref() {
        qb.push(" AND source.name = ");
        qb.push_bind(source);
    }
    if let Some(kind) = p.kind {
        qb.push(" AND what.kind = ");
        qb.push_bind(kind.code());
    }
    if let Some(query) = p.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        qb.push(" AND what.text LIKE ");
        qb.push_bind(format!("%{query}%"));
    }
    Ok(())
}

async fn events(app: &Arc<App>, p: EventsParams) -> Result<Page<EventRow>, RpcError> {
    const FROM: &str = " FROM event JOIN ip ON ip.id = event.ip JOIN what ON what.id = event.what \
                        JOIN source ON source.id = event.source";
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT event.hour, ip.addr, ip.country, what.kind, what.text, source.name, event.rule, event.count",
    );
    qb.push(FROM);
    events_where(&mut qb, &p)?;
    // All descending: the order of event_hour_order read backwards, so a page needs no sort.
    qb.push(" ORDER BY event.hour DESC, event.ip DESC, event.what DESC LIMIT ");
    qb.push_bind(limit(p.limit));
    qb.push(" OFFSET ");
    qb.push_bind(i64::from(p.offset));
    let rows = qb.build().fetch_all(&app.db.pool).await.map_err(internal)?;
    // Counting a large table exactly is slow: past 100 000 the count stops.
    let mut count = QueryBuilder::<Sqlite>::new("SELECT count(*) FROM (SELECT 1");
    count.push(FROM);
    events_where(&mut count, &p)?;
    count.push(" LIMIT 100000)");
    let total: i64 = count
        .build_query_scalar()
        .fetch_one(&app.db.pool)
        .await
        .map_err(internal)?;
    let rows = rows
        .iter()
        .filter_map(|row| {
            Some(EventRow {
                hour: row.try_get::<i64, _>("hour").ok()? * 3_600,
                ip: addr(row.try_get::<Vec<u8>, _>("addr").ok().as_deref())?.to_string(),
                country: row.try_get("country").ok()?,
                kind: Kind::from_code(row.try_get("kind").ok()?)?,
                what: row.try_get("text").ok()?,
                source: row.try_get("name").ok()?,
                rule: row.try_get("rule").ok()?,
                count: row.try_get("count").ok()?,
            })
        })
        .collect();
    Ok(Page { rows, total })
}

fn bans_where(qb: &mut QueryBuilder<Sqlite>, p: &BansParams, now: i64) -> Result<(), RpcError> {
    qb.push(" WHERE 1 = 1");
    if let Some(ip) = p.ip.as_deref().filter(|s| !s.is_empty()) {
        let ip: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| bad(format!("{ip:?} is not an address")))?;
        qb.push(" AND ban.ip = (SELECT id FROM ip WHERE addr = ");
        qb.push_bind(db::addr_bytes(barbican_common::net::canonical(ip)));
        qb.push(")");
    }
    if p.active {
        qb.push(" AND ban.lifted IS NULL AND (ban.until IS NULL OR ban.until > ");
        qb.push_bind(now);
        qb.push(")");
    }
    let Some(query) = p.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) else {
        return Ok(());
    };
    if let Some((first, last)) = search_range(query) {
        qb.push(" AND length(ip.addr) = ");
        qb.push_bind(i64::try_from(first.len()).unwrap_or(0));
        qb.push(" AND ip.addr BETWEEN ");
        qb.push_bind(first);
        qb.push(" AND ");
        qb.push_bind(last);
    } else if query.len() == 2 && query.chars().all(|c| c.is_ascii_alphabetic()) {
        qb.push(" AND ip.country = ");
        qb.push_bind(query.to_ascii_uppercase());
    } else {
        qb.push(" AND ban.reason LIKE ");
        qb.push_bind(format!("%{query}%"));
    }
    Ok(())
}

async fn bans(app: &Arc<App>, p: BansParams) -> Result<Page<crate::api::Ban>, RpcError> {
    let now = now();
    let mut qb = QueryBuilder::<Sqlite>::new(BAN_COLUMNS);
    bans_where(&mut qb, &p, now)?;
    qb.push(" ORDER BY ban.id DESC LIMIT ");
    qb.push_bind(limit(p.limit));
    qb.push(" OFFSET ");
    qb.push_bind(i64::from(p.offset));
    let rows = qb.build().fetch_all(&app.db.pool).await.map_err(internal)?;
    let mut count =
        QueryBuilder::<Sqlite>::new("SELECT count(*) FROM ban LEFT JOIN ip ON ip.id = ban.ip");
    bans_where(&mut count, &p, now)?;
    let total: i64 = count
        .build_query_scalar()
        .fetch_one(&app.db.pool)
        .await
        .map_err(internal)?;
    let rows = rows.iter().map(ban_of_row).collect::<Result<Vec<_>, _>>()?;
    Ok(Page { rows, total })
}

async fn ban_create(app: &Arc<App>, p: BanCreateParams) -> Result<crate::api::Ban, RpcError> {
    let net = net(&p.net)?;
    let now = now();
    if p.secs.is_some_and(|s| s <= 0) {
        return Err(bad("a ban lasts a positive number of seconds"));
    }
    let until = p.secs.map(|s| now.saturating_add(s));
    let reason = if p.reason.trim().is_empty() {
        "By hand".to_owned()
    } else {
        p.reason.trim().to_owned()
    };
    let mut conn = app.db.pool.acquire().await.map_err(internal)?;
    // A single address is also recorded as an address, so it shows up with its history.
    let ip_id = if net.is_host() {
        let info = app.geo().lookup(net.addr());
        Some(
            db::ip_seen(
                &mut conn,
                &db::addr_bytes(net.addr()),
                now,
                info.country.as_deref(),
                info.asn.map(i64::from),
            )
            .await
            .map_err(internal)?,
        )
    } else {
        None
    };
    let id = db::ban_insert(&mut conn, &net, ip_id, None, &reason, now, until)
        .await
        .map_err(internal)?;
    let row = BanRow {
        id,
        net,
        ip: ip_id,
        rule: None,
        reason,
        created: now,
        until,
        lifted: None,
        lifted_by: None,
    };
    let country = app.geo().lookup(net.addr()).country;
    let ban = crate::api::ban(&row, net.is_host().then(|| net.addr()), country);
    if let Ok(mut state) = app.state.write() {
        state.bans.push(row);
    }
    app.firewall_wake.notify_one();
    app.publish(Live::Ban { ban: ban.clone() });
    Ok(ban)
}

async fn ban_lift(app: &Arc<App>, id: i64) -> Result<(), RpcError> {
    if !db::ban_lift(&app.db.pool, id, now(), "ui")
        .await
        .map_err(internal)?
    {
        return Err(error(ErrorCode::NotFound, "no such ban in force"));
    }
    if let Ok(mut state) = app.state.write() {
        state.bans.retain(|b| b.id != id);
    }
    app.firewall_wake.notify_one();
    app.publish(Live::Lift { id });
    Ok(())
}

fn entry(row: &EntryRow) -> Entry {
    Entry {
        id: row.id,
        net: row.net.to_string(),
        allow: row.allow,
        note: row.note.clone(),
        created: row.created,
        until: row.until,
    }
}

fn entries(app: &App) -> Vec<Entry> {
    app.state
        .read()
        .map(|s| s.entries.iter().map(entry).collect())
        .unwrap_or_default()
}

async fn entry_save(app: &Arc<App>, p: EntrySaveParams) -> Result<Entry, RpcError> {
    // Allowing a range everything is in would turn everything off; denying it would cut the host off.
    let net = net(&p.net)?;
    let now = now();
    if p.secs.is_some_and(|s| s <= 0) {
        return Err(bad("an entry lasts a positive number of seconds"));
    }
    let until = p.secs.map(|s| now.saturating_add(s));
    let id = db::entry_upsert(&app.db.pool, &net, p.allow, p.note.trim(), now, until)
        .await
        .map_err(internal)?;
    let row = EntryRow {
        id,
        net,
        allow: p.allow,
        note: p.note.trim().to_owned(),
        created: now,
        until,
    };
    if let Ok(mut state) = app.state.write() {
        state.entries.retain(|e| e.id != id);
        state.entries.push(row.clone());
    }
    rebuild_rules(app);
    app.firewall_wake.notify_one();
    Ok(entry(&row))
}

async fn entry_delete(app: &Arc<App>, id: i64) -> Result<(), RpcError> {
    if !db::entry_delete(&app.db.pool, id).await.map_err(internal)? {
        return Err(error(ErrorCode::NotFound, "no such entry"));
    }
    if let Ok(mut state) = app.state.write() {
        state.entries.retain(|e| e.id != id);
    }
    rebuild_rules(app);
    app.firewall_wake.notify_one();
    Ok(())
}

async fn trust_remove(app: &Arc<App>, text: &str) -> Result<(), RpcError> {
    let ip: IpAddr = text
        .trim()
        .parse()
        .map_err(|_| bad(format!("{text:?} is not an address")))?;
    let ip = barbican_common::net::canonical(ip);
    db::untrust(&app.db.pool, &db::addr_bytes(ip))
        .await
        .map_err(internal)?;
    if let Ok(mut state) = app.state.write() {
        state.trust.remove(&ip);
    }
    Ok(())
}

fn validate(rule: &Rule) -> Result<(), RpcError> {
    if rule.name.trim().is_empty() {
        return Err(bad("a rule needs a name"));
    }
    Compiled::new(rule.clone(), &[])
        .map(|_| ())
        .map_err(|e| bad(e.to_string()))
}

async fn rule_save(app: &Arc<App>, mut rule: Rule) -> Result<Rule, RpcError> {
    validate(&rule)?;
    rule.name = rule.name.trim().to_owned();
    let id = rule.id;
    rule.id = 0;
    let definition = serde_json::to_string(&rule).map_err(internal)?;
    if id == 0 {
        if app
            .state
            .read()
            .is_ok_and(|s| s.rules.len() >= crate::rules::MAX_RULES)
        {
            return Err(bad(format!("at most {} rules", crate::rules::MAX_RULES)));
        }
        rule.id = db::rule_insert(&app.db.pool, &definition)
            .await
            .map_err(internal)?;
    } else {
        if !db::rule_update(&app.db.pool, id, &definition)
            .await
            .map_err(internal)?
        {
            return Err(error(ErrorCode::NotFound, "no such rule"));
        }
        rule.id = id;
    }
    if let Ok(mut state) = app.state.write() {
        match state.rules.iter_mut().find(|r| r.id == rule.id) {
            Some(existing) => *existing = rule.clone(),
            None => state.rules.push(rule.clone()),
        }
    }
    rebuild_rules(app);
    Ok(rule)
}

async fn rule_delete(app: &Arc<App>, id: i64) -> Result<(), RpcError> {
    if !db::rule_delete(&app.db.pool, id).await.map_err(internal)? {
        return Err(error(ErrorCode::NotFound, "no such rule"));
    }
    if let Ok(mut state) = app.state.write() {
        state.rules.retain(|r| r.id != id);
    }
    rebuild_rules(app);
    Ok(())
}

async fn rules_order(app: &Arc<App>, ids: &[i64]) -> Result<(), RpcError> {
    db::rules_order(&app.db.pool, ids).await.map_err(internal)?;
    if let Ok(mut state) = app.state.write() {
        state
            .rules
            .sort_by_key(|r| ids.iter().position(|i| *i == r.id).unwrap_or(usize::MAX));
    }
    rebuild_rules(app);
    Ok(())
}

const CONTINENTS: [&str; 7] = ["AF", "AN", "AS", "EU", "NA", "OC", "SA"];

async fn policy_update(app: &Arc<App>, mut policy: Policy) -> Result<Policy, RpcError> {
    let code = |c: &mut String| {
        *c = c.trim().to_ascii_uppercase();
        c.len() == 2 && c.chars().all(|x| x.is_ascii_uppercase())
    };
    for c in &mut policy.blocked_countries {
        if !code(c) {
            return Err(bad(format!("{c:?} is not a country code")));
        }
    }
    for c in &mut policy.blocked_continents {
        if !code(c) || !CONTINENTS.contains(&c.as_str()) {
            return Err(bad(format!(
                "{c:?} is not a continent code ({})",
                CONTINENTS.join(", ")
            )));
        }
    }
    if policy.asn_lengths.iter().any(|l| l.asn == 0)
        || policy.list_lengths.iter().any(|l| l.list.trim().is_empty())
    {
        return Err(bad("an ASN length needs a number, a list length a list"));
    }
    for l in &mut policy.country_lengths {
        if !code(&mut l.country) {
            return Err(bad(format!("{:?} is not a country code", l.country)));
        }
    }
    policy.blocked_countries.sort();
    policy.blocked_countries.dedup();
    policy.blocked_continents.sort();
    policy.blocked_continents.dedup();
    if policy.ban_secs == 0
        || policy.max_ban_secs == 0
        || policy.trust_secs == 0
        || policy.retention_days == 0
    {
        return Err(bad("lengths must be positive"));
    }
    let json = serde_json::to_string(&policy).map_err(internal)?;
    db::set_setting(&app.db.pool, crate::run::POLICY, &json)
        .await
        .map_err(internal)?;
    let countries_changed = app.state.write().is_ok_and(|mut s| {
        let changed = s.policy.blocked_countries != policy.blocked_countries
            || s.policy.blocked_continents != policy.blocked_continents;
        s.policy = policy.clone();
        changed
    });
    if countries_changed {
        app.countries_wake.notify_one();
    }
    Ok(policy)
}

async fn coverage(app: &App, p: CoverageParams) -> Result<BlockCoverage, RpcError> {
    if p.countries.len() + p.continents.len() > 300 {
        return Err(bad("too many countries and continents"));
    }
    let geo = app.geo();
    let coverage = tokio::task::spawn_blocking(move || geo.coverage(&p.countries, &p.continents))
        .await
        .map_err(internal)?;
    let Some(c) = coverage else {
        return Ok(BlockCoverage {
            available: false,
            countries: Vec::new(),
            continents: Vec::new(),
            total: crate::api::Extent::default(),
            known: crate::api::Extent::default(),
        });
    };
    Ok(BlockCoverage {
        available: true,
        countries: c
            .countries
            .into_iter()
            .map(|(code, continent, extent)| PlaceExtent {
                code,
                continent,
                extent: extent.into(),
            })
            .collect(),
        continents: c
            .continents
            .into_iter()
            .map(|(code, extent)| PlaceExtent {
                code,
                continent: None,
                extent: extent.into(),
            })
            .collect(),
        total: c.total.into(),
        known: c.known.into(),
    })
}

fn feed(f: &StateFeed) -> Feed {
    let mut def = f.def.clone();
    // The password stays on the server.
    if def.password.is_some() {
        def.password = Some(String::new());
    }
    Feed {
        def,
        fetched: f.fetched,
        count: i64::try_from(f.loaded.nets.len()).unwrap_or(0),
        error: f.error.clone(),
    }
}

fn feeds(app: &App) -> Vec<Feed> {
    app.state
        .read()
        .map(|s| s.feeds.iter().map(feed).collect())
        .unwrap_or_default()
}

async fn feed_save(app: &Arc<App>, mut def: FeedDef) -> Result<Feed, RpcError> {
    def.name = def.name.trim().to_owned();
    if def.name.is_empty() {
        return Err(bad("a feed needs a name"));
    }
    let url = reqwest::Url::parse(def.url.trim()).map_err(|e| bad(format!("the URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(bad("the URL must be http or https"));
    }
    def.url = url.to_string();
    def.refresh_secs = def.refresh_secs.max(600);
    let previous = app.state.read().ok().and_then(|s| {
        s.feeds
            .iter()
            .find(|f| f.def.id == def.id)
            .map(|f| f.def.clone())
    });
    if app.state.read().is_ok_and(|s| {
        s.feeds
            .iter()
            .any(|f| f.def.name == def.name && f.def.id != def.id)
    }) {
        return Err(bad(format!("a feed is named {:?} already", def.name)));
    }
    // An empty password from the UI keeps the stored one.
    if def.password.as_deref() == Some("") {
        def.password = previous.as_ref().and_then(|p| p.password.clone());
    }
    let id = def.id;
    def.id = 0;
    let definition = serde_json::to_string(&def).map_err(internal)?;
    let same_source = previous
        .as_ref()
        .is_some_and(|p| p.url == def.url && p.username == def.username);
    if id == 0 {
        def.id = db::feed_insert(&app.db.pool, &definition)
            .await
            .map_err(internal)?;
    } else {
        if previous.is_none()
            || !db::feed_update(&app.db.pool, id, &definition, same_source)
                .await
                .map_err(internal)?
        {
            return Err(error(ErrorCode::NotFound, "no such feed"));
        }
        def.id = id;
    }
    let saved = {
        let mut state = app.state.write().map_err(internal)?;
        if let Some(existing) = state.feeds.iter_mut().find(|f| f.def.id == def.id) {
            existing.def = def.clone();
            if !same_source {
                existing.loaded = Arc::default();
                existing.fetched = None;
                existing.error = None;
            }
            feed(existing)
        } else {
            let new = StateFeed {
                def: def.clone(),
                loaded: Arc::default(),
                fetched: None,
                error: None,
            };
            let shown = feed(&new);
            state.feeds.push(new);
            shown
        }
    };
    rebuild_rules(app);
    refresh_lists(app);
    app.feeds_wake.notify_one();
    Ok(saved)
}

async fn feed_delete(app: &Arc<App>, id: i64) -> Result<(), RpcError> {
    if !db::feed_delete(&app.db.pool, id).await.map_err(internal)? {
        return Err(error(ErrorCode::NotFound, "no such feed"));
    }
    if let Ok(mut state) = app.state.write() {
        state.feeds.retain(|f| f.def.id != id);
    }
    rebuild_rules(app);
    refresh_lists(app);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_ranges() {
        let (a, b) = search_range("203.0.113").unwrap();
        assert_eq!((a, b), (vec![203, 0, 113, 0], vec![203, 0, 113, 255]));
        let (a, b) = search_range("198.51.100.7").unwrap();
        assert_eq!(a, b);
        assert_eq!(search_range("2001:db8::/32").unwrap().0.len(), 16);
        assert!(search_range("DE").is_none());
        assert!(search_range("hosting").is_none());
        assert!(search_range("300.1").is_none());
    }
}
