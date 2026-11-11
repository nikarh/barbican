//! Types of the UI's WebSocket RPC protocol, shared with the frontend.
//!
//! `cargo test` exports them as TypeScript into `web/src/api/generated/` (see `mise run bindings`).
//!
//! # Protocol
//!
//! The client sends text frames that are either a single [`Request`] or a JSON array of them. Every request carries
//! a client-chosen `id`, and the requests of one frame run concurrently: each gets its own response, a
//! [`ServerMessage::Result`] or [`ServerMessage::Error`] with the same `id`, as soon as it completes.
//!
//! A `*.subscribe` call answers with a `null` result and then pushes [`ServerMessage::Event`]s tagged with the
//! subscribing request's `id` until the client sends `unsubscribe` with that id, or disconnects.
//!
//! A client that offers the `barbican.deflate` subprotocol gets messages of [`DEFLATE_MIN`] bytes and more as binary
//! frames, compressed with zlib (RFC 1950), which browsers inflate natively (`DecompressionStream("deflate")`).
//! Smaller ones stay text. (The WebSocket stack has no permessage-deflate.)
//!
//! Times are unix seconds.

use serde::{Deserialize, Serialize};

/// The subprotocol by which a client asks for compressed messages.
pub const DEFLATE_PROTOCOL: &str = "barbican.deflate";
/// Messages from this size (serialized) on are compressed, for a client that asked: below it, the frame and the
/// work of inflating cost more than they save.
pub const DEFLATE_MIN: usize = 1024;

#[cfg(test)]
use ts_rs::TS;

use crate::feeds::FeedDef;
use crate::rules::{Policy, Rule};
use crate::signal::Kind;

/// One call from the client: a method and its parameters.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct Request {
    pub id: String,
    #[serde(flatten)]
    pub call: Call,
}

/// Every method the server implements, with its parameters.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(tag = "method", content = "params")]
pub enum Call {
    /// Result: [`Meta`].
    #[serde(rename = "meta.get")]
    MetaGet,
    /// Result: [`Overview`].
    #[serde(rename = "overview.get")]
    OverviewGet,
    /// Result: [`Page`] of [`IpRow`].
    #[serde(rename = "ips.list")]
    IpsList(IpsParams),
    /// Result: [`IpDetail`].
    #[serde(rename = "ip.get")]
    IpGet(IpParams),
    /// Result: [`Page`] of [`Activity`]: what an address did, by what, source and rule.
    #[serde(rename = "ip.activity")]
    IpActivity(IpActivityParams),
    /// Result: [`Page`] of [`EventRow`].
    #[serde(rename = "events.list")]
    EventsList(EventsParams),
    /// Result: [`Page`] of [`Ban`].
    #[serde(rename = "bans.list")]
    BansList(BansParams),
    /// Result: [`Ban`].
    #[serde(rename = "ban.create")]
    BanCreate(BanCreateParams),
    /// Result: `null`.
    #[serde(rename = "ban.lift")]
    BanLift(IdParams),
    /// Result: `Entry[]`.
    #[serde(rename = "entries.list")]
    EntriesList,
    /// Result: [`Entry`].
    #[serde(rename = "entry.save")]
    EntrySave(EntrySaveParams),
    /// Result: `null`.
    #[serde(rename = "entry.delete")]
    EntryDelete(IdParams),
    /// Result: `null`. Stops trusting an address someone logged in from.
    #[serde(rename = "trust.remove")]
    TrustRemove(IpParams),
    /// Result: `Rule[]`, in the order they are tried.
    #[serde(rename = "rules.list")]
    RulesList,
    /// Result: `Rule[]`, the rules a new database starts with.
    #[serde(rename = "rules.defaults")]
    RulesDefaults,
    /// Result: [`Rule`], as saved (with its id when it was new).
    #[serde(rename = "rule.save")]
    RuleSave(Rule),
    /// Result: `null`.
    #[serde(rename = "rule.delete")]
    RuleDelete(IdParams),
    /// Result: `null`.
    #[serde(rename = "rules.order")]
    RulesOrder(OrderParams),
    /// Result: [`Policy`].
    #[serde(rename = "policy.get")]
    PolicyGet,
    /// Result: [`Policy`], as saved.
    #[serde(rename = "policy.update")]
    PolicyUpdate(Policy),
    /// Result: [`BlockCoverage`]: how much blocking these countries and continents takes. Nothing is saved; the
    /// first call after the agent started (or loaded a new country database) takes a moment longer.
    #[serde(rename = "countries.coverage")]
    CountriesCoverage(CoverageParams),
    /// Result: [`GeoStatus`]: the geolocation databases in use, and their downloads.
    #[serde(rename = "geoip.status")]
    GeoipStatus,
    /// Result: `Feed[]`.
    #[serde(rename = "feeds.list")]
    FeedsList,
    /// Result: `FeedDef[]`, well-known lists to add.
    #[serde(rename = "feeds.presets")]
    FeedsPresets,
    /// Result: [`Feed`], as saved.
    #[serde(rename = "feed.save")]
    FeedSave(FeedDef),
    /// Result: `null`.
    #[serde(rename = "feed.delete")]
    FeedDelete(IdParams),
    /// Result: `null`, once the feed was fetched (or failed to be).
    #[serde(rename = "feed.refresh")]
    FeedRefresh(IdParams),
    /// Result: `null`, then [`Live`] events.
    #[serde(rename = "live.subscribe")]
    LiveSubscribe,
    /// Result: `EdgeStatus[]`: every configured edge client, connected or not.
    #[serde(rename = "edges.list")]
    EdgesList,
    /// Result: `null`, then `EdgeStatus[]` events: all edges, at once and whenever one of them changes.
    #[serde(rename = "edges.subscribe")]
    EdgesSubscribe,
    /// Result: `null`. Ends the subscription started by the request with this id.
    #[serde(rename = "unsubscribe")]
    Unsubscribe(UnsubscribeParams),
}

/// A message from the server.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ServerMessage {
    Result {
        id: String,
        #[cfg_attr(test, ts(type = "unknown"))]
        result: serde_json::Value,
    },
    Error {
        /// `null` when the frame couldn't be parsed far enough to know the request's id.
        id: Option<String>,
        error: RpcError,
    },
    Event {
        id: String,
        #[cfg_attr(test, ts(type = "unknown"))]
        event: serde_json::Value,
    },
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct RpcError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// The frame or the parameters are malformed.
    BadRequest,
    NotFound,
    Internal,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct IdParams {
    #[cfg_attr(test, ts(type = "number"))]
    pub id: i64,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct IpParams {
    pub ip: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct UnsubscribeParams {
    pub id: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct OrderParams {
    #[cfg_attr(test, ts(type = "Array<number>"))]
    pub ids: Vec<i64>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
pub struct CoverageParams {
    /// ISO codes.
    pub countries: Vec<String>,
    /// AF, AN, AS, EU, NA, OC, SA.
    pub continents: Vec<String>,
}

/// A slice of a long list.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub rows: Vec<T>,
    /// How many rows match in all.
    #[cfg_attr(test, ts(type = "number"))]
    pub total: i64,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase")]
pub enum IpFilter {
    #[default]
    All,
    Banned,
    Trusted,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase")]
pub enum IpSort {
    #[default]
    LastSeen,
    FirstSeen,
    Hits,
    Country,
}

#[derive(Debug, Deserialize, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase", default)]
pub struct IpsParams {
    /// The start of an address, a country code, or part of a network's name.
    #[cfg_attr(test, ts(optional))]
    pub query: Option<String>,
    pub filter: IpFilter,
    pub sort: IpSort,
    /// Ascending instead of descending.
    pub ascending: bool,
    pub offset: u32,
    #[cfg_attr(test, ts(optional))]
    pub limit: Option<u32>,
}

/// The order of an address's activity.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase")]
pub enum ActivitySort {
    #[default]
    Last,
    First,
    Count,
    What,
}

#[derive(Debug, Deserialize, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase", default)]
pub struct IpActivityParams {
    pub ip: String,
    pub sort: ActivitySort,
    /// Ascending instead of descending.
    pub ascending: bool,
    pub offset: u32,
    #[cfg_attr(test, ts(optional))]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase", default)]
pub struct EventsParams {
    /// Only this address's.
    #[cfg_attr(test, ts(optional))]
    pub ip: Option<String>,
    #[cfg_attr(test, ts(optional, type = "number"))]
    pub rule: Option<i64>,
    #[cfg_attr(test, ts(optional))]
    pub source: Option<String>,
    #[cfg_attr(test, ts(optional))]
    pub kind: Option<Kind>,
    /// Part of what happened (`/.env`, a user name).
    #[cfg_attr(test, ts(optional))]
    pub query: Option<String>,
    pub offset: u32,
    #[cfg_attr(test, ts(optional))]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase", default)]
pub struct BansParams {
    /// Only bans in force.
    pub active: bool,
    /// Only the bans this address's events made (or that were made by hand of it alone).
    #[cfg_attr(test, ts(optional))]
    pub ip: Option<String>,
    #[cfg_attr(test, ts(optional))]
    pub query: Option<String>,
    pub offset: u32,
    #[cfg_attr(test, ts(optional))]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase")]
pub struct BanCreateParams {
    /// An address or a prefix.
    pub net: String,
    /// How long; `null` until lifted.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub secs: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "rpc.ts"))]
#[serde(rename_all = "camelCase")]
pub struct EntrySaveParams {
    pub net: String,
    /// The allow list; otherwise the deny list.
    pub allow: bool,
    #[serde(default)]
    pub note: String,
    /// How long it stays; `null` until removed.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub secs: Option<i64>,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "a message, not a state machine"
)]
pub struct Meta {
    pub version: String,
    pub dry_run: bool,
    pub sources: Vec<String>,
    pub has_countries: bool,
    pub has_asns: bool,
    /// The edge API is enabled.
    pub edge_api: bool,
    /// SHA-256 of the edge API's TLS certificate, which edges are configured with.
    pub edge_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct FirewallStatus {
    /// Off: decisions are only recorded.
    pub enabled: bool,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub applied: Option<i64>,
    pub error: Option<String>,
    /// Addresses and prefixes blocked by bans and the deny list.
    #[cfg_attr(test, ts(type = "number"))]
    pub blocks: u64,
    /// Prefixes of countries and blocking feeds that go into the list sets (without IPv6, its prefixes don't).
    /// They are counted as the lists have them: the sets hold them merged into ranges, fewer elements.
    #[cfg_attr(test, ts(type = "number"))]
    pub listed: u64,
    /// Packets its firewall dropped for a ban, and for a country or a blocklist: in total, across restarts and
    /// reboots, since `dropped_since`.
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_blocked: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_listed: u64,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub dropped_since: Option<i64>,
}

#[derive(Debug, Serialize, Clone, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    pub name: String,
    pub parser: String,
    /// Where it reads from, e.g. `docker: traefik`.
    pub input: String,
    pub connected: bool,
    #[cfg_attr(test, ts(type = "number"))]
    pub lines: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub parsed: u64,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_line: Option<i64>,
    pub error: Option<String>,
}

/// An edge agent allowed to follow this agent (an `[[edge.client]]`), and what it last said about itself.
#[derive(Debug, Serialize, Clone, Default, PartialEq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct EdgeStatus {
    pub name: String,
    pub connected: bool,
    /// While connected: since when; otherwise since when it isn't. `null`: it hasn't connected since this agent
    /// started.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub since: Option<i64>,
    /// The address it connects from.
    pub address: Option<String>,
    /// The last of this agent's changes it was sent.
    #[cfg_attr(test, ts(type = "number"))]
    pub seq: u64,
    /// The edge agent's version, `barbican-edge` or `barbican-edge-ipset`'s.
    pub version: Option<String>,
    /// The firewall it changes, e.g. `nftables table inet barbican`.
    pub backend: Option<String>,
    /// It changes its firewall; `false`: a dry run. `null`: not known yet.
    pub enforcing: Option<bool>,
    /// Its last status report.
    pub report: Option<EdgeReport>,
}

/// What an edge reports about itself. Times are this agent's clock.
#[derive(Debug, Serialize, Clone, Default, PartialEq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct EdgeReport {
    /// When it arrived.
    #[cfg_attr(test, ts(type = "number"))]
    pub received: i64,
    /// Seconds since the edge agent started.
    #[cfg_attr(test, ts(type = "number"))]
    pub uptime: u64,
    /// Its resident memory, in bytes.
    #[cfg_attr(test, ts(type = "number"))]
    pub rss: u64,
    /// When it last brought its firewall up to date.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub applied: Option<i64>,
    /// Addresses and prefixes it blocks for bans and deny lists, of all the agents it follows.
    #[cfg_attr(test, ts(type = "number"))]
    pub blocks: u64,
    /// Country and blocklist prefixes it loads (without IPv6, its prefixes don't). An nftables edge holds them
    /// merged into ranges, fewer elements.
    #[cfg_attr(test, ts(type = "number"))]
    pub listed: u64,
    /// When this agent started counting what the edge dropped: the `dropped_*` totals are since then, across the
    /// edge's restarts (it reports its firewall's counters, which start again from 0 with its rules).
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_since: i64,
    /// Packets and bytes its firewall dropped for a ban, in total.
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_blocked: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_blocked_bytes: u64,
    /// Packets and bytes its firewall dropped for a country or a blocklist.
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_listed: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub dropped_listed_bytes: u64,
    /// Why its firewall can't be updated, while it can't.
    pub error: Option<String>,
    /// Every agent it follows, this one included.
    pub upstreams: Vec<EdgeUpstream>,
}

/// An agent an edge follows, as the edge sees it.
#[derive(Debug, Serialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct EdgeUpstream {
    /// The edge's name for it.
    pub name: String,
    /// It is this agent.
    pub this: bool,
    pub connected: bool,
    /// When the edge last heard from it.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_contact: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct DayStat {
    /// Unix time of the day's start (UTC).
    #[cfg_attr(test, ts(type = "number"))]
    pub day: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub events: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub bans: i64,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Count {
    pub key: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub count: i64,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    #[cfg_attr(test, ts(type = "number"))]
    pub bans_active: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub bans_today: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub events_today: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub ips: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub trusted: i64,
    pub firewall: FirewallStatus,
    pub sources: Vec<SourceStatus>,
    /// The last 30 days, oldest first.
    pub days: Vec<DayStat>,
    /// Countries of the addresses banned in the last 30 days.
    pub countries: Vec<Count>,
    /// Rules by events in the last 30 days.
    pub rules: Vec<Count>,
    pub recent: Vec<Ban>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Ban {
    #[cfg_attr(test, ts(type = "number"))]
    pub id: i64,
    /// What is blocked: the address, or a prefix.
    pub net: String,
    /// The address that made a rule ban.
    pub ip: Option<String>,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub rule: Option<i64>,
    pub reason: String,
    pub country: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub created: i64,
    /// `null`: until lifted.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub until: Option<i64>,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub lifted: Option<i64>,
    pub lifted_by: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct IpRow {
    pub ip: String,
    pub country: Option<String>,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub asn: Option<i64>,
    pub as_name: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub first_seen: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub last_seen: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub hits: i64,
    /// When the ban in force ends; `null` with `banned` set: never.
    pub banned: bool,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub ban_until: Option<i64>,
    pub trusted: bool,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub kind: Kind,
    pub what: String,
    pub source: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub rule: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub count: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub first: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub last: i64,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct TrustInfo {
    pub user: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub until: i64,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct IpDetail {
    pub ip: String,
    pub country: Option<String>,
    pub continent: Option<String>,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub asn: Option<i64>,
    pub as_name: Option<String>,
    /// `null`: never seen doing anything a rule matched.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub first_seen: Option<i64>,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_seen: Option<i64>,
    #[cfg_attr(test, ts(type = "number"))]
    pub hits: i64,
    /// Feeds that list the address.
    pub listed: Vec<String>,
    /// Whether its country or continent is blocked.
    pub country_blocked: bool,
    pub trusted: Option<TrustInfo>,
    /// On the allow list or exempt: no rule acts on it.
    pub allowed: bool,
    pub denied: bool,
    pub active_ban: Option<Ban>,
    /// Its bans, in force or not (`bans.list` with `ip`).
    #[cfg_attr(test, ts(type = "number"))]
    pub ban_count: i64,
    /// The rows of its activity (`ip.activity`): distinct whats, sources and rules.
    #[cfg_attr(test, ts(type = "number"))]
    pub activity_count: i64,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct EventRow {
    /// The hour (unix time of its start).
    #[cfg_attr(test, ts(type = "number"))]
    pub hour: i64,
    pub ip: String,
    pub country: Option<String>,
    pub kind: Kind,
    pub what: String,
    pub source: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub rule: i64,
    #[cfg_attr(test, ts(type = "number"))]
    pub count: i64,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    #[cfg_attr(test, ts(type = "number"))]
    pub id: i64,
    pub net: String,
    pub allow: bool,
    pub note: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub created: i64,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub until: Option<i64>,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Feed {
    pub def: FeedDef,
    /// The last attempt, failed or not.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub fetched: Option<i64>,
    /// The last fetch without an error: its list new, or unchanged.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub succeeded: Option<i64>,
    /// When its list last changed: the copy in use is from then.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub changed: Option<i64>,
    /// When it is fetched next (the agent looks for due feeds every 5 minutes); `null`: it is off.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub next: Option<i64>,
    /// Prefixes in the last good copy.
    #[cfg_attr(test, ts(type = "number"))]
    pub count: i64,
    pub error: Option<String>,
}

/// The geolocation databases, and how they are kept up to date.
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct GeoStatus {
    /// `geoip.download`: DB-IP's free databases are downloaded when missing, and when a month old.
    pub download: bool,
    /// When the agent last looked for databases due a download; `null` before the first time (or without
    /// downloads). It looks once a day, from its start.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub checked: Option<i64>,
    /// When it looks next.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub next_check: Option<i64>,
    /// How old a database gets before it is downloaded again, in seconds.
    #[cfg_attr(test, ts(type = "number"))]
    pub max_age: i64,
    pub country: GeoDatabase,
    pub asn: GeoDatabase,
}

#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct GeoDatabase {
    /// Where it is read from; `null`: not configured.
    pub path: Option<String>,
    /// What the database in use says about itself; `null`: none is in use (missing, or unreadable).
    pub kind: Option<String>,
    pub description: Option<String>,
    /// When it was built.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub built: Option<i64>,
    /// When its file was written: downloaded, or put there.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub written: Option<i64>,
    /// With downloads on: when it is due again (a missing one is due now). The download happens at the first
    /// daily check from then.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub due: Option<i64>,
    /// Why the last download failed, while it keeps failing.
    pub error: Option<String>,
}

/// Pushed to `live.subscribe` subscribers.
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Live {
    /// Something a rule matched (or a login).
    Event {
        #[cfg_attr(test, ts(type = "number"))]
        at: i64,
        ip: String,
        country: Option<String>,
        source: String,
        kind: Kind,
        what: String,
        rule: Option<String>,
    },
    Ban {
        ban: Ban,
    },
    Lift {
        #[cfg_attr(test, ts(type = "number"))]
        id: i64,
    },
}

/// A ban as the UI shows it.
#[must_use]
pub fn ban(row: &crate::db::BanRow, ip: Option<std::net::IpAddr>, country: Option<String>) -> Ban {
    Ban {
        id: row.id,
        net: row.net.to_string(),
        ip: ip.map(|ip| ip.to_string()),
        rule: row.rule,
        reason: row.reason.clone(),
        country,
        created: row.created,
        until: row.until,
        lifted: row.lifted,
        lifted_by: row.lifted_by.clone(),
    }
}

/// What `barbican ui-proxy` answers itself on `GET /api/proxy`, and in the body of its 502s: whether it reaches the
/// agent's socket, and if not, why. A browser can't read why a WebSocket handshake failed, so the UI asks this after
/// one does. Without the proxy (the UI reached on the agent's socket directly, as in development) the path is a 404.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    /// The agent's socket the proxy connects to.
    pub socket: String,
    /// `null`: the agent answers on it.
    pub problem: Option<ProxyProblem>,
}

/// Why the proxy can't reach the agent.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct ProxyProblem {
    pub kind: ProxyProblemKind,
    /// The error as the OS (or the HTTP client) put it.
    pub error: String,
    /// What it means and what to check.
    pub hint: String,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub enum ProxyProblemKind {
    /// No socket at the path.
    NotFound,
    /// The socket (or its directory) isn't the proxy's to use.
    PermissionDenied,
    /// A socket file nobody accepts connections on: a stopped agent's.
    Refused,
    /// Connected, but no HTTP answer.
    NoAnswer,
    Other,
}

/// How much a set of prefixes covers.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Extent {
    /// Prefixes, after merging adjacent and contained ones: the entries the firewall holds.
    #[cfg_attr(test, ts(type = "number"))]
    pub prefixes: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub v4_addresses: u64,
    /// IPv6 space, in /48 networks (one site's usual allocation).
    #[cfg_attr(test, ts(type = "number"))]
    pub v6_networks: u64,
}

impl From<crate::geo::Extent> for Extent {
    fn from(e: crate::geo::Extent) -> Self {
        Self {
            prefixes: e.prefixes,
            v4_addresses: e.v4_addresses,
            v6_networks: e.v6_networks,
        }
    }
}

/// A blocked country or continent, and how much of the address space it is.
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct PlaceExtent {
    pub code: String,
    /// Of a country: the continent the database places it on.
    pub continent: Option<String>,
    pub extent: Extent,
}

/// How much blocking some countries and continents takes, by the country database.
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct BlockCoverage {
    /// `false`: there is no country database, and the rest is empty.
    pub available: bool,
    pub countries: Vec<PlaceExtent>,
    pub continents: Vec<PlaceExtent>,
    /// All of them together, overlaps counted once: what is blocked.
    pub total: Extent,
    /// Everything the database places in a country: the share the total is of.
    pub known: Extent,
}
