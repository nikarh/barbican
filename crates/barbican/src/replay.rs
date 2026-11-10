//! `barbican replay`: runs logs through the rules, in an in-memory database, and says what would have been banned.
//! For trying rules on old logs before letting them ban anything.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;

use crate::app::App;
use crate::config::{Config, Database, Input, ParserKind, Source};
use crate::db::Db;
use crate::engine::{Engine, Prefilter};
use crate::parse::Parser;
use crate::rules::RuleSet;
use crate::signal::Hit;

pub struct ReplayInput {
    pub parser: ParserKind,
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub lines: u64,
    pub untimed: u64,
    pub hits: u64,
    /// `(net, reason, country)`.
    pub bans: Vec<(String, String, Option<String>)>,
}

/// Parses `traefik:/path/to/log`.
pub fn input(arg: &str) -> Option<ReplayInput> {
    let (parser, path) = arg.split_once(':')?;
    let parser = match parser {
        "traefik" => ParserKind::Traefik,
        "sshd" => ParserKind::Sshd,
        "authelia" => ParserKind::Authelia,
        _ => return None,
    };
    Some(ReplayInput {
        parser,
        path: PathBuf::from(path),
    })
}

/// Replays the files, each a log with an RFC 3339 time at the start of every line (`docker logs --timestamps`),
/// all in the order of their times.
pub async fn run(inputs: &[ReplayInput], geo: Option<PathBuf>) -> Result<Summary, String> {
    let sources: Vec<Source> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| Source {
            name: format!("{i}:{}", input.path.display()),
            parser: input.parser,
            pattern: None,
            kind: None,
            input: Input::File {
                path: input.path.clone(),
            },
        })
        .collect();
    let mut config: Config = toml::from_str("").map_err(|e| e.to_string())?;
    config.database = Database {
        path: PathBuf::from(":memory:"),
    };
    config.sources = sources;
    let db = Db::memory_db().await.map_err(|e| e.to_string())?;
    let app = App::new(config, db, crate::app::http_client(), true);
    if let Some(dir) = geo {
        let geo = crate::geo::Geo::open(
            Some(&dir.join("dbip-country-lite.mmdb")),
            Some(&dir.join("dbip-asn-lite.mmdb")),
        )
        .map_err(|e| e.to_string())?;
        if let Ok(mut g) = app.geo.write() {
            *g = Arc::new(geo);
        }
    }
    let mut rules = crate::rules::defaults();
    for (i, rule) in rules.iter_mut().enumerate() {
        rule.id = i64::try_from(i).unwrap_or(0) + 1;
    }
    let allowed = barbican_common::net::NetSet::new(&app.config.exempt.nets);
    if let Ok(mut state) = app.state.write() {
        state.exempt.clone_from(&app.config.exempt.nets);
        state.rules.clone_from(&rules);
    }
    let names: Vec<&str> = app.config.sources.iter().map(|s| s.name.as_str()).collect();
    let set = RuleSet::new(1, rules, &names, &[], allowed).map_err(|e| e.to_string())?;
    let (_keep, rx) = watch::channel(Arc::new(set));

    let mut summary = Summary::default();
    let lines = read(inputs, &mut summary)?;

    let mut prefilters: Vec<Prefilter> = inputs
        .iter()
        .enumerate()
        .filter_map(|(i, input)| {
            Some(Prefilter::new(
                u16::try_from(i).ok()?,
                Parser::builtin(input.parser)?,
                rx.clone(),
            ))
        })
        .collect();
    let mut engine = Engine::new(Arc::clone(&app), rx);
    let mut batch: Vec<Hit> = Vec::with_capacity(512);
    for (at, source, line) in &lines {
        let Some(p) = prefilters.get_mut(usize::from(*source)) else {
            continue;
        };
        if let Some(hit) = p.line(line, *at) {
            batch.push(hit);
        }
        if batch.len() == 512 {
            summary.hits += batch.len() as u64;
            engine.process(&batch).await.map_err(|e| e.to_string())?;
            batch.clear();
        }
    }
    summary.hits += batch.len() as u64;
    engine.process(&batch).await.map_err(|e| e.to_string())?;

    let geo = app.geo();
    if let Ok(state) = app.state.read() {
        summary.bans = state
            .bans
            .iter()
            .map(|b| {
                (
                    b.net.to_string(),
                    b.reason.clone(),
                    geo.lookup(b.net.addr()).country,
                )
            })
            .collect();
    }
    Ok(summary)
}

/// Every line, with its time and source, merged in time order.
fn read(inputs: &[ReplayInput], summary: &mut Summary) -> Result<Vec<(i64, u16, String)>, String> {
    // Every line, with its time and source, merged in time order.
    let mut lines: Vec<(i64, u16, String)> = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let file = std::fs::File::open(&input.path)
            .map_err(|e| format!("{}: {e}", input.path.display()))?;
        for line in std::io::BufReader::new(file).lines() {
            let line = line.map_err(|e| e.to_string())?;
            summary.lines += 1;
            match crate::time::split_timestamped(&line) {
                Some((at, rest)) => {
                    lines.push((at, u16::try_from(i).unwrap_or(u16::MAX), rest.to_owned()));
                }
                None => summary.untimed += 1,
            }
        }
    }
    lines.sort_by_key(|(at, ..)| *at);
    Ok(lines)
}

pub fn print(summary: &Summary, list: bool) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "{} lines ({} without a time, skipped), {} hits, {} bans",
        summary.lines,
        summary.untimed,
        summary.hits,
        summary.bans.len()
    );
    let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, reason, _) in &summary.bans {
        *by_reason.entry(reason).or_default() += 1;
    }
    for (reason, count) in by_reason {
        let _ = writeln!(out, "  {count:>6}  {reason}");
    }
    if list {
        for (net, reason, country) in &summary.bans {
            let _ = writeln!(
                out,
                "{net}\t{}\t{reason}",
                country.as_deref().unwrap_or("-")
            );
        }
    }
}
