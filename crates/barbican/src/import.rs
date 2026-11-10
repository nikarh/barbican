//! `barbican import`: old logs into the agent's own database, through its rules, as if they had been read live at
//! their times. Events are counted in their hours, bans start when their lines happened and end as they would have
//! (an old probe's year-long ban is still on; most others are long over). For the history of a log before the agent
//! first reads it. Run it while the agent is stopped: a running agent wouldn't see the new bans until it restarts.

use std::path::PathBuf;
use std::sync::Arc;

use crate::app::App;
use crate::config::{Config, Input};
use crate::db::{self, Db};
use crate::engine::{Engine, Prefilter};
use crate::parse::Parser;
use crate::signal::Hit;

pub struct ImportInput {
    /// The name of a source in the configuration: its parser reads the file, its events are counted under it.
    pub source: String,
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub lines: u64,
    pub untimed: u64,
    pub hits: u64,
    pub bans: u64,
    pub active: u64,
    /// Docker sources that will go on from the end of their import.
    pub cursors: Vec<String>,
}

/// Parses `traefik:/path/to/log`.
pub fn input(arg: &str) -> Option<ImportInput> {
    let (source, path) = arg.split_once(':')?;
    Some(ImportInput {
        source: source.to_owned(),
        path: PathBuf::from(path),
    })
}

pub async fn run(config: Config, inputs: &[ImportInput]) -> Result<Summary, String> {
    let db = Db::open(&config.database.path)
        .await
        .map_err(|e| format!("{}: {e}", config.database.path.display()))?;
    crate::run::seed(&db).await?;
    let geo = crate::run::open_geo(&config);
    let app = App::new(config, db, crate::app::http_client(), true);
    if let Ok(mut current) = app.geo.write() {
        *current = Arc::new(geo);
    }
    crate::run::load(&app).await?;
    crate::firewall::rebuild_rules(&app);

    let mut files = Vec::new();
    let mut prefilters = Vec::new();
    for input in inputs {
        let index = app
            .config
            .sources
            .iter()
            .position(|s| s.name == input.source)
            .ok_or_else(|| format!("no source {:?} in the configuration", input.source))?;
        let source = app.config.sources.get(index).ok_or("no source")?;
        let parser = Parser::for_source(source).map_err(|e| format!("{}: {e}", source.name))?;
        let id = u16::try_from(index).map_err(|e| e.to_string())?;
        files.push((id, input.path.as_path()));
        prefilters.push((id, Prefilter::new(id, parser, app.rules.subscribe())));
    }

    let mut summary = Summary::default();
    let lines = crate::replay::read(&files, &mut summary.lines, &mut summary.untimed)?;
    let before = db::bans_count(&app.db.pool)
        .await
        .map_err(|e| e.to_string())?;
    let mut engine = Engine::new(Arc::clone(&app), app.rules.subscribe());
    let mut batch: Vec<Hit> = Vec::with_capacity(512);
    let mut last: Vec<(u16, i64)> = Vec::new();
    for (at, source, line) in &lines {
        match last.iter_mut().find(|(s, _)| s == source) {
            Some((_, t)) => *t = (*t).max(*at),
            None => last.push((*source, *at)),
        }
        let Some((_, p)) = prefilters.iter_mut().find(|(s, _)| s == source) else {
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
    let after = db::bans_count(&app.db.pool)
        .await
        .map_err(|e| e.to_string())?;
    summary.bans = u64::try_from(after - before).unwrap_or(0);
    summary.active = db::bans_active(&app.db.pool, crate::app::now())
        .await
        .map_err(|e| e.to_string())?
        .len() as u64;

    // A docker source the agent hasn't read yet starts after the imported history, not an hour back.
    let mut conn = app.db.pool.acquire().await.map_err(|e| e.to_string())?;
    for (source, at) in last {
        let Some(s) = app.config.sources.get(usize::from(source)) else {
            continue;
        };
        if matches!(s.input, Input::Docker { .. })
            && db::cursor(&app.db.pool, &s.name)
                .await
                .map_err(|e| e.to_string())?
                .is_none()
        {
            db::set_cursor(&mut conn, &s.name, &format!("{}.000000000", at + 1))
                .await
                .map_err(|e| e.to_string())?;
            summary.cursors.push(s.name.clone());
        }
    }
    Ok(summary)
}
