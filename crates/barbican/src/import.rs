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

/// One input: its next timed line, read ahead.
struct Lines<R> {
    source: u16,
    reader: R,
    buffer: String,
    next: Option<(i64, String)>,
    spare: String,
}

impl<R: std::io::BufRead> Lines<R> {
    fn new(source: u16, reader: R) -> Self {
        Self {
            source,
            reader,
            buffer: String::new(),
            next: None,
            spare: String::new(),
        }
    }

    /// Reads up to the next line with a time (lines without one are counted and skipped).
    fn advance(&mut self, summary: &mut Summary) -> Result<(), String> {
        loop {
            self.buffer.clear();
            if self
                .reader
                .read_line(&mut self.buffer)
                .map_err(|e| e.to_string())?
                == 0
            {
                return Ok(());
            }
            summary.lines += 1;
            let line = self.buffer.trim_end_matches(['\n', '\r']);
            if let Some((at, rest)) = crate::time::split_timestamped(line) {
                let mut owned = std::mem::take(&mut self.spare);
                owned.clear();
                owned.push_str(rest);
                self.next = Some((at, owned));
                return Ok(());
            }
            summary.untimed += 1;
        }
    }

    /// Gives a line's buffer back, for the next one.
    fn recycle(&mut self, line: String) {
        self.spare = line;
    }
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
    let before = db::bans_count(&app.db.pool)
        .await
        .map_err(|e| e.to_string())?;
    let mut engine = Engine::new(Arc::clone(&app), app.rules.subscribe());
    let mut batch: Vec<Hit> = Vec::with_capacity(512);
    let mut last: Vec<(u16, i64)> = Vec::new();
    let mut report = 1_000_000;
    // Each file is read as it goes (they can be pipes, and far bigger than memory), merged by time: the file whose
    // next line is the oldest goes next.
    let mut readers = Vec::new();
    for (source, path) in &files {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        readers.push(Lines::new(
            *source,
            std::io::BufReader::with_capacity(1 << 20, file),
        ));
    }
    for r in &mut readers {
        r.advance(&mut summary)?;
    }
    while let Some(r) = readers
        .iter_mut()
        .filter(|r| r.next.is_some())
        .min_by_key(|r| r.next.as_ref().map(|(at, _)| *at))
    {
        let Some((at, line)) = r.next.take() else {
            break;
        };
        let source = r.source;
        match last.iter_mut().find(|(s, _)| *s == source) {
            Some((_, t)) => *t = (*t).max(at),
            None => last.push((source, at)),
        }
        if let Some((_, p)) = prefilters.iter_mut().find(|(s, _)| *s == source)
            && let Some(hit) = p.line(&line, at)
        {
            batch.push(hit);
        }
        r.recycle(line);
        r.advance(&mut summary)?;
        if batch.len() == 512 {
            summary.hits += batch.len() as u64;
            engine.process(&batch).await.map_err(|e| e.to_string())?;
            batch.clear();
        }
        if summary.lines >= report {
            report += 1_000_000;
            tracing::info!(lines = summary.lines, hits = summary.hits, "Importing");
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

    summary.cursors = continue_after(&app, &last).await?;
    Ok(summary)
}

/// A docker source the agent hasn't read yet starts after the imported history, not an hour back. Returns their names.
async fn continue_after(app: &App, last: &[(u16, i64)]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut conn = app.db.pool.acquire().await.map_err(|e| e.to_string())?;
    for &(source, at) in last {
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
            names.push(s.name.clone());
        }
    }
    Ok(names)
}
