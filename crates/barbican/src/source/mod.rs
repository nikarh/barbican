//! Log sources: where lines come from. Each runs on its own, reconnecting (with a growing pause) when its input
//! goes away, and continues where it stopped after a restart of the agent.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::api::SourceStatus;
use std::sync::atomic::Ordering;

use crate::app::{App, SourceCounters};
use crate::config::{Input, Source};
use crate::engine::Prefilter;
use crate::parse::Parser;
use crate::signal::Hit;

mod docker;
mod file;
mod journald;
mod victorialogs;

/// Cursors are saved at most this often.
const CURSOR_EVERY: Duration = Duration::from_secs(5);

/// What every source does with its lines: match them, send hits on, and keep its status and cursor.
pub struct Feeder {
    app: Arc<App>,
    name: String,
    prefilter: Prefilter,
    tx: mpsc::Sender<Hit>,
    counters: Arc<SourceCounters>,
    /// Shared with the agent, which saves it as it stops.
    cursor: Arc<Mutex<Option<String>>>,
    cursor_at: Instant,
}

impl Feeder {
    fn new(
        app: Arc<App>,
        index: u16,
        source: &Source,
        parser: Parser,
        tx: mpsc::Sender<Hit>,
    ) -> Self {
        let prefilter = Prefilter::new(index, parser, app.rules.subscribe());
        let now = Instant::now();
        let counters = Arc::new(SourceCounters::default());
        if let Ok(mut all) = app.source_counters.lock() {
            all.insert(source.name.clone(), Arc::clone(&counters));
        }
        let cursor = Arc::new(Mutex::new(None));
        if let Ok(mut all) = app.unsaved_cursors.lock() {
            all.insert(source.name.clone(), Arc::clone(&cursor));
        }
        Self {
            app,
            name: source.name.clone(),
            prefilter,
            tx,
            counters,
            cursor,
            cursor_at: now,
        }
    }

    /// Handles a line logged at `at`. `false` when the engine is gone.
    pub async fn line(&mut self, line: &str, at: i64) -> bool {
        self.counters.lines.fetch_add(1, Ordering::Relaxed);
        self.counters.last_line.store(at, Ordering::Relaxed);
        if let Some(hit) = self.prefilter.line(line, at) {
            self.counters.parsed.fetch_add(1, Ordering::Relaxed);
            if self.tx.send(hit).await.is_err() {
                return false;
            }
        }
        true
    }

    /// The same, from a thread that isn't the runtime's.
    pub fn blocking_line(&mut self, line: &str, at: i64) -> bool {
        self.counters.lines.fetch_add(1, Ordering::Relaxed);
        self.counters.last_line.store(at, Ordering::Relaxed);
        if let Some(hit) = self.prefilter.line(line, at) {
            self.counters.parsed.fetch_add(1, Ordering::Relaxed);
            if self.tx.blocking_send(hit).is_err() {
                return false;
            }
        }
        true
    }

    /// Changes the source's status in the shared map (with the counters as they are now).
    pub fn status(&self, change: impl FnOnce(&mut SourceStatus)) {
        if let Ok(mut sources) = self.app.sources.lock()
            && let Some(status) = sources.get_mut(&self.name)
        {
            change(status);
        }
    }

    pub fn connected(&self) {
        self.status(|s| {
            s.connected = true;
            s.error = None;
        });
    }

    pub fn failed(&self, error: &str) {
        tracing::warn!(source = %self.name, error, "Log source failed");
        self.status(|s| {
            s.connected = false;
            s.error = Some(error.to_owned());
        });
    }

    /// Where the source stopped reading, as it last saved it.
    pub async fn saved_cursor(&self) -> Option<String> {
        crate::db::cursor(&self.app.db.pool, &self.name)
            .await
            .ok()
            .flatten()
    }

    /// Remembers where reading got to; saved every few seconds (and by [`Self::flush_cursor`]).
    pub async fn cursor(&mut self, position: String) {
        if let Ok(mut cursor) = self.cursor.lock() {
            *cursor = Some(position);
        }
        if self.cursor_at.elapsed() >= CURSOR_EVERY {
            self.flush_cursor().await;
        }
    }

    pub async fn flush_cursor(&mut self) {
        self.cursor_at = Instant::now();
        let position = self.cursor.lock().ok().and_then(|mut c| c.take());
        if let Some(position) = position {
            save_cursor(&self.app, &self.name, &position).await;
        }
    }

    pub fn app(&self) -> &Arc<App> {
        &self.app
    }
}

async fn save_cursor(app: &App, name: &str, position: &str) {
    if let Ok(mut conn) = app.db.pool.acquire().await
        && let Err(e) = crate::db::set_cursor(&mut conn, name, position).await
    {
        tracing::warn!(source = %name, error = %e, "Saving where the source got to failed");
    }
}

/// Saves where every source got to, as the agent stops: otherwise its last few seconds of lines would be read
/// again after a restart, and a ban lifted meanwhile would come back.
pub async fn save_cursors(app: &App) {
    let unsaved: Vec<(String, String)> = app.unsaved_cursors.lock().map_or_else(
        |_| Vec::new(),
        |all| {
            all.iter()
                .filter_map(|(name, c)| Some((name.clone(), c.lock().ok()?.take()?)))
                .collect()
        },
    );
    for (name, position) in unsaved {
        save_cursor(app, &name, &position).await;
    }
}

/// Waits before trying again: 1 s, doubling up to a minute.
pub struct Backoff(Duration);

impl Default for Backoff {
    fn default() -> Self {
        Self(Duration::from_secs(1))
    }
}

impl Backoff {
    pub async fn wait(&mut self) {
        tokio::time::sleep(self.0).await;
        self.0 = (self.0 * 2).min(Duration::from_mins(1));
    }

    pub fn reset(&mut self) {
        self.0 = Duration::from_secs(1);
    }
}

fn describe(input: &Input) -> String {
    match input {
        Input::Docker { container } => format!("docker: {container}"),
        Input::File { path } => format!("file: {}", path.display()),
        Input::Journald { unit, identifier } => format!(
            "journald: {}",
            unit.as_deref().or(identifier.as_deref()).unwrap_or("all")
        ),
        Input::VictoriaLogs { url, query } => format!("victorialogs: {url} {query}"),
    }
}

/// Starts every configured source.
pub fn start(app: &Arc<App>, tx: &mpsc::Sender<Hit>) -> Result<(), crate::parse::Error> {
    for (index, source) in app.config.sources.iter().enumerate() {
        let parser = Parser::for_source(source)?;
        let parser_name = format!("{:?}", source.parser).to_lowercase();
        if let Ok(mut sources) = app.sources.lock() {
            sources.insert(
                source.name.clone(),
                SourceStatus {
                    name: source.name.clone(),
                    parser: parser_name,
                    input: describe(&source.input),
                    ..SourceStatus::default()
                },
            );
        }
        let index = u16::try_from(index).unwrap_or(u16::MAX);
        let feeder = Feeder::new(Arc::clone(app), index, source, parser, tx.clone());
        match source.input.clone() {
            Input::Docker { container } => {
                tokio::spawn(docker::run(
                    feeder,
                    app.config.docker.socket.clone(),
                    container,
                ));
            }
            Input::File { path } => {
                let handle = tokio::runtime::Handle::current();
                std::thread::Builder::new()
                    .name(format!("source-{index}"))
                    .spawn(move || file::run(feeder, &path, &handle))
                    .map_err(|e| crate::parse::Error {
                        source_name: source.name.clone(),
                        message: e.to_string(),
                    })?;
            }
            Input::Journald { unit, identifier } => {
                tokio::spawn(journald::run(feeder, unit, identifier));
            }
            Input::VictoriaLogs { url, query } => {
                tokio::spawn(victorialogs::run(feeder, url, query));
            }
        }
    }
    Ok(())
}
