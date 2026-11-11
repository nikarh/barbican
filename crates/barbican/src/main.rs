//! barbican: bans addresses that abuse services, from their logs.

use std::io::{BufRead, Write};
use std::process::ExitCode;

mod api;
mod app;
mod config;
mod db;
mod drops;
mod edge_api;
mod engine;
mod feeds;
mod firewall;
mod geo;
mod import;
mod parse;
mod peer;
mod proxy;
mod replay;
mod rpc;
mod rules;
mod run;
mod signal;
mod source;
mod state;
mod time;
mod ui;
mod web;

pub const VERSION: &str = env!("BARBICAN_VERSION");

const HELP: &str = "\
barbican: bans addresses that abuse services, from their logs

Usage:
  barbican [--config <path>] [--dry-run]     run the agent
  barbican parse <parser> [<file>]           print what a parser makes of each line (of stdin without a file)
  barbican ui-proxy [--socket <path>] [--listen <address>] [--trusted-proxy <cidr>...] [--user-header <name>]
                                             serve the UI (in a container) for an agent whose UI is on a unix
                                             socket [default: /run/barbican-ui/ui.sock, 0.0.0.0:8080]. Only
                                             requests from the authenticating reverse proxy's addresses
                                             (--trusted-proxy, repeatable, required) and with --user-header
                                             (e.g. Remote-User) only those naming a user
                                             ($BARBICAN_TRUSTED_PROXIES, comma-separated, $BARBICAN_USER_HEADER)
  barbican healthcheck [--address <address>]  exit 0 when the UI (or the proxy) answers [default: 127.0.0.1:8080]
  barbican edge-fingerprint [--config <path>]
                                             print the edge API certificate's fingerprint, for edges' configuration
  barbican import [--config <path>] <source>:<file>...
                                             old logs of configured sources into the database, judged at their
                                             times (stop the agent first)
  barbican replay [--list] [--geoip <dir>] <parser>:<file>...
                                             run logs through the default rules and say what would be banned;
                                             each line starts with an RFC 3339 time (docker logs --timestamps)
  barbican --version

Options:
  -c, --config <path>  The configuration file [default: /etc/barbican/config.toml, or $BARBICAN_CONFIG]
      --dry-run        Decide and record, but leave the firewall alone
  -h, --help           This help

Parsers: traefik, sshd, authelia.
";

fn main() -> ExitCode {
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        let _ = std::io::stdout().write_all(HELP.as_bytes());
        return ExitCode::SUCCESS;
    }
    if args.contains(["-V", "--version"]) {
        let _ = writeln!(std::io::stdout(), "barbican {VERSION}");
        return ExitCode::SUCCESS;
    }
    match args.subcommand() {
        Ok(Some(command)) if command == "parse" => parse_command(args),
        Ok(Some(command)) if command == "replay" => replay_command(args),
        Ok(Some(command)) if command == "import" => import_command(args),
        Ok(Some(command)) if command == "edge-fingerprint" => fingerprint_command(args),
        Ok(Some(command)) if command == "ui-proxy" => proxy_command(args),
        Ok(Some(command)) if command == "healthcheck" => {
            let address = args
                .opt_value_from_str("--address")
                .ok()
                .flatten()
                .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 8080)));
            if proxy::healthcheck(address, "/healthz") {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Some(other)) => {
            let _ = writeln!(std::io::stderr(), "unknown command {other:?}\n\n{HELP}");
            ExitCode::FAILURE
        }
        Ok(None) => agent(args),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command(mut args: pico_args::Arguments) -> ExitCode {
    let mut err = std::io::stderr();
    let kind = match args.free_from_str::<String>().as_deref() {
        Ok("traefik") => config::ParserKind::Traefik,
        Ok("sshd") => config::ParserKind::Sshd,
        Ok("authelia") => config::ParserKind::Authelia,
        _ => {
            let _ = writeln!(err, "parse: name a parser: traefik, sshd or authelia");
            return ExitCode::FAILURE;
        }
    };
    let input: Box<dyn BufRead> = match args.opt_free_from_str::<std::path::PathBuf>() {
        Ok(Some(path)) => match std::fs::File::open(&path) {
            Ok(f) => Box::new(std::io::BufReader::new(f)),
            Err(e) => {
                let _ = writeln!(err, "{}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        },
        _ => Box::new(std::io::stdin().lock()),
    };
    let Some(mut parser) = parse::Parser::builtin(kind) else {
        return ExitCode::FAILURE;
    };
    let mut out = std::io::stdout().lock();
    let mut what = String::new();
    let (mut lines, mut matched) = (0u64, 0u64);
    for line in input.lines() {
        let Ok(line) = line else { break };
        lines += 1;
        if let Some((ip, event)) = parser.parse(&line) {
            matched += 1;
            event.write_what(&mut what);
            let kind = event.kind().map_or("session", signal::Kind::name);
            let _ = writeln!(out, "{ip}	{kind}	{what}");
        }
    }
    let _ = writeln!(err, "{matched} of {lines} lines matched");
    ExitCode::SUCCESS
}

fn replay_command(mut args: pico_args::Arguments) -> ExitCode {
    let mut err = std::io::stderr();
    let list = args.contains("--list");
    let geo: Option<std::path::PathBuf> = args.opt_value_from_str("--geoip").ok().flatten();
    let mut inputs = Vec::new();
    for arg in args.finish() {
        let arg = arg.to_string_lossy();
        let Some(input) = replay::input(&arg) else {
            let _ = writeln!(
                err,
                "replay: {arg:?} isn't <parser>:<file> (parsers: traefik, sshd, authelia)"
            );
            return ExitCode::FAILURE;
        };
        inputs.push(input);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(replay::run(&inputs, geo)) {
        Ok(summary) => {
            replay::print(&summary, list);
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(err, "replay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn agent(mut args: pico_args::Arguments) -> ExitCode {
    let mut err = std::io::stderr();
    let dry_run = args.contains("--dry-run");
    let path: std::path::PathBuf = args
        .opt_value_from_str(["-c", "--config"])
        .ok()
        .flatten()
        .or_else(|| std::env::var_os("BARBICAN_CONFIG").map(Into::into))
        .unwrap_or_else(|| config::DEFAULT_PATH.into());
    let rest = args.finish();
    if !rest.is_empty() {
        let _ = writeln!(err, "unexpected arguments: {rest:?}\n\n{HELP}");
        return ExitCode::FAILURE;
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    // The journal has timestamps of its own.
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        builder.without_time().init();
    } else {
        builder.init();
    }
    let config = match config::Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run::run(config, dry_run)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn fingerprint_command(mut args: pico_args::Arguments) -> ExitCode {
    let mut err = std::io::stderr();
    let path: std::path::PathBuf = args
        .opt_value_from_str(["-c", "--config"])
        .ok()
        .flatten()
        .or_else(|| std::env::var_os("BARBICAN_CONFIG").map(Into::into))
        .unwrap_or_else(|| config::DEFAULT_PATH.into());
    let result = config::Config::load(&path)
        .map_err(|e| e.to_string())
        .and_then(|config| {
            let edge = config
                .edge
                .as_ref()
                .ok_or("the edge API isn't configured ([edge] in the configuration)")?;
            // Only read: the agent makes the certificate on its first start, as its own user.
            edge_api::identity(&config, edge, false)
                .map_err(|e| format!("{e} (has the agent started with [edge] yet?)"))
        });
    match result {
        Ok(identity) => {
            let _ = writeln!(std::io::stdout(), "{}", identity.fingerprint);
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            ExitCode::FAILURE
        }
    }
}

fn proxy_command(mut args: pico_args::Arguments) -> ExitCode {
    let socket: std::path::PathBuf = args
        .opt_value_from_str("--socket")
        .ok()
        .flatten()
        .unwrap_or_else(|| "/run/barbican-ui/ui.sock".into());
    let listen: std::net::SocketAddr = args
        .opt_value_from_str("--listen")
        .ok()
        .flatten()
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 8080)));
    let mut trusted: Vec<String> = args.values_from_str("--trusted-proxy").unwrap_or_default();
    if trusted.is_empty()
        && let Ok(env) = std::env::var("BARBICAN_TRUSTED_PROXIES")
    {
        trusted = env
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
    }
    let header: Option<String> = args
        .opt_value_from_str("--user-header")
        .ok()
        .flatten()
        .or_else(|| {
            std::env::var("BARBICAN_USER_HEADER")
                .ok()
                .filter(|h| !h.trim().is_empty())
        });
    let parsed = || {
        trusted
            .iter()
            .map(|t| t.parse().map_err(|e| format!("--trusted-proxy {t:?}: {e}")))
            .collect::<Result<Vec<_>, String>>()
            .and_then(|nets| proxy::Gate::new(nets, header.as_deref()))
    };
    // Development builds alone can do without a trusted proxy: release builds don't have this path at all.
    #[cfg(debug_assertions)]
    let gate = if args.contains("--insecure-no-trusted-proxy") {
        Ok(proxy::Gate::insecure_for_development())
    } else {
        parsed()
    };
    #[cfg(not(debug_assertions))]
    let gate = parsed();
    let gate = match gate {
        Ok(gate) => gate,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            return ExitCode::FAILURE;
        }
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(proxy::run(socket, listen, gate)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn import_command(mut args: pico_args::Arguments) -> ExitCode {
    let mut err = std::io::stderr();
    let path: std::path::PathBuf = args
        .opt_value_from_str(["-c", "--config"])
        .ok()
        .flatten()
        .or_else(|| std::env::var_os("BARBICAN_CONFIG").map(Into::into))
        .unwrap_or_else(|| config::DEFAULT_PATH.into());
    let mut inputs = Vec::new();
    for arg in args.finish() {
        let arg = arg.to_string_lossy();
        let Some(input) = import::input(&arg) else {
            let _ = writeln!(err, "import: {arg:?} isn't <source>:<file>");
            return ExitCode::FAILURE;
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        let _ = writeln!(err, "import: no files\n\n{HELP}");
        return ExitCode::FAILURE;
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,barbican::import=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    let config = match config::Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "import: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(import::run(config, &inputs)) {
        Ok(s) => {
            let _ = writeln!(
                err,
                "{} lines ({} without a time, skipped), {} hits, {} new bans ({} active now)",
                s.lines, s.untimed, s.hits, s.bans, s.active
            );
            for source in &s.cursors {
                let _ = writeln!(
                    err,
                    "{source}: the agent goes on from the end of the import"
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(err, "import: {e}");
            ExitCode::FAILURE
        }
    }
}
