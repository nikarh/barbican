//! barbican: bans addresses that abuse services, from their logs.

use std::io::{BufRead, Write};
use std::process::ExitCode;

mod api;
mod app;
mod config;
mod db;
mod engine;
mod feeds;
mod geo;
mod parse;
mod replay;
mod rules;
mod signal;
mod state;
mod time;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
barbican: bans addresses that abuse services, from their logs

Usage:
  barbican [--config <path>] [--dry-run]     run the agent
  barbican parse <parser> [<file>]           print what a parser makes of each line (of stdin without a file)
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
        Ok(Some(other)) => {
            let _ = writeln!(std::io::stderr(), "unknown command {other:?}\n\n{HELP}");
            ExitCode::FAILURE
        }
        Ok(None) => ExitCode::SUCCESS,
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
