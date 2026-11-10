//! The configuration file (`/etc/barbican/config.toml` by default): where logs come from, where the UI and the edge
//! API listen, and the firewall. Rules and the ban policy are not here: they live in the database and are edited in
//! the UI.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use barbican_common::net::Net;
use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/barbican/config.toml";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub database: Database,
    /// The web UI and its WebSocket API. Without it there is no UI.
    pub ui: Option<Ui>,
    /// The API edge agents follow. Without it no edge can follow this agent.
    pub edge: Option<Edge>,
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default)]
    pub geoip: GeoIp,
    #[serde(default)]
    pub docker: Docker,
    #[serde(default)]
    pub exempt: Exempt,
    #[serde(default, rename = "source")]
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub path: PathBuf,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/barbican/barbican.db"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub listen: SocketAddr,
    /// The TLS certificate (PEM) the edge API serves; edges pin it by its fingerprint. Without it (and `key`), a
    /// self-signed one is made on the first start, next to the database.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// Edge agents allowed to follow, each with its own token.
    #[serde(default, rename = "client")]
    pub clients: Vec<EdgeClient>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeClient {
    pub name: String,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    /// Off: decide and record everything, but leave nftables alone (as `--dry-run` does).
    pub enabled: bool,
    pub table: String,
    /// The chain's priority on the prerouting hook: after connection tracking (-200), before NAT (-100).
    pub priority: i32,
    /// The nft program.
    pub nft: String,
}

impl Default for Firewall {
    fn default() -> Self {
        Self {
            enabled: true,
            table: "barbican".to_owned(),
            priority: -190,
            nft: "nft".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoIp {
    /// A country database in the MaxMind DB format (DB-IP's IP to Country Lite, or MaxMind's GeoLite2 Country).
    pub country: Option<PathBuf>,
    /// An ASN database in the MaxMind DB format (DB-IP's IP to ASN Lite, or GeoLite2 ASN).
    pub asn: Option<PathBuf>,
    /// Download DB-IP's free databases to these paths when missing, and once a month.
    pub download: bool,
}

impl Default for GeoIp {
    fn default() -> Self {
        Self {
            country: Some(PathBuf::from("/var/lib/barbican/dbip-country-lite.mmdb")),
            asn: Some(PathBuf::from("/var/lib/barbican/dbip-asn-lite.mmdb")),
            download: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docker {
    /// The Docker API's socket (or a read-only proxy of it).
    pub socket: PathBuf,
}

impl Default for Docker {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/run/docker.sock"),
        }
    }
}

/// Addresses no rule acts on, and that are never blocked. The UI's allow list adds to these.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exempt {
    pub nets: Vec<Net>,
}

impl Default for Exempt {
    fn default() -> Self {
        let nets = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "fc00::/7",
        ];
        Self {
            nets: nets.iter().filter_map(|n| n.parse().ok()).collect(),
        }
    }
}

/// A log to read, and how to read its lines.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Shown in the UI and used by rules to limit themselves to some sources.
    pub name: String,
    pub parser: ParserKind,
    /// For `parser = "regex"`: the pattern, with named groups (see the README).
    pub pattern: Option<String>,
    /// For `parser = "regex"`: what a matching line is.
    pub kind: Option<RegexKind>,
    #[serde(flatten)]
    pub input: Input,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParserKind {
    /// Traefik's access log, in the common log format or as JSON.
    Traefik,
    /// OpenSSH's sshd.
    Sshd,
    /// Authelia.
    Authelia,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegexKind {
    Http,
    AuthFailure,
    AuthSuccess,
    InvalidUser,
    Probe,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Input {
    /// A container's log, through the Docker API.
    Docker { container: String },
    /// A file, followed across rotation.
    File { path: PathBuf },
    /// The systemd journal, through `journalctl`.
    Journald {
        #[serde(default)]
        unit: Option<String>,
        #[serde(default)]
        identifier: Option<String>,
    },
    /// A VictoriaLogs query, followed live.
    #[serde(rename = "victorialogs")]
    VictoriaLogs { url: String, query: String },
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| Error::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        let mut names = std::collections::HashSet::new();
        for source in &self.sources {
            if !names.insert(source.name.as_str()) {
                return Err(Error::Invalid(format!(
                    "two sources are named {:?}",
                    source.name
                )));
            }
            let regex = source.parser == ParserKind::Regex;
            if regex != source.pattern.is_some() || regex != source.kind.is_some() {
                return Err(Error::Invalid(format!(
                    "source {:?}: `pattern` and `kind` go with parser = \"regex\", and only with it",
                    source.name
                )));
            }
        }
        if let Some(edge) = &self.edge {
            if edge.cert.is_some() != edge.key.is_some() {
                return Err(Error::Invalid(
                    "edge: set both `cert` and `key`, or neither".to_owned(),
                ));
            }
            for client in &edge.clients {
                if client.token.is_some() == client.token_file.is_some() {
                    return Err(Error::Invalid(format!(
                        "edge client {:?}: set either `token` or `token_file`",
                        client.name
                    )));
                }
            }
        }
        if self.firewall.table.is_empty()
            || !self
                .firewall
                .table
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(Error::Invalid(
                "firewall.table: letters, digits, '_' and '-' only".to_owned(),
            ));
        }
        Ok(())
    }
}

impl EdgeClient {
    /// The token, read from `token_file` when that is set (trimmed).
    pub fn token(&self) -> Result<String, Error> {
        match (&self.token, &self.token_file) {
            (Some(token), _) => Ok(token.clone()),
            (None, Some(path)) => std::fs::read_to_string(path)
                .map(|t| t.trim().to_owned())
                .map_err(|source| Error::Read {
                    path: path.clone(),
                    source,
                }),
            (None, None) => Err(Error::Invalid(format!(
                "edge client {:?} has no token",
                self.name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, Error> {
        let config: Config = toml::from_str(text).map_err(|source| Error::Parse {
            path: PathBuf::new(),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn example_config_parses() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../dist/config.toml"
        ))
        .unwrap();
        let config = parse(&text).unwrap();
        assert!(!config.sources.is_empty());
    }

    #[test]
    fn sources() {
        let config = parse(
            r#"
            [[source]]
            name = "proxy"
            parser = "traefik"
            docker = { container = "traefik" }

            [[source]]
            name = "ssh"
            parser = "sshd"
            journald = { unit = "sshd.service" }

            [[source]]
            name = "app"
            parser = "regex"
            pattern = 'login failed from (?P<ip>\S+)'
            kind = "auth_failure"
            file = { path = "/var/log/app.log" }

            [[source]]
            name = "vl"
            parser = "authelia"
            victorialogs = { url = "http://127.0.0.1:9428", query = "container_name:authelia" }
            "#,
        )
        .unwrap();
        assert!(
            matches!(&config.sources[0].input, Input::Docker { container } if container == "traefik")
        );
        assert!(
            matches!(&config.sources[1].input, Input::Journald { unit: Some(u), .. } if u == "sshd.service")
        );
        assert_eq!(config.sources[2].kind, Some(RegexKind::AuthFailure));
        assert!(matches!(
            &config.sources[3].input,
            Input::VictoriaLogs { .. }
        ));
        assert!(config.firewall.enabled);
        assert_eq!(config.exempt.nets.len(), 5);
    }

    #[test]
    fn rejects_mistakes() {
        let regex_without_pattern = r#"
            [[source]]
            name = "a"
            parser = "regex"
            file = { path = "/x" }
        "#;
        assert!(parse(regex_without_pattern).is_err());
        let twice = r#"
            [[source]]
            name = "a"
            parser = "sshd"
            file = { path = "/x" }
            [[source]]
            name = "a"
            parser = "sshd"
            file = { path = "/y" }
        "#;
        assert!(parse(twice).is_err());
        let both_tokens = r#"
            [edge]
            listen = "0.0.0.0:7380"
            [[edge.client]]
            name = "r"
            token = "a"
            token_file = "/b"
        "#;
        assert!(parse(both_tokens).is_err());
        assert!(
            parse("[firewall]\ntable = \"a b\"\nenabled = true\npriority = 0\nnft = \"nft\"")
                .is_err()
        );
        assert!(parse("unknown = 1").is_err());
    }
}
