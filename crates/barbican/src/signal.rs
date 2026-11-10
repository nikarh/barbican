//! What parsers make of log lines: who did what.
//!
//! Parsing and matching rules happen for every line, so events borrow from the line ([`Event`]); only lines that
//! matched a rule (or are logins) become owned [`Hit`]s for the engine.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use ts_rs::TS;

/// What one log line says an address did. Borrows from the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    Http(Http<'a>),
    /// A wrong password, or a login that gave up halfway.
    AuthFailure {
        user: Option<&'a str>,
    },
    /// A login that worked: the address is someone's.
    AuthSuccess {
        user: &'a str,
    },
    /// A request of someone signed in (no login, but as good a sign).
    Session {
        user: &'a str,
    },
    /// A login as a user that doesn't exist.
    InvalidUser {
        user: &'a str,
    },
    /// Something only scanners send: garbage instead of a protocol, ancient algorithms, ...
    Probe {
        what: &'a str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Http<'a> {
    pub method: &'a str,
    /// With the query.
    pub path: &'a str,
    pub status: u16,
    pub host: Option<&'a str>,
    /// Whether the proxy found a route (a known host) for the request; `None` when the log doesn't say.
    pub routed: Option<bool>,
    pub user_agent: Option<&'a str>,
}

/// The kinds of events, as rules and the UI name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Http,
    AuthFailure,
    AuthSuccess,
    InvalidUser,
    Probe,
}

impl Kind {
    pub const ALL: [Self; 5] = [
        Self::Http,
        Self::AuthFailure,
        Self::AuthSuccess,
        Self::InvalidUser,
        Self::Probe,
    ];

    /// The number stored in the database.
    #[must_use]
    pub fn code(self) -> i64 {
        match self {
            Self::Http => 1,
            Self::AuthFailure => 2,
            Self::AuthSuccess => 3,
            Self::InvalidUser => 4,
            Self::Probe => 5,
        }
    }

    #[must_use]
    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.code() == code)
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::AuthFailure => "auth_failure",
            Self::AuthSuccess => "auth_success",
            Self::InvalidUser => "invalid_user",
            Self::Probe => "probe",
        }
    }
}

/// The longest description of an event that is stored.
const MAX_WHAT: usize = 300;

impl<'a> Event<'a> {
    /// `None` for sessions, which only keep an address trusted.
    #[must_use]
    pub fn kind(&self) -> Option<Kind> {
        match self {
            Self::Http(_) => Some(Kind::Http),
            Self::AuthFailure { .. } => Some(Kind::AuthFailure),
            Self::AuthSuccess { .. } => Some(Kind::AuthSuccess),
            Self::InvalidUser { .. } => Some(Kind::InvalidUser),
            Self::Probe { .. } => Some(Kind::Probe),
            Self::Session { .. } => None,
        }
    }

    /// The user name a login event names.
    #[must_use]
    pub fn user(&self) -> Option<&'a str> {
        match *self {
            Self::AuthFailure { user } => user,
            Self::AuthSuccess { user } | Self::Session { user } | Self::InvalidUser { user } => {
                Some(user)
            }
            Self::Http(_) | Self::Probe { .. } => None,
        }
    }

    /// Writes what happened, in a few words, as stored and shown (`GET example.com/.env → 404`, `root`, ...), into
    /// `out` (cleared first), so a caller can reuse one buffer for every line.
    pub fn write_what(&self, out: &mut String) {
        use std::fmt::Write as _;
        out.clear();
        match self {
            Self::Http(h) => {
                let _ = write!(
                    out,
                    "{} {}{} → {}",
                    h.method,
                    h.host.unwrap_or(""),
                    h.path,
                    h.status
                );
                if h.routed == Some(false) {
                    out.push_str(" (no route)");
                }
            }
            Self::AuthFailure { user } => out.push_str(user.unwrap_or("")),
            Self::AuthSuccess { user } | Self::Session { user } | Self::InvalidUser { user } => {
                out.push_str(user);
            }
            Self::Probe { what } => out.push_str(what),
        }
        if out.len() > MAX_WHAT {
            let mut end = MAX_WHAT;
            while !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
            out.push('…');
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn what(&self) -> String {
        let mut out = String::new();
        self.write_what(&mut out);
        out
    }
}

/// A line that matters, owned, on its way to the engine: the rules it matched (bits of the rule set it was
/// matched against), or a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Unix seconds.
    pub at: i64,
    pub ip: IpAddr,
    /// The source's index in the configuration.
    pub source: u16,
    /// `None` for a session (it only keeps an address trusted).
    pub kind: Option<Kind>,
    pub what: Box<str>,
    /// For logins and sessions: the user.
    pub user: Option<Box<str>>,
    /// Bit `i`: rule `i` of the rule set with this generation matched.
    pub matched: u64,
    pub generation: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what() {
        let http = Event::Http(Http {
            method: "GET",
            path: "/.env",
            status: 404,
            host: Some("example.com"),
            routed: Some(false),
            user_agent: None,
        });
        assert_eq!(http.what(), "GET example.com/.env → 404 (no route)");
        let long = "é".repeat(400);
        let mut buf = String::from("old");
        Event::Probe { what: &long }.write_what(&mut buf);
        assert!(buf.len() <= MAX_WHAT + "…".len() && buf.starts_with('é'));
        assert_eq!(Event::Session { user: "a" }.kind(), None);
        for kind in Kind::ALL {
            assert_eq!(Kind::from_code(kind.code()), Some(kind));
        }
    }
}
