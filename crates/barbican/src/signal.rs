//! What parsers make of log lines: who did what.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use ts_rs::TS;

/// One thing an address did, from one log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// Unix seconds.
    pub at: u64,
    pub ip: IpAddr,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Http(Http),
    /// A wrong password, or a login that gave up halfway.
    AuthFailure {
        user: Option<String>,
    },
    /// A login that worked: the address is someone's.
    AuthSuccess {
        user: String,
    },
    /// A request of someone signed in (no login, but as good a sign).
    Session {
        user: String,
    },
    /// A login as a user that doesn't exist.
    InvalidUser {
        user: String,
    },
    /// Something only scanners send: garbage instead of a protocol, ancient algorithms, ...
    Probe {
        what: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http {
    pub method: String,
    /// With the query.
    pub path: String,
    pub status: u16,
    pub host: Option<String>,
    /// Whether the proxy found a route (a known host) for the request; `None` when the log doesn't say.
    pub routed: Option<bool>,
    pub user_agent: Option<String>,
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
}

/// The longest description of an event that is stored.
const MAX_WHAT: usize = 300;

impl Event {
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

    /// What happened, in a few words, as stored and shown: `GET example.com/.env → 404`, `root`, ...
    #[must_use]
    pub fn what(&self) -> String {
        let mut what = match self {
            Self::Http(h) => {
                let host = h.host.as_deref().unwrap_or("");
                let route = if h.routed == Some(false) {
                    " (no route)"
                } else {
                    ""
                };
                format!("{} {host}{} → {}{route}", h.method, h.path, h.status)
            }
            Self::AuthFailure { user } => user.clone().unwrap_or_default(),
            Self::AuthSuccess { user } | Self::Session { user } | Self::InvalidUser { user } => {
                user.clone()
            }
            Self::Probe { what } => what.clone(),
        };
        if what.len() > MAX_WHAT {
            let mut end = MAX_WHAT;
            while !what.is_char_boundary(end) {
                end -= 1;
            }
            what.truncate(end);
            what.push('…');
        }
        what
    }

    /// The user name a login event names.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        match self {
            Self::AuthFailure { user } => user.as_deref(),
            Self::AuthSuccess { user } | Self::Session { user } | Self::InvalidUser { user } => {
                Some(user)
            }
            Self::Http(_) | Self::Probe { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what() {
        let http = Event::Http(Http {
            method: "GET".into(),
            path: "/.env".into(),
            status: 404,
            host: Some("example.com".into()),
            routed: Some(false),
            user_agent: None,
        });
        assert_eq!(http.what(), "GET example.com/.env → 404 (no route)");
        let long = Event::Probe {
            what: "é".repeat(400),
        };
        assert!(long.what().len() <= MAX_WHAT + "…".len());
        assert_eq!(Event::Session { user: "a".into() }.kind(), None);
        for kind in Kind::ALL {
            assert_eq!(Kind::from_code(kind.code()), Some(kind));
        }
    }
}
