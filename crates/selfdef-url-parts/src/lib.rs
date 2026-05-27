//! `selfdef-url-parts` — minimal URL split.
//!
//! parse("scheme://host[:port]/path[?query]") → UrlParts.
//! Validates scheme/host non-empty and port (if present)
//! 1..=65535. No url-encoding handling — caller-provided
//! raw fields.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// URL parts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UrlParts {
    /// Schema version.
    pub schema_version: String,
    /// Scheme.
    pub scheme: String,
    /// Host.
    pub host: String,
    /// Port (None = default).
    pub port: Option<u16>,
    /// Path (always starts with /).
    pub path: String,
    /// Query (raw, no leading ?).
    pub query: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum UrlError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad shape.
    #[error("invalid URL: {0}")]
    BadUrl(String),
    /// Bad port.
    #[error("invalid port: {0}")]
    BadPort(String),
}

impl UrlParts {
    /// Parse.
    pub fn parse(input: &str) -> Result<Self, UrlError> {
        // Split scheme.
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| UrlError::BadUrl(input.into()))?;
        if scheme.is_empty() {
            return Err(UrlError::BadUrl(input.into()));
        }
        // Split path from authority.
        let (authority, path_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        // Authority must be non-empty.
        if authority.is_empty() {
            return Err(UrlError::BadUrl(input.into()));
        }
        // Optional :port.
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port: u16 = p.parse().map_err(|_| UrlError::BadPort(p.into()))?;
                if port == 0 {
                    return Err(UrlError::BadPort(p.into()));
                }
                (h, Some(port))
            }
            _ => (authority, None),
        };
        if host.is_empty() {
            return Err(UrlError::BadUrl(input.into()));
        }
        // Path and query.
        let (path, query) = match path_query.find('?') {
            Some(i) => (&path_query[..i], &path_query[i + 1..]),
            None => (path_query, ""),
        };
        let path = if path.is_empty() { "/" } else { path };
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: path.into(),
            query: query.into(),
        })
    }

    /// Reassemble URL.
    pub fn to_string(&self) -> String {
        let mut out = String::with_capacity(64);
        out.push_str(&self.scheme);
        out.push_str("://");
        out.push_str(&self.host);
        if let Some(p) = self.port {
            out.push(':');
            out.push_str(&p.to_string());
        }
        out.push_str(&self.path);
        if !self.query.is_empty() {
            out.push('?');
            out.push_str(&self.query);
        }
        out
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), UrlError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(UrlError::SchemaMismatch);
        }
        if self.scheme.is_empty() || self.host.is_empty() {
            return Err(UrlError::BadUrl("".into()));
        }
        if let Some(p) = self.port {
            if p == 0 {
                return Err(UrlError::BadPort("0".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let u = UrlParts::parse("https://example.com/path?q=1").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, None);
        assert_eq!(u.path, "/path");
        assert_eq!(u.query, "q=1");
    }

    #[test]
    fn with_port() {
        let u = UrlParts::parse("http://localhost:8080/").unwrap();
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.path, "/");
    }

    #[test]
    fn no_path() {
        let u = UrlParts::parse("https://example.com").unwrap();
        assert_eq!(u.path, "/");
        assert_eq!(u.query, "");
    }

    #[test]
    fn roundtrip() {
        let s = "https://example.com:443/a/b?x=1";
        let u = UrlParts::parse(s).unwrap();
        assert_eq!(u.to_string(), s);
    }

    #[test]
    fn bad_url_rejected() {
        assert!(matches!(
            UrlParts::parse("noscheme.com/").unwrap_err(),
            UrlError::BadUrl(_)
        ));
        assert!(matches!(
            UrlParts::parse("://nohost").unwrap_err(),
            UrlError::BadUrl(_)
        ));
    }

    #[test]
    fn bad_port_rejected() {
        assert!(matches!(
            UrlParts::parse("http://example.com:0/").unwrap_err(),
            UrlError::BadPort(_)
        ));
    }

    #[test]
    fn empty_query_no_question_mark_in_output() {
        let u = UrlParts::parse("https://example.com/x").unwrap();
        assert_eq!(u.to_string(), "https://example.com/x");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut u = UrlParts::parse("https://example.com/").unwrap();
        u.schema_version = "9.9.9".into();
        assert!(matches!(
            u.validate().unwrap_err(),
            UrlError::SchemaMismatch
        ));
    }

    #[test]
    fn url_serde_roundtrip() {
        let u = UrlParts::parse("https://example.com:443/x?y=1").unwrap();
        let j = serde_json::to_string(&u).unwrap();
        let back: UrlParts = serde_json::from_str(&j).unwrap();
        assert_eq!(u, back);
    }
}
