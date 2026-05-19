//! `selfdef-egress-fingerprint` — content-free egress fingerprint.
//!
//! Hashes (host, port, method, path_shape, content_class) into a
//! deterministic id. Never logs raw payload.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// HTTP-like method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    /// GET / READ.
    Get,
    /// POST / WRITE.
    Post,
    /// PUT / UPDATE.
    Put,
    /// DELETE.
    Delete,
    /// Other / unknown.
    Other,
}

/// Content class (broad category).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentClass {
    /// Text / JSON / form.
    Text,
    /// Binary.
    Binary,
    /// Image.
    Image,
    /// Stream (chunked).
    Stream,
    /// Empty body.
    Empty,
}

/// Egress descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressDescriptor {
    /// Host (FQDN or dotted-quad).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Method.
    pub method: Method,
    /// Path shape (path with `:digit:` and `:uuid:` placeholders, no values).
    pub path_shape: String,
    /// Content class.
    pub content_class: ContentClass,
}

/// FNV-1a 64-bit.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Compute the fingerprint as `0x{16-hex}`.
pub fn fingerprint(d: &EgressDescriptor) -> String {
    let method = method_str(d.method);
    let content = content_str(d.content_class);
    let s = format!("{}|{}|{}|{}|{}", d.host, d.port, method, d.path_shape, content);
    let h = fnv1a_64(s.as_bytes());
    format!("0x{h:016x}")
}

fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Other => "OTHER",
    }
}

fn content_str(c: ContentClass) -> &'static str {
    match c {
        ContentClass::Text => "text",
        ContentClass::Binary => "binary",
        ContentClass::Image => "image",
        ContentClass::Stream => "stream",
        ContentClass::Empty => "empty",
    }
}

/// Errors.
#[derive(Debug, Error)]
pub enum EgressFingerprintError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty host.
    #[error("host empty")]
    EmptyHost,
    /// Empty path_shape.
    #[error("path_shape empty")]
    EmptyPathShape,
}

impl EgressDescriptor {
    /// Validate the descriptor.
    pub fn validate(&self) -> Result<(), EgressFingerprintError> {
        if self.host.is_empty() { return Err(EgressFingerprintError::EmptyHost); }
        if self.path_shape.is_empty() { return Err(EgressFingerprintError::EmptyPathShape); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> EgressDescriptor {
        EgressDescriptor {
            host: "api.anthropic.com".into(),
            port: 443,
            method: Method::Post,
            path_shape: "/v1/messages".into(),
            content_class: ContentClass::Text,
        }
    }

    #[test]
    fn fingerprint_deterministic() {
        assert_eq!(fingerprint(&d()), fingerprint(&d()));
    }

    #[test]
    fn fingerprint_changes_on_host() {
        let mut x = d();
        let a = fingerprint(&x);
        x.host = "api.openai.com".into();
        let b = fingerprint(&x);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_changes_on_method() {
        let mut x = d();
        let a = fingerprint(&x);
        x.method = Method::Get;
        let b = fingerprint(&x);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_format_hex_16() {
        let f = fingerprint(&d());
        assert!(f.starts_with("0x"));
        assert_eq!(f.len(), 2 + 16);
    }

    #[test]
    fn descriptor_validates() {
        d().validate().unwrap();
    }

    #[test]
    fn empty_host_rejected() {
        let mut x = d();
        x.host = String::new();
        assert!(matches!(x.validate().unwrap_err(), EgressFingerprintError::EmptyHost));
    }

    #[test]
    fn empty_path_shape_rejected() {
        let mut x = d();
        x.path_shape = String::new();
        assert!(matches!(x.validate().unwrap_err(), EgressFingerprintError::EmptyPathShape));
    }

    #[test]
    fn method_serde_kebab() {
        assert_eq!(serde_json::to_string(&Method::Get).unwrap(), "\"get\"");
        assert_eq!(serde_json::to_string(&Method::Delete).unwrap(), "\"delete\"");
    }

    #[test]
    fn content_serde_kebab() {
        assert_eq!(serde_json::to_string(&ContentClass::Text).unwrap(), "\"text\"");
        assert_eq!(serde_json::to_string(&ContentClass::Stream).unwrap(), "\"stream\"");
    }

    #[test]
    fn descriptor_serde_roundtrip() {
        let x = d();
        let j = serde_json::to_string(&x).unwrap();
        let back: EgressDescriptor = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
