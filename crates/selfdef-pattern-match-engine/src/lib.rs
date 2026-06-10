//! `selfdef-pattern-match-engine` — 4 unified pattern kinds.
//!
//! - `PathGlob`     — `*` wildcard matches a single path segment;
//!   `**` matches any number of segments.
//! - `Fqdn`         — exact match or `.suffix` (dot-prefixed) suffix.
//! - `Cidr`         — naive prefix match on `a.b.c.d/N` (N in 0..=32).
//! - `SubstringRule`— case-insensitive substring of input.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Pattern kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum Pattern {
    /// Filesystem glob (`*` segment, `**` recursive).
    PathGlob(String),
    /// Fully-qualified domain name (exact or dot-suffix).
    Fqdn(String),
    /// CIDR prefix.
    Cidr(String),
    /// Case-insensitive substring.
    SubstringRule(String),
}

/// Errors.
#[derive(Debug, Error)]
pub enum PatternError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty pattern body.
    #[error("empty pattern body")]
    Empty,
    /// CIDR missing '/'.
    #[error("cidr {0} missing '/'")]
    BadCidr(String),
}

impl Pattern {
    /// True if `input` satisfies the pattern.
    pub fn matches(&self, input: &str) -> bool {
        match self {
            Pattern::PathGlob(g) => match_path_glob(g, input),
            Pattern::Fqdn(s) => {
                // FQDNs are case-insensitive (DNS). Matching case-sensitively
                // lets a mixed-case destination (`sub.EVIL.com`) slip a deny
                // pattern (`.evil.com`) in network-rule-pack — a denylist
                // case-bypass — and wrongly miss a case-varied allow. Fold both
                // sides (SubstringRule already does; PathGlob stays case-
                // sensitive for Linux paths).
                let input_l = input.to_ascii_lowercase();
                let s_l = s.to_ascii_lowercase();
                if let Some(suffix) = s_l.strip_prefix('.') {
                    input_l == suffix || input_l.ends_with(&s_l)
                } else {
                    s_l == input_l
                }
            }
            Pattern::Cidr(c) => match_cidr(c, input),
            Pattern::SubstringRule(s) => {
                input.to_ascii_lowercase().contains(&s.to_ascii_lowercase())
            }
        }
    }

    /// Lightweight validation of the pattern body.
    pub fn validate(&self) -> Result<(), PatternError> {
        match self {
            Pattern::PathGlob(s) | Pattern::Fqdn(s) | Pattern::SubstringRule(s) => {
                if s.is_empty() {
                    return Err(PatternError::Empty);
                }
            }
            Pattern::Cidr(c) => {
                if c.is_empty() {
                    return Err(PatternError::Empty);
                }
                if !c.contains('/') {
                    return Err(PatternError::BadCidr(c.clone()));
                }
            }
        }
        Ok(())
    }
}

fn match_path_glob(pattern: &str, input: &str) -> bool {
    let p_segs: Vec<&str> = pattern.split('/').collect();
    let i_segs: Vec<&str> = input.split('/').collect();
    glob_segs(&p_segs, &i_segs)
}

fn glob_segs(pattern: &[&str], input: &[&str]) -> bool {
    if pattern.is_empty() && input.is_empty() {
        return true;
    }
    if pattern.is_empty() {
        return false;
    }
    let p0 = pattern[0];
    if p0 == "**" {
        // `**` matches zero or more segments — recurse on consuming patterns or input.
        for take in 0..=input.len() {
            if glob_segs(&pattern[1..], &input[take..]) {
                return true;
            }
        }
        false
    } else {
        if input.is_empty() {
            return false;
        }
        let i0 = input[0];
        let seg_match = p0 == "*" || p0 == i0;
        if !seg_match {
            return false;
        }
        glob_segs(&pattern[1..], &input[1..])
    }
}

fn match_cidr(cidr: &str, input: &str) -> bool {
    let Some((prefix, bits_s)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits_s.parse::<u32>() else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let prefix_parts: Vec<&str> = prefix.split('.').collect();
    let input_parts: Vec<&str> = input.split('.').collect();
    if prefix_parts.len() != 4 || input_parts.len() != 4 {
        return false;
    }
    let octets = (bits / 8) as usize;
    let remainder_bits = bits % 8;
    if octets <= 4 && prefix_parts[..octets] != input_parts[..octets] {
        return false;
    }
    if octets < 4 && remainder_bits > 0 {
        let mask: u8 = 0xff << (8 - remainder_bits);
        let p: u8 = prefix_parts[octets].parse().unwrap_or(0);
        let i: u8 = input_parts[octets].parse().unwrap_or(0);
        if (p & mask) != (i & mask) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_glob_exact() {
        let p = Pattern::PathGlob("/etc/sovereign/cfg.toml".into());
        assert!(p.matches("/etc/sovereign/cfg.toml"));
        assert!(!p.matches("/etc/other/cfg.toml"));
    }

    #[test]
    fn path_glob_single_star() {
        let p = Pattern::PathGlob("/etc/*/cfg.toml".into());
        assert!(p.matches("/etc/sovereign/cfg.toml"));
        assert!(p.matches("/etc/selfdef/cfg.toml"));
        assert!(!p.matches("/etc/a/b/cfg.toml"));
    }

    #[test]
    fn path_glob_double_star() {
        let p = Pattern::PathGlob("/workspace/**/main.rs".into());
        assert!(p.matches("/workspace/main.rs"));
        assert!(p.matches("/workspace/a/main.rs"));
        assert!(p.matches("/workspace/a/b/c/main.rs"));
        assert!(!p.matches("/workspace/main.py"));
    }

    #[test]
    fn fqdn_exact() {
        let p = Pattern::Fqdn("api.anthropic.com".into());
        assert!(p.matches("api.anthropic.com"));
        assert!(!p.matches("foo.api.anthropic.com"));
    }

    #[test]
    fn fqdn_suffix() {
        let p = Pattern::Fqdn(".example.org".into());
        assert!(p.matches("a.example.org"));
        assert!(p.matches("x.y.example.org"));
        assert!(p.matches("example.org"));
        assert!(!p.matches("example.com"));
    }

    #[test]
    fn fqdn_match_is_case_insensitive() {
        // FQDNs are case-insensitive (DNS). A deny pattern in network-rule-pack
        // must catch a mixed-case destination, and an allow must catch a
        // case-varied host — case-sensitive matching was a denylist case-bypass.
        let suffix = Pattern::Fqdn(".evil.com".into());
        assert!(suffix.matches("sub.EVIL.com"));
        assert!(suffix.matches("SUB.evil.COM"));
        assert!(suffix.matches("EVIL.com"));
        let exact = Pattern::Fqdn("Api.Anthropic.Com".into());
        assert!(exact.matches("api.anthropic.com"));
        assert!(exact.matches("API.ANTHROPIC.COM"));
        // Boundary still holds case-insensitively: not-a-subdomain doesn't match.
        assert!(!suffix.matches("notevil.com"));
        assert!(!suffix.matches("evil.com.attacker.net"));
    }

    #[test]
    fn cidr_byte_aligned() {
        let p = Pattern::Cidr("10.0.0.0/8".into());
        assert!(p.matches("10.1.2.3"));
        assert!(p.matches("10.255.0.0"));
        assert!(!p.matches("11.0.0.0"));
    }

    #[test]
    fn cidr_24() {
        let p = Pattern::Cidr("192.168.1.0/24".into());
        assert!(p.matches("192.168.1.5"));
        assert!(!p.matches("192.168.2.5"));
    }

    #[test]
    fn cidr_unaligned_bits() {
        // 192.168.0.0/20 → top 16 bits + 4 bits of third octet.
        let p = Pattern::Cidr("192.168.0.0/20".into());
        // 192.168.0.0 .. 192.168.15.255 match.
        assert!(p.matches("192.168.5.1"));
        assert!(p.matches("192.168.15.255"));
        // 192.168.16.0 is outside.
        assert!(!p.matches("192.168.16.0"));
    }

    #[test]
    fn cidr_malformed_no_match() {
        let p = Pattern::Cidr("not-a-cidr".into());
        assert!(!p.matches("10.0.0.1"));
    }

    #[test]
    fn substring_case_insensitive() {
        let p = Pattern::SubstringRule("PASSWORD".into());
        assert!(p.matches("operator password leaked"));
        assert!(p.matches("PASSWORD"));
        assert!(!p.matches("nothing"));
    }

    #[test]
    fn empty_pattern_rejected() {
        let p = Pattern::PathGlob(String::new());
        assert!(matches!(p.validate().unwrap_err(), PatternError::Empty));
    }

    #[test]
    fn bad_cidr_rejected() {
        let p = Pattern::Cidr("10.0.0.0".into());
        assert!(matches!(
            p.validate().unwrap_err(),
            PatternError::BadCidr(_)
        ));
    }

    #[test]
    fn pattern_serde_tagged_kebab() {
        let p = Pattern::PathGlob("/etc/x".into());
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"kind\":\"path-glob\""));
        assert!(j.contains("\"value\":\"/etc/x\""));
        let back: Pattern = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
