//! `selfdef-audit-redaction` — 6 redactor classes for outbound audit text.
//!
//! Each redactor is a literal-pattern matcher (no regex; deterministic on
//! `forbid(unsafe_code)`) that scans an audit summary string and replaces
//! the matched span with a canonical placeholder.
//!
//! - `Email`       → `[email]`
//! - `IPv4`        → `[ipv4]`
//! - `IPv6`        → `[ipv6]`
//! - `SshKey`      → `[ssh-key]`     (matches `ssh-rsa AAAA…` and `ssh-ed25519 AAAA…`)
//! - `BearerToken` → `[bearer]`       (matches `Bearer <token>` headers)
//! - `PathHome`    → `[~]`            (matches `/home/<user>/…` prefix; `<user>` stays redacted)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Redactor class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactorClass {
    /// Email.
    Email,
    /// IPv4 dotted-quad.
    Ipv4,
    /// IPv6 colon-hex.
    Ipv6,
    /// SSH public key (rsa / ed25519 prefix).
    SshKey,
    /// HTTP Bearer token header.
    BearerToken,
    /// /home/<user>/ filesystem path.
    PathHome,
}

/// Redactor manifest envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactorManifest {
    /// Schema version.
    pub schema_version: String,
    /// 6 redactors (canonical).
    pub redactors: Vec<RedactorClass>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RedactionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 6.
    #[error("redactor count {0} != 6 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing redactor: {0:?}")]
    Missing(RedactorClass),
}

impl RedactorManifest {
    /// Canonical 6-redactor manifest.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            redactors: vec![
                RedactorClass::Email,
                RedactorClass::Ipv4,
                RedactorClass::Ipv6,
                RedactorClass::SshKey,
                RedactorClass::BearerToken,
                RedactorClass::PathHome,
            ],
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RedactionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RedactionError::SchemaMismatch);
        }
        if self.redactors.len() != 6 {
            return Err(RedactionError::CountInvalid(self.redactors.len()));
        }
        for r in [
            RedactorClass::Email,
            RedactorClass::Ipv4,
            RedactorClass::Ipv6,
            RedactorClass::SshKey,
            RedactorClass::BearerToken,
            RedactorClass::PathHome,
        ] {
            if !self.redactors.contains(&r) {
                return Err(RedactionError::Missing(r));
            }
        }
        Ok(())
    }
}

// === Redactor implementations ===

/// Apply a single redactor class to `text`. Returns the redacted string.
pub fn redact_one(text: &str, class: RedactorClass) -> String {
    match class {
        RedactorClass::Email => redact_email(text),
        RedactorClass::Ipv4 => redact_ipv4(text),
        RedactorClass::Ipv6 => redact_ipv6(text),
        RedactorClass::SshKey => redact_ssh_key(text),
        RedactorClass::BearerToken => redact_bearer(text),
        RedactorClass::PathHome => redact_path_home(text),
    }
}

/// Apply all redactors in canonical order.
pub fn redact_all(text: &str) -> String {
    let mut s = text.to_string();
    for c in [
        RedactorClass::Email,
        RedactorClass::Ipv4,
        RedactorClass::Ipv6,
        RedactorClass::SshKey,
        RedactorClass::BearerToken,
        RedactorClass::PathHome,
    ] {
        s = redact_one(&s, c);
    }
    s
}

fn redact_email(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find '@' boundary.
        if bytes[i] == b'@' {
            // Walk left to find start of local part.
            let mut left = i;
            while left > 0 {
                let b = bytes[left - 1];
                if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'+' || b == b'-' {
                    left -= 1;
                } else {
                    break;
                }
            }
            // Walk right to find domain end (must contain at least one '.').
            let mut right = i + 1;
            let mut saw_dot = false;
            while right < bytes.len() {
                let b = bytes[right];
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'.' {
                    if b == b'.' {
                        saw_dot = true;
                    }
                    right += 1;
                } else {
                    break;
                }
            }
            if left < i && right > i + 1 && saw_dot {
                // Trim trailing dot from domain.
                let mut end = right;
                while end > i + 1 && bytes[end - 1] == b'.' {
                    end -= 1;
                }
                // Drop everything we'd already written for the local-part chars in `out`.
                let drop = i - left;
                for _ in 0..drop {
                    out.pop();
                }
                out.push_str("[email]");
                i = end;
                continue;
            }
        }
        // Not an email: emit the char at `i` UTF-8-correctly. `byte as char`
        // would split a multi-byte code point into mojibake.
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn is_ipv4_octet(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 3
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
}

fn redact_ipv4(text: &str) -> String {
    // Find runs of digits and dots; check if 4 dot-separated octets.
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            // Capture maximal run of digits and dots.
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let span = &text[start..i];
            // Try interpret as dotted-quad.
            let parts: Vec<&str> = span.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| is_ipv4_octet(p)) {
                out.push_str("[ipv4]");
            } else {
                out.push_str(span);
            }
            continue;
        }
        // Non-digit byte: emit the char UTF-8-correctly (not `byte as char`,
        // which would mangle multi-byte code points).
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_ipv6(text: &str) -> String {
    // Heuristic: any run with >=2 colons separating ascii-hex groups (1..4 chars).
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_hexdigit() || c == b':' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == b':') {
                i += 1;
            }
            let span = &text[start..i];
            let colon_count = span.bytes().filter(|b| *b == b':').count();
            let groups: Vec<&str> = span.split(':').collect();
            let valid_groups = groups.iter().all(|g| {
                g.is_empty() || (g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
            });
            if colon_count >= 2 && valid_groups && groups.len() >= 3 {
                out.push_str("[ipv6]");
            } else {
                out.push_str(span);
            }
            continue;
        }
        // Non-hex/colon byte: emit the char UTF-8-correctly (not `byte as
        // char`, which would mangle multi-byte code points).
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_ssh_key(text: &str) -> String {
    let mut s = text.to_string();
    for prefix in ["ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-nistp256 "] {
        while let Some(idx) = s.find(prefix) {
            // Find end of base64-ish blob (alnum, +, /, =).
            let after = idx + prefix.len();
            let bytes = s.as_bytes();
            let mut end = after;
            while end < bytes.len() {
                let b = bytes[end];
                if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
                    end += 1;
                } else {
                    break;
                }
            }
            if end > after {
                s.replace_range(idx..end, "[ssh-key]");
            } else {
                // Replace just the prefix to avoid infinite loop.
                s.replace_range(idx..after, "[ssh-key] ");
            }
        }
    }
    s
}

fn redact_bearer(text: &str) -> String {
    let mut s = text.to_string();
    while let Some(idx) = s.find("Bearer ") {
        let after = idx + "Bearer ".len();
        let bytes = s.as_bytes();
        let mut end = after;
        while end < bytes.len() {
            let b = bytes[end];
            if b.is_ascii_alphanumeric()
                || b == b'.'
                || b == b'-'
                || b == b'_'
                || b == b'+'
                || b == b'/'
                || b == b'='
            {
                end += 1;
            } else {
                break;
            }
        }
        if end > after {
            s.replace_range(idx..end, "[bearer]");
        } else {
            s.replace_range(idx..after, "[bearer] ");
        }
    }
    s
}

fn redact_path_home(text: &str) -> String {
    let mut s = text.to_string();
    while let Some(idx) = s.find("/home/") {
        // Find end of username segment.
        let after = idx + "/home/".len();
        let bytes = s.as_bytes();
        let mut end = after;
        while end < bytes.len() {
            let b = bytes[end];
            if b == b'/' || b == b' ' || b == b'"' || b == b'\n' || b == b',' {
                break;
            }
            end += 1;
        }
        if end > after {
            s.replace_range(idx..end, "[~]");
        } else {
            s.replace_range(idx..after, "[~]");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_canonical_validates() {
        RedactorManifest::canonical().validate().unwrap();
    }

    #[test]
    fn six_redactors_present() {
        let m = RedactorManifest::canonical();
        assert_eq!(m.redactors.len(), 6);
    }

    #[test]
    fn email_redacted() {
        let out = redact_one(
            "contact alice.smith+test@example.com here",
            RedactorClass::Email,
        );
        assert_eq!(out, "contact [email] here");
    }

    #[test]
    fn ipv4_redacted() {
        let out = redact_one("from 10.0.0.7 reply 192.168.1.1 done", RedactorClass::Ipv4);
        assert_eq!(out, "from [ipv4] reply [ipv4] done");
    }

    #[test]
    fn ipv6_redacted() {
        let out = redact_one("addr 2001:db8:85a3::8a2e", RedactorClass::Ipv6);
        assert_eq!(out, "addr [ipv6]");
    }

    #[test]
    fn non_ascii_audit_text_preserved_around_secrets() {
        // The byte-walking redactors emitted each non-secret byte via
        // `byte as char`, which mangles multi-byte UTF-8 into mojibake — an
        // audit-log fidelity bug (the log is a security artifact). The ASCII
        // secret must still be redacted while the surrounding Unicode survives
        // byte-for-byte.
        let out = redact_one("café 10.0.0.7 wörld ☂", RedactorClass::Ipv4);
        assert_eq!(out, "café [ipv4] wörld ☂");
        let out = redact_one("café 2001:db8::1 wörld ☂", RedactorClass::Ipv6);
        assert_eq!(out, "café [ipv6] wörld ☂");
        let out = redact_one("señor a@b.com ☂", RedactorClass::Email);
        assert_eq!(out, "señor [email] ☂");
    }

    #[test]
    fn ssh_key_redacted_rsa_and_ed25519() {
        let out = redact_one(
            "authorized: ssh-rsa AAAAB3NzaC1yc2E= user@host",
            RedactorClass::SshKey,
        );
        assert!(out.contains("[ssh-key]"));
        assert!(!out.contains("AAAAB3NzaC1yc2E="));
        let out2 = redact_one(
            "authorized: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
            RedactorClass::SshKey,
        );
        assert!(out2.contains("[ssh-key]"));
    }

    #[test]
    fn bearer_token_redacted() {
        let out = redact_one(
            "Authorization: Bearer abc.DEF-123_xyz== more",
            RedactorClass::BearerToken,
        );
        assert_eq!(out, "Authorization: [bearer] more");
    }

    #[test]
    fn path_home_redacted() {
        let out = redact_one("read /home/alice/.ssh/id_rsa now", RedactorClass::PathHome);
        assert_eq!(out, "read [~]/.ssh/id_rsa now");
    }

    #[test]
    fn redact_all_applies_every_class() {
        let s = "Bearer xyz from 10.0.0.1 to me@ex.com path /home/op/x";
        let out = redact_all(s);
        assert!(out.contains("[bearer]"));
        assert!(out.contains("[ipv4]"));
        assert!(out.contains("[email]"));
        assert!(out.contains("[~]"));
        assert!(!out.contains("me@ex.com"));
        assert!(!out.contains("10.0.0.1"));
    }

    #[test]
    fn non_matching_strings_untouched() {
        let s = "just plain text without secrets";
        assert_eq!(redact_all(s), s);
    }

    #[test]
    fn count_invalid_caught() {
        let mut m = RedactorManifest::canonical();
        m.redactors.pop();
        assert!(matches!(
            m.validate().unwrap_err(),
            RedactionError::CountInvalid(5)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = RedactorManifest::canonical();
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate().unwrap_err(),
            RedactionError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&RedactorClass::Email).unwrap(),
            "\"email\""
        );
        assert_eq!(
            serde_json::to_string(&RedactorClass::SshKey).unwrap(),
            "\"ssh-key\""
        );
        assert_eq!(
            serde_json::to_string(&RedactorClass::BearerToken).unwrap(),
            "\"bearer-token\""
        );
        assert_eq!(
            serde_json::to_string(&RedactorClass::PathHome).unwrap(),
            "\"path-home\""
        );
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = RedactorManifest::canonical();
        let j = serde_json::to_string(&m).unwrap();
        let back: RedactorManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
