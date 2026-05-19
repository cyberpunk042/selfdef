//! `selfdef-secret-redaction-policy` — IPS secret-redaction authority.
//!
//! Replaces detected secrets in operator-visible strings with
//! deterministic placeholders. Each placeholder records the secret
//! class + a stable short hash so the operator can correlate
//! occurrences across a transcript without seeing the literal value.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Secret class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretClass {
    /// AWS access key ID.
    AwsAccessKey,
    /// GitHub personal access token.
    GithubToken,
    /// JWT bearer token.
    Jwt,
    /// PEM block (BEGIN ...).
    PemBlock,
    /// Provider "sk-*" API key (OpenAI, Anthropic, etc.).
    ProviderApiKey,
    /// Slack / Discord webhook URL.
    WebhookUrl,
    /// Generic high-entropy hex/base64 blob (≥40 chars).
    GenericHighEntropy,
}

/// One redaction event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redaction {
    /// Class.
    pub class: SecretClass,
    /// Byte offset in the input where the secret started.
    pub offset: usize,
    /// Original literal length.
    pub original_len: usize,
    /// Placeholder used in output.
    pub placeholder: String,
}

/// Result of redacting one string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionResult {
    /// Schema version.
    pub schema_version: String,
    /// Redacted output text.
    pub redacted: String,
    /// Events in input order.
    pub events: Vec<Redaction>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RedactionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Pure redactor.
#[derive(Debug, Clone, Default)]
pub struct SecretRedactor;

impl SecretRedactor {
    /// Redact secrets in `input`.
    pub fn redact(input: &str) -> RedactionResult {
        let mut out = String::with_capacity(input.len());
        let mut events: Vec<Redaction> = Vec::new();
        let bytes = input.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if let Some((class, len)) = match_secret(input, i) {
                let literal = &input[i..i + len];
                let placeholder = format_placeholder(class, literal);
                events.push(Redaction {
                    class,
                    offset: i,
                    original_len: len,
                    placeholder: placeholder.clone(),
                });
                out.push_str(&placeholder);
                i += len;
            } else {
                let c = char_at(input, i);
                out.push(c);
                i += c.len_utf8();
            }
        }
        RedactionResult {
            schema_version: SCHEMA_VERSION.into(),
            redacted: out,
            events,
        }
    }
}

fn char_at(s: &str, i: usize) -> char {
    s[i..].chars().next().unwrap_or('\u{0}')
}

fn match_secret(input: &str, i: usize) -> Option<(SecretClass, usize)> {
    let rest = &input[i..];
    // PEM block.
    if rest.starts_with("-----BEGIN ") {
        if let Some(end) = rest.find("-----END ") {
            if let Some(after) = rest[end..].find("-----") {
                let total = end + after + "-----".len();
                return Some((SecretClass::PemBlock, total));
            }
        }
    }
    // GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ + 36 chars.
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if rest.starts_with(prefix) {
            let body_len = rest[prefix.len()..].chars().take_while(|c| c.is_ascii_alphanumeric()).count();
            if body_len >= 20 {
                return Some((SecretClass::GithubToken, prefix.len() + body_len));
            }
        }
    }
    // AWS access key: AKIA + 16 alnum.
    if rest.starts_with("AKIA") {
        let body_len = rest[4..].chars().take_while(|c| c.is_ascii_alphanumeric()).count();
        if body_len >= 16 {
            return Some((SecretClass::AwsAccessKey, 4 + body_len.min(16)));
        }
    }
    // Provider "sk-..." (sk-ant-, sk-proj-, sk-...).
    if rest.starts_with("sk-") {
        let body_len = rest[3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').count();
        if body_len >= 24 {
            return Some((SecretClass::ProviderApiKey, 3 + body_len));
        }
    }
    // JWT: three dot-separated base64 segments.
    if rest.starts_with("eyJ") {
        let seg = |s: &str| -> usize {
            s.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').count()
        };
        let a = seg(rest);
        if a >= 10 && rest.as_bytes().get(a) == Some(&b'.') {
            let b = seg(&rest[a + 1..]);
            if b >= 10 && rest.as_bytes().get(a + 1 + b) == Some(&b'.') {
                let c = seg(&rest[a + 1 + b + 1..]);
                if c >= 10 {
                    return Some((SecretClass::Jwt, a + 1 + b + 1 + c));
                }
            }
        }
    }
    // Webhook URL: https://hooks.slack.com/ or https://discord.com/api/webhooks/
    for prefix in [
        "https://hooks.slack.com/services/",
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/",
    ] {
        if rest.starts_with(prefix) {
            let body_len = rest[prefix.len()..].chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/')).count();
            if body_len >= 10 {
                return Some((SecretClass::WebhookUrl, prefix.len() + body_len));
            }
        }
    }
    // Generic high-entropy: 40+ hex chars (preceded by non-alnum / start of input).
    if i == 0 || !input[..i].chars().last().is_some_and(|c| c.is_ascii_alphanumeric()) {
        let body_len = rest.chars().take_while(|c| c.is_ascii_hexdigit()).count();
        if body_len >= 40 {
            return Some((SecretClass::GenericHighEntropy, body_len));
        }
    }
    None
}

fn format_placeholder(class: SecretClass, literal: &str) -> String {
    let h = fnv1a_64(literal.as_bytes());
    let tag = match class {
        SecretClass::AwsAccessKey => "AWS-KEY",
        SecretClass::GithubToken => "GH-TOK",
        SecretClass::Jwt => "JWT",
        SecretClass::PemBlock => "PEM",
        SecretClass::ProviderApiKey => "API-KEY",
        SecretClass::WebhookUrl => "WEBHOOK",
        SecretClass::GenericHighEntropy => "HIGH-ENT",
    };
    format!("[REDACTED:{tag}:{:016x}]", h)
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl RedactionResult {
    /// Validate.
    pub fn validate(&self) -> Result<(), RedactionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RedactionError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_unchanged() {
        let r = SecretRedactor::redact("hello world");
        assert_eq!(r.redacted, "hello world");
        assert!(r.events.is_empty());
    }

    #[test]
    fn github_token_redacted() {
        let r = SecretRedactor::redact("token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(r.events.iter().any(|e| e.class == SecretClass::GithubToken));
        assert!(r.redacted.contains("[REDACTED:GH-TOK:"));
    }

    #[test]
    fn aws_key_redacted() {
        let r = SecretRedactor::redact("AKIAIOSFODNN7EXAMPLE rest");
        assert!(r.events.iter().any(|e| e.class == SecretClass::AwsAccessKey));
        assert!(r.redacted.contains("[REDACTED:AWS-KEY:"));
    }

    #[test]
    fn provider_api_key_redacted() {
        let r = SecretRedactor::redact("sk-ant-abcdefghijklmnopqrstuvwx12345");
        assert!(r.events.iter().any(|e| e.class == SecretClass::ProviderApiKey));
    }

    #[test]
    fn jwt_redacted() {
        // header.payload.signature in URL-safe base64.
        let tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturetokenABC";
        let r = SecretRedactor::redact(tok);
        assert!(r.events.iter().any(|e| e.class == SecretClass::Jwt));
    }

    #[test]
    fn pem_block_redacted() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG\n-----END PRIVATE KEY-----";
        let r = SecretRedactor::redact(pem);
        assert!(r.events.iter().any(|e| e.class == SecretClass::PemBlock));
    }

    #[test]
    fn webhook_url_redacted() {
        let url = "https://hooks.slack.com/services/AAAAAA/BBBBBB/cccccccc";
        let r = SecretRedactor::redact(url);
        assert!(r.events.iter().any(|e| e.class == SecretClass::WebhookUrl));
    }

    #[test]
    fn generic_high_entropy_redacted() {
        let blob = "abcdef0123456789abcdef0123456789abcdef0123";
        let r = SecretRedactor::redact(blob);
        assert!(r.events.iter().any(|e| e.class == SecretClass::GenericHighEntropy));
    }

    #[test]
    fn placeholder_is_stable() {
        let a = SecretRedactor::redact("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b = SecretRedactor::redact("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(a.events[0].placeholder, b.events[0].placeholder);
    }

    #[test]
    fn placeholder_differs_per_secret() {
        let a = SecretRedactor::redact("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b = SecretRedactor::redact("ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        assert_ne!(a.events[0].placeholder, b.events[0].placeholder);
    }

    #[test]
    fn multiple_secrets_in_one_string() {
        let s = "key1=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA and key2=AKIAIOSFODNN7EXAMPLE";
        let r = SecretRedactor::redact(s);
        assert_eq!(r.events.len(), 2);
        assert_eq!(r.events[0].class, SecretClass::GithubToken);
        assert_eq!(r.events[1].class, SecretClass::AwsAccessKey);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = SecretRedactor::redact("ok");
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), RedactionError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&SecretClass::AwsAccessKey).unwrap(), "\"aws-access-key\"");
        assert_eq!(serde_json::to_string(&SecretClass::ProviderApiKey).unwrap(), "\"provider-api-key\"");
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = SecretRedactor::redact("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let j = serde_json::to_string(&r).unwrap();
        let back: RedactionResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
