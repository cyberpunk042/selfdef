//! `selfdef-secret-detection` — heuristic outbound-payload secret scanner.
//!
//! 4 detector classes:
//! - `AwsAccessKey`: matches `AKIA` + 16 base32 chars.
//! - `GitHubToken`:  matches `ghp_` / `gho_` / `ghs_` + 36 base62 chars.
//! - `GenericApiKey`: matches `(apikey|api_key|token)=` followed by 20+
//!   non-space chars.
//! - `GcpServiceAccount`: detects substring `"type": "service_account"`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 4 detector classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorClass {
    /// AWS Access Key id.
    AwsAccessKey,
    /// GitHub personal/oauth/server token.
    GitHubToken,
    /// Generic `apikey=` / `api_key=` / `token=` style.
    GenericApiKey,
    /// GCP service-account JSON key.
    GcpServiceAccount,
}

/// One detection hit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hit {
    /// Class.
    pub class: DetectorClass,
    /// Byte offset into input.
    pub offset: usize,
    /// Matched length.
    pub length: usize,
    /// 0..=100 confidence.
    pub score: u8,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DetectionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Scan input string for all 4 detector classes.
pub fn scan(input: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    hits.extend(scan_aws(input));
    hits.extend(scan_github(input));
    hits.extend(scan_generic(input));
    hits.extend(scan_gcp(input));
    hits
}

fn scan_aws(input: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 20 <= bytes.len() {
        if &bytes[i..i + 4] == b"AKIA" {
            let tail = &bytes[i + 4..i + 20];
            let ok = tail
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if ok {
                hits.push(Hit {
                    class: DetectorClass::AwsAccessKey,
                    offset: i,
                    length: 20,
                    score: 95,
                });
                i += 20;
                continue;
            }
        }
        i += 1;
    }
    hits
}

fn scan_github(input: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 40 <= bytes.len() {
        let prefix = &bytes[i..i + 4];
        if matches!(prefix, b"ghp_" | b"gho_" | b"ghs_" | b"ghr_") {
            let tail = &bytes[i + 4..i + 40];
            let ok = tail.iter().all(|b| b.is_ascii_alphanumeric());
            if ok {
                hits.push(Hit {
                    class: DetectorClass::GitHubToken,
                    offset: i,
                    length: 40,
                    score: 95,
                });
                i += 40;
                continue;
            }
        }
        i += 1;
    }
    hits
}

fn scan_generic(input: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let lower = input.to_ascii_lowercase();
    let lbytes = lower.as_bytes();
    for needle in [
        b"apikey=".as_slice(),
        b"api_key=".as_slice(),
        b"token=".as_slice(),
    ] {
        let mut start = 0;
        while let Some(pos) = find_substring(&lbytes[start..], needle) {
            let off = start + pos;
            let after = off + needle.len();
            let mut end = after;
            while end < lbytes.len()
                && !lbytes[end].is_ascii_whitespace()
                && lbytes[end] != b'&'
                && lbytes[end] != b'"'
            {
                end += 1;
            }
            let val_len = end - after;
            if val_len >= 20 {
                hits.push(Hit {
                    class: DetectorClass::GenericApiKey,
                    offset: off,
                    length: end - off,
                    score: 70,
                });
            }
            start = end;
        }
    }
    hits
}

fn scan_gcp(input: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let needle = "\"type\": \"service_account\"";
    if let Some(pos) = input.find(needle) {
        hits.push(Hit {
            class: DetectorClass::GcpServiceAccount,
            offset: pos,
            length: needle.len(),
            score: 90,
        });
    }
    hits
}

fn find_substring(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// True if any hit exceeds the score threshold.
pub fn blocks_egress(input: &str, threshold: u8) -> bool {
    scan(input).iter().any(|h| h.score >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_access_key_detected() {
        let hits = scan("aws=AKIAIOSFODNN7EXAMPLE here");
        assert!(
            hits.iter()
                .any(|h| h.class == DetectorClass::AwsAccessKey && h.score >= 90)
        );
    }

    #[test]
    fn aws_false_positive_avoided_short() {
        let hits = scan("AKIA short");
        assert!(hits.iter().all(|h| h.class != DetectorClass::AwsAccessKey));
    }

    #[test]
    fn github_token_detected() {
        let hits = scan("export GH=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH1234");
        assert!(hits.iter().any(|h| h.class == DetectorClass::GitHubToken));
    }

    #[test]
    fn generic_api_key_detected() {
        let hits = scan("curl -H 'apikey=abc123XYZ987DEFLONGTOKEN' https://example.org");
        assert!(hits.iter().any(|h| h.class == DetectorClass::GenericApiKey));
    }

    #[test]
    fn generic_api_key_short_value_ignored() {
        let hits = scan("apikey=short");
        assert!(hits.iter().all(|h| h.class != DetectorClass::GenericApiKey));
    }

    #[test]
    fn gcp_service_account_detected() {
        let json = r#"{"type": "service_account", "project_id": "x"}"#;
        let hits = scan(json);
        assert!(
            hits.iter()
                .any(|h| h.class == DetectorClass::GcpServiceAccount)
        );
    }

    #[test]
    fn no_match_returns_empty() {
        let hits = scan("plain text with nothing sensitive");
        assert!(hits.is_empty());
    }

    #[test]
    fn blocks_egress_at_threshold() {
        assert!(blocks_egress("AKIAIOSFODNN7EXAMPLE", 80));
        assert!(!blocks_egress("plain text", 50));
    }

    #[test]
    fn token_var_variants() {
        for variant in [
            "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "token=ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ] {
            let hits = scan(variant);
            assert!(
                hits.iter().any(|h| h.class == DetectorClass::GenericApiKey),
                "variant didn't match: {variant}"
            );
        }
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&DetectorClass::AwsAccessKey).unwrap(),
            "\"aws-access-key\""
        );
        assert_eq!(
            serde_json::to_string(&DetectorClass::GitHubToken).unwrap(),
            "\"git-hub-token\""
        );
        assert_eq!(
            serde_json::to_string(&DetectorClass::GenericApiKey).unwrap(),
            "\"generic-api-key\""
        );
        assert_eq!(
            serde_json::to_string(&DetectorClass::GcpServiceAccount).unwrap(),
            "\"gcp-service-account\""
        );
    }

    #[test]
    fn hit_serde_roundtrip() {
        let h = Hit {
            class: DetectorClass::AwsAccessKey,
            offset: 5,
            length: 20,
            score: 95,
        };
        let j = serde_json::to_string(&h).unwrap();
        let back: Hit = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
