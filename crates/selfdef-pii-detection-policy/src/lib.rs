//! `selfdef-pii-detection-policy` — PII pattern classifier.
//!
//! Detects 5 classes: Email, Phone (E.164 or US 10-digit),
//! SSN (US 3-2-4), CreditCard (16-digit Luhn-valid), and IPv4.
//! Output is a list of PiiHit{class, offset, len} for downstream
//! redaction/quarantine. Deterministic, no LLM.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// PII class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PiiClass {
    /// Email address.
    Email,
    /// Phone number (E.164 or US 10-digit).
    Phone,
    /// US Social-Security Number.
    SsnUs,
    /// Credit card (16-digit Luhn-valid).
    CreditCard,
    /// IPv4 address.
    IpV4,
}

/// One hit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PiiHit {
    /// Class.
    pub class: PiiClass,
    /// Byte offset start.
    pub offset: usize,
    /// Byte length.
    pub len: usize,
}

/// Detection result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PiiResult {
    /// Schema version.
    pub schema_version: String,
    /// Hits, ascending offset.
    pub hits: Vec<PiiHit>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PiiError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Detector (stateless).
#[derive(Debug, Clone, Default)]
pub struct PiiDetector;

impl PiiDetector {
    /// Scan.
    pub fn scan(input: &str) -> PiiResult {
        let bytes = input.as_bytes();
        let mut hits: Vec<PiiHit> = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if let Some((class, len)) = match_at(input, i) {
                hits.push(PiiHit {
                    class,
                    offset: i,
                    len,
                });
                i += len;
            } else {
                let c = input[i..].chars().next().unwrap_or('\0');
                i += c.len_utf8();
            }
        }
        PiiResult {
            schema_version: SCHEMA_VERSION.into(),
            hits,
        }
    }
}

fn match_at(s: &str, i: usize) -> Option<(PiiClass, usize)> {
    let rest = &s[i..];
    // Email: simple local@domain.tld
    if let Some(len) = match_email(rest) {
        return Some((PiiClass::Email, len));
    }
    // E.164 or US 10-digit (avoid mid-word matches).
    if i == 0 || !is_word_char(s.as_bytes()[i - 1]) {
        if let Some(len) = match_phone(rest) {
            return Some((PiiClass::Phone, len));
        }
        if let Some(len) = match_ssn(rest) {
            return Some((PiiClass::SsnUs, len));
        }
        if let Some(len) = match_ipv4(rest) {
            return Some((PiiClass::IpV4, len));
        }
        if let Some(len) = match_credit_card(rest) {
            return Some((PiiClass::CreditCard, len));
        }
    }
    None
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn match_email(rest: &str) -> Option<usize> {
    let b = rest.as_bytes();
    // local: 1+ chars [A-Za-z0-9._+-]
    let mut i = 0;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'.' | b'_' | b'+' | b'-'))
    {
        i += 1;
    }
    if i == 0 || i >= b.len() || b[i] != b'@' {
        return None;
    }
    let local_end = i;
    i += 1;
    let domain_start = i;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'.' | b'-')) {
        i += 1;
    }
    if i == domain_start {
        return None;
    }
    // Must contain a dot in domain.
    if !rest[domain_start..i].contains('.') {
        return None;
    }
    // Strip trailing dot.
    let mut end = i;
    while end > domain_start && b[end - 1] == b'.' {
        end -= 1;
    }
    if end <= domain_start {
        return None;
    }
    let _ = local_end;
    Some(end)
}

fn match_phone(rest: &str) -> Option<usize> {
    let b = rest.as_bytes();
    // E.164: +<8..15 digits>
    if b.first() == Some(&b'+') {
        let mut digits = 0;
        let mut i = 1;
        while i < b.len() && b[i].is_ascii_digit() {
            digits += 1;
            i += 1;
        }
        if (8..=15).contains(&digits) {
            return Some(i);
        }
    }
    // US 10-digit: NNN-NNN-NNNN or NNN.NNN.NNNN or (NNN) NNN-NNNN.
    if b.len() >= 12 {
        // NNN-NNN-NNNN
        let pat = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
        let sep = |i: usize| matches!(b.get(i), Some(&b'-') | Some(&b'.') | Some(&b' '));
        if pat(0)
            && pat(1)
            && pat(2)
            && sep(3)
            && pat(4)
            && pat(5)
            && pat(6)
            && sep(7)
            && pat(8)
            && pat(9)
            && pat(10)
            && pat(11)
        {
            return Some(12);
        }
    }
    None
}

fn match_ssn(rest: &str) -> Option<usize> {
    let b = rest.as_bytes();
    if b.len() >= 11 {
        let pat = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
        let dash = |i: usize| b.get(i) == Some(&b'-');
        if pat(0)
            && pat(1)
            && pat(2)
            && dash(3)
            && pat(4)
            && pat(5)
            && dash(6)
            && pat(7)
            && pat(8)
            && pat(9)
            && pat(10)
        {
            // Boundary check: not followed by digit/word.
            if b.get(11).is_some_and(|c| c.is_ascii_alphanumeric()) {
                return None;
            }
            return Some(11);
        }
    }
    None
}

fn match_ipv4(rest: &str) -> Option<usize> {
    let b = rest.as_bytes();
    let mut i = 0;
    let mut octets = 0;
    while octets < 4 {
        let start = i;
        let mut digits = 0;
        while i < b.len() && b[i].is_ascii_digit() && digits < 3 {
            digits += 1;
            i += 1;
        }
        if digits == 0 {
            return None;
        }
        let n: u32 = rest[start..i].parse().ok()?;
        if n > 255 {
            return None;
        }
        octets += 1;
        if octets < 4 {
            if i >= b.len() || b[i] != b'.' {
                return None;
            }
            i += 1;
        }
    }
    // Don't match if followed by another digit or dot (e.g., partial of bigger).
    if b.get(i).is_some_and(|c| c.is_ascii_digit() || *c == b'.') {
        return None;
    }
    Some(i)
}

fn match_credit_card(rest: &str) -> Option<usize> {
    let b = rest.as_bytes();
    // 16 digits, optionally with spaces/dashes between groups of 4.
    let mut digits: Vec<u8> = Vec::with_capacity(16);
    let mut i = 0;
    while i < b.len() && digits.len() < 16 {
        let c = b[i];
        if c.is_ascii_digit() {
            digits.push(c - b'0');
            i += 1;
        } else if matches!(c, b' ' | b'-') && !digits.is_empty() && !digits.is_empty() {
            i += 1;
        } else {
            break;
        }
    }
    if digits.len() != 16 {
        return None;
    }
    // Boundary check.
    if b.get(i).is_some_and(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if luhn_ok(&digits) { Some(i) } else { None }
}

fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (idx, d) in digits.iter().rev().enumerate() {
        let mut v = *d as u32;
        if idx % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

impl PiiResult {
    /// Validate.
    pub fn validate(&self) -> Result<(), PiiError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PiiError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_no_hits() {
        let r = PiiDetector::scan("nothing to see here");
        assert!(r.hits.is_empty());
    }

    #[test]
    fn email_detected() {
        let r = PiiDetector::scan("ping me at user@example.com please");
        assert!(r.hits.iter().any(|h| h.class == PiiClass::Email));
    }

    #[test]
    fn e164_phone_detected() {
        let r = PiiDetector::scan("call +14155551234 anytime");
        assert!(r.hits.iter().any(|h| h.class == PiiClass::Phone));
    }

    #[test]
    fn us_phone_detected() {
        let r = PiiDetector::scan("415-555-1234");
        assert!(r.hits.iter().any(|h| h.class == PiiClass::Phone));
    }

    #[test]
    fn ssn_detected() {
        let r = PiiDetector::scan("SSN 123-45-6789 follows");
        assert!(r.hits.iter().any(|h| h.class == PiiClass::SsnUs));
    }

    #[test]
    fn ipv4_detected() {
        let r = PiiDetector::scan("server at 192.168.1.42 reachable");
        assert!(r.hits.iter().any(|h| h.class == PiiClass::IpV4));
    }

    #[test]
    fn ipv4_out_of_range_not_matched() {
        let r = PiiDetector::scan("bad 999.999.999.999 nope");
        assert!(!r.hits.iter().any(|h| h.class == PiiClass::IpV4));
    }

    #[test]
    fn credit_card_luhn_valid_detected() {
        // Standard Visa test number 4111 1111 1111 1111 is Luhn-valid.
        let r = PiiDetector::scan("card 4111111111111111 expires");
        assert!(r.hits.iter().any(|h| h.class == PiiClass::CreditCard));
    }

    #[test]
    fn credit_card_luhn_invalid_not_matched() {
        let r = PiiDetector::scan("not 4111111111111112 valid");
        assert!(!r.hits.iter().any(|h| h.class == PiiClass::CreditCard));
    }

    #[test]
    fn multiple_classes_in_one_string() {
        let r = PiiDetector::scan("email user@x.com IP 10.0.0.1 phone +14155551234");
        let classes: Vec<_> = r.hits.iter().map(|h| h.class).collect();
        assert!(classes.contains(&PiiClass::Email));
        assert!(classes.contains(&PiiClass::IpV4));
        assert!(classes.contains(&PiiClass::Phone));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = PiiDetector::scan("ok");
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            PiiError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&PiiClass::SsnUs).unwrap(),
            "\"ssn-us\""
        );
        assert_eq!(
            serde_json::to_string(&PiiClass::CreditCard).unwrap(),
            "\"credit-card\""
        );
        assert_eq!(serde_json::to_string(&PiiClass::IpV4).unwrap(), "\"ip-v4\"");
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = PiiDetector::scan("user@example.com");
        let j = serde_json::to_string(&r).unwrap();
        let back: PiiResult = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
