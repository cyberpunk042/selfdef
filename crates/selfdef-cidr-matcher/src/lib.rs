//! `selfdef-cidr-matcher` — IPv4 CIDR matcher.
//!
//! parse_cidr("10.0.0.0/8") → (network u32, prefix u8). parse_ip
//! → u32. contains(network, prefix, ip) returns true iff
//! (ip ^ network) has 0 in the top `prefix` bits. Prefix == 0
//! matches everything; prefix == 32 matches exact IP.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State (versioned wrapper for one CIDR).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CidrMatcher {
    /// Schema version.
    pub schema_version: String,
    /// Network address (u32 big-endian).
    pub network: u32,
    /// Prefix length 0..=32.
    pub prefix: u8,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CidrError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad CIDR.
    #[error("invalid CIDR: {0}")]
    BadCidr(String),
    /// Bad IP.
    #[error("invalid IPv4: {0}")]
    BadIp(String),
    /// Bad prefix.
    #[error("prefix must be 0..=32")]
    BadPrefix,
}

/// Parse an IPv4 dotted-quad (e.g., "192.168.1.5").
pub fn parse_ip(s: &str) -> Result<u32, CidrError> {
    let mut parts: [u32; 4] = [0; 4];
    let mut count = 0usize;
    for (i, p) in s.split('.').enumerate() {
        if i >= 4 { return Err(CidrError::BadIp(s.into())); }
        let v: u32 = p.parse().map_err(|_| CidrError::BadIp(s.into()))?;
        if v > 255 { return Err(CidrError::BadIp(s.into())); }
        parts[i] = v;
        count += 1;
    }
    if count != 4 { return Err(CidrError::BadIp(s.into())); }
    Ok((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
}

/// Parse "A.B.C.D/p". Network is masked by the prefix (host bits zeroed).
pub fn parse_cidr(s: &str) -> Result<(u32, u8), CidrError> {
    let (ip_s, prefix_s) = s.split_once('/').ok_or_else(|| CidrError::BadCidr(s.into()))?;
    let ip = parse_ip(ip_s)?;
    let prefix: u8 = prefix_s.parse().map_err(|_| CidrError::BadCidr(s.into()))?;
    if prefix > 32 { return Err(CidrError::BadPrefix); }
    let mask = if prefix == 0 { 0u32 } else { (!0u32) << (32 - prefix) };
    let network = ip & mask;
    Ok((network, prefix))
}

/// True iff ip is within (network, prefix).
pub fn contains(network: u32, prefix: u8, ip: u32) -> Result<bool, CidrError> {
    if prefix > 32 { return Err(CidrError::BadPrefix); }
    let mask = if prefix == 0 { 0u32 } else { (!0u32) << (32 - prefix) };
    Ok((ip & mask) == (network & mask))
}

impl CidrMatcher {
    /// New from CIDR string.
    pub fn parse(cidr: &str) -> Result<Self, CidrError> {
        let (network, prefix) = parse_cidr(cidr)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            network,
            prefix,
        })
    }

    /// True iff ip is inside this CIDR.
    pub fn matches(&self, ip: u32) -> bool {
        contains(self.network, self.prefix, ip).unwrap_or(false)
    }

    /// True iff dotted-quad str is inside this CIDR.
    pub fn matches_str(&self, ip_s: &str) -> Result<bool, CidrError> {
        let ip = parse_ip(ip_s)?;
        Ok(self.matches(ip))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CidrError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CidrError::SchemaMismatch); }
        if self.prefix > 32 { return Err(CidrError::BadPrefix); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_ip() {
        assert_eq!(parse_ip("10.0.0.1").unwrap(), (10 << 24) | 1);
        assert_eq!(parse_ip("255.255.255.255").unwrap(), u32::MAX);
        assert_eq!(parse_ip("0.0.0.0").unwrap(), 0);
    }

    #[test]
    fn bad_ip_rejected() {
        assert!(matches!(parse_ip("256.0.0.1").unwrap_err(), CidrError::BadIp(_)));
        assert!(matches!(parse_ip("1.2.3").unwrap_err(), CidrError::BadIp(_)));
        assert!(matches!(parse_ip("a.b.c.d").unwrap_err(), CidrError::BadIp(_)));
    }

    #[test]
    fn parse_basic_cidr() {
        let (net, p) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(p, 8);
        assert_eq!(net, 10u32 << 24);
    }

    #[test]
    fn cidr_masks_host_bits() {
        let (net, _) = parse_cidr("10.1.2.3/8").unwrap();
        // Host bits should be zeroed.
        assert_eq!(net, 10u32 << 24);
    }

    #[test]
    fn contains_basic() {
        let m = CidrMatcher::parse("10.0.0.0/8").unwrap();
        assert!(m.matches(parse_ip("10.1.2.3").unwrap()));
        assert!(!m.matches(parse_ip("11.0.0.1").unwrap()));
    }

    #[test]
    fn prefix_0_matches_all() {
        let m = CidrMatcher::parse("0.0.0.0/0").unwrap();
        assert!(m.matches(parse_ip("192.168.1.1").unwrap()));
        assert!(m.matches(parse_ip("8.8.8.8").unwrap()));
    }

    #[test]
    fn prefix_32_matches_exact() {
        let m = CidrMatcher::parse("192.168.1.5/32").unwrap();
        assert!(m.matches(parse_ip("192.168.1.5").unwrap()));
        assert!(!m.matches(parse_ip("192.168.1.6").unwrap()));
    }

    #[test]
    fn bad_prefix_rejected() {
        assert!(matches!(parse_cidr("10.0.0.0/33").unwrap_err(), CidrError::BadPrefix));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = CidrMatcher::parse("10.0.0.0/8").unwrap();
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), CidrError::SchemaMismatch));
    }

    #[test]
    fn matcher_serde_roundtrip() {
        let m = CidrMatcher::parse("172.16.0.0/12").unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let back: CidrMatcher = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
