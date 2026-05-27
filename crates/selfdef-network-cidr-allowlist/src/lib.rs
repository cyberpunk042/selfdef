//! `selfdef-network-cidr-allowlist` — IPv4 CIDR allowlist.
//!
//! `add(cidr)` records an IPv4 CIDR like `"10.0.0.0/8"`. `decide(
//! ip)` returns `Allowed` if any allowlisted range contains the
//! IPv4 address; `Denied { reason }` otherwise. The format is
//! strict: exactly four dotted octets and a `/N` mask 0..=32.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One CIDR in canonical (network, prefix) form.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cidr {
    /// Network base (u32).
    pub network: u32,
    /// Prefix length.
    pub prefix_len: u8,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CidrAllowlist {
    /// Schema version.
    pub schema_version: String,
    /// Allowed CIDRs.
    pub cidrs: BTreeSet<Cidr>,
}

/// Decide verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CidrVerdict {
    /// Allowed.
    Allowed {
        /// matched cidr.
        matched: Cidr,
    },
    /// Denied.
    Denied,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CidrError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad CIDR.
    #[error("bad cidr: {0}")]
    BadCidr(String),
    /// Bad IP.
    #[error("bad ipv4: {0}")]
    BadIp(String),
}

/// Parse a dotted IPv4 → u32.
pub fn parse_ipv4(s: &str) -> Result<u32, CidrError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(CidrError::BadIp(s.into()));
    }
    let mut out: u32 = 0;
    for p in &parts {
        let n: u32 = p.parse().map_err(|_| CidrError::BadIp(s.into()))?;
        if n > 255 {
            return Err(CidrError::BadIp(s.into()));
        }
        out = (out << 8) | n;
    }
    Ok(out)
}

/// Parse `"a.b.c.d/n"` → Cidr.
pub fn parse_cidr(s: &str) -> Result<Cidr, CidrError> {
    let mut it = s.split('/');
    let ip = it.next().ok_or_else(|| CidrError::BadCidr(s.into()))?;
    let prefix = it.next().ok_or_else(|| CidrError::BadCidr(s.into()))?;
    if it.next().is_some() {
        return Err(CidrError::BadCidr(s.into()));
    }
    let p: u8 = prefix.parse().map_err(|_| CidrError::BadCidr(s.into()))?;
    if p > 32 {
        return Err(CidrError::BadCidr(s.into()));
    }
    let ip_u32 = parse_ipv4(ip)?;
    let mask = if p == 0 { 0 } else { (!0u32) << (32 - p) };
    Ok(Cidr {
        network: ip_u32 & mask,
        prefix_len: p,
    })
}

impl Cidr {
    /// Does this CIDR contain the address?
    pub fn contains(&self, ip: u32) -> bool {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            (!0u32) << (32 - self.prefix_len)
        };
        (ip & mask) == self.network
    }
}

impl CidrAllowlist {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cidrs: BTreeSet::new(),
        }
    }

    /// Add a CIDR string.
    pub fn add(&mut self, cidr: &str) -> Result<bool, CidrError> {
        Ok(self.cidrs.insert(parse_cidr(cidr)?))
    }

    /// Remove.
    pub fn remove(&mut self, cidr: &str) -> Result<bool, CidrError> {
        Ok(self.cidrs.remove(&parse_cidr(cidr)?))
    }

    /// Decide a dotted IP.
    pub fn decide_str(&self, ip: &str) -> Result<CidrVerdict, CidrError> {
        let u = parse_ipv4(ip)?;
        Ok(self.decide(u))
    }

    /// Decide a u32 IP.
    pub fn decide(&self, ip: u32) -> CidrVerdict {
        for c in &self.cidrs {
            if c.contains(ip) {
                return CidrVerdict::Allowed { matched: *c };
            }
        }
        CidrVerdict::Denied
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CidrError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CidrError::SchemaMismatch);
        }
        for c in &self.cidrs {
            if c.prefix_len > 32 {
                return Err(CidrError::BadCidr(format!("{c:?}")));
            }
        }
        Ok(())
    }
}

impl Default for CidrAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_ok() {
        assert_eq!(parse_ipv4("10.0.0.1").unwrap(), 0x0A_00_00_01);
        assert_eq!(parse_ipv4("255.255.255.255").unwrap(), 0xFFFFFFFF);
        assert_eq!(parse_ipv4("0.0.0.0").unwrap(), 0);
    }

    #[test]
    fn parse_ip_bad() {
        assert!(parse_ipv4("256.0.0.0").is_err());
        assert!(parse_ipv4("1.2.3").is_err());
        assert!(parse_ipv4("a.b.c.d").is_err());
    }

    #[test]
    fn parse_cidr_canonicalizes() {
        let c = parse_cidr("10.0.0.5/8").unwrap();
        assert_eq!(c.network, 0x0A_00_00_00);
        assert_eq!(c.prefix_len, 8);
    }

    #[test]
    fn contains_in_range() {
        let c = parse_cidr("10.0.0.0/8").unwrap();
        assert!(c.contains(parse_ipv4("10.5.6.7").unwrap()));
        assert!(!c.contains(parse_ipv4("11.0.0.0").unwrap()));
    }

    #[test]
    fn slash_zero_matches_all() {
        let c = parse_cidr("0.0.0.0/0").unwrap();
        assert!(c.contains(0));
        assert!(c.contains(0xFFFFFFFF));
    }

    #[test]
    fn allowlist_decide() {
        let mut a = CidrAllowlist::new();
        a.add("10.0.0.0/8").unwrap();
        a.add("192.168.0.0/16").unwrap();
        assert!(matches!(
            a.decide_str("10.5.6.7").unwrap(),
            CidrVerdict::Allowed { .. }
        ));
        assert!(matches!(
            a.decide_str("192.168.1.1").unwrap(),
            CidrVerdict::Allowed { .. }
        ));
        assert_eq!(a.decide_str("8.8.8.8").unwrap(), CidrVerdict::Denied);
    }

    #[test]
    fn add_remove() {
        let mut a = CidrAllowlist::new();
        assert!(a.add("10.0.0.0/8").unwrap());
        assert!(!a.add("10.0.0.0/8").unwrap()); // duplicate
        assert!(a.remove("10.0.0.0/8").unwrap());
        assert!(!a.remove("10.0.0.0/8").unwrap());
    }

    #[test]
    fn bad_cidr_rejected() {
        let mut a = CidrAllowlist::new();
        assert!(matches!(
            a.add("10.0.0.0/33").unwrap_err(),
            CidrError::BadCidr(_)
        ));
        assert!(matches!(
            a.add("10.0.0.0").unwrap_err(),
            CidrError::BadCidr(_)
        ));
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let a = CidrAllowlist::new();
        assert_eq!(a.decide_str("10.0.0.1").unwrap(), CidrVerdict::Denied);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = CidrAllowlist::new();
        a.schema_version = "9.9.9".into();
        assert!(matches!(
            a.validate().unwrap_err(),
            CidrError::SchemaMismatch
        ));
    }

    #[test]
    fn cidr_serde_roundtrip() {
        let mut a = CidrAllowlist::new();
        a.add("10.0.0.0/8").unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: CidrAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
