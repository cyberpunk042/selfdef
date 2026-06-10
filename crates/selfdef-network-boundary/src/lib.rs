//! `selfdef-network-boundary` — MS038 five-profile network egress enforcement.
//!
//! Per MS038 + E0382-E0386 + dump 3594-3620:
//!
//! | profile               | bits     | scope                              |
//! |-----------------------|----------|------------------------------------|
//! | offline               | 00000000 | no egress                          |
//! | package-registries    | 00000001 | npm/PyPI/crates.io/...             |
//! | docs-only             | 00000011 | + read-only documentation hosts    |
//! | arbitrary-web         | 00000111 | + general egress                   |
//! | authenticated-browser | 00001111 | + logged-in session websites       |
//!
//! Cross-cycle bindings:
//! - F04527 — Tier A=offline / Tier B=package-registries / Tier C=docs+arbitrary / Tier D=authenticated-browser
//! - F04526 — capability_word bits 16..23 encode the 5 profile values
//! - F04528 — composes with MS039 authority-graded egress (Ring 0-4)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// The 5 canonical network profiles per E0382-E0386.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkProfile {
    /// No egress at all. Bits 0b00000000 per F04472.
    Offline,
    /// Allow package registries. Bits 0b00000001 per F04473.
    PackageRegistries,
    /// Allow documentation web. Bits 0b00000011 per F04474.
    DocsOnly,
    /// Allow arbitrary web. Bits 0b00000111 per F04475.
    ArbitraryWeb,
    /// Allow authenticated browser sessions. Bits 0b00001111 per F04476.
    AuthenticatedBrowser,
}

impl NetworkProfile {
    /// 8-bit policy mask per F04472-F04476.
    pub fn policy_bits(self) -> u8 {
        match self {
            NetworkProfile::Offline => 0b00000000,
            NetworkProfile::PackageRegistries => 0b00000001,
            NetworkProfile::DocsOnly => 0b00000011,
            NetworkProfile::ArbitraryWeb => 0b00000111,
            NetworkProfile::AuthenticatedBrowser => 0b00001111,
        }
    }

    /// Recover profile from policy bits per F04472-F04476. Returns
    /// `None` for unknown bit patterns.
    pub fn from_policy_bits(b: u8) -> Option<Self> {
        match b {
            0b00000000 => Some(NetworkProfile::Offline),
            0b00000001 => Some(NetworkProfile::PackageRegistries),
            0b00000011 => Some(NetworkProfile::DocsOnly),
            0b00000111 => Some(NetworkProfile::ArbitraryWeb),
            0b00001111 => Some(NetworkProfile::AuthenticatedBrowser),
            _ => None,
        }
    }

    /// Whether this profile allows ANY egress.
    pub fn allows_egress(self) -> bool {
        self != NetworkProfile::Offline
    }
}

/// One allowlist entry. Supports exact FQDN, suffix-match (e.g. `.npmjs.org`),
/// or CIDR (e.g. `10.0.0.0/8`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AllowEntry {
    /// Exact FQDN match.
    Fqdn {
        /// Lowercase hostname.
        host: String,
    },
    /// Suffix match, e.g. ".npmjs.org" matches "registry.npmjs.org".
    FqdnSuffix {
        /// Suffix beginning with ".".
        suffix: String,
    },
    /// IPv4 CIDR.
    Cidr {
        /// e.g. "10.0.0.0/8".
        cidr: String,
    },
}

/// A per-profile grant: profile + allowlist + TTL + signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkGrant {
    /// Schema version (must equal [`SCHEMA_VERSION`]).
    pub schema_version: String,
    /// Active network profile.
    pub profile: NetworkProfile,
    /// FQDN/CIDR allowlist for this grant.
    pub allowlist: Vec<AllowEntry>,
    /// Grant TTL in seconds.
    pub ttl_seconds: u32,
    /// ISO-8601 UTC issuance timestamp.
    pub issued_at: String,
    /// MS003 signature (hex). Empty means unsigned (rejected at apply).
    pub signature: String,
}

/// Network boundary errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// TTL exceeds the MS038 ceiling.
    #[error("ttl {0}s exceeds 86400s ceiling")]
    TtlExceedsCeiling(u32),
    /// Grant missing MS003 signature.
    #[error("network grant unsigned (MS003 signature required)")]
    GrantUnsigned,
    /// Offline profile grant cannot carry allowlist entries.
    #[error("offline profile cannot carry allowlist entries (would contradict no-egress)")]
    OfflineGrantWithAllowlist,
    /// CIDR string fails parse.
    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),
    /// FQDN-suffix entry does not begin with '.'.
    #[error("FQDN suffix must start with '.': {0}")]
    InvalidSuffix(String),
}

/// Hard TTL ceiling per F04531 cross-ref MS041 (commit lifecycle) — 24h max
/// for an unsigned-only-reapprove path.
pub const TTL_CEILING_SECONDS: u32 = 86_400;

impl NetworkGrant {
    /// Validate canonical invariants.
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(NetworkError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.signature.is_empty() {
            return Err(NetworkError::GrantUnsigned);
        }
        if self.ttl_seconds > TTL_CEILING_SECONDS {
            return Err(NetworkError::TtlExceedsCeiling(self.ttl_seconds));
        }
        if self.profile == NetworkProfile::Offline && !self.allowlist.is_empty() {
            return Err(NetworkError::OfflineGrantWithAllowlist);
        }
        for entry in &self.allowlist {
            match entry {
                AllowEntry::Fqdn { host } => {
                    if host.is_empty() || host.contains('/') {
                        return Err(NetworkError::InvalidSuffix(host.clone()));
                    }
                }
                AllowEntry::FqdnSuffix { suffix } => {
                    if !suffix.starts_with('.') || suffix.len() < 2 {
                        return Err(NetworkError::InvalidSuffix(suffix.clone()));
                    }
                }
                AllowEntry::Cidr { cidr } => {
                    validate_cidr(cidr)?;
                }
            }
        }
        Ok(())
    }

    /// Decide whether a target host is permitted under this grant.
    /// Returns true when the profile allows egress AND the host matches
    /// the allowlist (or the profile is wide enough for any host).
    pub fn permits_host(&self, host: &str) -> bool {
        if !self.profile.allows_egress() {
            return false;
        }
        // Authenticated-browser profile (most permissive): allowlist still gates
        // unless explicitly opened. Empty allowlist on permissive profile = no egress.
        if self.allowlist.is_empty() {
            return false;
        }
        let host_lower = host.to_lowercase();
        self.allowlist.iter().any(|e| match e {
            AllowEntry::Fqdn { host: h } => h.to_lowercase() == host_lower,
            AllowEntry::FqdnSuffix { suffix } => host_lower.ends_with(&suffix.to_lowercase()),
            AllowEntry::Cidr { .. } => false, // host-name path doesn't match CIDR
        })
    }

    /// Decide whether a numeric IPv4 address is permitted under this grant.
    pub fn permits_ipv4(&self, ip: [u8; 4]) -> bool {
        if !self.profile.allows_egress() {
            return false;
        }
        if self.allowlist.is_empty() {
            return false;
        }
        self.allowlist.iter().any(|e| match e {
            AllowEntry::Cidr { cidr } => ipv4_in_cidr(ip, cidr).unwrap_or(false),
            _ => false,
        })
    }
}

fn validate_cidr(c: &str) -> Result<(), NetworkError> {
    let parts: Vec<&str> = c.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(NetworkError::InvalidCidr(c.into()));
    }
    let prefix_len: u32 = parts[1]
        .parse()
        .map_err(|_| NetworkError::InvalidCidr(c.into()))?;
    if prefix_len > 32 {
        return Err(NetworkError::InvalidCidr(c.into()));
    }
    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return Err(NetworkError::InvalidCidr(c.into()));
    }
    for part in &ip_parts {
        let _: u8 = part
            .parse()
            .map_err(|_| NetworkError::InvalidCidr(c.into()))?;
    }
    Ok(())
}

fn ipv4_in_cidr(ip: [u8; 4], cidr: &str) -> Option<bool> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix_len: u32 = parts[1].parse().ok()?;
    // Defend against an unvalidated CIDR (serde bypasses validate_cidr): a
    // prefix_len > 32 makes `32 - prefix_len` underflow — a panic in debug, and
    // in release Rust masks the shift amount to 5 bits so `/40` silently
    // becomes a `/24` mask, matching a 256-address range the rule never named
    // (a fail-OPEN egress allow). Reject out-of-range prefixes here so this
    // pub-reachable matcher is fail-closed on its own, not only when the caller
    // happened to run validate() first.
    if prefix_len > 32 {
        return None;
    }
    let cidr_ip_parts: Vec<&str> = parts[0].split('.').collect();
    if cidr_ip_parts.len() != 4 {
        return None;
    }
    let mut cidr_ip = [0u8; 4];
    for (i, part) in cidr_ip_parts.iter().enumerate() {
        cidr_ip[i] = part.parse().ok()?;
    }
    let ip_u32 = u32::from_be_bytes(ip);
    let cidr_u32 = u32::from_be_bytes(cidr_ip);
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        (!0u32) << (32 - prefix_len)
    };
    Some((ip_u32 & mask) == (cidr_u32 & mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_grant(profile: NetworkProfile, allowlist: Vec<AllowEntry>) -> NetworkGrant {
        NetworkGrant {
            schema_version: SCHEMA_VERSION.into(),
            profile,
            allowlist,
            ttl_seconds: 3600,
            issued_at: "2026-05-19T03:00:00Z".into(),
            signature: "ms003-sig".into(),
        }
    }

    // --- 5-profile policy-bit mapping ---

    #[test]
    fn policy_bits_match_f04472_to_f04476() {
        assert_eq!(NetworkProfile::Offline.policy_bits(), 0b00000000);
        assert_eq!(NetworkProfile::PackageRegistries.policy_bits(), 0b00000001);
        assert_eq!(NetworkProfile::DocsOnly.policy_bits(), 0b00000011);
        assert_eq!(NetworkProfile::ArbitraryWeb.policy_bits(), 0b00000111);
        assert_eq!(
            NetworkProfile::AuthenticatedBrowser.policy_bits(),
            0b00001111
        );
    }

    #[test]
    fn from_policy_bits_roundtrip() {
        for p in [
            NetworkProfile::Offline,
            NetworkProfile::PackageRegistries,
            NetworkProfile::DocsOnly,
            NetworkProfile::ArbitraryWeb,
            NetworkProfile::AuthenticatedBrowser,
        ] {
            assert_eq!(NetworkProfile::from_policy_bits(p.policy_bits()), Some(p));
        }
    }

    #[test]
    fn from_policy_bits_unknown_returns_none() {
        assert_eq!(NetworkProfile::from_policy_bits(0b11111111), None);
        assert_eq!(NetworkProfile::from_policy_bits(0b00000010), None);
    }

    #[test]
    fn offline_allows_no_egress() {
        assert!(!NetworkProfile::Offline.allows_egress());
        for p in [
            NetworkProfile::PackageRegistries,
            NetworkProfile::DocsOnly,
            NetworkProfile::ArbitraryWeb,
            NetworkProfile::AuthenticatedBrowser,
        ] {
            assert!(p.allows_egress());
        }
    }

    // --- Grant validation ---

    #[test]
    fn unsigned_grant_rejected() {
        let mut g = ok_grant(
            NetworkProfile::PackageRegistries,
            vec![AllowEntry::Fqdn {
                host: "registry.npmjs.org".into(),
            }],
        );
        g.signature = String::new();
        assert!(matches!(
            g.validate().unwrap_err(),
            NetworkError::GrantUnsigned
        ));
    }

    #[test]
    fn ttl_over_ceiling_rejected() {
        let mut g = ok_grant(
            NetworkProfile::PackageRegistries,
            vec![AllowEntry::Fqdn {
                host: "a.b.c".into(),
            }],
        );
        g.ttl_seconds = 100_000;
        assert!(matches!(
            g.validate().unwrap_err(),
            NetworkError::TtlExceedsCeiling(100_000)
        ));
    }

    #[test]
    fn offline_with_allowlist_rejected() {
        let g = ok_grant(
            NetworkProfile::Offline,
            vec![AllowEntry::Fqdn {
                host: "x.com".into(),
            }],
        );
        assert!(matches!(
            g.validate().unwrap_err(),
            NetworkError::OfflineGrantWithAllowlist
        ));
    }

    #[test]
    fn invalid_suffix_rejected() {
        let g = ok_grant(
            NetworkProfile::PackageRegistries,
            vec![AllowEntry::FqdnSuffix {
                suffix: "no-dot".into(),
            }],
        );
        assert!(matches!(
            g.validate().unwrap_err(),
            NetworkError::InvalidSuffix(_)
        ));
    }

    #[test]
    fn invalid_cidr_rejected() {
        let g = ok_grant(
            NetworkProfile::ArbitraryWeb,
            vec![AllowEntry::Cidr {
                cidr: "not-a-cidr".into(),
            }],
        );
        assert!(matches!(
            g.validate().unwrap_err(),
            NetworkError::InvalidCidr(_)
        ));
    }

    #[test]
    fn out_of_range_cidr_prefix_does_not_permit() {
        // A grant that bypassed validate() (e.g. deserialized) carrying a CIDR
        // with prefix_len > 32 must NOT permit egress. Before the guard,
        // `32 - prefix_len` underflowed: a debug panic, and in release Rust
        // masked the shift so /40 silently became a /24 mask — a fail-OPEN
        // match against a 256-address range. permits_ipv4 must be fail-closed
        // (deny) on the unvalidated out-of-range prefix instead.
        let g = ok_grant(
            NetworkProfile::ArbitraryWeb,
            vec![AllowEntry::Cidr {
                cidr: "10.0.0.0/40".into(),
            }],
        );
        // 10.0.0.5 would be inside a (wrongly-masked) /24 of 10.0.0.0 — it must
        // still be denied because the prefix is invalid.
        assert!(
            !g.permits_ipv4([10, 0, 0, 5]),
            "out-of-range CIDR prefix must not permit egress"
        );
        // And a normal address is likewise not permitted.
        assert!(!g.permits_ipv4([203, 0, 113, 1]));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = ok_grant(
            NetworkProfile::PackageRegistries,
            vec![AllowEntry::Fqdn { host: "x.y".into() }],
        );
        g.schema_version = "9.9.9".into();
        assert!(matches!(
            g.validate().unwrap_err(),
            NetworkError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn valid_grant_passes_with_mixed_allowlist() {
        let g = ok_grant(
            NetworkProfile::AuthenticatedBrowser,
            vec![
                AllowEntry::Fqdn {
                    host: "api.github.com".into(),
                },
                AllowEntry::FqdnSuffix {
                    suffix: ".npmjs.org".into(),
                },
                AllowEntry::Cidr {
                    cidr: "10.0.0.0/8".into(),
                },
            ],
        );
        g.validate().unwrap();
    }

    // --- Host permission ---

    #[test]
    fn offline_permits_nothing() {
        let g = ok_grant(NetworkProfile::Offline, vec![]);
        assert!(!g.permits_host("anywhere.example.com"));
    }

    #[test]
    fn exact_fqdn_match_permitted() {
        let g = ok_grant(
            NetworkProfile::PackageRegistries,
            vec![AllowEntry::Fqdn {
                host: "registry.npmjs.org".into(),
            }],
        );
        assert!(g.permits_host("registry.npmjs.org"));
        assert!(g.permits_host("Registry.NPMJS.ORG")); // case-insensitive
        assert!(!g.permits_host("evil.example.com"));
    }

    #[test]
    fn suffix_fqdn_match_permitted() {
        let g = ok_grant(
            NetworkProfile::ArbitraryWeb,
            vec![AllowEntry::FqdnSuffix {
                suffix: ".npmjs.org".into(),
            }],
        );
        assert!(g.permits_host("registry.npmjs.org"));
        assert!(g.permits_host("downloads.npmjs.org"));
        assert!(!g.permits_host("evilnpmjs.org")); // suffix needs preceding dot
        assert!(!g.permits_host("evil.example.com"));
    }

    #[test]
    fn empty_allowlist_blocks_all_even_on_permissive_profile() {
        // Per "offline = no egress" doctrine extended: empty allowlist also blocks
        // even when profile is otherwise permissive. Operator must opt-in explicitly.
        let g = ok_grant(NetworkProfile::AuthenticatedBrowser, vec![]);
        assert!(!g.permits_host("anywhere.example.com"));
    }

    // --- IPv4 / CIDR permission ---

    #[test]
    fn cidr_match_permitted() {
        let g = ok_grant(
            NetworkProfile::ArbitraryWeb,
            vec![AllowEntry::Cidr {
                cidr: "10.0.0.0/8".into(),
            }],
        );
        assert!(g.permits_ipv4([10, 1, 2, 3]));
        assert!(g.permits_ipv4([10, 255, 255, 255]));
        assert!(!g.permits_ipv4([192, 168, 1, 1]));
    }

    #[test]
    fn cidr_exact_32_match() {
        let g = ok_grant(
            NetworkProfile::ArbitraryWeb,
            vec![AllowEntry::Cidr {
                cidr: "127.0.0.1/32".into(),
            }],
        );
        assert!(g.permits_ipv4([127, 0, 0, 1]));
        assert!(!g.permits_ipv4([127, 0, 0, 2]));
    }

    #[test]
    fn cidr_zero_prefix_matches_all() {
        let g = ok_grant(
            NetworkProfile::ArbitraryWeb,
            vec![AllowEntry::Cidr {
                cidr: "0.0.0.0/0".into(),
            }],
        );
        assert!(g.permits_ipv4([1, 2, 3, 4]));
        assert!(g.permits_ipv4([255, 255, 255, 255]));
    }

    #[test]
    fn offline_blocks_cidr_too() {
        let g = ok_grant(NetworkProfile::Offline, vec![]);
        assert!(!g.permits_ipv4([127, 0, 0, 1]));
    }

    // --- Serde ---

    #[test]
    fn network_profile_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&NetworkProfile::PackageRegistries).unwrap(),
            "\"package-registries\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkProfile::AuthenticatedBrowser).unwrap(),
            "\"authenticated-browser\""
        );
    }

    #[test]
    fn allow_entry_serde_tagged_kind() {
        let e = AllowEntry::Fqdn { host: "x".into() };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"kind\":\"fqdn\""));
        assert!(j.contains("\"host\":\"x\""));
        let back: AllowEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn full_grant_serde_roundtrip() {
        let g = ok_grant(
            NetworkProfile::DocsOnly,
            vec![
                AllowEntry::Fqdn {
                    host: "docs.rs".into(),
                },
                AllowEntry::FqdnSuffix {
                    suffix: ".readthedocs.io".into(),
                },
            ],
        );
        let j = serde_json::to_string(&g).unwrap();
        let back: NetworkGrant = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
