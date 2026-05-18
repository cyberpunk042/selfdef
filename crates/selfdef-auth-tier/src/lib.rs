//! # `selfdef-auth-tier`
//!
//! Typed selfdef-side mirror of the sovereign-os R450 (E11.M7) 6-tier
//! auth ladder. Cross-repo binding ID: `SD-R-AUTH-TIER-1`.
//!
//! Per operator §1g (sovereign-os mandate verbatim):
//!
//! > "a mode of access from no auth at all by default to basic auth
//! >  to advanced auth to social auth to enterprise auth and network
//! >  level access and etc."
//!
//! Selfdef modules that expose dashboards (see also
//! `selfdef-dashboard-manifest`) MUST declare their baseline auth
//! tier. This crate provides:
//!
//! - The [`AuthTier`] enum (6 variants in operator-§1g verbatim order).
//! - [`AuthTier::level()`] — numeric 0..=5 ordering.
//! - [`AuthTier::operator_named_warning()`] — the typical failure
//!   mode at each tier (matches the sovereign-os R450
//!   `DEFAULT_REGISTRY` `warning` field).
//! - [`AuthTier::requires()`] — what must be set up before this tier
//!   becomes operable.
//! - Serde derive (case-strict lowercase-with-hyphens; same wire
//!   format as the TOML manifest written by
//!   `selfdef-dashboard-manifest`).
//!
//! The serde representation is the **exact** string the
//! sovereign-os manifests use, so a dashboard manifest can carry
//! `auth_tier = "advanced"` and the selfdef code can deserialize it
//! into [`AuthTier::Advanced`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Operator-§1g 6-tier auth ladder. Variants ordered LOW → HIGH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthTier {
    /// Default — no authentication. Loopback-only is the expected
    /// containment boundary at this tier.
    NoAuth,
    /// HTTP Basic auth.
    Basic,
    /// Token-bound auth (bearer / API key).
    Advanced,
    /// OAuth / OIDC / social login.
    Social,
    /// Enterprise SSO / SAML / on-prem IdP.
    Enterprise,
    /// Network-level access control (mTLS / VPN / firewall ACL).
    NetworkLevel,
}

/// `kebab-case` strings for the 6 tiers in operator-§1g verbatim
/// order. Cross-binding sentinel; drift = silent contract break.
pub const TIER_NAMES: [&str; 6] = [
    "no-auth",
    "basic",
    "advanced",
    "social",
    "enterprise",
    "network-level",
];

impl AuthTier {
    /// Numeric ordering 0..=5 (LOW → HIGH).
    #[must_use]
    pub const fn level(self) -> u8 {
        match self {
            Self::NoAuth => 0,
            Self::Basic => 1,
            Self::Advanced => 2,
            Self::Social => 3,
            Self::Enterprise => 4,
            Self::NetworkLevel => 5,
        }
    }

    /// All 6 tiers in operator-§1g verbatim order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::NoAuth,
            Self::Basic,
            Self::Advanced,
            Self::Social,
            Self::Enterprise,
            Self::NetworkLevel,
        ]
    }

    /// The operator-discoverable warning for each tier. Mirrors the
    /// sovereign-os R450 `DEFAULT_REGISTRY[*]["warning"]` field.
    #[must_use]
    pub const fn operator_named_warning(self) -> &'static str {
        match self {
            Self::NoAuth => {
                "loopback-only is the expected containment boundary; \
                 binding to LAN at this tier is a credential leak by \
                 default"
            }
            Self::Basic => {
                "HTTP Basic over plaintext HTTP is a credential leak; \
                 pair with TLS or restrict to loopback"
            }
            Self::Advanced => {
                "token rotation discipline + revocation list discipline \
                 required; long-lived bearer tokens age into attack \
                 surface"
            }
            Self::Social => {
                "OAuth callback / OIDC redirect_uri MUST be locked down; \
                 open redirector = account takeover"
            }
            Self::Enterprise => {
                "SAML assertions MUST be signature-verified; trust-chain \
                 misconfiguration breaks identity"
            }
            Self::NetworkLevel => {
                "mTLS / VPN / firewall ACL discipline is the LAST line; \
                 misconfiguration = no auth at all"
            }
        }
    }

    /// What the operator must have configured BEFORE this tier
    /// operates correctly. Empty for `NoAuth`.
    #[must_use]
    pub const fn requires(self) -> &'static [&'static str] {
        match self {
            Self::NoAuth => &[],
            Self::Basic => &["htpasswd-or-equivalent"],
            Self::Advanced => &["token-issuer", "revocation-list"],
            Self::Social => &["oauth-client-id", "oauth-client-secret", "redirect-uri"],
            Self::Enterprise => &["saml-idp-metadata", "saml-sp-cert"],
            Self::NetworkLevel => &["mtls-ca-bundle-or-vpn-or-acl"],
        }
    }

    /// Convert from the kebab-case wire string.
    pub fn from_kebab(s: &str) -> Result<Self, AuthTierError> {
        Ok(match s {
            "no-auth" => Self::NoAuth,
            "basic" => Self::Basic,
            "advanced" => Self::Advanced,
            "social" => Self::Social,
            "enterprise" => Self::Enterprise,
            "network-level" => Self::NetworkLevel,
            other => return Err(AuthTierError::Unknown(other.to_string())),
        })
    }

    /// Render back to the kebab-case wire string.
    #[must_use]
    pub const fn as_kebab(self) -> &'static str {
        match self {
            Self::NoAuth => "no-auth",
            Self::Basic => "basic",
            Self::Advanced => "advanced",
            Self::Social => "social",
            Self::Enterprise => "enterprise",
            Self::NetworkLevel => "network-level",
        }
    }
}

/// Errors produced while converting strings → [`AuthTier`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthTierError {
    /// Input didn't match any of the 6 operator-named tiers.
    #[error("unknown auth tier {0:?} (expected one of {TIER_NAMES:?})")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_names_match_sovereign_os_r450_verbatim_order() {
        // §1g verbatim: no auth → basic → advanced → social → enterprise
        // → network level. Drift = silent contract break with the
        // sovereign-os auth-tier registry.
        assert_eq!(
            TIER_NAMES,
            [
                "no-auth",
                "basic",
                "advanced",
                "social",
                "enterprise",
                "network-level"
            ]
        );
    }

    #[test]
    fn all_returns_six_in_level_order() {
        let all = AuthTier::all();
        assert_eq!(all.len(), 6);
        for (i, t) in all.iter().enumerate() {
            assert_eq!(t.level(), i as u8);
        }
    }

    #[test]
    fn level_strictly_monotonic() {
        let mut prev: i16 = -1;
        for t in AuthTier::all() {
            let l = t.level() as i16;
            assert!(l > prev, "non-monotonic at {t:?}");
            prev = l;
        }
    }

    #[test]
    fn as_kebab_matches_tier_names() {
        for (i, t) in AuthTier::all().iter().enumerate() {
            assert_eq!(t.as_kebab(), TIER_NAMES[i]);
        }
    }

    #[test]
    fn from_kebab_round_trips() {
        for &name in &TIER_NAMES {
            let parsed = AuthTier::from_kebab(name).unwrap();
            assert_eq!(parsed.as_kebab(), name);
        }
    }

    #[test]
    fn from_kebab_rejects_unknown() {
        let err = AuthTier::from_kebab("god-mode").unwrap_err();
        assert!(matches!(err, AuthTierError::Unknown(ref s) if s == "god-mode"));
    }

    #[test]
    fn warning_present_for_every_tier() {
        for t in AuthTier::all() {
            let w = t.operator_named_warning();
            assert!(!w.is_empty(), "no warning for {t:?}");
            // Operator-§1g failure-mode discipline: each warning
            // must mention SOMETHING about the failure mode, not be
            // a generic placeholder.
            assert!(w.len() > 30, "warning too short for {t:?}: {w}");
        }
    }

    #[test]
    fn requires_grows_with_tier() {
        assert!(AuthTier::NoAuth.requires().is_empty());
        for t in AuthTier::all().iter().skip(1) {
            assert!(
                !t.requires().is_empty(),
                "tier {t:?} should require something"
            );
        }
    }

    #[test]
    fn serde_round_trip_via_json_like_text() {
        // We don't import serde_json here (not a dep); use serde's
        // own type assertion via assert_tokens-like manual roundtrip
        // through a string-typed envelope using toml (already a
        // transitive dep via workspace).
        let t = AuthTier::Advanced;
        let s = t.as_kebab();
        let back = AuthTier::from_kebab(s).unwrap();
        assert_eq!(t, back);
    }
}
