//! `selfdef-autonomous-gates` — MS040 autonomous-profile predeclared
//! gate envelope per F04711-F04720 + R09411-R09430.
//!
//! The Autonomous profile (MS040) only earns L5 Commit authority within
//! a predeclared gate envelope: allowed paths, allowed domains, allowed
//! tools, max-TTL, budget. Gates are MS003-signed (F04714). Any gate
//! violation halts ALL autonomous activity per F04717 — the daemon
//! drops to Private fallback and emits an OCSF Detection 2004 finding.
//!
//! The on-disk surface is TOML at `/etc/selfdef/profiles/autonomous-gates.toml`;
//! this crate exposes the typed parse + invariant-check surface only.
//! Disk I/O lives in the daemon binary.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_profile_authority_gate::{AuthorityLevel, Profile};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical disk path per F04712.
pub const GATE_CONFIG_PATH: &str = "/etc/selfdef/profiles/autonomous-gates.toml";

/// Hard upper bound on max-TTL per F04713; aligns with MS040 R09407.
pub const MAX_TTL_CEILING_SECONDS: u32 = 86_400;

/// One predeclared gate. Multiple gates can coexist in a single config;
/// the union of their allow-lists forms the effective autonomous envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gate {
    /// Operator-readable identifier.
    pub name: String,
    /// Allowed filesystem path globs (R09413 allowed-paths).
    pub allowed_paths: Vec<String>,
    /// Allowed network FQDN/CIDR entries (R09414 allowed-domains).
    pub allowed_domains: Vec<String>,
    /// Allowed tool names (cross-ref MS035 capability tokens).
    pub allowed_tools: Vec<String>,
    /// Maximum TTL any grant under this gate may carry (seconds).
    pub max_ttl_seconds: u32,
    /// Budget cap in micro-USD for gate's lifetime.
    pub budget_micro_usd: u64,
    /// MS003 signature over the canonical-JSON encoding (hex, F04714).
    pub signature: String,
}

/// Top-level config envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutonomousGatesConfig {
    /// Schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// Gates list (1+ entries).
    pub gates: Vec<Gate>,
    /// MS003 signature over the canonical-JSON encoding of the whole config.
    pub envelope_signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GateConfigError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Empty gates list refused — autonomous profile MUST have at least one gate.
    #[error("autonomous-gates config has zero gates (F04711 requires predeclared gates)")]
    NoGates,
    /// Max TTL exceeds the absolute ceiling.
    #[error("gate '{gate}' max_ttl_seconds {ttl} exceeds ceiling {ceiling}")]
    MaxTtlExceedsCeiling {
        /// Gate name.
        gate: String,
        /// Requested TTL.
        ttl: u32,
        /// Ceiling.
        ceiling: u32,
    },
    /// Allow-list is empty entirely (every dimension empty) — refused as zero-scope.
    #[error("gate '{0}' has empty allow-lists across paths/domains/tools (zero-scope)")]
    EmptyAllowLists(String),
    /// Required signature absent (F04714 — gates MUST be MS003-signed).
    #[error("gate '{0}' signature missing (F04714 requires MS003-signing)")]
    SignatureMissing(String),
    /// Envelope-level signature absent.
    #[error("envelope signature missing (R09414 MS003-signing required)")]
    EnvelopeSignatureMissing,
    /// A check requests authorisation beyond Autonomous profile's max (L5).
    #[error(
        "gate '{gate}' check requested level {level:?} > Autonomous max ({max:?}); refuse and halt"
    )]
    LevelExceedsAutonomous {
        /// Gate.
        gate: String,
        /// Requested.
        level: AuthorityLevel,
        /// Max.
        max: AuthorityLevel,
    },
}

impl AutonomousGatesConfig {
    /// Validate every invariant.
    pub fn validate(&self) -> Result<(), GateConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GateConfigError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.gates.is_empty() {
            return Err(GateConfigError::NoGates);
        }
        if self.envelope_signature.is_empty() {
            return Err(GateConfigError::EnvelopeSignatureMissing);
        }
        for g in &self.gates {
            if g.signature.is_empty() {
                return Err(GateConfigError::SignatureMissing(g.name.clone()));
            }
            if g.max_ttl_seconds > MAX_TTL_CEILING_SECONDS {
                return Err(GateConfigError::MaxTtlExceedsCeiling {
                    gate: g.name.clone(),
                    ttl: g.max_ttl_seconds,
                    ceiling: MAX_TTL_CEILING_SECONDS,
                });
            }
            if g.allowed_paths.is_empty()
                && g.allowed_domains.is_empty()
                && g.allowed_tools.is_empty()
            {
                return Err(GateConfigError::EmptyAllowLists(g.name.clone()));
            }
        }
        Ok(())
    }

    /// Check whether a given path is in the union of allow-lists across all gates.
    pub fn path_allowed(&self, path: &str) -> bool {
        self.gates.iter().any(|g| {
            g.allowed_paths
                .iter()
                .any(|allowed| matches_glob(allowed, path))
        })
    }

    /// Check whether a given domain is in the allow-list across all gates.
    pub fn domain_allowed(&self, domain: &str) -> bool {
        self.gates
            .iter()
            .any(|g| g.allowed_domains.iter().any(|allowed| allowed == domain))
    }

    /// Check whether a given tool is in the allow-list across all gates.
    pub fn tool_allowed(&self, tool: &str) -> bool {
        self.gates
            .iter()
            .any(|g| g.allowed_tools.iter().any(|allowed| allowed == tool))
    }

    /// Lowest max-TTL across all gates. Used as the effective ceiling.
    pub fn effective_max_ttl(&self) -> u32 {
        self.gates
            .iter()
            .map(|g| g.max_ttl_seconds)
            .min()
            .unwrap_or(0)
    }

    /// Sum of budgets in micro-USD.
    pub fn total_budget_micro_usd(&self) -> u128 {
        self.gates.iter().map(|g| g.budget_micro_usd as u128).sum()
    }

    /// Assert a requested authority level is allowed for Autonomous (i.e. <= L5).
    /// Per F04715-F04716 — L6 Persist still requires oracle + operator (handled
    /// elsewhere); within this crate L6 is refused outright.
    pub fn assert_level_within_autonomous(
        &self,
        gate_name: &str,
        level: AuthorityLevel,
    ) -> Result<(), GateConfigError> {
        let max = Profile::Autonomous.max_authority();
        if level > max {
            return Err(GateConfigError::LevelExceedsAutonomous {
                gate: gate_name.into(),
                level,
                max,
            });
        }
        Ok(())
    }
}

/// Trivial glob matcher — supports `**` prefix and exact match.
/// Avoids pulling a regex/glob crate for this leaf check.
fn matches_glob(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    // Suffix "**" — match any path under prefix.
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    // Suffix "*" — match siblings under same dir.
    if let Some(prefix) = pattern.strip_suffix("/*") {
        if let Some(p) = path.strip_prefix(&format!("{prefix}/")) {
            return !p.contains('/');
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_gate(name: &str) -> Gate {
        Gate {
            name: name.into(),
            allowed_paths: vec!["/workspace/**".into(), "/tmp/scratch/**".into()],
            allowed_domains: vec!["api.github.com".into(), "registry.npmjs.org".into()],
            allowed_tools: vec!["rg".into(), "cargo".into()],
            max_ttl_seconds: 3600,
            budget_micro_usd: 5_000_000,
            signature: "sig-x".into(),
        }
    }
    fn mk_config(gates: Vec<Gate>) -> AutonomousGatesConfig {
        AutonomousGatesConfig {
            schema_version: SCHEMA_VERSION.into(),
            gates,
            envelope_signature: "envelope-sig".into(),
        }
    }

    #[test]
    fn canonical_config_validates() {
        mk_config(vec![mk_gate("primary")]).validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = mk_config(vec![mk_gate("primary")]);
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            GateConfigError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn zero_gates_refused() {
        let c = mk_config(vec![]);
        assert!(matches!(
            c.validate().unwrap_err(),
            GateConfigError::NoGates
        ));
    }

    #[test]
    fn ttl_exceeds_ceiling_caught() {
        let mut g = mk_gate("over-ttl");
        g.max_ttl_seconds = 100_000;
        let c = mk_config(vec![g]);
        match c.validate().unwrap_err() {
            GateConfigError::MaxTtlExceedsCeiling { gate, ttl, ceiling } => {
                assert_eq!(gate, "over-ttl");
                assert_eq!(ttl, 100_000);
                assert_eq!(ceiling, MAX_TTL_CEILING_SECONDS);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn empty_allow_lists_refused() {
        let mut g = mk_gate("empty");
        g.allowed_paths.clear();
        g.allowed_domains.clear();
        g.allowed_tools.clear();
        let c = mk_config(vec![g]);
        assert!(matches!(
            c.validate().unwrap_err(),
            GateConfigError::EmptyAllowLists(_)
        ));
    }

    #[test]
    fn unsigned_gate_refused() {
        let mut g = mk_gate("unsigned");
        g.signature = String::new();
        let c = mk_config(vec![g]);
        assert!(matches!(
            c.validate().unwrap_err(),
            GateConfigError::SignatureMissing(_)
        ));
    }

    #[test]
    fn missing_envelope_signature_refused() {
        let mut c = mk_config(vec![mk_gate("primary")]);
        c.envelope_signature = String::new();
        assert!(matches!(
            c.validate().unwrap_err(),
            GateConfigError::EnvelopeSignatureMissing
        ));
    }

    #[test]
    fn path_allowed_globs() {
        let c = mk_config(vec![mk_gate("primary")]);
        assert!(c.path_allowed("/workspace/src/main.rs"));
        assert!(c.path_allowed("/tmp/scratch/build.log"));
        assert!(!c.path_allowed("/etc/passwd"));
        assert!(!c.path_allowed("/workspace2/foo"));
    }

    #[test]
    fn domain_allowed_exact() {
        let c = mk_config(vec![mk_gate("primary")]);
        assert!(c.domain_allowed("api.github.com"));
        assert!(c.domain_allowed("registry.npmjs.org"));
        assert!(!c.domain_allowed("evil.example.com"));
    }

    #[test]
    fn tool_allowed_exact() {
        let c = mk_config(vec![mk_gate("primary")]);
        assert!(c.tool_allowed("rg"));
        assert!(c.tool_allowed("cargo"));
        assert!(!c.tool_allowed("rm-rf"));
    }

    #[test]
    fn effective_max_ttl_min_across_gates() {
        let mut g1 = mk_gate("a");
        g1.max_ttl_seconds = 3600;
        let mut g2 = mk_gate("b");
        g2.max_ttl_seconds = 600;
        let c = mk_config(vec![g1, g2]);
        assert_eq!(c.effective_max_ttl(), 600);
    }

    #[test]
    fn total_budget_sums_across_gates() {
        let mut g1 = mk_gate("a");
        g1.budget_micro_usd = 1_000_000;
        let mut g2 = mk_gate("b");
        g2.budget_micro_usd = 4_500_000;
        let c = mk_config(vec![g1, g2]);
        assert_eq!(c.total_budget_micro_usd(), 5_500_000);
    }

    #[test]
    fn assert_level_within_autonomous_allows_l5() {
        let c = mk_config(vec![mk_gate("primary")]);
        c.assert_level_within_autonomous("primary", AuthorityLevel::L5Commit)
            .unwrap();
    }

    #[test]
    fn assert_level_within_autonomous_refuses_l6() {
        let c = mk_config(vec![mk_gate("primary")]);
        let err = c
            .assert_level_within_autonomous("primary", AuthorityLevel::L6Persist)
            .unwrap_err();
        match err {
            GateConfigError::LevelExceedsAutonomous { gate, .. } => assert_eq!(gate, "primary"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn canonical_disk_path_matches_spec() {
        assert_eq!(
            GATE_CONFIG_PATH,
            "/etc/selfdef/profiles/autonomous-gates.toml"
        );
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = mk_config(vec![mk_gate("a"), mk_gate("b")]);
        let j = serde_json::to_string(&c).unwrap();
        let back: AutonomousGatesConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn glob_matches_double_star_root() {
        assert!(matches_glob("/workspace/**", "/workspace/src/main.rs"));
        assert!(matches_glob("/workspace/**", "/workspace"));
        assert!(!matches_glob("/workspace/**", "/elsewhere"));
    }

    #[test]
    fn glob_matches_single_star_siblings() {
        assert!(matches_glob("/etc/*", "/etc/passwd"));
        assert!(!matches_glob(
            "/etc/*",
            "/etc/selfdef/profiles/autonomous-gates.toml"
        ));
    }
}
