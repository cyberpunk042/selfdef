//! `selfdef-profile-authority-gate` — MS040 six-profile authority matrix.
//!
//! Per MS040 + dump 17468-17500 + R09361-R09600, the IPS daemon enforces
//! six profile-specific authority envelopes:
//!
//! | profile      | max L | trust-ring cap | sandbox req | gate                    |
//! |--------------|-------|----------------|-------------|-------------------------|
//! | private      | L1    | Ring 2         | A           | operator approval       |
//! | fast         | L4    | Ring 2         | A           | TTL ≤ 60s default       |
//! | careful      | L5    | Ring 2         | A or B      | oracle + tests + sim    |
//! | autonomous   | L5    | Ring 2         | A/B + gates | predeclared gate envelope|
//! | experimental | L4    | Ring 3         | C or D      | sandbox tier C/D        |
//! | production   | L6    | Ring 2         | A           | triple/quadruple gate   |
//!
//! Doctrinal preservation — verbatim per R09362, dump 17501:
//!
//! > "Authority follows evidence"
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version of the gate decisions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Operator doctrine surface preserved verbatim per R09362 dump 17501.
pub const DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE: &str = "Authority follows evidence";

/// The six MS040 profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private — local observe/suggest only unless explicitly approved.
    Private,
    /// Fast — bounded L4 Execute for safe tools (Tier A).
    Fast,
    /// Careful — oracle + test gates before L5 Commit.
    Careful,
    /// Autonomous — execute bounded tasks within predeclared gate envelope.
    Autonomous,
    /// Experimental — high exploration in Tier C/D sandbox, zero host commit.
    Experimental,
    /// Production — strict commit gates, strong trace, rollback required.
    Production,
}

/// Authority level per MS039 R09413 L0..L6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLevel {
    /// L0 Observe — read state, no side effects.
    L0Observe,
    /// L1 Suggest — produce candidate.
    L1Suggest,
    /// L2 Simulate — dry-run with side-effect equivalence.
    L2Simulate,
    /// L3 Prepare — stage durable change.
    L3Prepare,
    /// L4 Execute — apply ephemeral side effect.
    L4Execute,
    /// L5 Commit — apply durable change.
    L5Commit,
    /// L6 Persist — change survives reboot + replication.
    L6Persist,
}

/// MS039 R09430 Ring 0..4 trust topology cap per profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRing {
    /// Ring 0 — daemon.
    Ring0,
    /// Ring 1 — Guardian + audit.
    Ring1,
    /// Ring 2 — operator-signed CLI.
    Ring2,
    /// Ring 3 — sandboxed agent.
    Ring3,
    /// Ring 4 — untrusted.
    Ring4,
}

/// MS036 sandbox tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxTier {
    /// Tier A.
    TierA,
    /// Tier B.
    TierB,
    /// Tier C.
    TierC,
    /// Tier D.
    TierD,
}

/// Evidence items per the "Authority follows evidence" check ladder
/// (R09362 + check ladder: valid schema / safe policy / successful sandbox
/// / tests pass / oracle agrees / user approves).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    /// Schema validation passed.
    pub valid_schema: bool,
    /// Policy bus marked the request safe.
    pub safe_policy: bool,
    /// Sandbox simulation passed.
    pub successful_sandbox: bool,
    /// MS009 audit cycle / test gate passed.
    pub tests_pass: bool,
    /// Oracle (Blackwell) gate agreed.
    pub oracle_agrees: bool,
    /// Operator MS003-signed approval present.
    pub user_approves: bool,
    /// Optional snapshot present (R09401 + R09736).
    pub snapshot_present: bool,
    /// Evidence digest (sha256 hex) — non-empty for Careful per R09402.
    pub evidence_digest: String,
}

/// A request to be authorised: target authority + trust + tier + evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityRequest {
    /// Requested authority level.
    pub target_authority: AuthorityLevel,
    /// Trust ring the request lands in.
    pub trust_ring: TrustRing,
    /// Sandbox tier the request would run in.
    pub sandbox_tier: SandboxTier,
    /// Evidence collected so far.
    pub evidence: Evidence,
    /// TTL the requested grant should carry (seconds).
    pub ttl_seconds: u32,
}

/// Decision returned by the gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityDecision {
    /// True if the request was approved.
    pub allowed: bool,
    /// Profile that decided.
    pub profile: Profile,
    /// Reason text (single line; operator-readable).
    pub reason: String,
    /// Recorded "required evidence not met" list (empty when allowed).
    pub missing_evidence: Vec<String>,
}

/// Errors raised when a gate request is malformed.
#[derive(Debug, Error)]
pub enum GateError {
    /// Provided TTL exceeds the profile's per-grant ceiling.
    #[error("ttl {ttl_seconds}s exceeds {profile:?} profile ceiling {ceiling_seconds}s")]
    TtlExceedsCeiling {
        /// Profile.
        profile: Profile,
        /// Requested ttl.
        ttl_seconds: u32,
        /// Profile ceiling.
        ceiling_seconds: u32,
    },
    /// Doctrine constant was tampered with at compile time / wire load.
    #[error("doctrine surface tampered: expected verbatim {expected:?}")]
    DoctrineTampered {
        /// Expected canonical doctrine.
        expected: String,
    },
}

impl Profile {
    /// Profile's maximum authority level per MS040 envelope.
    pub fn max_authority(self) -> AuthorityLevel {
        match self {
            Profile::Private => AuthorityLevel::L1Suggest, // R09366
            Profile::Fast => AuthorityLevel::L4Execute,    // R09380 (dump 17473)
            Profile::Careful => AuthorityLevel::L6Persist, // R09401 L6 allowed with double-gate
            Profile::Autonomous => AuthorityLevel::L5Commit, // R09411 + R09415
            Profile::Experimental => AuthorityLevel::L4Execute, // F04722 zero host commit
            Profile::Production => AuthorityLevel::L6Persist, // F04736 quadruple-gate L6
        }
    }

    /// Maximum trust ring this profile allows tokens to carry.
    pub fn max_trust_ring(self) -> TrustRing {
        match self {
            Profile::Private => TrustRing::Ring2, // F04687 never >= 3
            Profile::Fast => TrustRing::Ring2,    // F04696 up to 2
            Profile::Careful => TrustRing::Ring2,
            Profile::Autonomous => TrustRing::Ring2,
            Profile::Experimental => TrustRing::Ring3, // F04726 Ring 3 default
            Profile::Production => TrustRing::Ring2,   // F04737 never >= 4
        }
    }

    /// Per-grant TTL ceiling without re-approval (seconds).
    pub fn ttl_ceiling_seconds(self) -> u32 {
        match self {
            Profile::Private => 60,
            Profile::Fast => 3600,      // R09390 max 3600s
            Profile::Careful => 86_400, // R09407 default 24h gate timeout
            Profile::Autonomous => 86_400,
            Profile::Experimental => 1800,
            Profile::Production => 600, // R09449 / F04734 max 600s
        }
    }

    /// Whether this profile requires sandbox simulation as evidence.
    pub fn requires_sandbox(self) -> bool {
        matches!(
            self,
            Profile::Careful | Profile::Autonomous | Profile::Experimental
        )
    }

    /// Whether this profile requires the oracle gate for L5 Commit.
    pub fn requires_oracle(self) -> bool {
        matches!(
            self,
            Profile::Careful | Profile::Autonomous | Profile::Production
        )
    }

    /// Whether this profile requires snapshot for L5/L6 (R09401 + R09736).
    pub fn requires_snapshot_for_persist(self) -> bool {
        matches!(
            self,
            Profile::Careful | Profile::Autonomous | Profile::Production
        )
    }
}

/// Decide whether a request is authorised under the active profile.
pub fn decide(profile: Profile, req: &AuthorityRequest) -> AuthorityDecision {
    let mut missing: Vec<String> = Vec::new();
    let max = profile.max_authority();

    // R09361 — different profiles allow different maximum authority levels.
    if req.target_authority > max {
        return AuthorityDecision {
            allowed: false,
            profile,
            reason: format!(
                "target authority exceeds {profile:?} ceiling ({:?} > {max:?})",
                req.target_authority
            ),
            missing_evidence: vec!["operator_promotion".into()],
        };
    }
    // Trust-ring cap per profile.
    if req.trust_ring > profile.max_trust_ring() {
        return AuthorityDecision {
            allowed: false,
            profile,
            reason: format!(
                "trust ring exceeds {profile:?} cap ({:?} > {:?})",
                req.trust_ring,
                profile.max_trust_ring()
            ),
            missing_evidence: vec!["trust_ring_demotion".into()],
        };
    }

    // Universal evidence: valid schema + safe policy.
    if !req.evidence.valid_schema {
        missing.push("valid_schema".into());
    }
    if !req.evidence.safe_policy {
        missing.push("safe_policy".into());
    }

    match profile {
        Profile::Private => {
            // R09369..R09371: anything above L1 requires explicit user_approves.
            if req.target_authority > AuthorityLevel::L1Suggest && !req.evidence.user_approves {
                missing.push("user_approves".into());
            }
        }
        Profile::Fast => {
            // Fast allows L4 on Tier A safe tools; require sandbox sim for L4.
            if req.target_authority == AuthorityLevel::L4Execute
                && req.sandbox_tier != SandboxTier::TierA
            {
                missing.push("sandbox_tier_a_for_fast_l4".into());
            }
        }
        Profile::Careful => {
            // R09396 + R09397: oracle + tests before L5.
            if req.target_authority >= AuthorityLevel::L5Commit {
                if !req.evidence.tests_pass {
                    missing.push("tests_pass".into());
                }
                if !req.evidence.oracle_agrees {
                    missing.push("oracle_agrees".into());
                }
                if req.evidence.evidence_digest.is_empty() {
                    missing.push("evidence_digest".into()); // R09402
                }
            }
            // R09400 — L4 requires sandbox simulation pass first.
            if req.target_authority >= AuthorityLevel::L4Execute && !req.evidence.successful_sandbox
            {
                missing.push("successful_sandbox".into());
            }
            // R09401 — L6 double-gate adds snapshot.
            if req.target_authority == AuthorityLevel::L6Persist && !req.evidence.snapshot_present {
                missing.push("snapshot_present".into());
            }
        }
        Profile::Autonomous => {
            // F04715 — L5 only within predeclared gate envelope (assume schema-validated).
            if req.target_authority >= AuthorityLevel::L5Commit && !req.evidence.tests_pass {
                missing.push("tests_pass".into());
            }
            // F04716 — L6 still requires oracle + operator.
            if req.target_authority == AuthorityLevel::L6Persist {
                if !req.evidence.oracle_agrees {
                    missing.push("oracle_agrees".into());
                }
                if !req.evidence.user_approves {
                    missing.push("user_approves".into());
                }
            }
        }
        Profile::Experimental => {
            // F04722 — zero host commit (no L5 / no L6).
            if req.target_authority >= AuthorityLevel::L5Commit {
                missing.push("experimental_no_host_commit".into());
            }
            // F04723 — Tier C or D required.
            if !matches!(req.sandbox_tier, SandboxTier::TierC | SandboxTier::TierD) {
                missing.push("sandbox_tier_c_or_d".into());
            }
        }
        Profile::Production => {
            // F04735 — L5 triple gate (test + oracle + operator).
            if req.target_authority >= AuthorityLevel::L5Commit {
                if !req.evidence.tests_pass {
                    missing.push("tests_pass".into());
                }
                if !req.evidence.oracle_agrees {
                    missing.push("oracle_agrees".into());
                }
                if !req.evidence.user_approves {
                    missing.push("user_approves".into());
                }
            }
            // F04736 — L6 quadruple gate adds snapshot.
            if req.target_authority == AuthorityLevel::L6Persist && !req.evidence.snapshot_present {
                missing.push("snapshot_present".into());
            }
        }
    }

    if !missing.is_empty() {
        return AuthorityDecision {
            allowed: false,
            profile,
            reason: format!("evidence ladder incomplete for {profile:?}: missing {missing:?}"),
            missing_evidence: missing,
        };
    }

    AuthorityDecision {
        allowed: true,
        profile,
        reason: format!("{profile:?} envelope OK at {:?}", req.target_authority),
        missing_evidence: vec![],
    }
}

/// Validate a request's TTL against the active profile.
pub fn validate_ttl(profile: Profile, ttl_seconds: u32) -> Result<(), GateError> {
    let ceiling = profile.ttl_ceiling_seconds();
    if ttl_seconds > ceiling {
        return Err(GateError::TtlExceedsCeiling {
            profile,
            ttl_seconds,
            ceiling_seconds: ceiling,
        });
    }
    Ok(())
}

/// Validate the doctrine constant is intact.
pub fn assert_doctrine_intact(observed: &str) -> Result<(), GateError> {
    if observed != DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE {
        return Err(GateError::DoctrineTampered {
            expected: DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_evidence() -> Evidence {
        Evidence {
            valid_schema: true,
            safe_policy: true,
            successful_sandbox: true,
            tests_pass: true,
            oracle_agrees: true,
            user_approves: true,
            snapshot_present: true,
            evidence_digest: "sha256:deadbeef".into(),
        }
    }

    fn req(
        target: AuthorityLevel,
        ring: TrustRing,
        tier: SandboxTier,
        ev: Evidence,
    ) -> AuthorityRequest {
        AuthorityRequest {
            target_authority: target,
            trust_ring: ring,
            sandbox_tier: tier,
            evidence: ev,
            ttl_seconds: 60,
        }
    }

    // --- Profile::Private envelope ---

    #[test]
    fn private_observe_allowed_without_evidence() {
        let r = req(
            AuthorityLevel::L0Observe,
            TrustRing::Ring2,
            SandboxTier::TierA,
            Evidence {
                valid_schema: true,
                safe_policy: true,
                ..Default::default()
            },
        );
        assert!(decide(Profile::Private, &r).allowed);
    }

    #[test]
    fn private_l4_refused_without_user_approves() {
        let r = req(
            AuthorityLevel::L4Execute,
            TrustRing::Ring2,
            SandboxTier::TierA,
            Evidence {
                valid_schema: true,
                safe_policy: true,
                ..Default::default()
            },
        );
        let d = decide(Profile::Private, &r);
        assert!(!d.allowed);
        assert_eq!(d.missing_evidence, vec!["operator_promotion"]);
    }

    #[test]
    fn private_max_authority_is_l1() {
        assert_eq!(Profile::Private.max_authority(), AuthorityLevel::L1Suggest);
    }

    // --- Profile::Fast envelope ---

    #[test]
    fn fast_l4_allowed_on_tier_a_with_universal_evidence() {
        let r = req(
            AuthorityLevel::L4Execute,
            TrustRing::Ring2,
            SandboxTier::TierA,
            Evidence {
                valid_schema: true,
                safe_policy: true,
                ..Default::default()
            },
        );
        assert!(decide(Profile::Fast, &r).allowed);
    }

    #[test]
    fn fast_l4_refused_off_tier_a() {
        let r = req(
            AuthorityLevel::L4Execute,
            TrustRing::Ring2,
            SandboxTier::TierB,
            Evidence {
                valid_schema: true,
                safe_policy: true,
                ..Default::default()
            },
        );
        let d = decide(Profile::Fast, &r);
        assert!(!d.allowed);
        assert!(
            d.missing_evidence
                .iter()
                .any(|x| x == "sandbox_tier_a_for_fast_l4")
        );
    }

    #[test]
    fn fast_l5_refused_above_ceiling() {
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            full_evidence(),
        );
        let d = decide(Profile::Fast, &r);
        assert!(!d.allowed);
        assert!(d.reason.contains("exceeds Fast ceiling"));
    }

    // --- Profile::Careful envelope ---

    #[test]
    fn careful_l5_requires_oracle_and_tests() {
        // Tests missing
        let mut ev = full_evidence();
        ev.tests_pass = false;
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev,
        );
        let d = decide(Profile::Careful, &r);
        assert!(!d.allowed);
        assert!(d.missing_evidence.iter().any(|x| x == "tests_pass"));
        // Oracle missing
        let mut ev2 = full_evidence();
        ev2.oracle_agrees = false;
        let r2 = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev2,
        );
        let d2 = decide(Profile::Careful, &r2);
        assert!(!d2.allowed);
        assert!(d2.missing_evidence.iter().any(|x| x == "oracle_agrees"));
    }

    #[test]
    fn careful_l5_requires_evidence_digest() {
        let mut ev = full_evidence();
        ev.evidence_digest = String::new();
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev,
        );
        let d = decide(Profile::Careful, &r);
        assert!(!d.allowed);
        assert!(d.missing_evidence.iter().any(|x| x == "evidence_digest"));
    }

    #[test]
    fn careful_l6_double_gate_adds_snapshot() {
        let mut ev = full_evidence();
        ev.snapshot_present = false;
        let r = req(
            AuthorityLevel::L6Persist,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev,
        );
        let d = decide(Profile::Careful, &r);
        assert!(!d.allowed);
        assert!(d.missing_evidence.iter().any(|x| x == "snapshot_present"));
    }

    #[test]
    fn careful_l5_fully_evidenced_allowed() {
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            full_evidence(),
        );
        assert!(decide(Profile::Careful, &r).allowed);
    }

    // --- Profile::Autonomous envelope ---

    #[test]
    fn autonomous_l5_within_predeclared_gates() {
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            full_evidence(),
        );
        assert!(decide(Profile::Autonomous, &r).allowed);
    }

    #[test]
    fn autonomous_l6_still_needs_oracle_and_operator() {
        let mut ev = full_evidence();
        ev.user_approves = false;
        let r = req(
            AuthorityLevel::L6Persist,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev,
        );
        // L6 exceeds Autonomous max (L5)
        let d = decide(Profile::Autonomous, &r);
        assert!(!d.allowed);
    }

    // --- Profile::Experimental envelope ---

    #[test]
    fn experimental_refuses_l5_zero_host_commit() {
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring3,
            SandboxTier::TierC,
            full_evidence(),
        );
        let d = decide(Profile::Experimental, &r);
        assert!(!d.allowed);
        // Either over ceiling or experimental_no_host_commit; we check the message.
        assert!(
            d.reason.to_lowercase().contains("ceiling")
                || d.missing_evidence
                    .iter()
                    .any(|x| x == "experimental_no_host_commit")
        );
    }

    #[test]
    fn experimental_requires_tier_c_or_d() {
        let r = req(
            AuthorityLevel::L4Execute,
            TrustRing::Ring3,
            SandboxTier::TierA,
            full_evidence(),
        );
        let d = decide(Profile::Experimental, &r);
        assert!(!d.allowed);
        assert!(
            d.missing_evidence
                .iter()
                .any(|x| x == "sandbox_tier_c_or_d")
        );
    }

    #[test]
    fn experimental_ring_3_allowed() {
        let r = req(
            AuthorityLevel::L4Execute,
            TrustRing::Ring3,
            SandboxTier::TierC,
            full_evidence(),
        );
        assert!(decide(Profile::Experimental, &r).allowed);
    }

    #[test]
    fn experimental_ring_4_refused() {
        let r = req(
            AuthorityLevel::L4Execute,
            TrustRing::Ring4,
            SandboxTier::TierD,
            full_evidence(),
        );
        let d = decide(Profile::Experimental, &r);
        assert!(!d.allowed);
    }

    // --- Profile::Production envelope ---

    #[test]
    fn production_l5_requires_triple_gate() {
        let mut ev = full_evidence();
        ev.user_approves = false;
        let r = req(
            AuthorityLevel::L5Commit,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev,
        );
        let d = decide(Profile::Production, &r);
        assert!(!d.allowed);
        assert!(d.missing_evidence.iter().any(|x| x == "user_approves"));
    }

    #[test]
    fn production_l6_requires_quadruple_gate_with_snapshot() {
        let mut ev = full_evidence();
        ev.snapshot_present = false;
        let r = req(
            AuthorityLevel::L6Persist,
            TrustRing::Ring2,
            SandboxTier::TierA,
            ev,
        );
        let d = decide(Profile::Production, &r);
        assert!(!d.allowed);
        assert!(d.missing_evidence.iter().any(|x| x == "snapshot_present"));
    }

    #[test]
    fn production_l6_full_evidence_allowed() {
        let r = req(
            AuthorityLevel::L6Persist,
            TrustRing::Ring2,
            SandboxTier::TierA,
            full_evidence(),
        );
        assert!(decide(Profile::Production, &r).allowed);
    }

    // --- TTL ceilings ---

    #[test]
    fn ttl_ceiling_per_profile() {
        assert_eq!(Profile::Production.ttl_ceiling_seconds(), 600);
        assert_eq!(Profile::Fast.ttl_ceiling_seconds(), 3600);
        validate_ttl(Profile::Fast, 3600).unwrap();
        let err = validate_ttl(Profile::Production, 1000).unwrap_err();
        match err {
            GateError::TtlExceedsCeiling {
                profile,
                ttl_seconds,
                ceiling_seconds,
            } => {
                assert_eq!(profile, Profile::Production);
                assert_eq!(ttl_seconds, 1000);
                assert_eq!(ceiling_seconds, 600);
            }
            _ => panic!(),
        }
    }

    // --- Trust-ring caps ---

    #[test]
    fn experimental_ring_cap_is_3() {
        assert_eq!(Profile::Experimental.max_trust_ring(), TrustRing::Ring3);
    }

    #[test]
    fn production_ring_cap_is_2() {
        assert_eq!(Profile::Production.max_trust_ring(), TrustRing::Ring2);
    }

    // --- Doctrine ---

    #[test]
    fn doctrine_verbatim_constant() {
        assert_eq!(
            DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE,
            "Authority follows evidence"
        );
        assert_doctrine_intact("Authority follows evidence").unwrap();
    }

    #[test]
    fn doctrine_tamper_caught() {
        let err = assert_doctrine_intact("authority follows nothing").unwrap_err();
        assert!(matches!(err, GateError::DoctrineTampered { .. }));
    }

    // --- Universal "evidence must be valid" path ---

    #[test]
    fn universal_evidence_required_even_for_l0() {
        let r = req(
            AuthorityLevel::L0Observe,
            TrustRing::Ring2,
            SandboxTier::TierA,
            Evidence::default(),
        );
        let d = decide(Profile::Production, &r);
        assert!(!d.allowed);
        assert!(d.missing_evidence.iter().any(|x| x == "valid_schema"));
        assert!(d.missing_evidence.iter().any(|x| x == "safe_policy"));
    }

    // --- Serde ---

    #[test]
    fn profile_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&Profile::Experimental).unwrap(),
            "\"experimental\""
        );
        assert_eq!(
            serde_json::to_string(&Profile::Production).unwrap(),
            "\"production\""
        );
    }

    #[test]
    fn authority_level_ordering() {
        assert!(AuthorityLevel::L0Observe < AuthorityLevel::L1Suggest);
        assert!(AuthorityLevel::L4Execute < AuthorityLevel::L5Commit);
        assert!(AuthorityLevel::L5Commit < AuthorityLevel::L6Persist);
    }
}
