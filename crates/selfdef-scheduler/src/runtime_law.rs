//! `runtime_law` — the six runtime-law invariants (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Updated Runtime Law"** verbatim (dump
//! lines 3637-3648) — the foundational security invariants the IPS host
//! runtime enforces, under which the Goldilocks Scheduler operates. The dump
//! frames the whole system as *"trust zones, deterministic commit, speculative
//! cognition, and hardware-enforced isolation"* (3672); these six invariants
//! are the law of that system:
//!
//! ```text
//! 1. No model has ambient write authority.
//! 2. No sandbox output is trusted until host validation.
//! 3. No network access without explicit capability bits.
//! 4. No tool side effect without replay log entry.
//! 5. No VM result bypasses policy/oracle commit.
//! 6. Host owns memory, truth, and final state.
//! ```
//!
//! Each invariant cites the selfdef mechanism that enforces it (mirroring the
//! [`crate::golden_rule`] technique→module index). Every invariant is verbatim
//! — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The system framing the law upholds (dump 3672, verbatim).
pub const SYSTEM_FRAMING: &str =
    "trust zones, deterministic commit, speculative cognition, and hardware-enforced isolation";

/// The six runtime-law invariants (dump 3641-3646).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeLaw {
    /// 1. No model has ambient write authority.
    NoAmbientWriteAuthority,
    /// 2. No sandbox output is trusted until host validation.
    NoUntrustedSandboxOutput,
    /// 3. No network access without explicit capability bits.
    NoNetworkWithoutCapability,
    /// 4. No tool side effect without replay log entry.
    NoSideEffectWithoutReplayLog,
    /// 5. No VM result bypasses policy/oracle commit.
    NoBypassOfPolicyCommit,
    /// 6. Host owns memory, truth, and final state.
    HostOwnsTruth,
}

impl RuntimeLaw {
    /// 1-based invariant number.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::NoAmbientWriteAuthority => 1,
            Self::NoUntrustedSandboxOutput => 2,
            Self::NoNetworkWithoutCapability => 3,
            Self::NoSideEffectWithoutReplayLog => 4,
            Self::NoBypassOfPolicyCommit => 5,
            Self::HostOwnsTruth => 6,
        }
    }

    /// The verbatim invariant text.
    #[must_use]
    pub const fn invariant(self) -> &'static str {
        match self {
            Self::NoAmbientWriteAuthority => "No model has ambient write authority.",
            Self::NoUntrustedSandboxOutput => "No sandbox output is trusted until host validation.",
            Self::NoNetworkWithoutCapability => {
                "No network access without explicit capability bits."
            }
            Self::NoSideEffectWithoutReplayLog => "No tool side effect without replay log entry.",
            Self::NoBypassOfPolicyCommit => "No VM result bypasses policy/oracle commit.",
            Self::HostOwnsTruth => "Host owns memory, truth, and final state.",
        }
    }

    /// The selfdef mechanism / module that enforces this invariant.
    #[must_use]
    pub const fn enforced_by(self) -> &'static str {
        match self {
            // commit-authority + capability-word gate ambient writes
            Self::NoAmbientWriteAuthority => "selfdef-commit-authority / capability_word",
            // the execution pipeline's Validate stage (CPU masks/parses/scans/checks)
            Self::NoUntrustedSandboxOutput => "execution_pipeline (Validate)",
            // the MS038 network boundary gates egress on capability bits
            Self::NoNetworkWithoutCapability => "selfdef-network-boundary / capability_word",
            // every tool call transaction + the audit chain
            Self::NoSideEffectWithoutReplayLog => "tool_call_transaction / decision_audit",
            // the execution pipeline's Commit stage + policy-decision
            Self::NoBypassOfPolicyCommit => "execution_pipeline (Commit) / selfdef-policy-decision",
            // the CPU governs memory ("Let the CPU govern memory")
            Self::HostOwnsTruth => "kv_cache_controller",
        }
    }
}

/// The six invariants in dump order.
#[must_use]
pub fn invariants() -> [RuntimeLaw; 6] {
    [
        RuntimeLaw::NoAmbientWriteAuthority,
        RuntimeLaw::NoUntrustedSandboxOutput,
        RuntimeLaw::NoNetworkWithoutCapability,
        RuntimeLaw::NoSideEffectWithoutReplayLog,
        RuntimeLaw::NoBypassOfPolicyCommit,
        RuntimeLaw::HostOwnsTruth,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_invariants_in_order() {
        let inv = invariants();
        assert_eq!(inv.len(), 6);
        for (i, l) in inv.iter().enumerate() {
            assert_eq!(l.number(), (i + 1) as u8);
        }
    }

    #[test]
    fn invariants_verbatim() {
        assert_eq!(
            RuntimeLaw::NoAmbientWriteAuthority.invariant(),
            "No model has ambient write authority."
        );
        assert_eq!(
            RuntimeLaw::HostOwnsTruth.invariant(),
            "Host owns memory, truth, and final state."
        );
        assert_eq!(
            RuntimeLaw::NoSideEffectWithoutReplayLog.invariant(),
            "No tool side effect without replay log entry."
        );
    }

    #[test]
    fn every_invariant_has_an_enforcing_mechanism() {
        for l in invariants() {
            assert!(!l.enforced_by().is_empty(), "{l:?} not enforced");
        }
        // spot-check key mappings
        assert!(
            RuntimeLaw::NoSideEffectWithoutReplayLog
                .enforced_by()
                .contains("decision_audit")
        );
        assert!(
            RuntimeLaw::HostOwnsTruth
                .enforced_by()
                .contains("kv_cache_controller")
        );
    }

    #[test]
    fn invariants_distinct() {
        let inv = invariants();
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(inv[i], inv[j]);
                assert_ne!(inv[i].invariant(), inv[j].invariant());
            }
        }
    }

    #[test]
    fn system_framing_verbatim() {
        assert!(SYSTEM_FRAMING.contains("hardware-enforced isolation"));
    }

    #[test]
    fn serde_roundtrip() {
        for l in invariants() {
            let j = serde_json::to_string(&l).unwrap();
            let back: RuntimeLaw = serde_json::from_str(&j).unwrap();
            assert_eq!(l, back);
        }
    }
}
