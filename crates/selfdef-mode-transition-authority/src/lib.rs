//! `selfdef-mode-transition-authority` — IPS authority over mode transitions.
//!
//! Owns the matrix of which (from, to) ExecutionMode pairs are:
//! - Forbidden outright (would skip required gates)
//! - Direct-shift only (requires explicit operator acknowledgement)
//! - Snapshot-required (must take a ZFS snapshot before)
//! - Routine (no extra gate)
//!
//! The runtime side never invents transition policy; the cockpit
//! mode-transition log mirrors approvals issued by this authority.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_execution_mode_policy::ExecutionMode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Gate the transition triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionGate {
    /// Routine — no extra check.
    Routine,
    /// Direct-shift required — operator must explicitly acknowledge.
    DirectShift,
    /// Snapshot required first.
    Snapshot,
    /// Forbidden outright.
    Forbidden,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TransitionAuthorityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Transition forbidden.
    #[error("transition forbidden: {from:?} -> {to:?}")]
    Forbidden {
        /// from.
        from: ExecutionMode,
        /// to.
        to: ExecutionMode,
    },
    /// Direct-shift required but operator didn't acknowledge.
    #[error("transition {from:?} -> {to:?} requires direct-shift acknowledgement")]
    DirectShiftRequired {
        /// from.
        from: ExecutionMode,
        /// to.
        to: ExecutionMode,
    },
    /// Snapshot required first.
    #[error("transition {from:?} -> {to:?} requires snapshot")]
    SnapshotRequired {
        /// from.
        from: ExecutionMode,
        /// to.
        to: ExecutionMode,
    },
    /// Self-transition (from == to).
    #[error("self-transition {0:?} -> {0:?}")]
    SelfTransition(ExecutionMode),
}

/// IPS-authoritative gate classification for a (from, to) pair.
pub fn gate_for(from: ExecutionMode, to: ExecutionMode) -> TransitionGate {
    if from == to {
        return TransitionGate::Routine;
    }
    use ExecutionMode::*;
    // 1) Forbidden transitions: Replay can only return to Plan.
    if from == Replay && to != Plan {
        return TransitionGate::Forbidden;
    }
    // 2) Direct-shift: Plan->Execute, DryRun->Execute (skipping Sandbox),
    //    Shadow->Execute, any non-Execute non-Debug -> Debug.
    if matches!(
        (from, to),
        (Plan, Execute)
            | (DryRun, Execute)
            | (Shadow, Execute)
            | (Plan, Debug)
            | (DryRun, Debug)
            | (Shadow, Debug)
    ) {
        return TransitionGate::DirectShift;
    }
    // 3) Snapshot required when entering Execute from any non-DirectShift source.
    if to == Execute {
        return TransitionGate::Snapshot;
    }
    TransitionGate::Routine
}

/// Run the authority check.
///
/// `direct_shift_ack` — operator's "I know what I'm doing" flag.
/// `snapshot_taken`   — daemon confirms a fresh ZFS snapshot exists.
pub fn approve_transition(
    from: ExecutionMode,
    to: ExecutionMode,
    direct_shift_ack: bool,
    snapshot_taken: bool,
) -> Result<(), TransitionAuthorityError> {
    if from == to {
        return Err(TransitionAuthorityError::SelfTransition(from));
    }
    match gate_for(from, to) {
        TransitionGate::Forbidden => Err(TransitionAuthorityError::Forbidden { from, to }),
        TransitionGate::DirectShift => {
            if !direct_shift_ack {
                Err(TransitionAuthorityError::DirectShiftRequired { from, to })
            } else {
                // DirectShift to Execute also wants snapshot.
                if to == ExecutionMode::Execute && !snapshot_taken {
                    Err(TransitionAuthorityError::SnapshotRequired { from, to })
                } else {
                    Ok(())
                }
            }
        }
        TransitionGate::Snapshot => {
            if !snapshot_taken {
                Err(TransitionAuthorityError::SnapshotRequired { from, to })
            } else {
                Ok(())
            }
        }
        TransitionGate::Routine => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExecutionMode::*;

    #[test]
    fn routine_path() {
        assert_eq!(gate_for(Plan, DryRun), TransitionGate::Routine);
        approve_transition(Plan, DryRun, false, false).unwrap();
    }

    #[test]
    fn plan_to_execute_needs_direct_shift_and_snapshot() {
        assert_eq!(gate_for(Plan, Execute), TransitionGate::DirectShift);
        // No ack → DirectShiftRequired
        assert!(matches!(
            approve_transition(Plan, Execute, false, false).unwrap_err(),
            TransitionAuthorityError::DirectShiftRequired { .. }
        ));
        // Ack but no snapshot → SnapshotRequired
        assert!(matches!(
            approve_transition(Plan, Execute, true, false).unwrap_err(),
            TransitionAuthorityError::SnapshotRequired { .. }
        ));
        // Both → ok.
        approve_transition(Plan, Execute, true, true).unwrap();
    }

    #[test]
    fn sandbox_to_execute_needs_only_snapshot_not_direct_shift() {
        assert_eq!(gate_for(Sandbox, Execute), TransitionGate::Snapshot);
        approve_transition(Sandbox, Execute, false, true).unwrap();
    }

    #[test]
    fn execute_to_sandbox_routine() {
        assert_eq!(gate_for(Execute, Sandbox), TransitionGate::Routine);
        approve_transition(Execute, Sandbox, false, false).unwrap();
    }

    #[test]
    fn replay_can_only_exit_to_plan() {
        assert_eq!(gate_for(Replay, Plan), TransitionGate::Routine);
        for to in [DryRun, Shadow, Sandbox, Execute, Debug] {
            assert_eq!(
                gate_for(Replay, to),
                TransitionGate::Forbidden,
                "Replay -> {to:?} should be forbidden"
            );
            assert!(matches!(
                approve_transition(Replay, to, true, true).unwrap_err(),
                TransitionAuthorityError::Forbidden { .. }
            ));
        }
    }

    #[test]
    fn self_transition_rejected() {
        assert!(matches!(
            approve_transition(Plan, Plan, false, false).unwrap_err(),
            TransitionAuthorityError::SelfTransition(Plan)
        ));
    }

    #[test]
    fn dry_run_to_execute_direct_shift() {
        assert_eq!(gate_for(DryRun, Execute), TransitionGate::DirectShift);
    }

    #[test]
    fn shadow_to_execute_direct_shift() {
        assert_eq!(gate_for(Shadow, Execute), TransitionGate::DirectShift);
    }

    #[test]
    fn plan_to_debug_direct_shift() {
        assert_eq!(gate_for(Plan, Debug), TransitionGate::DirectShift);
    }

    #[test]
    fn sandbox_to_debug_routine() {
        assert_eq!(gate_for(Sandbox, Debug), TransitionGate::Routine);
    }

    #[test]
    fn execute_to_plan_routine() {
        assert_eq!(gate_for(Execute, Plan), TransitionGate::Routine);
    }

    #[test]
    fn gate_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&TransitionGate::Routine).unwrap(),
            "\"routine\""
        );
        assert_eq!(
            serde_json::to_string(&TransitionGate::DirectShift).unwrap(),
            "\"direct-shift\""
        );
        assert_eq!(
            serde_json::to_string(&TransitionGate::Snapshot).unwrap(),
            "\"snapshot\""
        );
        assert_eq!(
            serde_json::to_string(&TransitionGate::Forbidden).unwrap(),
            "\"forbidden\""
        );
    }
}
