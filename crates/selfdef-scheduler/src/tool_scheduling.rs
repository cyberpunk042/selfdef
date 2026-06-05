//! `tool_scheduling` — M01154: per-tool-class scheduling treatment.
//!
//! Encodes the avx-plus-plus dump's **"Tool Scheduling"** table verbatim
//! (dump lines 18154-18176), inside the Goldilocks scheduler section. The
//! dump opens: *"Tools are slow and risky compared to pure logic."* and gives
//! a five-class treatment:
//!
//! ```text
//! read-only tools:   can run early and parallel
//! write tools:       require snapshot/policy
//! network tools:     require profile permission
//! long tests:        can run async, branch hibernates
//! destructive tools: human gate
//! ```
//!
//! This is the scheduler's WHEN/HOW for a tool invocation (run-early /
//! snapshot-first / hibernate-async / human-gate), distinct from the IPS
//! authority layer's WHETHER (capability word / tool-capability-policy). Each
//! [`ToolScheduling`] field maps to one verbatim phrase above — no class or
//! treatment is invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The five tool classes the dump's Tool Scheduling table enumerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolClass {
    /// Read-only tools (dump: "can run early and parallel").
    ReadOnly,
    /// Write tools (dump: "require snapshot/policy").
    Write,
    /// Network tools (dump: "require profile permission").
    Network,
    /// Long-running tests (dump: "can run async, branch hibernates").
    LongTest,
    /// Destructive tools (dump: "human gate").
    Destructive,
}

/// The scheduling treatment for a tool class. Every field corresponds to a
/// verbatim phrase from the dump's Tool Scheduling table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolScheduling {
    /// Read-only: "can run early".
    pub can_run_early: bool,
    /// Read-only: "and parallel".
    pub parallel: bool,
    /// Write: "require snapshot".
    pub requires_snapshot: bool,
    /// Write: "/policy".
    pub requires_policy: bool,
    /// Network: "require profile permission".
    pub requires_profile_permission: bool,
    /// Long tests: "can run async, branch hibernates".
    pub async_branch_hibernates: bool,
    /// Destructive: "human gate".
    pub human_gate: bool,
}

impl ToolScheduling {
    const fn none() -> Self {
        Self {
            can_run_early: false,
            parallel: false,
            requires_snapshot: false,
            requires_policy: false,
            requires_profile_permission: false,
            async_branch_hibernates: false,
            human_gate: false,
        }
    }
}

/// Map a [`ToolClass`] to its verbatim scheduling treatment (dump 18156-18176).
#[must_use]
pub fn schedule(class: ToolClass) -> ToolScheduling {
    match class {
        // "read-only tools: can run early and parallel"
        ToolClass::ReadOnly => ToolScheduling {
            can_run_early: true,
            parallel: true,
            ..ToolScheduling::none()
        },
        // "write tools: require snapshot/policy"
        ToolClass::Write => ToolScheduling {
            requires_snapshot: true,
            requires_policy: true,
            ..ToolScheduling::none()
        },
        // "network tools: require profile permission"
        ToolClass::Network => ToolScheduling {
            requires_profile_permission: true,
            ..ToolScheduling::none()
        },
        // "long tests: can run async, branch hibernates"
        ToolClass::LongTest => ToolScheduling {
            async_branch_hibernates: true,
            ..ToolScheduling::none()
        },
        // "destructive tools: human gate"
        ToolClass::Destructive => ToolScheduling {
            human_gate: true,
            ..ToolScheduling::none()
        },
    }
}

/// All five tool classes in dump order.
#[must_use]
pub fn all_classes() -> [ToolClass; 5] {
    [
        ToolClass::ReadOnly,
        ToolClass::Write,
        ToolClass::Network,
        ToolClass::LongTest,
        ToolClass::Destructive,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_runs_early_and_parallel() {
        let s = schedule(ToolClass::ReadOnly);
        assert!(s.can_run_early && s.parallel);
        // and nothing else
        assert!(!s.requires_snapshot && !s.human_gate && !s.async_branch_hibernates);
    }

    #[test]
    fn write_requires_snapshot_and_policy() {
        let s = schedule(ToolClass::Write);
        assert!(s.requires_snapshot && s.requires_policy);
        assert!(!s.can_run_early && !s.human_gate);
    }

    #[test]
    fn network_requires_profile_permission() {
        let s = schedule(ToolClass::Network);
        assert!(s.requires_profile_permission);
        assert!(!s.requires_snapshot && !s.parallel);
    }

    #[test]
    fn long_test_is_async_hibernating() {
        let s = schedule(ToolClass::LongTest);
        assert!(s.async_branch_hibernates);
        assert!(!s.human_gate && !s.can_run_early);
    }

    #[test]
    fn destructive_is_human_gated() {
        let s = schedule(ToolClass::Destructive);
        assert!(s.human_gate);
        // human gate is the ONLY treatment — nothing runs early/parallel/async
        assert!(!s.can_run_early && !s.parallel && !s.async_branch_hibernates);
    }

    #[test]
    fn every_class_has_a_distinct_nonempty_treatment() {
        let none = ToolScheduling::none();
        for c in all_classes() {
            assert_ne!(schedule(c), none, "{c:?} has an empty treatment");
        }
    }

    #[test]
    fn serde_roundtrip_preserves_treatment() {
        for c in all_classes() {
            let s = schedule(c);
            let json = serde_json::to_string(&s).unwrap();
            let back: ToolScheduling = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }
}
