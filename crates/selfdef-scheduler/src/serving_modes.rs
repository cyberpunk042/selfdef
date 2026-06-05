//! `serving_modes` — the three workload serving modes (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Three Serving Modes"** verbatim (dump
//! lines 4737-4786). These are the WORKLOAD shapes the scheduler serves —
//! orthogonal to the six [`crate::Profile`]s (which are the
//! safety/authority envelope). Each mode has a goal + a tier flow + a "use
//! for":
//!
//! - **Mode A: Low-Latency Interactive** — goal *"fastest good answer"*; for
//!   chat, coding help, command planning.
//! - **Mode B: Agentic Batch** — goal *"many branches / tool loops"*; for
//!   coding agents, research agents, automation.
//! - **Mode C: Long-Context Workbench** — goal *"huge docs / repo / long
//!   sessions"*; for repo-wide work, documents, audits.
//!
//! Every mode name, goal, and use-for is verbatim — none invented (operator
//! rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The three serving modes (dump 4741-4786).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServingMode {
    /// Mode A: Low-Latency Interactive.
    LowLatencyInteractive,
    /// Mode B: Agentic Batch.
    AgenticBatch,
    /// Mode C: Long-Context Workbench.
    LongContextWorkbench,
}

impl ServingMode {
    /// The verbatim mode label (`Mode A: …`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LowLatencyInteractive => "Mode A: Low-Latency Interactive",
            Self::AgenticBatch => "Mode B: Agentic Batch",
            Self::LongContextWorkbench => "Mode C: Long-Context Workbench",
        }
    }

    /// The verbatim goal.
    #[must_use]
    pub const fn goal(self) -> &'static str {
        match self {
            Self::LowLatencyInteractive => "fastest good answer",
            Self::AgenticBatch => "many branches / tool loops",
            Self::LongContextWorkbench => "huge docs / repo / long sessions",
        }
    }

    /// The verbatim "use for" workloads.
    #[must_use]
    pub const fn use_for(self) -> &'static str {
        match self {
            Self::LowLatencyInteractive => "chat, coding help, command planning",
            Self::AgenticBatch => "coding agents, research agents, automation",
            Self::LongContextWorkbench => "repo-wide work, documents, audits",
        }
    }
}

/// The three modes in dump order (A, B, C).
#[must_use]
pub fn modes() -> [ServingMode; 3] {
    [
        ServingMode::LowLatencyInteractive,
        ServingMode::AgenticBatch,
        ServingMode::LongContextWorkbench,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_modes_with_verbatim_labels() {
        let m = modes();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].label(), "Mode A: Low-Latency Interactive");
        assert_eq!(m[1].label(), "Mode B: Agentic Batch");
        assert_eq!(m[2].label(), "Mode C: Long-Context Workbench");
    }

    #[test]
    fn goals_verbatim() {
        assert_eq!(ServingMode::LowLatencyInteractive.goal(), "fastest good answer");
        assert_eq!(ServingMode::AgenticBatch.goal(), "many branches / tool loops");
        assert_eq!(
            ServingMode::LongContextWorkbench.goal(),
            "huge docs / repo / long sessions"
        );
    }

    #[test]
    fn use_for_verbatim() {
        assert_eq!(
            ServingMode::LowLatencyInteractive.use_for(),
            "chat, coding help, command planning"
        );
        assert!(ServingMode::AgenticBatch.use_for().contains("research agents"));
        assert!(ServingMode::LongContextWorkbench.use_for().contains("repo-wide work"));
    }

    #[test]
    fn modes_distinct() {
        let m = modes();
        for i in 0..3 {
            for j in (i + 1)..3 {
                assert_ne!(m[i], m[j]);
                assert_ne!(m[i].label(), m[j].label());
                assert_ne!(m[i].goal(), m[j].goal());
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        for m in modes() {
            let j = serde_json::to_string(&m).unwrap();
            let back: ServingMode = serde_json::from_str(&j).unwrap();
            assert_eq!(m, back);
        }
    }
}
