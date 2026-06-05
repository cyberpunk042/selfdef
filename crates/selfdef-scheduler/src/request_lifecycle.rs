//! `request_lifecycle` — canonical 10-step request lifecycle (MS048).
//!
//! Encodes the avx-plus-plus dump's **"A good request lifecycle"** verbatim
//! (dump lines 846-862). This is the end-to-end flow that ties the per-tier
//! work policies ([`crate::tier_work_policy`]), the routing decision
//! ([`crate::scheduling_law`]), and the memory/KV/tool stages together — the
//! sequence a request travels from arrival to logged result:
//!
//! ```text
//! 1.  User request arrives
//! 2.  CPU creates root branch
//! 3.  Memory plane retrieves context candidates
//! 4.  3090 reranks/summarizes/expands cheap candidates
//! 5.  CPU packs prompt plan
//! 6.  RTX PRO 6000 performs high-quality generation
//! 7.  3090 drafts ahead where useful
//! 8.  CPU validates constraints and branch health
//! 9.  RTX PRO 6000 verifies or finalizes
//! 10. Memory plane logs result and useful traces
//! ```
//!
//! Step 1, *"User request arrives"*, is the request-ingress entry point: the
//! scheduling "request" the rest of MS048 acts on enters here (a task, scored
//! by the 7-axis objective per [`crate::evaluate_objective`] and routed per
//! [`crate::scheduling_law::recommend_route`]). Each step's plane is verbatim
//! from the dump — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The plane responsible for a lifecycle step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Plane {
    /// Request ingress ("User request arrives").
    Entry,
    /// Ryzen 9900X AVX-512 deterministic cortex.
    Cpu,
    /// RTX 3090 scout.
    Scout,
    /// RTX PRO 6000 Blackwell oracle.
    Oracle,
    /// Memory plane (retrieval + logging).
    Memory,
}

/// One step in the canonical request lifecycle. Const-constructed (the
/// `action` is a `&'static str` literal), so it serializes for emission to
/// consumers but is not parsed back — `Serialize` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LifecycleStep {
    /// 1-based step order.
    pub order: u8,
    /// The plane that performs the step.
    pub plane: Plane,
    /// The verbatim action text.
    pub action: &'static str,
}

/// The canonical 10-step request lifecycle (dump 846-862, verbatim).
#[must_use]
pub fn request_lifecycle() -> [LifecycleStep; 10] {
    [
        LifecycleStep { order: 1, plane: Plane::Entry, action: "User request arrives" },
        LifecycleStep { order: 2, plane: Plane::Cpu, action: "CPU creates root branch" },
        LifecycleStep {
            order: 3,
            plane: Plane::Memory,
            action: "Memory plane retrieves context candidates",
        },
        LifecycleStep {
            order: 4,
            plane: Plane::Scout,
            action: "3090 reranks/summarizes/expands cheap candidates",
        },
        LifecycleStep { order: 5, plane: Plane::Cpu, action: "CPU packs prompt plan" },
        LifecycleStep {
            order: 6,
            plane: Plane::Oracle,
            action: "RTX PRO 6000 performs high-quality generation",
        },
        LifecycleStep {
            order: 7,
            plane: Plane::Scout,
            action: "3090 drafts ahead where useful",
        },
        LifecycleStep {
            order: 8,
            plane: Plane::Cpu,
            action: "CPU validates constraints and branch health",
        },
        LifecycleStep {
            order: 9,
            plane: Plane::Oracle,
            action: "RTX PRO 6000 verifies or finalizes",
        },
        LifecycleStep {
            order: 10,
            plane: Plane::Memory,
            action: "Memory plane logs result and useful traces",
        },
    ]
}

/// The step where the request enters (the ingress point).
#[must_use]
pub fn entry_step() -> LifecycleStep {
    request_lifecycle()[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_has_ten_ordered_steps() {
        let steps = request_lifecycle();
        assert_eq!(steps.len(), 10);
        for (i, s) in steps.iter().enumerate() {
            assert_eq!(s.order, (i + 1) as u8, "step {i} out of order");
        }
    }

    #[test]
    fn step_one_is_request_arrival_entry() {
        let e = entry_step();
        assert_eq!(e.order, 1);
        assert_eq!(e.plane, Plane::Entry);
        assert_eq!(e.action, "User request arrives");
    }

    #[test]
    fn oracle_does_generation_and_verification() {
        let steps = request_lifecycle();
        let oracle: Vec<&str> = steps
            .iter()
            .filter(|s| s.plane == Plane::Oracle)
            .map(|s| s.action)
            .collect();
        assert_eq!(
            oracle,
            vec![
                "RTX PRO 6000 performs high-quality generation",
                "RTX PRO 6000 verifies or finalizes"
            ]
        );
    }

    #[test]
    fn memory_bookends_retrieval_and_logging() {
        let steps = request_lifecycle();
        let mem: Vec<u8> = steps
            .iter()
            .filter(|s| s.plane == Plane::Memory)
            .map(|s| s.order)
            .collect();
        // retrieval early (3), logging last (10)
        assert_eq!(mem, vec![3, 10]);
    }

    #[test]
    fn cpu_appears_three_times_as_the_exchange() {
        // "The CPU is the exchange" — root branch, prompt plan, validation.
        let cpu = request_lifecycle()
            .iter()
            .filter(|s| s.plane == Plane::Cpu)
            .count();
        assert_eq!(cpu, 3);
    }

    #[test]
    fn entry_appears_exactly_once() {
        let entry = request_lifecycle()
            .iter()
            .filter(|s| s.plane == Plane::Entry)
            .count();
        assert_eq!(entry, 1);
    }

    #[test]
    fn step_serializes_with_order_plane_action() {
        let s = entry_step();
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"order\":1"));
        assert!(j.contains("\"Entry\""));
        assert!(j.contains("User request arrives"));
    }

    #[test]
    fn plane_serde_roundtrips() {
        for p in [Plane::Entry, Plane::Cpu, Plane::Scout, Plane::Oracle, Plane::Memory] {
            let j = serde_json::to_string(&p).unwrap();
            let back: Plane = serde_json::from_str(&j).unwrap();
            assert_eq!(p, back);
        }
    }
}
