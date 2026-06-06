//! `reflexion` — disciplined reflection pipeline (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Reflexion, But Disciplined"** verbatim
//! (dump lines 4111-4140). Reflexion (reflect in natural language and store it)
//! is good, but *"we should not let reflection become vague self-talk."* The
//! disciplined version is a six-step pipeline where a reflection must be
//! attached to facts and validated against the trace:
//!
//! ```text
//! 1. collect objective outcome
//! 2. classify failure code
//! 3. generate short reflection
//! 4. validate reflection against trace
//! 5. store typed lesson + text
//! 6. retrieve only when matching conditions apply
//! ```
//!
//! A reflection is fact-attached: *"npm test failed because jest config
//! expected ESM."* — NOT *"I should be more careful."* (dump 4136-4140). The
//! doctrine (4142): *"The CPU/runtime should reject low-information
//! reflections."* Pairs with [`crate::failure_codes`] (step 2). Every step is
//! verbatim — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump 4142, verbatim).
pub const DOCTRINE: &str = "The CPU/runtime should reject low-information reflections.";

/// A fact-attached reflection example (dump 4138, verbatim) — the GOOD shape.
pub const GOOD_EXAMPLE: &str = "npm test failed because jest config expected ESM.";

/// A vague-self-talk example (dump 4140, verbatim) — the REJECTED shape.
pub const BAD_EXAMPLE: &str = "I should be more careful.";

/// The six disciplined-reflection steps (dump 4117-4122).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReflectionStep {
    /// 1. collect objective outcome.
    CollectObjectiveOutcome,
    /// 2. classify failure code.
    ClassifyFailureCode,
    /// 3. generate short reflection.
    GenerateShortReflection,
    /// 4. validate reflection against trace.
    ValidateAgainstTrace,
    /// 5. store typed lesson + text.
    StoreTypedLesson,
    /// 6. retrieve only when matching conditions apply.
    RetrieveOnMatch,
}

impl ReflectionStep {
    /// 1-based step order.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::CollectObjectiveOutcome => 1,
            Self::ClassifyFailureCode => 2,
            Self::GenerateShortReflection => 3,
            Self::ValidateAgainstTrace => 4,
            Self::StoreTypedLesson => 5,
            Self::RetrieveOnMatch => 6,
        }
    }

    /// The verbatim step text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::CollectObjectiveOutcome => "collect objective outcome",
            Self::ClassifyFailureCode => "classify failure code",
            Self::GenerateShortReflection => "generate short reflection",
            Self::ValidateAgainstTrace => "validate reflection against trace",
            Self::StoreTypedLesson => "store typed lesson + text",
            Self::RetrieveOnMatch => "retrieve only when matching conditions apply",
        }
    }
}

/// The six steps in order.
#[must_use]
pub fn pipeline() -> [ReflectionStep; 6] {
    [
        ReflectionStep::CollectObjectiveOutcome,
        ReflectionStep::ClassifyFailureCode,
        ReflectionStep::GenerateShortReflection,
        ReflectionStep::ValidateAgainstTrace,
        ReflectionStep::StoreTypedLesson,
        ReflectionStep::RetrieveOnMatch,
    ]
}

/// A minimal information-quality gate matching the doctrine "reject
/// low-information reflections": a reflection must be non-empty and reference a
/// cause (contain "because" / "expected" / "failed" / "due to" style fact
/// markers) rather than being pure self-talk. This is a conservative,
/// dump-grounded heuristic — the GOOD example passes, the BAD example fails.
#[must_use]
pub fn is_high_information(reflection: &str) -> bool {
    let r = reflection.trim();
    if r.len() < 8 {
        return false;
    }
    let lower = r.to_ascii_lowercase();
    const FACT_MARKERS: [&str; 6] = [
        "because", "expected", "failed", "due to", "caused", "returned",
    ];
    FACT_MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_steps_in_order() {
        let p = pipeline();
        assert_eq!(p.len(), 6);
        for (i, s) in p.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8);
        }
    }

    #[test]
    fn step_text_verbatim() {
        assert_eq!(
            ReflectionStep::CollectObjectiveOutcome.text(),
            "collect objective outcome"
        );
        assert_eq!(
            ReflectionStep::ValidateAgainstTrace.text(),
            "validate reflection against trace"
        );
        assert_eq!(
            ReflectionStep::RetrieveOnMatch.text(),
            "retrieve only when matching conditions apply"
        );
    }

    #[test]
    fn good_example_is_high_information() {
        assert!(is_high_information(GOOD_EXAMPLE));
    }

    #[test]
    fn bad_example_is_rejected() {
        assert!(!is_high_information(BAD_EXAMPLE));
    }

    #[test]
    fn empty_and_short_rejected() {
        assert!(!is_high_information(""));
        assert!(!is_high_information("oops"));
    }

    #[test]
    fn examples_verbatim() {
        assert_eq!(
            GOOD_EXAMPLE,
            "npm test failed because jest config expected ESM."
        );
        assert_eq!(BAD_EXAMPLE, "I should be more careful.");
        assert_eq!(
            DOCTRINE,
            "The CPU/runtime should reject low-information reflections."
        );
    }

    #[test]
    fn serde_roundtrip() {
        for s in pipeline() {
            let j = serde_json::to_string(&s).unwrap();
            let back: ReflectionStep = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }
}
