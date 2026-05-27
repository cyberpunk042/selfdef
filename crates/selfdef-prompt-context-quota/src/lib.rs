//! `selfdef-prompt-context-quota` — assembled-prompt segment quota.
//!
//! Per-class sub-cap + global cap. assemble(segments) sums tokens
//! per class, then checks each sub-cap, then the global cap; reports
//! per-class actual + cap so the cockpit can show what to trim.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Segment class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SegmentClass {
    /// System prompt (engine-controlled).
    System,
    /// Operator instructions.
    Operator,
    /// Persistent / long-term memory.
    Persistent,
    /// Tool outputs (potentially-attacker-controlled).
    Tool,
    /// Untrusted external (web/email/etc.).
    Untrusted,
}

/// One segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Segment {
    /// Stable id.
    pub id: String,
    /// Class.
    pub class: SegmentClass,
    /// Token count.
    pub tokens: u32,
}

/// Sub-cap per class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassCaps {
    /// System max.
    pub system: u32,
    /// Operator max.
    pub operator: u32,
    /// Persistent max.
    pub persistent: u32,
    /// Tool max.
    pub tool: u32,
    /// Untrusted max.
    pub untrusted: u32,
}

/// Per-class actuals after summing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassActuals {
    /// system.
    pub system: u32,
    /// operator.
    pub operator: u32,
    /// persistent.
    pub persistent: u32,
    /// tool.
    pub tool: u32,
    /// untrusted.
    pub untrusted: u32,
}

impl ClassActuals {
    /// Sum.
    pub fn total(&self) -> u32 {
        self.system + self.operator + self.persistent + self.tool + self.untrusted
    }
}

/// Decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum QuotaDecision {
    /// All fits.
    Allow {
        /// totals.
        actuals: ClassActuals,
    },
    /// A single class exceeded.
    ExceedClass {
        /// class.
        class: SegmentClass,
        /// actual.
        actual: u32,
        /// cap.
        cap: u32,
    },
    /// Global cap exceeded.
    ExceedTotal {
        /// actual total.
        actual: u32,
        /// cap.
        cap: u32,
        /// totals.
        actuals: ClassActuals,
    },
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptContextQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-class caps.
    pub caps: ClassCaps,
    /// Global cap.
    pub global_cap: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QuotaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// global_cap zero.
    #[error("global_cap is zero")]
    GlobalZero,
    /// per-class cap zero.
    #[error("class {0:?} cap is zero")]
    ClassZero(SegmentClass),
}

impl PromptContextQuota {
    /// Canonical: System 2k, Operator 6k, Persistent 8k, Tool 16k,
    /// Untrusted 4k; global 32k.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            caps: ClassCaps {
                system: 2_000,
                operator: 6_000,
                persistent: 8_000,
                tool: 16_000,
                untrusted: 4_000,
            },
            global_cap: 32_000,
        }
    }

    /// Sum per class.
    pub fn sum(&self, segments: &[Segment]) -> ClassActuals {
        let mut a = ClassActuals {
            system: 0,
            operator: 0,
            persistent: 0,
            tool: 0,
            untrusted: 0,
        };
        for s in segments {
            match s.class {
                SegmentClass::System => a.system += s.tokens,
                SegmentClass::Operator => a.operator += s.tokens,
                SegmentClass::Persistent => a.persistent += s.tokens,
                SegmentClass::Tool => a.tool += s.tokens,
                SegmentClass::Untrusted => a.untrusted += s.tokens,
            }
        }
        a
    }

    /// Decide assembly.
    pub fn assemble(&self, segments: &[Segment]) -> QuotaDecision {
        let a = self.sum(segments);
        if a.system > self.caps.system {
            return QuotaDecision::ExceedClass {
                class: SegmentClass::System,
                actual: a.system,
                cap: self.caps.system,
            };
        }
        if a.operator > self.caps.operator {
            return QuotaDecision::ExceedClass {
                class: SegmentClass::Operator,
                actual: a.operator,
                cap: self.caps.operator,
            };
        }
        if a.persistent > self.caps.persistent {
            return QuotaDecision::ExceedClass {
                class: SegmentClass::Persistent,
                actual: a.persistent,
                cap: self.caps.persistent,
            };
        }
        if a.tool > self.caps.tool {
            return QuotaDecision::ExceedClass {
                class: SegmentClass::Tool,
                actual: a.tool,
                cap: self.caps.tool,
            };
        }
        if a.untrusted > self.caps.untrusted {
            return QuotaDecision::ExceedClass {
                class: SegmentClass::Untrusted,
                actual: a.untrusted,
                cap: self.caps.untrusted,
            };
        }
        let total = a.total();
        if total > self.global_cap {
            return QuotaDecision::ExceedTotal {
                actual: total,
                cap: self.global_cap,
                actuals: a,
            };
        }
        QuotaDecision::Allow { actuals: a }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QuotaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QuotaError::SchemaMismatch);
        }
        if self.global_cap == 0 {
            return Err(QuotaError::GlobalZero);
        }
        if self.caps.system == 0 {
            return Err(QuotaError::ClassZero(SegmentClass::System));
        }
        if self.caps.operator == 0 {
            return Err(QuotaError::ClassZero(SegmentClass::Operator));
        }
        if self.caps.persistent == 0 {
            return Err(QuotaError::ClassZero(SegmentClass::Persistent));
        }
        if self.caps.tool == 0 {
            return Err(QuotaError::ClassZero(SegmentClass::Tool));
        }
        if self.caps.untrusted == 0 {
            return Err(QuotaError::ClassZero(SegmentClass::Untrusted));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(id: &str, class: SegmentClass, tokens: u32) -> Segment {
        Segment {
            id: id.into(),
            class,
            tokens,
        }
    }

    #[test]
    fn canonical_validates() {
        PromptContextQuota::canonical().validate().unwrap();
    }

    #[test]
    fn under_caps_allows() {
        let p = PromptContextQuota::canonical();
        let d = p.assemble(&[
            seg("s", SegmentClass::System, 500),
            seg("o", SegmentClass::Operator, 1000),
        ]);
        assert!(matches!(d, QuotaDecision::Allow { .. }));
    }

    #[test]
    fn exceed_class_reported() {
        let p = PromptContextQuota::canonical();
        let d = p.assemble(&[seg("u", SegmentClass::Untrusted, 99_999)]);
        assert!(matches!(
            d,
            QuotaDecision::ExceedClass {
                class: SegmentClass::Untrusted,
                ..
            }
        ));
    }

    #[test]
    fn exceed_total_reported() {
        let mut p = PromptContextQuota::canonical();
        p.caps.tool = 50_000;
        let d = p.assemble(&[
            seg("t", SegmentClass::Tool, 40_000),
            seg("u", SegmentClass::Untrusted, 1_000),
        ]);
        // 41k > 32k global.
        assert!(matches!(d, QuotaDecision::ExceedTotal { .. }));
    }

    #[test]
    fn sum_correct() {
        let p = PromptContextQuota::canonical();
        let a = p.sum(&[
            seg("s", SegmentClass::System, 100),
            seg("o", SegmentClass::Operator, 200),
            seg("t", SegmentClass::Tool, 300),
        ]);
        assert_eq!(a.system, 100);
        assert_eq!(a.tool, 300);
        assert_eq!(a.total(), 600);
    }

    #[test]
    fn empty_segments_allows() {
        let p = PromptContextQuota::canonical();
        let d = p.assemble(&[]);
        assert!(matches!(d, QuotaDecision::Allow { .. }));
    }

    #[test]
    fn class_cap_zero_rejected() {
        let mut p = PromptContextQuota::canonical();
        p.caps.system = 0;
        assert!(matches!(
            p.validate().unwrap_err(),
            QuotaError::ClassZero(SegmentClass::System)
        ));
    }

    #[test]
    fn global_cap_zero_rejected() {
        let mut p = PromptContextQuota::canonical();
        p.global_cap = 0;
        assert!(matches!(p.validate().unwrap_err(), QuotaError::GlobalZero));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PromptContextQuota::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            QuotaError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&SegmentClass::Persistent).unwrap(),
            "\"persistent\""
        );
    }

    #[test]
    fn decision_serde_kebab() {
        let d = QuotaDecision::ExceedClass {
            class: SegmentClass::Tool,
            actual: 100,
            cap: 50,
        };
        let j = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"kind\":\"exceed-class\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = PromptContextQuota::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: PromptContextQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
