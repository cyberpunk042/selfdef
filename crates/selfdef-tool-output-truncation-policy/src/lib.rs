//! `selfdef-tool-output-truncation-policy` — tool-output IPS gate.
//!
//! Each tool class declares a per-call byte budget and a truncation
//! strategy: HeadOnly (keep first N), HeadTail (split between first
//! and last halves), MiddleEllipsis (keep first + last, drop
//! middle). truncate() applies the strategy and returns a
//! TruncationReceipt {kept_bytes, dropped_bytes, strategy}.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Truncation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    /// Keep the first `budget_bytes`.
    HeadOnly,
    /// Keep first half + last half of budget.
    HeadTail,
    /// Keep first 20% + last 20% of budget; middle replaced by " … ".
    MiddleEllipsis,
}

/// One tool class config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolBudget {
    /// Max bytes after truncation.
    pub budget_bytes: u32,
    /// Strategy.
    pub strategy: Strategy,
}

/// Per-call receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TruncationReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Bytes kept.
    pub kept_bytes: u32,
    /// Bytes dropped.
    pub dropped_bytes: u32,
    /// Strategy used (no-op if input was already under budget).
    pub strategy: Strategy,
    /// True when no truncation was needed.
    pub no_op: bool,
}

/// Tool class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolClass {
    /// Read-only filesystem (e.g., ls / cat / grep).
    FsRead,
    /// File-system write.
    FsWrite,
    /// Network IO.
    Net,
    /// Shell exec.
    Shell,
    /// LLM call.
    Llm,
    /// Other.
    Other,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolOutputTruncationPolicy {
    /// Schema version.
    pub schema_version: String,
    /// fs-read budget.
    pub fs_read: ToolBudget,
    /// fs-write budget.
    pub fs_write: ToolBudget,
    /// net budget.
    pub net: ToolBudget,
    /// shell budget.
    pub shell: ToolBudget,
    /// llm budget.
    pub llm: ToolBudget,
    /// fallback budget.
    pub other: ToolBudget,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TruncationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Budget too small for strategy.
    #[error("class {0:?} budget {1} too small")]
    BudgetTooSmall(ToolClass, u32),
}

impl ToolOutputTruncationPolicy {
    /// Canonical defaults (in bytes):
    /// FsRead 64 KiB HeadTail, FsWrite 8 KiB HeadOnly, Net 32 KiB
    /// HeadTail, Shell 16 KiB HeadTail, Llm 128 KiB MiddleEllipsis,
    /// Other 8 KiB HeadOnly.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            fs_read: ToolBudget { budget_bytes: 64 * 1024, strategy: Strategy::HeadTail },
            fs_write: ToolBudget { budget_bytes: 8 * 1024, strategy: Strategy::HeadOnly },
            net: ToolBudget { budget_bytes: 32 * 1024, strategy: Strategy::HeadTail },
            shell: ToolBudget { budget_bytes: 16 * 1024, strategy: Strategy::HeadTail },
            llm: ToolBudget { budget_bytes: 128 * 1024, strategy: Strategy::MiddleEllipsis },
            other: ToolBudget { budget_bytes: 8 * 1024, strategy: Strategy::HeadOnly },
        }
    }

    /// Get config by tool class.
    pub fn budget(&self, class: ToolClass) -> ToolBudget {
        match class {
            ToolClass::FsRead => self.fs_read,
            ToolClass::FsWrite => self.fs_write,
            ToolClass::Net => self.net,
            ToolClass::Shell => self.shell,
            ToolClass::Llm => self.llm,
            ToolClass::Other => self.other,
        }
    }

    /// Apply truncation. Returns (truncated_text, receipt).
    pub fn truncate(&self, class: ToolClass, input: &str) -> (String, TruncationReceipt) {
        let b = self.budget(class);
        let n = input.len() as u32;
        if n <= b.budget_bytes {
            return (
                input.to_string(),
                TruncationReceipt {
                    schema_version: SCHEMA_VERSION.into(),
                    kept_bytes: n,
                    dropped_bytes: 0,
                    strategy: b.strategy,
                    no_op: true,
                },
            );
        }
        let bytes = input.as_bytes();
        let cap = b.budget_bytes as usize;
        let kept: String = match b.strategy {
            Strategy::HeadOnly => take_utf8(bytes, 0..cap),
            Strategy::HeadTail => {
                let half = cap / 2;
                let head = take_utf8(bytes, 0..half);
                let tail_start = bytes.len() - (cap - half);
                let tail = take_utf8(bytes, tail_start..bytes.len());
                format!("{head}{tail}")
            }
            Strategy::MiddleEllipsis => {
                let side = cap / 5;
                let head = take_utf8(bytes, 0..side);
                let tail_start = bytes.len() - side;
                let tail = take_utf8(bytes, tail_start..bytes.len());
                format!("{head} … {tail}")
            }
        };
        let kept_bytes = kept.len() as u32;
        (
            kept,
            TruncationReceipt {
                schema_version: SCHEMA_VERSION.into(),
                kept_bytes,
                dropped_bytes: n - kept_bytes.min(n),
                strategy: b.strategy,
                no_op: false,
            },
        )
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TruncationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TruncationError::SchemaMismatch);
        }
        for (cls, b) in [
            (ToolClass::FsRead, self.fs_read),
            (ToolClass::FsWrite, self.fs_write),
            (ToolClass::Net, self.net),
            (ToolClass::Shell, self.shell),
            (ToolClass::Llm, self.llm),
            (ToolClass::Other, self.other),
        ] {
            // Need at least 32 bytes per strategy to be sensible.
            if b.budget_bytes < 32 {
                return Err(TruncationError::BudgetTooSmall(cls, b.budget_bytes));
            }
        }
        Ok(())
    }
}

fn take_utf8(bytes: &[u8], range: std::ops::Range<usize>) -> String {
    // Clip range and round down to nearest UTF-8 char boundary on both ends.
    let lo_clip = range.start.min(bytes.len());
    let hi_clip = range.end.min(bytes.len());
    // Move lo forward off any continuation byte.
    let mut lo = lo_clip;
    while lo < hi_clip && (bytes[lo] & 0b1100_0000) == 0b1000_0000 {
        lo += 1;
    }
    // Move hi backward until [lo..hi] is valid UTF-8.
    let mut hi = hi_clip;
    while hi > lo {
        if std::str::from_utf8(&bytes[lo..hi]).is_ok() {
            break;
        }
        hi -= 1;
    }
    std::str::from_utf8(&bytes[lo..hi]).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ToolOutputTruncationPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn under_budget_noop() {
        let p = ToolOutputTruncationPolicy::canonical();
        let (out, r) = p.truncate(ToolClass::Other, "hello");
        assert_eq!(out, "hello");
        assert!(r.no_op);
        assert_eq!(r.dropped_bytes, 0);
    }

    #[test]
    fn head_only_truncates() {
        let mut p = ToolOutputTruncationPolicy::canonical();
        p.other = ToolBudget { budget_bytes: 64, strategy: Strategy::HeadOnly };
        let input = "x".repeat(200);
        let (out, r) = p.truncate(ToolClass::Other, &input);
        assert_eq!(out.len(), 64);
        assert!(!r.no_op);
        assert_eq!(r.dropped_bytes, 200 - 64);
    }

    #[test]
    fn head_tail_truncates_split() {
        let mut p = ToolOutputTruncationPolicy::canonical();
        p.shell = ToolBudget { budget_bytes: 64, strategy: Strategy::HeadTail };
        let input = format!("{}{}", "a".repeat(100), "z".repeat(100));
        let (out, _) = p.truncate(ToolClass::Shell, &input);
        assert_eq!(out.len(), 64);
        assert!(out.starts_with("aaa"));
        assert!(out.ends_with("zzz"));
    }

    #[test]
    fn middle_ellipsis_truncates() {
        let mut p = ToolOutputTruncationPolicy::canonical();
        p.llm = ToolBudget { budget_bytes: 100, strategy: Strategy::MiddleEllipsis };
        let input = format!("{}{}", "a".repeat(200), "z".repeat(200));
        let (out, _) = p.truncate(ToolClass::Llm, &input);
        assert!(out.starts_with("a"));
        assert!(out.ends_with("z"));
        assert!(out.contains("…"));
    }

    #[test]
    fn utf8_boundary_preserved_head_only() {
        let mut p = ToolOutputTruncationPolicy::canonical();
        // Budget that would fall mid-codepoint if not for boundary logic.
        // "abc" = 3 bytes, then 🎉 = 4 bytes. Budget 5 -> rollback to 3.
        p.other = ToolBudget { budget_bytes: 5, strategy: Strategy::HeadOnly };
        let input = "abc🎉xyz";
        let (out, _) = p.truncate(ToolClass::Other, input);
        // Must end at a valid utf-8 boundary (rolled back to "abc").
        assert_eq!(out, "abc");
    }

    #[test]
    fn budget_too_small_rejected() {
        let mut p = ToolOutputTruncationPolicy::canonical();
        p.other = ToolBudget { budget_bytes: 5, strategy: Strategy::HeadOnly };
        assert!(matches!(p.validate().unwrap_err(), TruncationError::BudgetTooSmall(_, 5)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ToolOutputTruncationPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), TruncationError::SchemaMismatch));
    }

    #[test]
    fn strategy_serde_kebab() {
        assert_eq!(serde_json::to_string(&Strategy::HeadOnly).unwrap(), "\"head-only\"");
        assert_eq!(serde_json::to_string(&Strategy::MiddleEllipsis).unwrap(), "\"middle-ellipsis\"");
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&ToolClass::FsRead).unwrap(), "\"fs-read\"");
        assert_eq!(serde_json::to_string(&ToolClass::FsWrite).unwrap(), "\"fs-write\"");
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let p = ToolOutputTruncationPolicy::canonical();
        let (_, r) = p.truncate(ToolClass::Other, &"x".repeat(99_999));
        let j = serde_json::to_string(&r).unwrap();
        let back: TruncationReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = ToolOutputTruncationPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: ToolOutputTruncationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
