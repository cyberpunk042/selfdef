//! `selfdef-line-diff` — LCS line-by-line diff.
//!
//! Op{Keep(line)/Add(line)/Del(line)}. diff(a, b) computes the
//! sequence of operations to turn `a` into `b` using a simple
//! O(N*M) LCS table. Output preserves stable order.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "op", content = "line")]
pub enum Op {
    /// Keep (common line).
    Keep(String),
    /// Add (only in b).
    Add(String),
    /// Del (only in a).
    Del(String),
}

/// Versioned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineDiff {
    /// Schema version.
    pub schema_version: String,
    /// Last computed ops.
    pub last_ops: Vec<Op>,
    /// Diffs computed.
    pub diffs: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DiffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Compute LCS-based diff between two line lists.
pub fn diff(a: &[String], b: &[String]) -> Vec<Op> {
    let n = a.len();
    let m = b.len();
    // LCS DP table.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in 0..n {
        for j in 0..m {
            dp[i + 1][j + 1] = if a[i] == b[j] {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    // Walk back.
    let mut ops_rev: Vec<Op> = Vec::new();
    let mut i = n;
    let mut j = m;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            ops_rev.push(Op::Keep(a[i - 1].clone()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            ops_rev.push(Op::Add(b[j - 1].clone()));
            j -= 1;
        } else {
            ops_rev.push(Op::Del(a[i - 1].clone()));
            i -= 1;
        }
    }
    ops_rev.reverse();
    ops_rev
}

impl LineDiff {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last_ops: Vec::new(),
            diffs: 0,
        }
    }

    /// Diff + store.
    pub fn diff_and_store(&mut self, a: &[String], b: &[String]) -> &[Op] {
        self.last_ops = diff(a, b);
        self.diffs = self.diffs.saturating_add(1);
        &self.last_ops
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DiffError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DiffError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for LineDiff {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identical_inputs_all_keep() {
        let a = lines(&["a", "b", "c"]);
        let ops = diff(&a, &a);
        assert!(ops.iter().all(|op| matches!(op, Op::Keep(_))));
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn pure_add() {
        let a = lines(&[]);
        let b = lines(&["x", "y"]);
        let ops = diff(&a, &b);
        assert_eq!(ops, vec![Op::Add("x".into()), Op::Add("y".into())]);
    }

    #[test]
    fn pure_del() {
        let a = lines(&["x", "y"]);
        let b = lines(&[]);
        let ops = diff(&a, &b);
        assert_eq!(ops, vec![Op::Del("x".into()), Op::Del("y".into())]);
    }

    #[test]
    fn mixed_diff() {
        let a = lines(&["a", "b", "c"]);
        let b = lines(&["a", "c", "d"]);
        let ops = diff(&a, &b);
        // Expect: Keep(a) Del(b) Keep(c) Add(d).
        assert_eq!(ops, vec![
            Op::Keep("a".into()),
            Op::Del("b".into()),
            Op::Keep("c".into()),
            Op::Add("d".into()),
        ]);
    }

    #[test]
    fn replace_block() {
        let a = lines(&["a", "x", "y", "b"]);
        let b = lines(&["a", "p", "q", "b"]);
        let ops = diff(&a, &b);
        let keeps = ops.iter().filter(|op| matches!(op, Op::Keep(_))).count();
        assert_eq!(keeps, 2);
    }

    #[test]
    fn state_stores_last_ops() {
        let mut d = LineDiff::new();
        d.diff_and_store(&lines(&["a"]), &lines(&["b"]));
        assert_eq!(d.diffs, 1);
        assert_eq!(d.last_ops.len(), 2);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = LineDiff::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DiffError::SchemaMismatch));
    }

    #[test]
    fn diff_serde_roundtrip() {
        let mut d = LineDiff::new();
        d.diff_and_store(&lines(&["a", "b"]), &lines(&["a", "c"]));
        let j = serde_json::to_string(&d).unwrap();
        let back: LineDiff = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
