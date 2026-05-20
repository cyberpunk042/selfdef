//! `selfdef-delta-pack` — Add/Remove/Update delta between snapshots.
//!
//! diff(old, new) walks two sorted BTreeMap<String, String> in
//! lockstep and emits a Vec<Op> in key-ascending order:
//!   Add{key, value}     for keys in new but not old
//!   Remove{key}         for keys in old but not new
//!   Update{key, value}  for keys in both with differing values
//!   Equal keys with same value emit no op.
//! apply(map, ops) replays ops onto map (Remove on absent key is a
//! no-op; Add on present key overrides — for replay idempotence).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "op")]
pub enum Op {
    /// Add.
    Add {
        /// Key.
        key: String,
        /// Value.
        value: String,
    },
    /// Remove.
    Remove {
        /// Key.
        key: String,
    },
    /// Update.
    Update {
        /// Key.
        key: String,
        /// Value.
        value: String,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum DeltaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// diff produces sorted ops in key-ascending order.
pub fn diff(
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
) -> Vec<Op> {
    let mut out = Vec::new();
    let mut a = old.iter().peekable();
    let mut b = new.iter().peekable();
    loop {
        match (a.peek(), b.peek()) {
            (None, None) => break,
            (Some((k, v)), None) => {
                out.push(Op::Remove { key: (*k).clone() });
                let _ = v;
                a.next();
            }
            (None, Some((k, v))) => {
                out.push(Op::Add { key: (*k).clone(), value: (*v).clone() });
                b.next();
            }
            (Some((ka, va)), Some((kb, vb))) => {
                use std::cmp::Ordering::*;
                match ka.cmp(kb) {
                    Less => {
                        out.push(Op::Remove { key: (*ka).clone() });
                        let _ = va;
                        a.next();
                    }
                    Greater => {
                        out.push(Op::Add { key: (*kb).clone(), value: (*vb).clone() });
                        b.next();
                    }
                    Equal => {
                        if va != vb {
                            out.push(Op::Update { key: (*ka).clone(), value: (*vb).clone() });
                        }
                        a.next();
                        b.next();
                    }
                }
            }
        }
    }
    out
}

/// Replay ops onto a mutable map.
pub fn apply(map: &mut BTreeMap<String, String>, ops: &[Op]) {
    for op in ops {
        match op {
            Op::Add { key, value } => { map.insert(key.clone(), value.clone()); }
            Op::Remove { key } => { map.remove(key); }
            Op::Update { key, value } => { map.insert(key.clone(), value.clone()); }
        }
    }
}

/// Validate.
pub fn validate_schema_version(s: &str) -> Result<(), DeltaError> {
    if s != SCHEMA_VERSION { return Err(DeltaError::SchemaMismatch); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn add_remove_update_classified() {
        let old = m(&[("a", "1"), ("b", "2"), ("c", "3")]);
        let new = m(&[("a", "1"), ("c", "X"), ("d", "4")]);
        let ops = diff(&old, &new);
        assert_eq!(ops, vec![
            Op::Remove { key: "b".into() },
            Op::Update { key: "c".into(), value: "X".into() },
            Op::Add { key: "d".into(), value: "4".into() },
        ]);
    }

    #[test]
    fn no_change_no_ops() {
        let map = m(&[("a", "1"), ("b", "2")]);
        let ops = diff(&map, &map);
        assert!(ops.is_empty());
    }

    #[test]
    fn apply_roundtrip() {
        let old = m(&[("a", "1"), ("b", "2"), ("c", "3")]);
        let new = m(&[("a", "1"), ("c", "X"), ("d", "4")]);
        let ops = diff(&old, &new);
        let mut work = old.clone();
        apply(&mut work, &ops);
        assert_eq!(work, new);
    }

    #[test]
    fn apply_idempotent_on_double_replay() {
        let old = m(&[("a", "1")]);
        let new = m(&[("b", "2")]);
        let ops = diff(&old, &new);
        let mut work = old.clone();
        apply(&mut work, &ops);
        apply(&mut work, &ops);
        assert_eq!(work, new);
    }

    #[test]
    fn empty_to_full_all_adds() {
        let old = m(&[]);
        let new = m(&[("a", "1"), ("b", "2")]);
        let ops = diff(&old, &new);
        assert_eq!(ops.len(), 2);
        assert!(matches!(ops[0], Op::Add { .. }));
    }

    #[test]
    fn full_to_empty_all_removes() {
        let old = m(&[("a", "1"), ("b", "2")]);
        let new = m(&[]);
        let ops = diff(&old, &new);
        assert!(ops.iter().all(|o| matches!(o, Op::Remove { .. })));
    }

    #[test]
    fn schema_check() {
        assert!(validate_schema_version("1.0.0").is_ok());
        assert!(matches!(
            validate_schema_version("9.9.9").unwrap_err(),
            DeltaError::SchemaMismatch
        ));
    }

    #[test]
    fn op_serde_roundtrip() {
        let ops = vec![
            Op::Add { key: "a".into(), value: "1".into() },
            Op::Remove { key: "b".into() },
            Op::Update { key: "c".into(), value: "x".into() },
        ];
        let j = serde_json::to_string(&ops).unwrap();
        let back: Vec<Op> = serde_json::from_str(&j).unwrap();
        assert_eq!(ops, back);
    }
}
