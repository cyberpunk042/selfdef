//! `selfdef-operator-approval-queue` — pending approvals.
//!
//! Each `Item { id, summary, submitted_at_ms, deadline_ms, priority,
//! status }` waits for an operator to `approve` or `reject`. Items
//! past their deadline transition to `Expired` automatically when
//! queried; this state is durable on disk only after `mark_expired_
//! at(now)` runs.
//!
//! Operations:
//!   * `submit(item)` — enqueue.
//!   * `approve(id, ts, reviewer)` / `reject(id, ts, reviewer, reason)`.
//!   * `mark_expired_at(now)` — advance Expired status for overdue
//!     pending items.
//!   * `pending()` — items still pending, ordered by priority desc
//!     then submitted_at asc.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Priority (higher numeric = more urgent).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Low.
    Low,
    /// Normal.
    Normal,
    /// High.
    High,
    /// Urgent.
    Urgent,
}

/// Lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Status {
    /// Pending operator action.
    Pending,
    /// Approved.
    Approved {
        /// reviewer.
        reviewer: String,
        /// when.
        at_ms: u64,
    },
    /// Rejected.
    Rejected {
        /// reviewer.
        reviewer: String,
        /// when.
        at_ms: u64,
        /// reason.
        reason: String,
    },
    /// Expired.
    Expired {
        /// when marked expired.
        at_ms: u64,
    },
}

/// One item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {
    /// Id.
    pub id: String,
    /// Operator-visible summary.
    pub summary: String,
    /// Submitted ts.
    pub submitted_at_ms: u64,
    /// Deadline ts.
    pub deadline_ms: u64,
    /// Priority.
    pub priority: Priority,
    /// Status.
    pub status: Status,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorApprovalQueue {
    /// Schema version.
    pub schema_version: String,
    /// id → item.
    pub items: BTreeMap<String, Item>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ApprovalError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Empty summary.
    #[error("summary empty")]
    EmptySummary,
    /// Empty reviewer.
    #[error("reviewer empty")]
    EmptyReviewer,
    /// Empty reason.
    #[error("reason empty")]
    EmptyReason,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown item: {0}")]
    UnknownItem(String),
    /// Already resolved.
    #[error("item {0} not pending")]
    NotPending(String),
}

impl OperatorApprovalQueue {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            items: BTreeMap::new(),
        }
    }

    /// Submit.
    pub fn submit(
        &mut self,
        id: &str,
        summary: &str,
        submitted_at_ms: u64,
        deadline_ms: u64,
        priority: Priority,
    ) -> Result<(), ApprovalError> {
        if id.is_empty() {
            return Err(ApprovalError::EmptyId);
        }
        if summary.is_empty() {
            return Err(ApprovalError::EmptySummary);
        }
        if self.items.contains_key(id) {
            return Err(ApprovalError::DuplicateId(id.into()));
        }
        self.items.insert(
            id.into(),
            Item {
                id: id.into(),
                summary: summary.into(),
                submitted_at_ms,
                deadline_ms,
                priority,
                status: Status::Pending,
            },
        );
        Ok(())
    }

    /// Approve.
    pub fn approve(&mut self, id: &str, reviewer: &str, at_ms: u64) -> Result<(), ApprovalError> {
        if reviewer.is_empty() {
            return Err(ApprovalError::EmptyReviewer);
        }
        let item = self
            .items
            .get_mut(id)
            .ok_or_else(|| ApprovalError::UnknownItem(id.into()))?;
        if !matches!(item.status, Status::Pending) {
            return Err(ApprovalError::NotPending(id.into()));
        }
        item.status = Status::Approved {
            reviewer: reviewer.into(),
            at_ms,
        };
        Ok(())
    }

    /// Reject.
    pub fn reject(
        &mut self,
        id: &str,
        reviewer: &str,
        at_ms: u64,
        reason: &str,
    ) -> Result<(), ApprovalError> {
        if reviewer.is_empty() {
            return Err(ApprovalError::EmptyReviewer);
        }
        if reason.is_empty() {
            return Err(ApprovalError::EmptyReason);
        }
        let item = self
            .items
            .get_mut(id)
            .ok_or_else(|| ApprovalError::UnknownItem(id.into()))?;
        if !matches!(item.status, Status::Pending) {
            return Err(ApprovalError::NotPending(id.into()));
        }
        item.status = Status::Rejected {
            reviewer: reviewer.into(),
            at_ms,
            reason: reason.into(),
        };
        Ok(())
    }

    /// Mark overdue items Expired (irreversible).
    pub fn mark_expired_at(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for item in self.items.values_mut() {
            if matches!(item.status, Status::Pending) && now_ms > item.deadline_ms {
                item.status = Status::Expired { at_ms: now_ms };
                n += 1;
            }
        }
        n
    }

    /// Pending list, ordered priority desc then submitted asc.
    pub fn pending(&self) -> Vec<Item> {
        let mut v: Vec<Item> = self
            .items
            .values()
            .filter(|i| matches!(i.status, Status::Pending))
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.submitted_at_ms.cmp(&b.submitted_at_ms))
        });
        v
    }

    /// Get.
    pub fn get(&self, id: &str) -> Option<&Item> {
        self.items.get(id)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ApprovalError::SchemaMismatch);
        }
        for (id, item) in &self.items {
            if id.is_empty() {
                return Err(ApprovalError::EmptyId);
            }
            if item.summary.is_empty() {
                return Err(ApprovalError::EmptySummary);
            }
        }
        Ok(())
    }
}

impl Default for OperatorApprovalQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_and_approve() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "thing", 0, 1000, Priority::Normal).unwrap();
        q.approve("a", "alice", 100).unwrap();
        match &q.get("a").unwrap().status {
            Status::Approved { reviewer, .. } => assert_eq!(reviewer, "alice"),
            _ => panic!(),
        }
    }

    #[test]
    fn reject_with_reason() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "x", 0, 1000, Priority::Normal).unwrap();
        q.reject("a", "alice", 100, "too risky").unwrap();
        match &q.get("a").unwrap().status {
            Status::Rejected { reason, .. } => assert_eq!(reason, "too risky"),
            _ => panic!(),
        }
    }

    #[test]
    fn double_resolve_rejected() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "x", 0, 1000, Priority::Normal).unwrap();
        q.approve("a", "alice", 100).unwrap();
        assert!(matches!(
            q.reject("a", "alice", 200, "x").unwrap_err(),
            ApprovalError::NotPending(_)
        ));
    }

    #[test]
    fn expire_after_deadline() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "x", 0, 1000, Priority::Normal).unwrap();
        let n = q.mark_expired_at(2000);
        assert_eq!(n, 1);
        assert!(matches!(q.get("a").unwrap().status, Status::Expired { .. }));
    }

    #[test]
    fn pending_priority_order() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "x", 100, 99999, Priority::Low).unwrap();
        q.submit("b", "x", 200, 99999, Priority::Urgent).unwrap();
        q.submit("c", "x", 300, 99999, Priority::Normal).unwrap();
        let p = q.pending();
        assert_eq!(p[0].id, "b"); // urgent
        assert_eq!(p[1].id, "c"); // normal
        assert_eq!(p[2].id, "a"); // low
    }

    #[test]
    fn pending_ties_broken_by_submit_time() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("late", "x", 200, 99999, Priority::Normal).unwrap();
        q.submit("early", "x", 100, 99999, Priority::Normal)
            .unwrap();
        let p = q.pending();
        assert_eq!(p[0].id, "early");
    }

    #[test]
    fn duplicate_rejected() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "x", 0, 1, Priority::Normal).unwrap();
        assert!(matches!(
            q.submit("a", "x", 0, 1, Priority::Normal).unwrap_err(),
            ApprovalError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut q = OperatorApprovalQueue::new();
        assert!(matches!(
            q.submit("", "x", 0, 1, Priority::Normal).unwrap_err(),
            ApprovalError::EmptyId
        ));
        assert!(matches!(
            q.submit("a", "", 0, 1, Priority::Normal).unwrap_err(),
            ApprovalError::EmptySummary
        ));
        q.submit("a", "x", 0, 1, Priority::Normal).unwrap();
        assert!(matches!(
            q.approve("a", "", 0).unwrap_err(),
            ApprovalError::EmptyReviewer
        ));
        assert!(matches!(
            q.reject("a", "r", 0, "").unwrap_err(),
            ApprovalError::EmptyReason
        ));
    }

    #[test]
    fn approve_unknown_rejected() {
        let mut q = OperatorApprovalQueue::new();
        assert!(matches!(
            q.approve("nope", "r", 0).unwrap_err(),
            ApprovalError::UnknownItem(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = OperatorApprovalQueue::new();
        q.schema_version = "9.9.9".into();
        assert!(matches!(
            q.validate().unwrap_err(),
            ApprovalError::SchemaMismatch
        ));
    }

    #[test]
    fn approval_serde_roundtrip() {
        let mut q = OperatorApprovalQueue::new();
        q.submit("a", "x", 0, 1000, Priority::Urgent).unwrap();
        q.approve("a", "alice", 100).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: OperatorApprovalQueue = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
