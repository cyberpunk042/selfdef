//! `selfdef-recursion-guard` — bounded-depth + cycle tracker.
//!
//! enter(frame_id) pushes; leave pops. Two rejections:
//!   - DepthExceeded if push would exceed max_depth.
//!   - CycleDetected if frame_id is already on the stack.
//! Both are observed without mutating state (caller can retry or
//! abort). depth() returns current size. Suitable for nested IPS
//! rule evaluation where cycles or runaway recursion must be a
//! hard fault.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursionGuard {
    /// Schema version.
    pub schema_version: String,
    /// Max depth.
    pub max_depth: u32,
    /// Stack (bottom→top).
    pub stack: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GuardError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero depth.
    #[error("max_depth must be >= 1")]
    ZeroDepth,
    /// Depth exceeded.
    #[error("depth exceeded: {0}")]
    DepthExceeded(u32),
    /// Cycle.
    #[error("cycle on frame: {0}")]
    CycleDetected(String),
    /// Empty.
    #[error("frame id empty")]
    EmptyFrame,
    /// Underflow.
    #[error("leave on empty stack")]
    Underflow,
}

impl RecursionGuard {
    /// New.
    pub fn new(max_depth: u32) -> Result<Self, GuardError> {
        if max_depth == 0 {
            return Err(GuardError::ZeroDepth);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            max_depth,
            stack: Vec::new(),
        })
    }

    /// Enter a frame.
    pub fn enter(&mut self, frame_id: &str) -> Result<(), GuardError> {
        if frame_id.is_empty() {
            return Err(GuardError::EmptyFrame);
        }
        if self.stack.len() + 1 > self.max_depth as usize {
            return Err(GuardError::DepthExceeded(self.max_depth));
        }
        if self.stack.iter().any(|f| f == frame_id) {
            return Err(GuardError::CycleDetected(frame_id.into()));
        }
        self.stack.push(frame_id.into());
        Ok(())
    }

    /// Leave a frame.
    pub fn leave(&mut self) -> Result<(), GuardError> {
        if self.stack.pop().is_none() {
            return Err(GuardError::Underflow);
        }
        Ok(())
    }

    /// Depth.
    pub fn depth(&self) -> u32 {
        self.stack.len() as u32
    }

    /// Contains.
    pub fn contains(&self, frame_id: &str) -> bool {
        self.stack.iter().any(|f| f == frame_id)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GuardError::SchemaMismatch);
        }
        if self.max_depth == 0 {
            return Err(GuardError::ZeroDepth);
        }
        if self.stack.len() > self.max_depth as usize {
            return Err(GuardError::DepthExceeded(self.max_depth));
        }
        for f in &self.stack {
            if f.is_empty() {
                return Err(GuardError::EmptyFrame);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_and_leave() {
        let mut g = RecursionGuard::new(5).unwrap();
        g.enter("a").unwrap();
        g.enter("b").unwrap();
        assert_eq!(g.depth(), 2);
        g.leave().unwrap();
        assert_eq!(g.depth(), 1);
    }

    #[test]
    fn depth_exceeded() {
        let mut g = RecursionGuard::new(2).unwrap();
        g.enter("a").unwrap();
        g.enter("b").unwrap();
        assert!(matches!(
            g.enter("c").unwrap_err(),
            GuardError::DepthExceeded(2)
        ));
        // State unchanged.
        assert_eq!(g.depth(), 2);
    }

    #[test]
    fn cycle_detected() {
        let mut g = RecursionGuard::new(5).unwrap();
        g.enter("a").unwrap();
        g.enter("b").unwrap();
        assert!(matches!(
            g.enter("a").unwrap_err(),
            GuardError::CycleDetected(_)
        ));
        assert_eq!(g.depth(), 2);
    }

    #[test]
    fn underflow_rejected() {
        let mut g = RecursionGuard::new(5).unwrap();
        assert!(matches!(g.leave().unwrap_err(), GuardError::Underflow));
    }

    #[test]
    fn empty_frame_rejected() {
        let mut g = RecursionGuard::new(5).unwrap();
        assert!(matches!(g.enter("").unwrap_err(), GuardError::EmptyFrame));
    }

    #[test]
    fn zero_depth_rejected() {
        assert!(matches!(
            RecursionGuard::new(0).unwrap_err(),
            GuardError::ZeroDepth
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = RecursionGuard::new(5).unwrap();
        g.schema_version = "9.9.9".into();
        assert!(matches!(
            g.validate().unwrap_err(),
            GuardError::SchemaMismatch
        ));
    }

    #[test]
    fn guard_serde_roundtrip() {
        let mut g = RecursionGuard::new(5).unwrap();
        g.enter("a").unwrap();
        g.enter("b").unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: RecursionGuard = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
