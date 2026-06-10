//! `selfdef-ring-buffer` — fixed-capacity u64 ring.
//!
//! capacity N. push(x) appends; when full, overwrites oldest.
//! samples() yields chronological order. mean/min/max/last
//! over current contents.
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
pub struct RingBuffer {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Underlying samples (length 0..=capacity).
    pub buf: Vec<u64>,
    /// Head index in chronological order.
    pub head: u32,
    /// Total pushes ever.
    pub pushes: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BufferError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
}

impl RingBuffer {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, BufferError> {
        if capacity == 0 {
            return Err(BufferError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            buf: Vec::with_capacity(capacity as usize),
            head: 0,
            pushes: 0,
        })
    }

    /// Push a sample.
    pub fn push(&mut self, x: u64) {
        // new()/validate() reject capacity==0, but serde deserialization can
        // set it directly; the wrap branch's `% self.capacity` would then panic
        // in every build (integer mod-by-zero is never masked). A zero-capacity
        // buffer can store nothing — no-op rather than crash.
        if self.capacity == 0 {
            return;
        }
        if (self.buf.len() as u32) < self.capacity {
            self.buf.push(x);
        } else {
            // head is advanced only via `% capacity`, so it stays < buf.len()
            // under normal use — but serde can persist head >= buf.len(). The
            // index below would then panic (out-of-bounds, every build).
            // Normalize a corrupt head back to 0 before indexing.
            if self.head as usize >= self.buf.len() {
                self.head = 0;
            }
            let idx = self.head as usize;
            self.buf[idx] = x;
            self.head = (self.head + 1) % self.capacity;
        }
        self.pushes = self.pushes.saturating_add(1);
    }

    /// Samples in chronological order (oldest → newest).
    pub fn samples(&self) -> Vec<u64> {
        if (self.buf.len() as u32) < self.capacity {
            self.buf.clone()
        } else {
            let n = self.capacity as usize;
            let h = self.head as usize;
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                out.push(self.buf[(h + i) % n]);
            }
            out
        }
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Mean (None when empty).
    pub fn mean(&self) -> Option<u64> {
        if self.buf.is_empty() {
            return None;
        }
        let sum: u128 = self.buf.iter().map(|x| *x as u128).sum();
        Some((sum / self.buf.len() as u128) as u64)
    }

    /// Min.
    pub fn min(&self) -> Option<u64> {
        self.buf.iter().min().copied()
    }

    /// Max.
    pub fn max(&self) -> Option<u64> {
        self.buf.iter().max().copied()
    }

    /// Last pushed (newest).
    pub fn last(&self) -> Option<u64> {
        if self.buf.is_empty() {
            return None;
        }
        if (self.buf.len() as u32) < self.capacity {
            self.buf.last().copied()
        } else {
            let n = self.capacity as usize;
            let h = self.head as usize;
            Some(self.buf[(h + n - 1) % n])
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BufferError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BufferError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(BufferError::ZeroCapacity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_head_serde_bypass_does_not_panic() {
        // head is advanced only via `% capacity`, staying < buf.len(); serde can
        // persist head >= buf.len(). push()'s wrap branch indexes self.buf[head]
        // — an OOB panic in every build. The normalize-to-0 guard prevents it.
        let mut b = RingBuffer {
            schema_version: SCHEMA_VERSION.into(),
            capacity: 3,
            buf: vec![1, 2, 3], // full → push takes the wrap branch
            head: 99,           // serde-bypassed, way past buf.len()
            pushes: 3,
        };
        b.push(7); // must not panic
        assert!(b.samples().contains(&7));
    }

    #[test]
    fn zero_capacity_serde_bypass_does_not_panic() {
        // new()/validate() reject capacity==0, but serde can construct it. The
        // wrap branch's `% self.capacity` would panic in every build. Guard
        // makes push a no-op instead of crashing.
        let mut b = RingBuffer {
            schema_version: SCHEMA_VERSION.into(),
            capacity: 0,
            buf: vec![1, 2, 3], // non-empty to force the wrap branch
            head: 0,
            pushes: 0,
        };
        b.push(9); // must not panic
    }

    #[test]
    fn under_capacity() {
        let mut r = RingBuffer::new(5).unwrap();
        r.push(1);
        r.push(2);
        r.push(3);
        assert_eq!(r.samples(), vec![1, 2, 3]);
        assert_eq!(r.last(), Some(3));
    }

    #[test]
    fn over_capacity_overwrites_oldest() {
        let mut r = RingBuffer::new(3).unwrap();
        r.push(1);
        r.push(2);
        r.push(3);
        r.push(4);
        r.push(5);
        assert_eq!(r.samples(), vec![3, 4, 5]);
        assert_eq!(r.last(), Some(5));
        assert_eq!(r.pushes, 5);
    }

    #[test]
    fn mean_min_max() {
        let mut r = RingBuffer::new(5).unwrap();
        for x in &[10, 20, 30, 40, 50] {
            r.push(*x);
        }
        assert_eq!(r.mean(), Some(30));
        assert_eq!(r.min(), Some(10));
        assert_eq!(r.max(), Some(50));
    }

    #[test]
    fn empty_aggregates_none() {
        let r = RingBuffer::new(5).unwrap();
        assert!(r.mean().is_none());
        assert!(r.min().is_none());
        assert!(r.max().is_none());
        assert!(r.last().is_none());
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            RingBuffer::new(0).unwrap_err(),
            BufferError::ZeroCapacity
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = RingBuffer::new(3).unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            BufferError::SchemaMismatch
        ));
    }

    #[test]
    fn ring_serde_roundtrip() {
        let mut r = RingBuffer::new(3).unwrap();
        r.push(1);
        r.push(2);
        r.push(3);
        r.push(4);
        let j = serde_json::to_string(&r).unwrap();
        let back: RingBuffer = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
