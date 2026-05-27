//! `selfdef-resource-reservation` — pre-action reservations.
//!
//! Per resource: a `Pool { capacity, held }`. `reserve(resource_id,
//! units, ts)` returns a Reservation id when capacity allows.
//! `commit(reservation_id)` consumes — capacity stays held but is no
//! longer pending. `abandon(reservation_id)` releases. `expire(now,
//! max_age_ms)` drops reservations older than `max_age_ms`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One reservation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    /// Reservation id.
    pub id: u64,
    /// Resource id.
    pub resource_id: String,
    /// Units.
    pub units: u64,
    /// Reserved at.
    pub reserved_at_ms: u64,
    /// Committed?
    pub committed: bool,
}

/// Per-resource pool.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pool {
    /// Capacity.
    pub capacity: u64,
    /// Held units (both pending + committed).
    pub held: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceReservation {
    /// Schema version.
    pub schema_version: String,
    /// resource → pool.
    pub pools: BTreeMap<String, Pool>,
    /// reservation id → reservation.
    pub reservations: BTreeMap<u64, Reservation>,
    /// Next id.
    pub next_id: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReservationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty resource.
    #[error("resource id empty")]
    EmptyResource,
    /// Unknown resource.
    #[error("unknown resource: {0}")]
    UnknownResource(String),
    /// Insufficient capacity.
    #[error("insufficient capacity: requested {0}, free {1}")]
    Insufficient(u64, u64),
    /// Unknown reservation.
    #[error("unknown reservation: {0}")]
    UnknownReservation(u64),
}

impl ResourceReservation {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pools: BTreeMap::new(),
            reservations: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Register a pool.
    pub fn set_capacity(
        &mut self,
        resource_id: &str,
        capacity: u64,
    ) -> Result<(), ReservationError> {
        if resource_id.is_empty() {
            return Err(ReservationError::EmptyResource);
        }
        let held = self.pools.get(resource_id).map(|p| p.held).unwrap_or(0);
        self.pools
            .insert(resource_id.into(), Pool { capacity, held });
        Ok(())
    }

    /// Reserve.
    pub fn reserve(
        &mut self,
        resource_id: &str,
        units: u64,
        ts_ms: u64,
    ) -> Result<u64, ReservationError> {
        let pool = self
            .pools
            .get_mut(resource_id)
            .ok_or_else(|| ReservationError::UnknownResource(resource_id.into()))?;
        let free = pool.capacity.saturating_sub(pool.held);
        if units > free {
            return Err(ReservationError::Insufficient(units, free));
        }
        pool.held = pool.held.saturating_add(units);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.reservations.insert(
            id,
            Reservation {
                id,
                resource_id: resource_id.into(),
                units,
                reserved_at_ms: ts_ms,
                committed: false,
            },
        );
        Ok(id)
    }

    /// Commit.
    pub fn commit(&mut self, reservation_id: u64) -> Result<(), ReservationError> {
        let r = self
            .reservations
            .get_mut(&reservation_id)
            .ok_or(ReservationError::UnknownReservation(reservation_id))?;
        r.committed = true;
        Ok(())
    }

    /// Abandon.
    pub fn abandon(&mut self, reservation_id: u64) -> Result<(), ReservationError> {
        let r = self
            .reservations
            .remove(&reservation_id)
            .ok_or(ReservationError::UnknownReservation(reservation_id))?;
        if let Some(p) = self.pools.get_mut(&r.resource_id) {
            p.held = p.held.saturating_sub(r.units);
        }
        Ok(())
    }

    /// Expire stale reservations (not yet committed).
    pub fn expire(&mut self, now_ms: u64, max_age_ms: u64) -> usize {
        let stale_ids: Vec<u64> = self
            .reservations
            .iter()
            .filter(|(_, r)| !r.committed && now_ms.saturating_sub(r.reserved_at_ms) > max_age_ms)
            .map(|(id, _)| *id)
            .collect();
        let mut count = 0;
        for id in stale_ids {
            if self.abandon(id).is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ReservationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReservationError::SchemaMismatch);
        }
        for k in self.pools.keys() {
            if k.is_empty() {
                return Err(ReservationError::EmptyResource);
            }
        }
        Ok(())
    }
}

impl Default for ResourceReservation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_commit() {
        let mut r = ResourceReservation::new();
        r.set_capacity("disk", 1000).unwrap();
        let id = r.reserve("disk", 300, 0).unwrap();
        r.commit(id).unwrap();
        assert_eq!(r.pools["disk"].held, 300);
    }

    #[test]
    fn abandon_releases() {
        let mut r = ResourceReservation::new();
        r.set_capacity("disk", 1000).unwrap();
        let id = r.reserve("disk", 300, 0).unwrap();
        r.abandon(id).unwrap();
        assert_eq!(r.pools["disk"].held, 0);
    }

    #[test]
    fn insufficient_rejected() {
        let mut r = ResourceReservation::new();
        r.set_capacity("disk", 100).unwrap();
        assert!(matches!(
            r.reserve("disk", 200, 0).unwrap_err(),
            ReservationError::Insufficient(_, _)
        ));
    }

    #[test]
    fn unknown_resource() {
        let mut r = ResourceReservation::new();
        assert!(matches!(
            r.reserve("nope", 1, 0).unwrap_err(),
            ReservationError::UnknownResource(_)
        ));
    }

    #[test]
    fn unknown_reservation() {
        let mut r = ResourceReservation::new();
        assert!(matches!(
            r.commit(999).unwrap_err(),
            ReservationError::UnknownReservation(_)
        ));
    }

    #[test]
    fn expire_drops_stale_uncommitted() {
        let mut r = ResourceReservation::new();
        r.set_capacity("disk", 1000).unwrap();
        let _id = r.reserve("disk", 100, 0).unwrap();
        let committed = r.reserve("disk", 200, 0).unwrap();
        r.commit(committed).unwrap();
        let n = r.expire(10_000, 1000);
        assert_eq!(n, 1);
        // Committed reservation survives.
        assert_eq!(r.pools["disk"].held, 200);
    }

    #[test]
    fn set_capacity_preserves_held() {
        let mut r = ResourceReservation::new();
        r.set_capacity("disk", 100).unwrap();
        r.reserve("disk", 50, 0).unwrap();
        r.set_capacity("disk", 1000).unwrap();
        assert_eq!(r.pools["disk"].held, 50);
    }

    #[test]
    fn empty_resource_rejected() {
        let mut r = ResourceReservation::new();
        assert!(matches!(
            r.set_capacity("", 1).unwrap_err(),
            ReservationError::EmptyResource
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ResourceReservation::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            ReservationError::SchemaMismatch
        ));
    }

    #[test]
    fn reservation_serde_roundtrip() {
        let mut r = ResourceReservation::new();
        r.set_capacity("disk", 1000).unwrap();
        r.reserve("disk", 100, 0).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ResourceReservation = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
