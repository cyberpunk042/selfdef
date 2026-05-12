//! Schema and event envelope for the selfdef workspace.
//!
//! This crate is the single source of truth for the [`Event`] shape that every
//! collector produces and every consumer (store, correlator, notifier) reads.
//!
//! The schema is intentionally aligned with the
//! [OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework)
//! taxonomy — class UIDs, severity IDs, activity IDs, and field names match
//! OCSF where they correspond, so events from `selfdef` are consumable by
//! any SIEM or analytic tool that speaks OCSF.
//!
//! ## Stability
//!
//! [`SCHEMA_VERSION`] is incremented on any breaking change to the envelope.
//! Stored events carry their `schema` field; readers must consult it before
//! decoding. See `migrations` (added in a later milestone) for upcast paths.
//!
//! ## Layout
//!
//! - [`envelope`] — the [`Event`] struct itself.
//! - [`category`], [`activity`] — OCSF class/activity taxonomy.
//! - [`severity`], [`status`] — typed enum wrappers around OCSF int IDs.
//! - [`observable`] — typed observables (actors, files, endpoints, hashes).
//! - [`attack`] — MITRE ATT&CK technique/tactic references.
//! - [`metadata`] — product, host, and processing metadata.
//! - [`error`] — crate-level error type.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

pub mod activity;
pub mod attack;
pub mod category;
pub mod envelope;
pub mod error;
pub mod metadata;
pub mod observable;
pub mod severity;
pub mod status;

pub mod prelude;

pub use envelope::Event;
pub use error::Error;

/// Envelope schema version. Bumped on any breaking change to [`Event`].
///
/// `0` was the M1 placeholder; `1` is the first real schema.
pub const SCHEMA_VERSION: u32 = 1;

/// Crate version, exposed for diagnostics.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
