//! `GET /v1/hardware*` — MS010 hardware-aware-modules HTTP surface.
//!
//! Three read-only endpoints surfacing the host hardware snapshot
//! that drives MS010's hardware-aware module activation + SDD-018's
//! tune-surface decisions:
//!
//! - `GET /v1/hardware`              full [`HardwareSnapshot`] JSON
//! - `GET /v1/hardware/capabilities` derived capability flags
//! - `GET /v1/hardware/sain01`       Sain-01 reference-platform match
//!
//! The probe is cached per-process via [`OnceLock`] — hardware doesn't
//! hot-swap at runtime, so probing once at first request is fine and
//! keeps the HTTP path cheap. Subsequent requests are pure JSON
//! serialization of the cached snapshot.
//!
//! Source: MS010 catalog rows + SDD-018 hardware-aware modules +
//! `crates/selfdef-hardware/src/lib.rs` (the only authorized prober).

use std::sync::OnceLock;

use axum::Json;
use axum::http::StatusCode;
use selfdef_hardware::{
    HardwareCapabilities, HardwareSnapshot, Sain01Match, derive_capabilities, matches_sain01, probe,
};
use serde::Serialize;

static HARDWARE_SNAPSHOT: OnceLock<Result<HardwareSnapshot, String>> = OnceLock::new();

/// Return the cached snapshot (probing it once on first call).
/// Probe errors are stringified and cached too — repeated requests
/// don't keep re-attempting a probe that's already known to fail.
pub(crate) fn cached_snapshot() -> Result<&'static HardwareSnapshot, &'static str> {
    let cell = HARDWARE_SNAPSHOT.get_or_init(|| probe().map_err(|e| e.to_string()));
    cell.as_ref().map_err(|s| s.as_str())
}

/// `GET /v1/hardware` — full snapshot.
pub(crate) async fn snapshot() -> Result<Json<HardwareSnapshot>, (StatusCode, String)> {
    match cached_snapshot() {
        Ok(s) => Ok(Json(s.clone())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("hardware probe failed: {e}"),
        )),
    }
}

/// `GET /v1/hardware/capabilities` — derived capability flags.
pub(crate) async fn capabilities() -> Result<Json<HardwareCapabilities>, (StatusCode, String)> {
    match cached_snapshot() {
        Ok(s) => Ok(Json(derive_capabilities(s))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("hardware probe failed: {e}"),
        )),
    }
}

/// `GET /v1/hardware/sain01` — Sain-01 reference-platform match.
/// Wraps the `Sain01Match` (which contains an enum) in a stable
/// envelope so older clients don't break when new fields land.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Sain01Envelope {
    /// Sain-01 match verdict (`Match | NearMatch | NoMatch`) plus
    /// the per-component agreement / disagreement reasons.
    pub sain01: Sain01Match,
}

pub(crate) async fn sain01() -> Result<Json<Sain01Envelope>, (StatusCode, String)> {
    match cached_snapshot() {
        Ok(s) => Ok(Json(Sain01Envelope {
            sain01: matches_sain01(s),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("hardware probe failed: {e}"),
        )),
    }
}
