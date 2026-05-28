//! `selfdef-trust-score-registry` — daemon-resident, persistent
//! registry of per-tool trust scores. The live D-18 state the selfdef
//! daemon projects into the `selfdef-trust-score-mirror` MS007
//! snapshot for sovereign-os to render READ-ONLY.
//!
//! Daemon-populated by scoring events (`record_delta` using the
//! engine's `canonical_delta` per DeltaReason); operator surface is
//! manual deltas (MS003-signed) for override. History tail is bounded
//! per `MAX_HISTORY_ENTRIES`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use selfdef_trust_score_engine::{apply_delta, band_for_score, canonical_delta};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports.
pub use selfdef_trust_score_mirror::{
    BandSummary, DeltaEntry, DeltaReason, SCHEMA_VERSION, ToolScoreEntry, TrustBand,
    TrustScoreMirrorSnapshot,
};

/// Default on-disk path for the persisted registry (operator override
/// via `SELFDEF_TRUST_SCORES_PATH`).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/trust-scores.json";

/// Bounded history tail per tool — the published snapshot truncates to
/// this many most-recent deltas (spark-line render budget on D-18).
pub const MAX_HISTORY_ENTRIES: usize = 64;

/// Operator-signed manual delta (override).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorDeltaRequest {
    /// Tool whose score the operator is adjusting.
    pub tool: String,
    /// Operator MS003 fingerprint authorizing the adjustment.
    pub actor: String,
    /// Reason for the adjustment.
    pub reason: DeltaReason,
    /// Signed delta amount (negative for penalty, positive for credit).
    /// The engine's `canonical_delta(reason)` is the recommended
    /// magnitude; the operator may override for forensic reasons.
    pub delta: i32,
    /// Optional M049 trace_id of the triggering incident.
    #[serde(default)]
    pub trace_id: String,
    /// MS003 signature over the canonical-JSON request (hex).
    pub signature: String,
}

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Request missing the MS003 signature.
    #[error("request unsigned (MS003 signature required)")]
    Unsigned,
    /// Mandatory string field empty.
    #[error("mandatory field empty: {0}")]
    EmptyField(&'static str),
    /// Initial score out of range (must be 0..=1000).
    #[error("initial_score {0} out of range (0..=1000)")]
    InitialScoreOutOfRange(u16),
    /// Persisted store was present but malformed.
    #[error("malformed trust-scores store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("trust-scores store io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// Timestamp formatting failed (should not happen with Rfc3339).
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
}

/// Daemon-resident trust-score registry.
#[derive(Debug, Clone)]
pub struct TrustScoreRegistry {
    snapshot: TrustScoreMirrorSnapshot,
}

impl Default for TrustScoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustScoreRegistry {
    /// New empty registry, schema pinned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: TrustScoreMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: String::new(),
                summaries: Vec::new(),
                tools: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Adopt an existing snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: TrustScoreMirrorSnapshot) -> Self {
        Self { snapshot }
    }

    /// Load. Absent → empty; malformed → error.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => {
                return Err(RegistryError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };
        let snapshot = serde_json::from_str(&text).map_err(|e| RegistryError::Malformed {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(Self { snapshot })
    }

    /// Atomically persist.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let io_err = |e: std::io::Error| RegistryError::Io {
            path: path.display().to_string(),
            source: e,
        };
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(io_err)?;
            }
        }
        let body =
            serde_json::to_string_pretty(&self.snapshot).map_err(|e| RegistryError::Malformed {
                path: path.display().to_string(),
                source: e,
            })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body).map_err(io_err)?;
        std::fs::rename(&tmp, path).map_err(io_err)?;
        Ok(())
    }

    /// Admit a new tool with an explicit starting score. Idempotent —
    /// admitting an already-known tool is a no-op (returns false).
    pub fn admit(
        &mut self,
        tool: &str,
        declarer: &str,
        initial_score: u16,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        if tool.is_empty() {
            return Err(RegistryError::EmptyField("tool"));
        }
        if declarer.is_empty() {
            return Err(RegistryError::EmptyField("declarer"));
        }
        if initial_score > 1000 {
            return Err(RegistryError::InitialScoreOutOfRange(initial_score));
        }
        if self.snapshot.tools.iter().any(|t| t.tool == tool) {
            return Ok(false);
        }
        let stamp = now.format(&Rfc3339)?;
        let entry = ToolScoreEntry {
            tool: tool.to_string(),
            declarer: declarer.to_string(),
            current_score: initial_score,
            band: band_for_score(initial_score),
            first_admitted_at: stamp.clone(),
            last_delta_at: stamp,
            executions_total: 0,
            mismatches_total: 0,
            history: Vec::new(),
            last_trace_id: String::new(),
            signature: String::new(),
        };
        self.snapshot.tools.push(entry);
        self.recompute(now)?;
        Ok(true)
    }

    /// Daemon-side: record a scoring event using the engine's
    /// `canonical_delta(reason)`. Updates score + band, appends to the
    /// tool's history (bounded to [`MAX_HISTORY_ENTRIES`]), bumps
    /// execution/mismatch counters. Returns true if the tool exists.
    pub fn record_delta(
        &mut self,
        tool: &str,
        reason: DeltaReason,
        trace_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        let delta = canonical_delta(reason);
        self.apply_internal(tool, reason, delta, trace_id, String::new(), now)
    }

    /// Operator-signed manual delta (override). The signature is
    /// mandatory; the operator may pass any `delta` magnitude.
    pub fn apply_operator_delta(
        &mut self,
        req: &OperatorDeltaRequest,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        if req.signature.is_empty() {
            return Err(RegistryError::Unsigned);
        }
        if req.actor.is_empty() {
            return Err(RegistryError::EmptyField("actor"));
        }
        if req.tool.is_empty() {
            return Err(RegistryError::EmptyField("tool"));
        }
        self.apply_internal(
            &req.tool,
            req.reason,
            req.delta,
            &req.trace_id,
            req.signature.clone(),
            now,
        )
    }

    fn apply_internal(
        &mut self,
        tool: &str,
        reason: DeltaReason,
        delta: i32,
        trace_id: &str,
        signature: String,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        let stamp = now.format(&Rfc3339)?;
        let Some(entry) = self.snapshot.tools.iter_mut().find(|t| t.tool == tool) else {
            return Ok(false);
        };
        let new_score = apply_delta(entry.current_score, delta);
        entry.current_score = new_score;
        entry.band = band_for_score(new_score);
        entry.last_delta_at = stamp.clone();
        entry.last_trace_id = trace_id.to_string();
        entry.executions_total = entry.executions_total.saturating_add(1);
        if delta < 0 {
            entry.mismatches_total = entry.mismatches_total.saturating_add(1);
        }
        entry.history.push(DeltaEntry {
            applied_at: stamp,
            reason,
            delta,
            score_after: new_score,
            trace_id: trace_id.to_string(),
            signature,
        });
        if entry.history.len() > MAX_HISTORY_ENTRIES {
            let drop = entry.history.len() - MAX_HISTORY_ENTRIES;
            entry.history.drain(0..drop);
        }
        self.recompute(now)?;
        Ok(true)
    }

    fn recompute(&mut self, now: OffsetDateTime) -> Result<(), RegistryError> {
        self.snapshot.summaries = self.snapshot.recompute_summaries();
        self.snapshot.captured_at = now.format(&Rfc3339)?;
        Ok(())
    }

    /// Current published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &TrustScoreMirrorSnapshot {
        &self.snapshot
    }

    /// Live tool score entries.
    #[must_use]
    pub fn tools(&self) -> &[ToolScoreEntry] {
        &self.snapshot.tools
    }

    /// Look up a tool's current score.
    #[must_use]
    pub fn score_of(&self, tool: &str) -> Option<u16> {
        self.snapshot
            .tools
            .iter()
            .find(|t| t.tool == tool)
            .map(|t| t.current_score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn new_is_empty_and_schema_pinned() {
        let r = TrustScoreRegistry::new();
        assert!(r.tools().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn admit_appends_tool_with_band() {
        let mut r = TrustScoreRegistry::new();
        assert!(r.admit("rg", "operator-fp", 750, now()).unwrap());
        let t = &r.tools()[0];
        assert_eq!(t.tool, "rg");
        assert_eq!(t.current_score, 750);
        assert_eq!(t.first_admitted_at, "2027-01-15T08:00:00Z");
        assert_eq!(r.score_of("rg"), Some(750));
    }

    #[test]
    fn admit_is_idempotent() {
        let mut r = TrustScoreRegistry::new();
        r.admit("rg", "op", 750, now()).unwrap();
        assert!(!r.admit("rg", "op", 800, now()).unwrap());
        // Score unchanged.
        assert_eq!(r.score_of("rg"), Some(750));
    }

    #[test]
    fn admit_rejects_empty_required_fields() {
        let mut r = TrustScoreRegistry::new();
        assert!(matches!(
            r.admit("", "op", 750, now()).unwrap_err(),
            RegistryError::EmptyField("tool")
        ));
        assert!(matches!(
            r.admit("rg", "", 750, now()).unwrap_err(),
            RegistryError::EmptyField("declarer")
        ));
    }

    #[test]
    fn admit_rejects_score_above_1000() {
        let mut r = TrustScoreRegistry::new();
        assert!(matches!(
            r.admit("rg", "op", 1001, now()).unwrap_err(),
            RegistryError::InitialScoreOutOfRange(1001)
        ));
    }

    #[test]
    fn record_delta_updates_score_history_and_counters() {
        let mut r = TrustScoreRegistry::new();
        r.admit("rg", "op", 750, now()).unwrap();
        let reason = DeltaReason::MismatchMajor;
        let delta = canonical_delta(reason);
        assert!(r.record_delta("rg", reason, "trace-1", now()).unwrap());
        let t = &r.tools()[0];
        assert_eq!(t.current_score as i32, (750_i32 + delta).clamp(0, 1000));
        assert_eq!(t.history.len(), 1);
        assert_eq!(t.history[0].delta, delta);
        assert_eq!(t.executions_total, 1);
        if delta < 0 {
            assert_eq!(t.mismatches_total, 1);
        }
        assert_eq!(t.last_trace_id, "trace-1");
    }

    #[test]
    fn record_delta_unknown_tool_returns_false() {
        let mut r = TrustScoreRegistry::new();
        assert!(
            !r.record_delta("nope", DeltaReason::MismatchMajor, "t", now())
                .unwrap()
        );
    }

    #[test]
    fn history_is_bounded() {
        let mut r = TrustScoreRegistry::new();
        r.admit("rg", "op", 500, now()).unwrap();
        for i in 0..(MAX_HISTORY_ENTRIES + 5) {
            r.record_delta(
                "rg",
                DeltaReason::SuccessfulExecution,
                &format!("t{i}"),
                now(),
            )
            .unwrap();
        }
        let t = &r.tools()[0];
        assert_eq!(t.history.len(), MAX_HISTORY_ENTRIES);
        // Oldest entries dropped — the first remaining should be at
        // index 5 of the originally-applied set.
        assert_eq!(t.history[0].trace_id, "t5");
    }

    #[test]
    fn operator_delta_requires_signature() {
        let mut r = TrustScoreRegistry::new();
        r.admit("rg", "op", 500, now()).unwrap();
        let bad = OperatorDeltaRequest {
            tool: "rg".into(),
            actor: "operator-fp".into(),
            reason: DeltaReason::MismatchMajor,
            delta: -100,
            trace_id: String::new(),
            signature: String::new(),
        };
        assert!(matches!(
            r.apply_operator_delta(&bad, now()).unwrap_err(),
            RegistryError::Unsigned
        ));
    }

    #[test]
    fn operator_delta_applies_signed() {
        let mut r = TrustScoreRegistry::new();
        r.admit("rg", "op", 500, now()).unwrap();
        let req = OperatorDeltaRequest {
            tool: "rg".into(),
            actor: "operator-fp".into(),
            reason: DeltaReason::MismatchMajor,
            delta: -200,
            trace_id: "incident-1".into(),
            signature: "ms003-sig".into(),
        };
        assert!(r.apply_operator_delta(&req, now()).unwrap());
        assert_eq!(r.score_of("rg"), Some(300));
        let t = &r.tools()[0];
        assert_eq!(t.history[0].signature, "ms003-sig");
        assert_eq!(t.mismatches_total, 1);
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-scores.json");
        let mut r = TrustScoreRegistry::new();
        r.admit("rg", "op", 750, now()).unwrap();
        r.record_delta("rg", DeltaReason::SuccessfulExecution, "t1", now())
            .unwrap();
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        let back = TrustScoreRegistry::load(&path).unwrap();
        assert_eq!(back.tools().len(), 1);
        assert_eq!(back.tools()[0].tool, "rg");
        back.snapshot().validate_schema().unwrap();
    }

    #[test]
    fn load_absent_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = TrustScoreRegistry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.tools().is_empty());
    }
}
