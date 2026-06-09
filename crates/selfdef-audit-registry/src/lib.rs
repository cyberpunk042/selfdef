//! `selfdef-audit-registry` — daemon-resident, persistent registry of
//! MS016 audit chain spans. The live D-16 state the selfdef daemon
//! projects into the `selfdef-audit-mirror` MS007 snapshot for
//! sovereign-os to render READ-ONLY.
//!
//! **Daemon-populated** (like quarantine + trust): every IPS decision
//! appends a span via `append_span()`. The registry maintains the
//! SHA-256 hash chain (each entry's `prev_chain_hash` = the prior
//! entry's `chain_hash`) and bounds the published `spans` list to the
//! [`MAX_PUBLISHED_SPANS`] most-recent tail so the snapshot stays
//! dashboard-friendly. The integrity report is recomputed on each
//! append (head hash + total entries + continuity flag).
//!
//! Operator has no mutation surface here — the audit chain is
//! append-only by design (MS016 R03567 "audit log is the IPS truth").
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports.
pub use selfdef_audit_mirror::{
    AuditMirrorSnapshot, CategorySummary, ChainIntegrityReport, OcsfCategory, PolicyOutcome,
    SCHEMA_VERSION, SpanEntry,
};

/// Default on-disk path for the persisted registry (operator override
/// via `SELFDEF_AUDIT_PATH`).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/audit.json";

/// Bounded tail published in each snapshot — dashboard-friendly limit
/// so D-16 stays responsive at high audit volume. The full chain lives
/// in the daemon's audit log (this is the spans *tail*, not the full
/// chain).
pub const MAX_PUBLISHED_SPANS: usize = 256;

/// Daemon-side span-append input. Mirrors `SpanEntry` field-for-field
/// except for the chain-hash fields (the registry computes those).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpanAppend {
    /// Field 1 — trace_id.
    pub trace_id: String,
    /// Field 2 — profile name at span time.
    pub profile: String,
    /// Field 3 — model identifier.
    pub model: String,
    /// Field 4 — provider.
    pub provider: String,
    /// Field 5 — hardware target.
    pub hardware: String,
    /// Field 6 — prompt token count.
    pub tokens_prompt: u32,
    /// Field 6b — completion token count.
    pub tokens_completion: u32,
    /// Field 7 — latency total milliseconds.
    pub latency_ms: u32,
    /// Field 8 — cost in USD millicents.
    pub cost_millicents: u32,
    /// Field 9 — risk score (0..100).
    pub risk_score: u8,
    /// Field 10 — memory references.
    pub memory_refs: Vec<String>,
    /// Field 11 — tool references.
    pub tool_refs: Vec<String>,
    /// Field 12 — policy result.
    pub policy_result: PolicyOutcome,
    /// Field 13 — branch_id.
    pub branch_id: String,
    /// MS026 OCSF category.
    pub ocsf_category: OcsfCategory,
    /// MS003 signature over canonical-JSON envelope.
    pub signature: String,
}

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Mandatory field empty.
    #[error("mandatory field empty: {0}")]
    EmptyField(&'static str),
    /// Risk score out of range (0..=100).
    #[error("risk_score {0} out of range (0..=100)")]
    RiskOutOfRange(u8),
    /// Persisted store was present but malformed.
    #[error("malformed audit store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("audit store io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// Timestamp formatting failed.
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
}

/// Daemon-resident audit-chain registry.
#[derive(Debug, Clone)]
pub struct AuditRegistry {
    snapshot: AuditMirrorSnapshot,
}

impl Default for AuditRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn initial_integrity() -> ChainIntegrityReport {
    ChainIntegrityReport {
        head_hash: String::new(),
        total_entries: 0,
        continuous: true,
        first_gap_at: None,
        verified_at: String::new(),
    }
}

/// SHA-256 hex of the canonical-JSON envelope (the 13 MS049 fields +
/// `prev_chain_hash`). Deterministic per the audit-chain doctrine —
/// every byte the daemon writes contributes to the next entry's
/// `prev_chain_hash`.
fn compute_chain_hash(entry: &SpanEntry) -> String {
    // Build a deterministic JSON view; exclude chain_hash + signature
    // (signature is per-entry; chain_hash is what we're computing).
    let envelope = serde_json::json!({
        "trace_id": entry.trace_id,
        "profile": entry.profile,
        "model": entry.model,
        "provider": entry.provider,
        "hardware": entry.hardware,
        "tokens_prompt": entry.tokens_prompt,
        "tokens_completion": entry.tokens_completion,
        "latency_ms": entry.latency_ms,
        "cost_millicents": entry.cost_millicents,
        "risk_score": entry.risk_score,
        "memory_refs": entry.memory_refs,
        "tool_refs": entry.tool_refs,
        "policy_result": entry.policy_result,
        "branch_id": entry.branch_id,
        "ocsf_category": entry.ocsf_category,
        "closed_at": entry.closed_at,
        "prev_chain_hash": entry.prev_chain_hash,
    });
    let canonical = envelope.to_string();
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

impl AuditRegistry {
    /// New empty registry, schema pinned, empty integrity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: AuditMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: String::new(),
                summaries: Vec::new(),
                integrity: initial_integrity(),
                spans: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Adopt an existing snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: AuditMirrorSnapshot) -> Self {
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

    /// Atomically and durably persist (tempfile + fsync + rename + dir fsync).
    ///
    /// Rename gives crash *consistency* (no torn read); the fsyncs give crash
    /// *durability*. This is an append-only, hash-chained audit log: write+
    /// rename can both return Ok with the bytes still in the page cache, so a
    /// power loss right after appending a span could lose that span, resurrect
    /// a stale chain tail, or leave a zero-length store — and a dropped span
    /// breaks the `prev_chain_hash` linkage, which is exactly the tamper
    /// signal the chain exists to make detectable. The audit chain must
    /// survive a crash, not merely avoid tearing. Fsync the tempfile contents
    /// before the rename, then fsync the parent directory so the rename's new
    /// directory entry is durable too. Directory fsync is best-effort. Matches
    /// the selfdef-cli init / guardian fsync convention.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        use std::io::Write as _;

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
        {
            let mut f = std::fs::File::create(&tmp).map_err(io_err)?;
            f.write_all(body.as_bytes()).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        std::fs::rename(&tmp, path).map_err(io_err)?;
        if let Some(dir) = path.parent() {
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    /// Daemon-side: append a new span to the chain. Computes
    /// `prev_chain_hash` (= prior tail's `chain_hash`) and `chain_hash`
    /// (= SHA-256 of the canonical envelope), bounds the published
    /// spans tail to [`MAX_PUBLISHED_SPANS`], updates integrity, and
    /// recomputes per-category summaries + captured_at.
    pub fn append_span(
        &mut self,
        a: &SpanAppend,
        now: OffsetDateTime,
    ) -> Result<String, RegistryError> {
        if a.trace_id.is_empty() {
            return Err(RegistryError::EmptyField("trace_id"));
        }
        if a.profile.is_empty() {
            return Err(RegistryError::EmptyField("profile"));
        }
        if a.model.is_empty() {
            return Err(RegistryError::EmptyField("model"));
        }
        if a.risk_score > 100 {
            return Err(RegistryError::RiskOutOfRange(a.risk_score));
        }

        let prev = self
            .snapshot
            .spans
            .last()
            .map(|s| s.chain_hash.clone())
            .unwrap_or_default();
        let closed_at = now.format(&Rfc3339)?;

        let mut entry = SpanEntry {
            trace_id: a.trace_id.clone(),
            profile: a.profile.clone(),
            model: a.model.clone(),
            provider: a.provider.clone(),
            hardware: a.hardware.clone(),
            tokens_prompt: a.tokens_prompt,
            tokens_completion: a.tokens_completion,
            latency_ms: a.latency_ms,
            cost_millicents: a.cost_millicents,
            risk_score: a.risk_score,
            memory_refs: a.memory_refs.clone(),
            tool_refs: a.tool_refs.clone(),
            policy_result: a.policy_result,
            branch_id: a.branch_id.clone(),
            ocsf_category: a.ocsf_category,
            closed_at,
            prev_chain_hash: prev,
            chain_hash: String::new(),
            signature: a.signature.clone(),
        };
        entry.chain_hash = compute_chain_hash(&entry);

        let chain_hash = entry.chain_hash.clone();
        self.snapshot.spans.push(entry);
        // Bound the published tail.
        if self.snapshot.spans.len() > MAX_PUBLISHED_SPANS {
            let drop = self.snapshot.spans.len() - MAX_PUBLISHED_SPANS;
            self.snapshot.spans.drain(0..drop);
        }
        self.recompute(now)?;
        Ok(chain_hash)
    }

    /// Verify the published tail's chain continuity. Walks the published
    /// spans (newest at tail) and asserts each entry's `prev_chain_hash`
    /// matches the prior entry's `chain_hash`. Updates integrity report.
    /// Note: this only checks the *published tail*; the full historic
    /// chain lives in the daemon's audit log.
    pub fn verify_tail(&mut self, now: OffsetDateTime) -> Result<bool, RegistryError> {
        let mut continuous = true;
        let mut first_gap_at: Option<u64> = None;
        for (i, w) in self.snapshot.spans.windows(2).enumerate() {
            if w[1].prev_chain_hash != w[0].chain_hash {
                continuous = false;
                first_gap_at = Some((i + 1) as u64);
                break;
            }
        }
        let head_hash = self
            .snapshot
            .spans
            .last()
            .map(|s| s.chain_hash.clone())
            .unwrap_or_default();
        let verified_at = now.format(&Rfc3339)?;
        let total_entries_now = self.snapshot.integrity.total_entries;
        self.snapshot.integrity = ChainIntegrityReport {
            head_hash,
            total_entries: total_entries_now,
            continuous,
            first_gap_at,
            verified_at,
        };
        Ok(continuous)
    }

    fn recompute(&mut self, now: OffsetDateTime) -> Result<(), RegistryError> {
        self.snapshot.summaries = self.snapshot.recompute_summaries();
        self.snapshot.captured_at = now.format(&Rfc3339)?;
        // Bump total_entries — the chain is append-only.
        self.snapshot.integrity.total_entries =
            self.snapshot.integrity.total_entries.saturating_add(1);
        self.snapshot.integrity.head_hash = self
            .snapshot
            .spans
            .last()
            .map(|s| s.chain_hash.clone())
            .unwrap_or_default();
        Ok(())
    }

    /// Current published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &AuditMirrorSnapshot {
        &self.snapshot
    }

    /// Published spans tail.
    #[must_use]
    pub fn spans(&self) -> &[SpanEntry] {
        &self.snapshot.spans
    }

    /// Total chain entries (since-genesis, monotonic per `append_span`).
    #[must_use]
    pub fn total_entries(&self) -> u64 {
        self.snapshot.integrity.total_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn span(trace_id: &str) -> SpanAppend {
        SpanAppend {
            trace_id: trace_id.into(),
            profile: "careful".into(),
            model: "qwen3-coder-32b".into(),
            provider: "local-cuda".into(),
            hardware: "3090_logic".into(),
            tokens_prompt: 1024,
            tokens_completion: 256,
            latency_ms: 1500,
            cost_millicents: 5,
            risk_score: 12,
            memory_refs: vec![],
            tool_refs: vec!["read-only-host".into()],
            policy_result: PolicyOutcome::Allow,
            branch_id: "b1".into(),
            ocsf_category: OcsfCategory::ProcessActivity,
            signature: "sig".into(),
        }
    }

    #[test]
    fn new_is_empty_and_schema_pinned() {
        let r = AuditRegistry::new();
        assert!(r.spans().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
        assert_eq!(r.total_entries(), 0);
        assert!(r.snapshot().integrity.continuous);
    }

    #[test]
    fn append_span_chains_hashes() {
        let mut r = AuditRegistry::new();
        let h1 = r.append_span(&span("t1"), now()).unwrap();
        let h2 = r.append_span(&span("t2"), now()).unwrap();
        assert_eq!(r.spans().len(), 2);
        assert!(!h1.is_empty());
        assert!(!h2.is_empty());
        assert_ne!(h1, h2);
        // The second entry's prev_chain_hash should equal the first's chain_hash.
        assert_eq!(r.spans()[1].prev_chain_hash, h1);
        assert_eq!(r.spans()[1].chain_hash, h2);
        // Genesis has empty prev.
        assert_eq!(r.spans()[0].prev_chain_hash, "");
        assert_eq!(r.total_entries(), 2);
    }

    #[test]
    fn append_rejects_empty_required_fields() {
        let mut r = AuditRegistry::new();
        let mut bad = span("t1");
        bad.trace_id = String::new();
        assert!(matches!(
            r.append_span(&bad, now()).unwrap_err(),
            RegistryError::EmptyField("trace_id")
        ));
        let mut bad2 = span("t1");
        bad2.profile = String::new();
        assert!(matches!(
            r.append_span(&bad2, now()).unwrap_err(),
            RegistryError::EmptyField("profile")
        ));
        let mut bad3 = span("t1");
        bad3.model = String::new();
        assert!(matches!(
            r.append_span(&bad3, now()).unwrap_err(),
            RegistryError::EmptyField("model")
        ));
    }

    #[test]
    fn append_rejects_bad_risk_score() {
        let mut r = AuditRegistry::new();
        let mut bad = span("t1");
        bad.risk_score = 101;
        assert!(matches!(
            r.append_span(&bad, now()).unwrap_err(),
            RegistryError::RiskOutOfRange(101)
        ));
    }

    #[test]
    fn published_tail_is_bounded() {
        let mut r = AuditRegistry::new();
        for i in 0..(MAX_PUBLISHED_SPANS + 5) {
            r.append_span(&span(&format!("t{i}")), now()).unwrap();
        }
        assert_eq!(r.spans().len(), MAX_PUBLISHED_SPANS);
        // total_entries reflects the full append count (not the bounded tail).
        assert_eq!(r.total_entries(), (MAX_PUBLISHED_SPANS + 5) as u64);
        // Oldest entries dropped — first remaining is t5.
        assert_eq!(r.spans()[0].trace_id, "t5");
    }

    #[test]
    fn verify_tail_detects_chain_intact() {
        let mut r = AuditRegistry::new();
        for i in 0..5 {
            r.append_span(&span(&format!("t{i}")), now()).unwrap();
        }
        assert!(r.verify_tail(now()).unwrap());
        assert!(r.snapshot().integrity.continuous);
        assert!(r.snapshot().integrity.first_gap_at.is_none());
    }

    #[test]
    fn verify_tail_detects_tampering() {
        let mut r = AuditRegistry::new();
        for i in 0..5 {
            r.append_span(&span(&format!("t{i}")), now()).unwrap();
        }
        // Tamper: corrupt span 2's prev_chain_hash.
        r.snapshot.spans[2].prev_chain_hash = "0".repeat(64);
        assert!(!r.verify_tail(now()).unwrap());
        assert!(!r.snapshot().integrity.continuous);
        assert_eq!(r.snapshot().integrity.first_gap_at, Some(2));
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let mut r = AuditRegistry::new();
        r.append_span(&span("t1"), now()).unwrap();
        r.append_span(&span("t2"), now()).unwrap();
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        let back = AuditRegistry::load(&path).unwrap();
        assert_eq!(back.spans().len(), 2);
        assert_eq!(back.spans()[0].trace_id, "t1");
        back.snapshot().validate_schema().unwrap();
    }

    #[test]
    fn save_overwrites_existing_and_creates_missing_dirs_chain_intact() {
        // Durable save must create absent parent dirs and truncate a longer
        // prior file (File::create) so a shorter re-save leaves no stale tail,
        // and the reloaded chain must still verify (prev_chain_hash linkage).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/audit.json");

        let mut r = AuditRegistry::new();
        r.append_span(&span("t1"), now()).unwrap();
        r.append_span(&span("t2"), now()).unwrap();
        r.append_span(&span("t3"), now()).unwrap();
        r.save(&path).unwrap();
        assert_eq!(AuditRegistry::load(&path).unwrap().spans().len(), 3);

        // Shorter re-save over the longer file: no stale tail, chain valid.
        let mut r2 = AuditRegistry::new();
        r2.append_span(&span("only"), now()).unwrap();
        r2.save(&path).unwrap();

        let mut back = AuditRegistry::load(&path).unwrap();
        assert_eq!(back.spans().len(), 1);
        assert_eq!(back.spans()[0].trace_id, "only");
        assert!(back.verify_tail(now()).unwrap(), "reloaded chain verifies");
        back.snapshot().validate_schema().unwrap();
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn load_absent_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = AuditRegistry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.spans().is_empty());
    }

    /// Deterministic SHA-256: appending the same span twice in a fresh
    /// registry yields the same chain_hash (both have empty prev).
    #[test]
    fn chain_hash_is_deterministic() {
        let mut r1 = AuditRegistry::new();
        let mut r2 = AuditRegistry::new();
        let h1 = r1.append_span(&span("same"), now()).unwrap();
        let h2 = r2.append_span(&span("same"), now()).unwrap();
        assert_eq!(h1, h2);
    }
}
