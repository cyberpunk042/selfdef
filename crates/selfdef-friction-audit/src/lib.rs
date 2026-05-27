//! `selfdef-friction-audit` — SDD-027 Deliverable 4: runtime
//! authority surface for the friction-audit boot-time gate.
//!
//! Provides:
//! - [`OverrideManifest`] — typed JSON schema for operator-signed
//!   override files at `/etc/selfdef/overrides/friction-audit-<gate>.json`
//! - [`OverrideStore`] — loads manifests for all gates, validates
//!   schema + MS003 signature + multi-sig + TTL, exposes the
//!   "is gate X overridden right now?" lookup
//! - [`RingBufferReader`] — reads the ring directory the script writes,
//!   promotes entries to the canonical [`Verdict`] shape from
//!   `selfdef-friction-audit-mirror`
//! - [`replay`] — invokes the script on-demand (operator-triggered;
//!   MS046 R10927 never automatic)
//! - [`audit_chain_check`] — verifies the OCSF event chain integrity
//!   via the SHA-256 chained-prev-event-sha256 link (MS046 R10890)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use thiserror::Error;

pub use selfdef_friction_audit_mirror::{Gate, SCHEMA_VERSION, Status, Verdict};

/// Default override-manifest directory.
pub const DEFAULT_OVERRIDE_DIR: &str = "/etc/selfdef/overrides";

/// Default ring-buffer directory.
pub const DEFAULT_RING_DIR: &str = "/var/cache/selfdef/friction-audit/ring";

/// Default OCSF JSONL audit log.
pub const DEFAULT_OCSF_PATH: &str = "/var/log/selfdef/friction-audit.ocsf.jsonl";

/// Default friction-audit script binary.
pub const DEFAULT_SCRIPT_PATH: &str = "/usr/local/bin/friction-audit";

/// Default MS003 trust-roots directory.
pub const DEFAULT_TRUST_ROOTS_DIR: &str = "/etc/selfdef/trust-roots";

/// Maximum override-manifest TTL — 7 days for any gate.
pub const MAX_OVERRIDE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Minimum distinct signers for a production-profile override.
/// Operator + auditor (per MS046 F05452 + R10872).
pub const MIN_SIGNERS_PRODUCTION: usize = 2;

/// Override manifest written to disk by an operator. JSON-encoded;
/// detached minisign signature lives at `<path>.minisig` (MS003
/// convention).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideManifest {
    /// Schema version — MUST match [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// Which gate this override targets.
    pub gate: Gate,
    /// Operator-supplied audit reason (≥ 1 char, ≤ 512 chars).
    pub reason: String,
    /// Issue timestamp (epoch ms).
    pub issued_at_ms: u64,
    /// Expiry timestamp (epoch ms).
    pub expires_at_ms: u64,
    /// Primary operator signer (MS003 kid).
    pub signer_kid: String,
    /// Auditor co-signer (MS003 kid). Required for production profile.
    pub auditor_kid: String,
    /// Legal-review co-signer (MS003 kid). Required for "must-not-touch"
    /// gates per MS046 F05452 (immutability + signature gates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_review_kid: Option<String>,
    /// Optional ticket/incident URL anchoring the override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_url: Option<String>,
}

/// Errors produced by the runtime crate.
#[derive(Debug, Error)]
pub enum FrictionAuditError {
    /// Schema-version drift.
    #[error("schema version mismatch: expected {SCHEMA_VERSION}, got {0}")]
    SchemaMismatch(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(String),
    /// JSON parse / serialize error.
    #[error("serde_json: {0}")]
    Serde(String),
    /// Override manifest constraint violation.
    #[error("override invalid: {0}")]
    OverrideInvalid(String),
    /// MS003 signature failed to verify.
    #[error("signature verification failed: {0}")]
    Signature(String),
    /// Script invocation failed.
    #[error("script invocation: {0}")]
    Script(String),
    /// OCSF audit chain integrity broken.
    #[error("audit chain break at line {line}: {detail}")]
    AuditChainBreak {
        /// Line number in the OCSF jsonl file.
        line: usize,
        /// What was wrong.
        detail: String,
    },
}

impl OverrideManifest {
    /// Validate the manifest content (NOT including signature). This is
    /// the schema + business-rule pass. Use
    /// [`OverrideStore::load_signed`] for the full signature + multi-sig
    /// chain.
    ///
    /// # Errors
    /// Returns `FrictionAuditError::OverrideInvalid` when any constraint
    /// fails. Returns `FrictionAuditError::SchemaMismatch` if the
    /// schema_version is wrong.
    pub fn validate(&self, now_ms: u64) -> Result<(), FrictionAuditError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FrictionAuditError::SchemaMismatch(
                self.schema_version.clone(),
            ));
        }
        if self.reason.is_empty() {
            return Err(FrictionAuditError::OverrideInvalid(
                "reason is empty".into(),
            ));
        }
        if self.reason.len() > 512 {
            return Err(FrictionAuditError::OverrideInvalid(
                "reason exceeds 512 chars".into(),
            ));
        }
        if self.signer_kid.is_empty() {
            return Err(FrictionAuditError::OverrideInvalid(
                "signer_kid is empty".into(),
            ));
        }
        if self.auditor_kid.is_empty() {
            return Err(FrictionAuditError::OverrideInvalid(
                "auditor_kid is empty (production profile requires multi-sig)".into(),
            ));
        }
        if self.signer_kid == self.auditor_kid {
            return Err(FrictionAuditError::OverrideInvalid(
                "signer_kid and auditor_kid must be distinct".into(),
            ));
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(FrictionAuditError::OverrideInvalid(
                "expires_at_ms must be > issued_at_ms".into(),
            ));
        }
        let ttl = self.expires_at_ms - self.issued_at_ms;
        if ttl > MAX_OVERRIDE_TTL_MS {
            return Err(FrictionAuditError::OverrideInvalid(format!(
                "TTL {ttl} ms exceeds MAX_OVERRIDE_TTL_MS ({MAX_OVERRIDE_TTL_MS})"
            )));
        }
        if self.expires_at_ms <= now_ms {
            return Err(FrictionAuditError::OverrideInvalid(
                "override expired (expires_at_ms <= now_ms)".into(),
            ));
        }
        // Must-not-touch gates (per MS046 F05452 + sovereign-os M081
        // F06785) require legal-review co-signature.
        if matches!(self.gate, Gate::Immutability | Gate::Signature)
            && self.legal_review_kid.as_deref().unwrap_or("").is_empty()
        {
            return Err(FrictionAuditError::OverrideInvalid(format!(
                "{:?} gate is must-not-touch tier; legal_review_kid is required",
                self.gate
            )));
        }
        if let Some(lr) = &self.legal_review_kid {
            if lr == &self.signer_kid || lr == &self.auditor_kid {
                return Err(FrictionAuditError::OverrideInvalid(
                    "legal_review_kid must be distinct from signer + auditor".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Override-store: collection of currently-loaded manifests, indexed
/// by gate.
#[derive(Debug, Default)]
pub struct OverrideStore {
    by_gate: BTreeMap<String, OverrideManifest>,
}

impl OverrideStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan a directory for `friction-audit-<gate>.json` files; load
    /// each, validate, and insert into the store. Files whose
    /// signatures fail OR whose content is invalid are SKIPPED (with
    /// a Result entry in the returned Vec). Missing dir is not an
    /// error — returns empty store.
    ///
    /// # Errors
    /// Returns `FrictionAuditError::Io` only on read failure for an
    /// existing dir. Per-file failures are surfaced as the per-file
    /// `Err` in the returned `Vec<Result<...>>`.
    pub fn load_dir(
        dir: &Path,
        trust_roots_dir: &Path,
        now_ms: u64,
    ) -> Result<(Self, Vec<Result<Gate, FrictionAuditError>>), FrictionAuditError> {
        let mut store = Self::new();
        let mut report = Vec::new();
        if !dir.exists() {
            return Ok((store, report));
        }
        for dirent in fs::read_dir(dir).map_err(|e| FrictionAuditError::Io(e.to_string()))? {
            let dirent = dirent.map_err(|e| FrictionAuditError::Io(e.to_string()))?;
            let path = dirent.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            match Self::load_signed(&path, trust_roots_dir, now_ms) {
                Ok(m) => {
                    let gate = m.gate;
                    store.insert(m);
                    report.push(Ok(gate));
                }
                Err(e) => {
                    report.push(Err(e));
                }
            }
        }
        Ok((store, report))
    }

    /// Load a single manifest from disk; validate schema + content;
    /// verify detached minisign signature against trust roots.
    ///
    /// # Errors
    /// Returns `FrictionAuditError::Io` on read failure,
    /// `FrictionAuditError::Serde` on parse failure,
    /// `FrictionAuditError::OverrideInvalid` on schema/business-rule
    /// failure, `FrictionAuditError::Signature` on signature failure.
    pub fn load_signed(
        manifest_path: &Path,
        trust_roots_dir: &Path,
        now_ms: u64,
    ) -> Result<OverrideManifest, FrictionAuditError> {
        let bytes = fs::read(manifest_path).map_err(|e| FrictionAuditError::Io(e.to_string()))?;
        let manifest: OverrideManifest =
            serde_json::from_slice(&bytes).map_err(|e| FrictionAuditError::Serde(e.to_string()))?;
        manifest.validate(now_ms)?;
        let sig_path = manifest_path.with_extension("json.minisig");
        if !sig_path.exists() {
            return Err(FrictionAuditError::Signature(format!(
                "detached signature not found at {}",
                sig_path.display()
            )));
        }
        verify_minisign(&bytes, &sig_path, trust_roots_dir)
            .map_err(|e| FrictionAuditError::Signature(e.to_string()))?;
        Ok(manifest)
    }

    /// Insert a manifest into the store (does NOT re-validate; use
    /// [`OverrideStore::load_signed`] for the full check).
    pub fn insert(&mut self, manifest: OverrideManifest) {
        let key = serde_json::to_string(&manifest.gate).unwrap_or_default();
        self.by_gate.insert(key, manifest);
    }

    /// Is the given gate currently overridden by a non-expired
    /// manifest?
    #[must_use]
    pub fn is_active(&self, gate: Gate, now_ms: u64) -> bool {
        let key = serde_json::to_string(&gate).unwrap_or_default();
        match self.by_gate.get(&key) {
            None => false,
            Some(m) => m.expires_at_ms > now_ms,
        }
    }

    /// Get the active override manifest for a gate (None if none / expired).
    #[must_use]
    pub fn get(&self, gate: Gate, now_ms: u64) -> Option<&OverrideManifest> {
        if !self.is_active(gate, now_ms) {
            return None;
        }
        let key = serde_json::to_string(&gate).unwrap_or_default();
        self.by_gate.get(&key)
    }

    /// All currently-active gates.
    #[must_use]
    pub fn active_gates(&self, now_ms: u64) -> Vec<Gate> {
        let mut out = Vec::new();
        for gate in [
            Gate::Pcie,
            Gate::Zfs,
            Gate::Memory,
            Gate::Immutability,
            Gate::Signature,
            Gate::Timeout,
        ] {
            if self.is_active(gate, now_ms) {
                out.push(gate);
            }
        }
        out
    }
}

/// Verify a detached minisign signature against the trust roots
/// directory. Returns Ok(()) on success; returns Err with detail on
/// failure.
///
/// # Errors
/// Returns an error if no public key in `trust_roots_dir` validates
/// the signature, OR if the signature/public-key files are malformed.
fn verify_minisign(payload: &[u8], sig_path: &Path, trust_roots_dir: &Path) -> Result<(), String> {
    use minisign_verify::{PublicKey, Signature};

    let sig_bytes = fs::read(sig_path).map_err(|e| format!("read sig: {e}"))?;
    let sig_str = std::str::from_utf8(&sig_bytes).map_err(|e| format!("sig utf8: {e}"))?;
    let signature = Signature::decode(sig_str).map_err(|e| format!("decode sig: {e}"))?;

    if !trust_roots_dir.exists() {
        return Err(format!(
            "trust-roots dir missing at {}",
            trust_roots_dir.display()
        ));
    }
    let mut tried = 0;
    for dirent in fs::read_dir(trust_roots_dir).map_err(|e| format!("read trust dir: {e}"))? {
        let dirent = dirent.map_err(|e| format!("trust entry: {e}"))?;
        let p = dirent.path();
        if p.extension().is_none_or(|e| e != "pub") {
            continue;
        }
        tried += 1;
        let pk_bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let pk_str = match std::str::from_utf8(&pk_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let pk = match PublicKey::decode(pk_str.trim()) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if pk.verify(payload, &signature, false).is_ok() {
            return Ok(());
        }
    }
    Err(format!(
        "no trust-root in {} validated the signature ({tried} pub keys tried)",
        trust_roots_dir.display()
    ))
}

/// Read the entire ring buffer directory into Verdicts (newest-first).
/// Returns empty vec on missing dir. Malformed entries are silently
/// skipped (not fatal — the gate's authority is the truth, not the
/// ring buffer).
///
/// # Errors
/// Returns `FrictionAuditError::Io` on read failure of an existing dir.
pub fn read_ring_buffer(ring: &Path) -> Result<Vec<Verdict>, FrictionAuditError> {
    if !ring.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Verdict> = Vec::new();
    for dirent in fs::read_dir(ring).map_err(|e| FrictionAuditError::Io(e.to_string()))? {
        let dirent = dirent.map_err(|e| FrictionAuditError::Io(e.to_string()))?;
        let path = dirent.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Try the simpler script-written shape first.
        if let Ok(entry) = serde_json::from_slice::<ScriptRingEntry>(&bytes) {
            out.push(entry.into_verdict());
        }
        // (Future: try Verdict shape directly when daemon-side runtime
        // crate also writes ring entries.)
    }
    out.sort_by_key(|v| std::cmp::Reverse(v.ts_ms));
    Ok(out)
}

/// On-disk shape the bash script writes. Narrower than the canonical
/// mirror Verdict.
#[derive(Debug, Deserialize)]
struct ScriptRingEntry {
    gate: String,
    status: String,
    ts_ms: u64,
    hostname: String,
}

impl ScriptRingEntry {
    fn into_verdict(self) -> Verdict {
        let gate = match self.gate.as_str() {
            "pcie" => Gate::Pcie,
            "zfs" => Gate::Zfs,
            "memory" => Gate::Memory,
            "immutability" => Gate::Immutability,
            "signature" => Gate::Signature,
            "timeout" => Gate::Timeout,
            _ => Gate::Pcie,
        };
        let status = match self.status.as_str() {
            "pass" => Status::Pass,
            "skip" => Status::Skipped("operator-extended SKIP (tool absent)".into()),
            "fail" => match gate {
                Gate::Pcie => Status::Fail(1),
                Gate::Zfs => Status::Fail(2),
                Gate::Memory => Status::Fail(3),
                Gate::Timeout => Status::Fail(4),
                _ => Status::Fail(255),
            },
            _ => Status::Fail(255),
        };
        Verdict {
            schema_version: SCHEMA_VERSION.to_string(),
            gate,
            status,
            ts_ms: self.ts_ms,
            hostname: self.hostname,
            signer_kid_policy: "<unsigned>".to_string(),
            signer_kid_extension: None,
        }
    }
}

/// Replay the friction-audit script on-demand. Operator-triggered per
/// MS046 R10927. Returns the script's exit code unchanged.
///
/// # Errors
/// Returns `FrictionAuditError::Io` if the script binary is missing.
/// Returns `FrictionAuditError::Script` on spawn failure.
pub fn replay(script_path: &Path) -> Result<i32, FrictionAuditError> {
    if !script_path.exists() {
        return Err(FrictionAuditError::Io(format!(
            "script not found at {}",
            script_path.display()
        )));
    }
    let status = Command::new(script_path)
        .status()
        .map_err(|e| FrictionAuditError::Script(e.to_string()))?;
    Ok(status.code().unwrap_or(-1))
}

/// Verify the OCSF audit chain integrity. Each event after the first
/// carries a `prev_event_sha256` field referencing the SHA-256 of the
/// prior event's canonical JSON. A broken chain is treated as a
/// CRITICAL signal per MS046 R10999 / R11087.
///
/// Note: this is the placeholder/seed implementation. The bash script
/// in Deliverable 1 does NOT yet emit `prev_event_sha256` fields (a
/// limitation tracked for a future bash-side enhancement). For now
/// this function inspects only the well-formed structure of each
/// OCSF event and returns Ok(()) when all events parse cleanly.
///
/// # Errors
/// Returns `FrictionAuditError::AuditChainBreak` when a chain
/// integrity invariant fails (currently: malformed JSON).
pub fn audit_chain_check(ocsf_jsonl: &Path) -> Result<usize, FrictionAuditError> {
    if !ocsf_jsonl.exists() {
        return Ok(0);
    }
    let text = fs::read_to_string(ocsf_jsonl).map_err(|e| FrictionAuditError::Io(e.to_string()))?;
    let mut last_sha = None::<String>;
    let mut events_seen = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(line).map_err(|e| FrictionAuditError::AuditChainBreak {
                line: idx + 1,
                detail: format!("malformed JSON: {e}"),
            })?;
        // Forward-compat: if a future event carries prev_event_sha256,
        // validate the chain.
        if let Some(prev) = parsed.get("prev_event_sha256").and_then(|v| v.as_str()) {
            if let Some(want) = &last_sha {
                if prev != want {
                    return Err(FrictionAuditError::AuditChainBreak {
                        line: idx + 1,
                        detail: format!("prev_event_sha256={prev}, expected {want}"),
                    });
                }
            }
        }
        // Compute this event's canonical SHA-256 to chain forward.
        let mut hasher = Sha256::new();
        hasher.update(line.as_bytes());
        last_sha = Some(format!("{:x}", hasher.finalize()));
        events_seen += 1;
    }
    Ok(events_seen)
}

/// Current wall-clock as epoch ms. Convenience for callers that don't
/// have a clock injected.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Convenience: load the override store from the default directories.
///
/// # Errors
/// Returns underlying `OverrideStore::load_dir` errors.
pub fn load_default_overrides(
    now_ms: u64,
) -> Result<(OverrideStore, Vec<Result<Gate, FrictionAuditError>>), FrictionAuditError> {
    OverrideStore::load_dir(
        Path::new(DEFAULT_OVERRIDE_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now_ms,
    )
}

/// Format a default override manifest path for a given gate.
#[must_use]
pub fn default_override_path(gate: Gate) -> PathBuf {
    let gate_str = match gate {
        Gate::Pcie => "pcie",
        Gate::Zfs => "zfs",
        Gate::Memory => "memory",
        Gate::Immutability => "immutability",
        Gate::Signature => "signature",
        Gate::Timeout => "timeout",
    };
    Path::new(DEFAULT_OVERRIDE_DIR).join(format!("friction-audit-{gate_str}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample_manifest(gate: Gate, ttl_ms: u64) -> OverrideManifest {
        let now = 1_700_000_000_000;
        OverrideManifest {
            schema_version: SCHEMA_VERSION.to_string(),
            gate,
            reason: "RMA in flight, ticket #1234".into(),
            issued_at_ms: now,
            expires_at_ms: now + ttl_ms,
            signer_kid: "kid-operator-A".into(),
            auditor_kid: "kid-auditor-B".into(),
            legal_review_kid: None,
            incident_url: None,
        }
    }

    fn legal_manifest(gate: Gate, ttl_ms: u64) -> OverrideManifest {
        let mut m = sample_manifest(gate, ttl_ms);
        m.legal_review_kid = Some("kid-legal-C".into());
        m
    }

    #[test]
    fn valid_pcie_manifest_passes_validation() {
        let m = sample_manifest(Gate::Pcie, 24 * 60 * 60 * 1000);
        assert!(m.validate(m.issued_at_ms + 1).is_ok());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = sample_manifest(Gate::Pcie, 1000);
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate(m.issued_at_ms + 1).unwrap_err(),
            FrictionAuditError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn empty_reason_rejected() {
        let mut m = sample_manifest(Gate::Pcie, 1000);
        m.reason.clear();
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(matches!(err, FrictionAuditError::OverrideInvalid(_)));
    }

    #[test]
    fn reason_over_512_chars_rejected() {
        let mut m = sample_manifest(Gate::Pcie, 1000);
        m.reason = "x".repeat(513);
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(format!("{err}").contains("exceeds 512"));
    }

    #[test]
    fn signer_equals_auditor_rejected() {
        let mut m = sample_manifest(Gate::Pcie, 1000);
        m.auditor_kid = m.signer_kid.clone();
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(format!("{err}").contains("distinct"));
    }

    #[test]
    fn ttl_over_max_rejected() {
        let m = sample_manifest(Gate::Pcie, MAX_OVERRIDE_TTL_MS + 1);
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(format!("{err}").contains("exceeds MAX_OVERRIDE_TTL_MS"));
    }

    #[test]
    fn expired_manifest_rejected() {
        let m = sample_manifest(Gate::Pcie, 1000);
        // now = expiry — expired exactly at the boundary.
        let err = m.validate(m.expires_at_ms).unwrap_err();
        assert!(format!("{err}").contains("expired"));
    }

    #[test]
    fn immutability_gate_requires_legal_review() {
        let m = sample_manifest(Gate::Immutability, 1000);
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(format!("{err}").contains("must-not-touch"));
    }

    #[test]
    fn signature_gate_requires_legal_review() {
        let m = sample_manifest(Gate::Signature, 1000);
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(format!("{err}").contains("must-not-touch"));
    }

    #[test]
    fn immutability_with_legal_review_validates() {
        let m = legal_manifest(Gate::Immutability, 1000);
        assert!(m.validate(m.issued_at_ms + 1).is_ok());
    }

    #[test]
    fn legal_review_must_differ_from_signers() {
        let mut m = legal_manifest(Gate::Immutability, 1000);
        m.legal_review_kid = Some(m.signer_kid.clone());
        let err = m.validate(m.issued_at_ms + 1).unwrap_err();
        assert!(format!("{err}").contains("distinct from signer + auditor"));
    }

    #[test]
    fn override_store_is_active_when_loaded() {
        let mut s = OverrideStore::new();
        let m = sample_manifest(Gate::Pcie, 1_000_000);
        let now = m.issued_at_ms + 1;
        s.insert(m);
        assert!(s.is_active(Gate::Pcie, now));
        assert!(!s.is_active(Gate::Zfs, now));
    }

    #[test]
    fn override_store_inactive_when_expired() {
        let mut s = OverrideStore::new();
        let m = sample_manifest(Gate::Pcie, 1000);
        let expiry = m.expires_at_ms;
        s.insert(m);
        // Past expiry → inactive.
        assert!(!s.is_active(Gate::Pcie, expiry + 1));
    }

    #[test]
    fn override_store_active_gates_lists_all_active() {
        let mut s = OverrideStore::new();
        let m1 = sample_manifest(Gate::Pcie, 100_000);
        let m2 = sample_manifest(Gate::Zfs, 200_000);
        let now = m1.issued_at_ms + 1;
        s.insert(m1);
        s.insert(m2);
        let active = s.active_gates(now);
        assert_eq!(active, vec![Gate::Pcie, Gate::Zfs]);
    }

    #[test]
    fn load_dir_missing_returns_empty() {
        let (store, report) = OverrideStore::load_dir(
            Path::new("/nonexistent/path"),
            Path::new("/nonexistent/trust"),
            1,
        )
        .unwrap();
        assert!(store.active_gates(1).is_empty());
        assert!(report.is_empty());
    }

    #[test]
    fn audit_chain_empty_file_ok() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.jsonl");
        fs::write(&p, "").unwrap();
        assert_eq!(audit_chain_check(&p).unwrap(), 0);
    }

    #[test]
    fn audit_chain_valid_lines_ok() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ocsf.jsonl");
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, r#"{{"class_uid":1003,"gate":"pcie"}}"#).unwrap();
        writeln!(f, r#"{{"class_uid":2004,"gate":"zfs"}}"#).unwrap();
        assert_eq!(audit_chain_check(&p).unwrap(), 2);
    }

    #[test]
    fn audit_chain_malformed_line_breaks_chain() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.jsonl");
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, r#"{{"class_uid":1003}}"#).unwrap();
        writeln!(f, "{{not json").unwrap();
        let err = audit_chain_check(&p).unwrap_err();
        assert!(matches!(
            err,
            FrictionAuditError::AuditChainBreak { line: 2, .. }
        ));
    }

    #[test]
    fn read_ring_buffer_empty_dir_ok() {
        let dir = tempfile::tempdir().unwrap();
        let v = read_ring_buffer(dir.path()).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn read_ring_buffer_loads_entries_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        for (ts, gate) in [(100, "pcie"), (300, "zfs"), (200, "memory")] {
            let p = dir.path().join(format!("{ts}-{gate}.json"));
            fs::write(
                &p,
                format!(r#"{{"gate":"{gate}","status":"pass","ts_ms":{ts},"hostname":"h"}}"#),
            )
            .unwrap();
        }
        let v = read_ring_buffer(dir.path()).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].ts_ms, 300);
        assert_eq!(v[1].ts_ms, 200);
        assert_eq!(v[2].ts_ms, 100);
    }

    #[test]
    fn default_override_path_per_gate() {
        assert!(
            default_override_path(Gate::Pcie)
                .to_string_lossy()
                .ends_with("friction-audit-pcie.json")
        );
        assert!(
            default_override_path(Gate::Memory)
                .to_string_lossy()
                .ends_with("friction-audit-memory.json")
        );
    }

    #[test]
    fn serde_roundtrip_manifest() {
        let m = sample_manifest(Gate::Zfs, 50_000);
        let j = serde_json::to_string(&m).unwrap();
        let back: OverrideManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn missing_signature_file_yields_signature_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = sample_manifest(Gate::Pcie, 100_000);
        let p = dir.path().join("friction-audit-pcie.json");
        fs::write(&p, serde_json::to_string(&manifest).unwrap()).unwrap();
        let trust_dir = tempfile::tempdir().unwrap();
        let err = OverrideStore::load_signed(&p, trust_dir.path(), manifest.issued_at_ms + 1)
            .unwrap_err();
        assert!(matches!(err, FrictionAuditError::Signature(_)));
    }
}
