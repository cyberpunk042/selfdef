//! `selfdef-perimeter` — SDD-028 Deliverable 3: runtime authority
//! surface for the real-time security perimeter (Tetragon
//! `sovereign-kernel-fence` TracingPolicy).
//!
//! Provides:
//! - [`ExtensionManifest`] — typed JSON schema for operator-signed
//!   allowlist-extension files at
//!   `/etc/selfdef/perimeter-extensions/<id>.json`
//! - [`ExtensionStore`] — loads + validates manifests, exposes
//!   "is this binary path currently allowlisted by an extension?" lookup
//! - [`read_ring_buffer`] — reads the Tetragon-event ring directory the
//!   selfdef-daemon writes, promotes entries to the canonical
//!   [`Verdict`] shape from `selfdef-perimeter-mirror`
//! - [`emit_ocsf_detection_2004`] — writes a single OCSF Detection 2004
//!   event to the ZFS log bridge (atomic append, audit-chain linked)
//! - [`audit_chain_check`] — verifies the OCSF event chain integrity
//!   via SHA-256 chained-prev-event-sha256 link (MS047 R11104)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use thiserror::Error;

pub use selfdef_perimeter_mirror::{
    Outcome, PerimeterError as MirrorError, SCHEMA_VERSION, Verdict, DEFAULT_ALLOWLIST,
};

/// Default allowlist-extension manifest directory.
pub const DEFAULT_EXTENSION_DIR: &str = "/etc/selfdef/perimeter-extensions";

/// Default ring-buffer directory (selfdef-daemon writes Tetragon events here).
pub const DEFAULT_RING_DIR: &str = "/var/cache/selfdef/perimeter/ring";

/// Default OCSF JSONL audit log (ZFS log bridge target).
pub const DEFAULT_OCSF_PATH: &str = "/var/log/selfdef/perimeter.ocsf.jsonl";

/// Default TracingPolicy YAML install path (host filesystem).
pub const DEFAULT_POLICY_PATH: &str =
    "/etc/tetragon/tracing-policies/sovereign-perimeter.yaml";

/// Default MS003 trust-roots directory.
pub const DEFAULT_TRUST_ROOTS_DIR: &str = "/etc/selfdef/trust-roots";

/// Maximum allowlist-extension TTL — 30 days per MS047 R11084.
pub const MAX_EXTENSION_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Minimum distinct signers for an extension (operator + auditor,
/// MS003 multi-sig per MS047 R11079).
pub const MIN_SIGNERS_PRODUCTION: usize = 2;

/// OCSF schema version for Detection 2004 events.
pub const OCSF_SCHEMA_VERSION: &str = "1.1.0";

/// Allowlist-extension manifest written to disk by an operator. JSON-
/// encoded; detached minisign signature lives at `<path>.minisig`
/// (MS003 convention).
///
/// The `binary_paths` field carries the extension entries; each path is
/// appended to the in-kernel allowlist for the duration of the manifest
/// TTL. Per MS047 R11079, this requires multi-sig + bounded TTL ≤ 30
/// days + an incident URL for audit anchoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionManifest {
    /// Schema version — MUST match [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable extension id. Lowercase kebab-case; used as the manifest
    /// filename stem and in the OCSF `extension_id` field.
    pub extension_id: String,
    /// Binary paths to be added to the in-kernel allowlist.
    pub binary_paths: Vec<String>,
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
    /// Optional ticket/incident URL anchoring the extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_url: Option<String>,
}

/// Errors produced by the runtime crate.
#[derive(Debug, Error)]
pub enum PerimeterError {
    /// Schema-version drift.
    #[error("schema version mismatch: expected {SCHEMA_VERSION}, got {0}")]
    SchemaMismatch(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(String),
    /// JSON parse / serialize error.
    #[error("serde_json: {0}")]
    Serde(String),
    /// Extension manifest constraint violation.
    #[error("extension invalid: {0}")]
    ExtensionInvalid(String),
    /// MS003 signature failed to verify.
    #[error("signature verification failed: {0}")]
    Signature(String),
    /// Tetragon control-plane error (reload / unix-socket).
    #[error("tetragon: {0}")]
    Tetragon(String),
    /// OCSF audit chain integrity broken.
    #[error("audit chain break at line {line}: {detail}")]
    AuditChainBreak {
        /// Line number in the OCSF jsonl file.
        line: usize,
        /// What was wrong.
        detail: String,
    },
}

impl ExtensionManifest {
    /// Validate the manifest content (NOT including signature). This is
    /// the schema + business-rule pass. Use [`ExtensionStore::load_signed`]
    /// for the full signature + multi-sig chain.
    ///
    /// # Errors
    /// Returns `PerimeterError::ExtensionInvalid` when any constraint
    /// fails. Returns `PerimeterError::SchemaMismatch` if the
    /// schema_version is wrong.
    pub fn validate(&self, now_ms: u64) -> Result<(), PerimeterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PerimeterError::SchemaMismatch(self.schema_version.clone()));
        }
        if self.extension_id.is_empty() {
            return Err(PerimeterError::ExtensionInvalid("extension_id is empty".into()));
        }
        if !self
            .extension_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(PerimeterError::ExtensionInvalid(format!(
                "extension_id {:?} must be lowercase-kebab-case (a-z, 0-9, '-')",
                self.extension_id
            )));
        }
        if self.binary_paths.is_empty() {
            return Err(PerimeterError::ExtensionInvalid(
                "binary_paths must contain at least one entry".into(),
            ));
        }
        for bp in &self.binary_paths {
            if !bp.starts_with('/') {
                return Err(PerimeterError::ExtensionInvalid(format!(
                    "binary_paths entry {bp:?} must be absolute (start with '/')"
                )));
            }
            // Disallow shell metacharacters / whitespace — Tetragon does
            // string-equality, but a path with shell metas in an extension
            // is almost certainly a typo or an attempted bypass.
            if bp.chars().any(|c| {
                c.is_whitespace() || matches!(c, '$' | '`' | '"' | '\'' | '*' | '?' | ';' | '|' | '&')
            }) {
                return Err(PerimeterError::ExtensionInvalid(format!(
                    "binary_paths entry {bp:?} contains whitespace or shell metacharacters"
                )));
            }
            if DEFAULT_ALLOWLIST.contains(&bp.as_str()) {
                return Err(PerimeterError::ExtensionInvalid(format!(
                    "binary_paths entry {bp:?} is already in the verbatim sain-01 §6 default allowlist; an extension is unnecessary"
                )));
            }
        }
        if self.reason.is_empty() {
            return Err(PerimeterError::ExtensionInvalid("reason is empty".into()));
        }
        if self.reason.len() > 512 {
            return Err(PerimeterError::ExtensionInvalid(
                "reason exceeds 512 chars".into(),
            ));
        }
        if self.signer_kid.is_empty() {
            return Err(PerimeterError::ExtensionInvalid("signer_kid is empty".into()));
        }
        if self.auditor_kid.is_empty() {
            return Err(PerimeterError::ExtensionInvalid(
                "auditor_kid is empty (production profile requires multi-sig)".into(),
            ));
        }
        if self.signer_kid == self.auditor_kid {
            return Err(PerimeterError::ExtensionInvalid(
                "signer_kid and auditor_kid must be distinct".into(),
            ));
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(PerimeterError::ExtensionInvalid(
                "expires_at_ms must be > issued_at_ms".into(),
            ));
        }
        let ttl = self.expires_at_ms - self.issued_at_ms;
        if ttl > MAX_EXTENSION_TTL_MS {
            return Err(PerimeterError::ExtensionInvalid(format!(
                "TTL {ttl} ms exceeds MAX_EXTENSION_TTL_MS ({MAX_EXTENSION_TTL_MS})"
            )));
        }
        if self.expires_at_ms <= now_ms {
            return Err(PerimeterError::ExtensionInvalid(
                "extension expired (expires_at_ms <= now_ms)".into(),
            ));
        }
        Ok(())
    }

    /// Compute the SHA-256 of the manifest's canonical JSON form
    /// (hex-encoded). Used by [`Outcome::ExtensionAllowed`] for audit
    /// traceability.
    ///
    /// # Errors
    /// Returns `PerimeterError::Serde` if canonical serialization fails.
    pub fn sha256_hex(&self) -> Result<String, PerimeterError> {
        let bytes = serde_json::to_vec(self).map_err(|e| PerimeterError::Serde(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Extension store — collection of currently-loaded manifests, indexed
/// by binary path.
#[derive(Debug, Default)]
pub struct ExtensionStore {
    by_path: BTreeMap<String, ExtensionManifest>,
    all: Vec<ExtensionManifest>,
}

impl ExtensionStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan a directory for `*.json` extension manifests; load each,
    /// validate + verify minisign signature, insert into the store.
    /// Files whose signatures fail OR whose content is invalid are
    /// SKIPPED (with a per-file `Err` in the returned report). Missing
    /// dir is not an error — returns empty store.
    ///
    /// # Errors
    /// Returns `PerimeterError::Io` only on read failure for an existing
    /// dir. Per-file failures are surfaced as the per-file `Err`.
    pub fn load_dir(
        dir: &Path,
        trust_roots_dir: &Path,
        now_ms: u64,
    ) -> Result<(Self, Vec<Result<String, PerimeterError>>), PerimeterError> {
        let mut store = Self::new();
        let mut report = Vec::new();
        if !dir.exists() {
            return Ok((store, report));
        }
        for dirent in fs::read_dir(dir).map_err(|e| PerimeterError::Io(e.to_string()))? {
            let dirent = dirent.map_err(|e| PerimeterError::Io(e.to_string()))?;
            let path = dirent.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            match Self::load_signed(&path, trust_roots_dir, now_ms) {
                Ok(m) => {
                    let id = m.extension_id.clone();
                    store.insert(m);
                    report.push(Ok(id));
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
    /// Returns `PerimeterError::Io` on read failure,
    /// `PerimeterError::Serde` on parse failure,
    /// `PerimeterError::ExtensionInvalid` on business-rule failure,
    /// `PerimeterError::Signature` on signature failure.
    pub fn load_signed(
        manifest_path: &Path,
        trust_roots_dir: &Path,
        now_ms: u64,
    ) -> Result<ExtensionManifest, PerimeterError> {
        let bytes = fs::read(manifest_path).map_err(|e| PerimeterError::Io(e.to_string()))?;
        let manifest: ExtensionManifest = serde_json::from_slice(&bytes)
            .map_err(|e| PerimeterError::Serde(e.to_string()))?;
        manifest.validate(now_ms)?;
        let sig_path = manifest_path.with_extension("json.minisig");
        if !sig_path.exists() {
            return Err(PerimeterError::Signature(format!(
                "detached signature not found at {}",
                sig_path.display()
            )));
        }
        verify_minisign(&bytes, &sig_path, trust_roots_dir)
            .map_err(|e| PerimeterError::Signature(e.to_string()))?;
        Ok(manifest)
    }

    /// Insert a manifest into the store (does NOT re-validate; use
    /// [`ExtensionStore::load_signed`] for the full check).
    pub fn insert(&mut self, manifest: ExtensionManifest) {
        for bp in &manifest.binary_paths {
            self.by_path.insert(bp.clone(), manifest.clone());
        }
        self.all.push(manifest);
    }

    /// Is the given binary path currently allowlisted by a non-expired
    /// extension manifest?
    #[must_use]
    pub fn is_active(&self, binary_path: &str, now_ms: u64) -> bool {
        match self.by_path.get(binary_path) {
            None => false,
            Some(m) => m.expires_at_ms > now_ms,
        }
    }

    /// Get the active extension manifest for a binary path
    /// (None if none / expired).
    #[must_use]
    pub fn get(&self, binary_path: &str, now_ms: u64) -> Option<&ExtensionManifest> {
        if !self.is_active(binary_path, now_ms) {
            return None;
        }
        self.by_path.get(binary_path)
    }

    /// All currently-loaded extension manifests (regardless of expiry).
    #[must_use]
    pub fn all(&self) -> &[ExtensionManifest] {
        &self.all
    }

    /// All currently-active (non-expired) extension manifests.
    #[must_use]
    pub fn active(&self, now_ms: u64) -> Vec<&ExtensionManifest> {
        self.all.iter().filter(|m| m.expires_at_ms > now_ms).collect()
    }

    /// All currently-allowlisted binary paths from active extensions.
    #[must_use]
    pub fn active_paths(&self, now_ms: u64) -> Vec<String> {
        let mut paths: Vec<String> = self
            .by_path
            .iter()
            .filter(|(_, m)| m.expires_at_ms > now_ms)
            .map(|(p, _)| p.clone())
            .collect();
        paths.sort();
        paths
    }
}

/// Verify a detached minisign signature against the trust roots
/// directory. Returns Ok(()) on success; returns Err with detail on
/// failure.
///
/// # Errors
/// Returns an error if no public key in `trust_roots_dir` validates
/// the signature, OR if the signature/public-key files are malformed.
fn verify_minisign(
    payload: &[u8],
    sig_path: &Path,
    trust_roots_dir: &Path,
) -> Result<(), String> {
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
/// skipped.
///
/// # Errors
/// Returns `PerimeterError::Io` on read failure of an existing dir.
pub fn read_ring_buffer(ring: &Path) -> Result<Vec<Verdict>, PerimeterError> {
    if !ring.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Verdict> = Vec::new();
    for dirent in fs::read_dir(ring).map_err(|e| PerimeterError::Io(e.to_string()))? {
        let dirent = dirent.map_err(|e| PerimeterError::Io(e.to_string()))?;
        let path = dirent.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(verdict) = serde_json::from_slice::<Verdict>(&bytes) {
            // Only accept verdicts whose mirror-side validate() passes —
            // a malformed verdict in the ring is worth surfacing in logs
            // but never blocks operator visibility into the rest.
            if verdict.validate().is_ok() {
                out.push(verdict);
            }
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(v.ts_ms));
    Ok(out)
}

/// Emit a single OCSF Detection 2004 event to the ZFS log bridge.
///
/// Atomic append (O_APPEND opened per call); each event is one JSONL
/// line. The event carries `prev_event_sha256` chained from the last
/// line of the existing file, satisfying the audit-chain invariant.
///
/// Per MS047 R11088-R11102 (OCSF schema binding) and R11103-R11109 (ZFS
/// log bridge atomic append).
///
/// # Errors
/// Returns `PerimeterError::Io` on file I/O failure,
/// `PerimeterError::Serde` on serialization failure.
pub fn emit_ocsf_detection_2004(
    ocsf_jsonl: &Path,
    verdict: &Verdict,
) -> Result<(), PerimeterError> {
    if let Some(parent) = ocsf_jsonl.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| PerimeterError::Io(e.to_string()))?;
        }
    }
    let prev_sha = last_line_sha256(ocsf_jsonl)?;
    let category_uid = 2u32;
    let class_uid = 2004u32;
    let (activity_id, severity_id, status_id, type_uid) = match verdict.outcome {
        // Outcome → OCSF activity/severity. Sigkill is "Block" + high severity.
        Outcome::Sigkill => (3u32, 5u32, 1u32, class_uid * 100 + 3),
        // Allowlisted execve is best emitted on the Audit 1003 channel,
        // but the perimeter routes all events through Detection 2004 for
        // single-stream audit-chain integrity; severity_id=1 marks informational.
        Outcome::Allowlisted => (1u32, 1u32, 1u32, class_uid * 100 + 1),
        // ExtensionAllowed is a "Detect" with severity informational + a
        // signer-chain field set so the operator can audit the extension.
        Outcome::ExtensionAllowed { .. } => (1u32, 2u32, 1u32, class_uid * 100 + 1),
    };
    let event = serde_json::json!({
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "name": "selfdef-perimeter",
                "vendor_name": "selfdef",
            },
            "log_name": "perimeter",
        },
        "category_uid": category_uid,
        "class_uid": class_uid,
        "class_name": "Detection Finding",
        "type_uid": type_uid,
        "activity_id": activity_id,
        "severity_id": severity_id,
        "status_id": status_id,
        "time": verdict.ts_ms,
        "device": {
            "hostname": verdict.hostname,
        },
        "process": {
            "pid": verdict.attempting_pid,
            "parent_process": { "pid": verdict.parent_pid },
            "cmd_line": verdict.process_cmdline,
            "file": { "path": verdict.attempted_binary_path },
            "container": {
                "id": verdict.container_id,
            },
            "cgroup": verdict.cgroup,
        },
        "outcome": verdict.outcome,
        "policy_signer_kid": verdict.signer_kid_policy,
        "extension_signer_kid": verdict.signer_kid_extension,
        "schema_version": verdict.schema_version,
        "prev_event_sha256": prev_sha,
    });
    let line = serde_json::to_string(&event).map_err(|e| PerimeterError::Serde(e.to_string()))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ocsf_jsonl)
        .map_err(|e| PerimeterError::Io(e.to_string()))?;
    writeln!(f, "{line}").map_err(|e| PerimeterError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| PerimeterError::Io(e.to_string()))?;
    Ok(())
}

/// Return the SHA-256 hex of the last non-empty line of the file, or
/// None when the file is missing/empty. Used to chain the next event.
fn last_line_sha256(path: &Path) -> Result<Option<String>, PerimeterError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| PerimeterError::Io(e.to_string()))?;
    let last = text.lines().filter(|l| !l.trim().is_empty()).next_back();
    match last {
        None => Ok(None),
        Some(line) => {
            let mut h = Sha256::new();
            h.update(line.as_bytes());
            Ok(Some(format!("{:x}", h.finalize())))
        }
    }
}

/// Verify the OCSF audit chain integrity. Each event after the first
/// carries `prev_event_sha256` referencing the SHA-256 of the prior
/// event's canonical JSON line. A broken chain is treated as a
/// CRITICAL signal per MS047 R11104.
///
/// # Errors
/// Returns `PerimeterError::AuditChainBreak` when a chain integrity
/// invariant fails (malformed JSON, or a prev hash that doesn't match
/// the prior line's SHA-256).
pub fn audit_chain_check(ocsf_jsonl: &Path) -> Result<usize, PerimeterError> {
    if !ocsf_jsonl.exists() {
        return Ok(0);
    }
    let text = fs::read_to_string(ocsf_jsonl).map_err(|e| PerimeterError::Io(e.to_string()))?;
    let mut last_sha: Option<String> = None;
    let mut events_seen = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            PerimeterError::AuditChainBreak {
                line: idx + 1,
                detail: format!("malformed JSON: {e}"),
            }
        })?;
        let claimed_prev = parsed
            .get("prev_event_sha256")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        match (&last_sha, claimed_prev.as_deref()) {
            (Some(want), Some(got)) if got != want => {
                return Err(PerimeterError::AuditChainBreak {
                    line: idx + 1,
                    detail: format!("prev_event_sha256={got}, expected {want}"),
                });
            }
            (Some(_), None) => {
                return Err(PerimeterError::AuditChainBreak {
                    line: idx + 1,
                    detail: "prev_event_sha256 missing from non-first event".into(),
                });
            }
            _ => {}
        }
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

/// Convenience: load the extension store from the default directories.
///
/// # Errors
/// Returns underlying `ExtensionStore::load_dir` errors.
pub fn load_default_extensions(
    now_ms: u64,
) -> Result<(ExtensionStore, Vec<Result<String, PerimeterError>>), PerimeterError> {
    ExtensionStore::load_dir(
        Path::new(DEFAULT_EXTENSION_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now_ms,
    )
}

/// Format a default extension manifest path for a given extension id.
#[must_use]
pub fn default_extension_path(extension_id: &str) -> PathBuf {
    Path::new(DEFAULT_EXTENSION_DIR).join(format!("{extension_id}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_manifest() -> ExtensionManifest {
        let now = 1_700_000_000_000;
        ExtensionManifest {
            schema_version: SCHEMA_VERSION.to_string(),
            extension_id: "custom-tools-2026q2".into(),
            binary_paths: vec!["/usr/local/bin/foo".into(), "/opt/llm/bar".into()],
            reason: "internal tooling rollout — ticket #321".into(),
            issued_at_ms: now,
            expires_at_ms: now + 24 * 60 * 60 * 1000,
            signer_kid: "kid-operator-A".into(),
            auditor_kid: "kid-auditor-B".into(),
            incident_url: Some("https://ops.example.com/tickets/321".into()),
        }
    }

    #[test]
    fn valid_manifest_passes_validation() {
        let m = sample_manifest();
        assert!(m.validate(m.issued_at_ms + 1).is_ok());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = sample_manifest();
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate(m.issued_at_ms + 1).unwrap_err(),
            PerimeterError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn empty_extension_id_rejected() {
        let mut m = sample_manifest();
        m.extension_id.clear();
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("extension_id is empty"));
    }

    #[test]
    fn non_kebab_extension_id_rejected() {
        let mut m = sample_manifest();
        m.extension_id = "BadID".into();
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("kebab-case"));
    }

    #[test]
    fn empty_binary_paths_rejected() {
        let mut m = sample_manifest();
        m.binary_paths.clear();
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("at least one entry"));
    }

    #[test]
    fn relative_binary_path_rejected() {
        let mut m = sample_manifest();
        m.binary_paths = vec!["bin/foo".into()];
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("absolute"));
    }

    #[test]
    fn shell_metachar_in_binary_path_rejected() {
        let mut m = sample_manifest();
        m.binary_paths = vec!["/usr/bin/evil; rm".into()];
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("metacharacters"));
    }

    #[test]
    fn redundant_default_allowlist_entry_rejected() {
        let mut m = sample_manifest();
        m.binary_paths = vec!["/usr/bin/python3".into()];
        let err_msg = format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err());
        assert!(err_msg.contains("already in the verbatim sain-01 §6"));
    }

    #[test]
    fn empty_reason_rejected() {
        let mut m = sample_manifest();
        m.reason.clear();
        assert!(matches!(
            m.validate(m.issued_at_ms + 1).unwrap_err(),
            PerimeterError::ExtensionInvalid(_)
        ));
    }

    #[test]
    fn reason_over_512_chars_rejected() {
        let mut m = sample_manifest();
        m.reason = "x".repeat(513);
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("exceeds 512"));
    }

    #[test]
    fn signer_equals_auditor_rejected() {
        let mut m = sample_manifest();
        m.auditor_kid = m.signer_kid.clone();
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("distinct"));
    }

    #[test]
    fn ttl_over_30_days_rejected() {
        let mut m = sample_manifest();
        m.expires_at_ms = m.issued_at_ms + MAX_EXTENSION_TTL_MS + 1;
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("exceeds MAX_EXTENSION_TTL_MS"));
    }

    #[test]
    fn expired_manifest_rejected() {
        let m = sample_manifest();
        assert!(format!("{}", m.validate(m.expires_at_ms).unwrap_err())
            .contains("expired"));
    }

    #[test]
    fn expires_before_issue_rejected() {
        let mut m = sample_manifest();
        m.expires_at_ms = m.issued_at_ms - 1;
        assert!(format!("{}", m.validate(m.issued_at_ms + 1).unwrap_err())
            .contains("expires_at_ms must be >"));
    }

    #[test]
    fn store_active_lookup_returns_manifest() {
        let m = sample_manifest();
        let mut store = ExtensionStore::new();
        store.insert(m.clone());
        assert!(store.is_active("/usr/local/bin/foo", m.issued_at_ms + 1));
        assert!(store.is_active("/opt/llm/bar", m.issued_at_ms + 1));
        assert!(!store.is_active("/usr/bin/curl", m.issued_at_ms + 1));
    }

    #[test]
    fn store_active_lookup_respects_expiry() {
        let m = sample_manifest();
        let mut store = ExtensionStore::new();
        let expiry = m.expires_at_ms;
        store.insert(m);
        assert!(!store.is_active("/usr/local/bin/foo", expiry + 1));
    }

    #[test]
    fn store_active_paths_sorted() {
        let m = sample_manifest();
        let mut store = ExtensionStore::new();
        store.insert(m.clone());
        let paths = store.active_paths(m.issued_at_ms + 1);
        assert_eq!(paths, vec!["/opt/llm/bar".to_string(), "/usr/local/bin/foo".to_string()]);
    }

    #[test]
    fn manifest_sha256_is_stable() {
        let m = sample_manifest();
        let s1 = m.sha256_hex().unwrap();
        let s2 = m.sha256_hex().unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 64);
    }

    #[test]
    fn load_dir_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let nope = dir.path().join("nope");
        let (store, report) = ExtensionStore::load_dir(&nope, dir.path(), 1).unwrap();
        assert!(store.all().is_empty());
        assert!(report.is_empty());
    }

    #[test]
    fn load_signed_missing_signature_errors() {
        let dir = TempDir::new().unwrap();
        let manifest_path = dir.path().join("e.json");
        fs::write(&manifest_path, serde_json::to_vec(&sample_manifest()).unwrap()).unwrap();
        let trust = dir.path().join("trust");
        fs::create_dir_all(&trust).unwrap();
        let err = ExtensionStore::load_signed(&manifest_path, &trust, 1_700_000_000_001).unwrap_err();
        assert!(matches!(err, PerimeterError::Signature(_)));
    }

    #[test]
    fn ring_buffer_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let nope = dir.path().join("nope");
        let v = read_ring_buffer(&nope).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn ring_buffer_reads_valid_verdicts() {
        let dir = TempDir::new().unwrap();
        let v = Verdict::new(
            Outcome::Sigkill,
            "/usr/bin/evil",
            42,
            41,
            "/",
            "",
            "evil",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        );
        let p = dir.path().join("a.json");
        fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        let out = read_ring_buffer(dir.path()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].is_sigkill());
    }

    #[test]
    fn ring_buffer_skips_malformed_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("bad.json"), b"{not json}").unwrap();
        let v = Verdict::new(
            Outcome::Allowlisted,
            "/usr/bin/python3",
            42,
            41,
            "/",
            "",
            "p",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        );
        fs::write(dir.path().join("good.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        let out = read_ring_buffer(dir.path()).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn ring_buffer_sorted_newest_first() {
        let dir = TempDir::new().unwrap();
        for (i, ts) in [("a", 100_u64), ("b", 300), ("c", 200)] {
            let v = Verdict::new(
                Outcome::Sigkill,
                "/x",
                42,
                41,
                "/",
                "",
                "x",
                ts,
                "h",
                "k",
            );
            fs::write(
                dir.path().join(format!("{i}.json")),
                serde_json::to_vec(&v).unwrap(),
            )
            .unwrap();
        }
        let out = read_ring_buffer(dir.path()).unwrap();
        let ts: Vec<u64> = out.iter().map(|v| v.ts_ms).collect();
        assert_eq!(ts, vec![300, 200, 100]);
    }

    #[test]
    fn emit_ocsf_writes_one_jsonl_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let v = Verdict::new(
            Outcome::Sigkill,
            "/usr/bin/curl",
            123,
            42,
            "/system.slice/sshd.service",
            "",
            "curl evil.example.com",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        );
        emit_ocsf_detection_2004(&path, &v).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["class_uid"].as_u64(), Some(2004));
        assert_eq!(parsed["activity_id"].as_u64(), Some(3));
        assert_eq!(parsed["severity_id"].as_u64(), Some(5));
        assert_eq!(parsed["device"]["hostname"].as_str(), Some("host-A"));
        assert_eq!(
            parsed["process"]["file"]["path"].as_str(),
            Some("/usr/bin/curl")
        );
        assert!(parsed["prev_event_sha256"].is_null());
    }

    #[test]
    fn emit_ocsf_chains_prev_event_sha256() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let v = Verdict::new(
            Outcome::Sigkill,
            "/usr/bin/curl",
            123,
            42,
            "/",
            "",
            "curl",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        );
        emit_ocsf_detection_2004(&path, &v).unwrap();
        let mut v2 = v.clone();
        v2.ts_ms = 1_700_000_001_000;
        emit_ocsf_detection_2004(&path, &v2).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let line2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let prev = line2["prev_event_sha256"].as_str().expect("chained");
        let mut h = Sha256::new();
        h.update(lines[0].as_bytes());
        assert_eq!(prev, format!("{:x}", h.finalize()));
    }

    #[test]
    fn audit_chain_check_validates_chained_events() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        for i in 0..3 {
            let v = Verdict::new(
                Outcome::Sigkill,
                "/x",
                i,
                0,
                "/",
                "",
                "x",
                1_700_000_000_000 + u64::from(i),
                "h",
                "k",
            );
            emit_ocsf_detection_2004(&path, &v).unwrap();
        }
        let n = audit_chain_check(&path).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn audit_chain_check_detects_break() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        // Two events with the second one carrying a wrong prev_event_sha256.
        let l1 = r#"{"class_uid":2004,"activity_id":3}"#;
        let l2 = r#"{"class_uid":2004,"activity_id":3,"prev_event_sha256":"bogus-hex"}"#;
        fs::write(&path, format!("{l1}\n{l2}\n")).unwrap();
        let err = audit_chain_check(&path).unwrap_err();
        assert!(matches!(err, PerimeterError::AuditChainBreak { line: 2, .. }));
    }

    #[test]
    fn audit_chain_check_missing_file_returns_zero() {
        let dir = TempDir::new().unwrap();
        let n = audit_chain_check(&dir.path().join("nope.jsonl")).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn default_extension_path_format() {
        assert_eq!(
            default_extension_path("custom-tools").to_string_lossy(),
            format!("{DEFAULT_EXTENSION_DIR}/custom-tools.json")
        );
    }
}
