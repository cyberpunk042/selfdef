//! `selfdef-capability-registry` — daemon-resident, persistent registry
//! of issued MS035 capability tokens. The live D-14 state the selfdef
//! daemon projects into the `selfdef-capability-mirror` MS007 snapshot
//! for sovereign-os to render READ-ONLY.
//!
//! Closes the publisher gap for D-14: `selfdef-capability-mirror`
//! defines the wire schema and `selfdef-capability-word` provides the
//! 64-bit `capability_word` bit-field, but nothing held the *set* of
//! live tokens or persisted it. This crate is that registry:
//!
//! - holds a [`CapabilityMirrorSnapshot`] (the same wire type the mirror
//!   publishes — no parallel schema),
//! - persists atomically to `/var/lib/selfdef/capability-tokens.json`
//!   ([`DEFAULT_STATE_PATH`]) — the daemon-resident store the mirror-
//!   export loop reads,
//! - issues by composing [`selfdef_capability_word::CapabilityWord`]
//!   from the operator's requested [`ToolClass`] set + trust ring
//!   numeric (per MS039 R09430),
//! - transitions tokens through their MS035 lifecycle (Pending →
//!   Active, → Revoked/Expired/Quarantined) with summary recompute,
//! - supports F04146 parent-child inheritance (`parent_token_id`).
//!
//! Mutation is an IPS-side verb (selfdefctl + MS003); sovereign-os never
//! mutates this — it renders the published mirror READ-ONLY (MS043 R10212).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use selfdef_capability_word::{CapabilityWord, ToolClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports: consumers (daemon, CLI) depend only on this crate
// for the capability types, not the underlying mirror/word crates.
pub use selfdef_capability_mirror::{
    AuthorityLevel, CapabilityEntry, CapabilityMirrorSnapshot, RingSummary, SCHEMA_VERSION,
    TokenState, TrustRing,
};
pub use selfdef_capability_word::ToolClass as Tool;

/// Default on-disk path for the persisted registry (operator override
/// via `SELFDEF_CAPABILITY_TOKENS_PATH`). The daemon's mirror-export
/// loop reads this resident store and republishes it to the sovereign-os
/// mirror dir.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/capability-tokens.json";

/// Hard upper bound on token TTL — 86400 seconds (24h) per MS040 R09407.
pub const MAX_TTL_SECONDS: u32 = 86_400;

/// Sandbox-tier discriminator. Operator-readable single letter per
/// MS036 A/B/C/D. Kept as a `String` on the wire to match the mirror
/// `CapabilityEntry::sandbox_tier` field shape.
pub const SANDBOX_TIERS: [&str; 4] = ["A", "B", "C", "D"];

/// Operator-signed capability-token issuance request. Mirrors the
/// MS035 issuance envelope; signature is mandatory per the verify-only
/// signing doctrine (operators sign externally with the `minisign` CLI).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRequest {
    /// Requesting actor MS003 fingerprint.
    pub actor: String,
    /// Active profile at issuance time (MS040).
    pub profile: String,
    /// Allowed tool kebab-case tokens (e.g. `read-only-host`,
    /// `gpu-compute`). Non-empty per MS035 — a token granting nothing
    /// is rejected.
    pub allowed_tools: Vec<String>,
    /// Trust ring assignment (MS039 Ring 0..4).
    pub trust_ring: TrustRing,
    /// Highest authority level minted into the token.
    pub authority_level: AuthorityLevel,
    /// Sandbox tier (MS036 A/B/C/D).
    pub sandbox_tier: String,
    /// Parent capability-token id for inheritance per F04146. Empty for
    /// root tokens.
    #[serde(default)]
    pub parent_token_id: String,
    /// Desired TTL in seconds (≤ [`MAX_TTL_SECONDS`]).
    pub ttl_seconds: u32,
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
    /// `allowed_tools` empty — a token granting nothing is meaningless.
    #[error("allowed_tools empty (token must grant at least one tool)")]
    EmptyTools,
    /// `allowed_tools` contained an unknown tool token.
    #[error("unknown tool {0:?} (expected one of {1})")]
    UnknownTool(String, String),
    /// `sandbox_tier` not one of A/B/C/D.
    #[error("invalid sandbox_tier {0:?} (expected one of A/B/C/D)")]
    InvalidSandboxTier(String),
    /// TTL above ceiling.
    #[error("ttl {0}s above {1}s ceiling")]
    TtlAboveCeiling(u32, u32),
    /// TTL zero.
    #[error("ttl=0 not allowed (tokens must have non-zero lifetime)")]
    TtlZero,
    /// `capability_word` construction failed (e.g. trust level out of range).
    #[error("capability_word build failed: {0}")]
    WordBuild(String),
    /// Persisted store was present but malformed.
    #[error("malformed capability-tokens store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("capability-tokens store io error at {path}: {source}")]
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

/// Daemon-resident capability-token registry.
#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    snapshot: CapabilityMirrorSnapshot,
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an operator-supplied kebab-case tool token into [`ToolClass`].
fn parse_tool(token: &str) -> Option<ToolClass> {
    match token {
        "read-only-host" => Some(ToolClass::ReadOnlyHost),
        "write-host" => Some(ToolClass::WriteHost),
        "tests" => Some(ToolClass::Tests),
        "builds" => Some(ToolClass::Builds),
        "network-egress" => Some(ToolClass::NetworkEgress),
        "gpu-compute" => Some(ToolClass::GpuCompute),
        "vm-spawn" => Some(ToolClass::VmSpawn),
        "browser" => Some(ToolClass::Browser),
        _ => None,
    }
}

/// Lowercase list of all valid tool tokens, for error messages.
fn valid_tools_csv() -> String {
    [
        "read-only-host",
        "write-host",
        "tests",
        "builds",
        "network-egress",
        "gpu-compute",
        "vm-spawn",
        "browser",
    ]
    .join(", ")
}

/// Numeric position of a trust ring per MS039 R09430 (Ring0 → 0 … Ring4 → 4).
fn trust_ring_numeric(r: TrustRing) -> u8 {
    match r {
        TrustRing::Ring0 => 0,
        TrustRing::Ring1 => 1,
        TrustRing::Ring2 => 2,
        TrustRing::Ring3 => 3,
        TrustRing::Ring4 => 4,
    }
}

impl CapabilityRegistry {
    /// New empty registry, schema pinned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: CapabilityMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: String::new(),
                summaries: Vec::new(),
                tokens: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Adopt an existing snapshot as the registry state.
    #[must_use]
    pub fn from_snapshot(snapshot: CapabilityMirrorSnapshot) -> Self {
        Self { snapshot }
    }

    /// Load the persisted registry. ABSENT → empty. PRESENT-but-malformed
    /// → error (operators see corruption loudly, not silent loss).
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

    /// Atomically persist the registry (sibling tempfile + rename).
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

    /// Issue a capability token from a signed request as of `now`.
    /// Composes `capability_word` from the requested tools + trust ring,
    /// appends a Pending entry, recomputes per-ring summaries + capture
    /// timestamp, returns the new token id.
    pub fn issue(
        &mut self,
        req: &CapabilityRequest,
        token_id: &str,
        trace_id: &str,
        now: OffsetDateTime,
    ) -> Result<String, RegistryError> {
        // Validation gates (mirror grant-issuer discipline).
        if req.signature.is_empty() {
            return Err(RegistryError::Unsigned);
        }
        if req.actor.is_empty() {
            return Err(RegistryError::EmptyField("actor"));
        }
        if req.profile.is_empty() {
            return Err(RegistryError::EmptyField("profile"));
        }
        if req.allowed_tools.is_empty() {
            return Err(RegistryError::EmptyTools);
        }
        if !SANDBOX_TIERS.contains(&req.sandbox_tier.as_str()) {
            return Err(RegistryError::InvalidSandboxTier(req.sandbox_tier.clone()));
        }
        if req.ttl_seconds == 0 {
            return Err(RegistryError::TtlZero);
        }
        if req.ttl_seconds > MAX_TTL_SECONDS {
            return Err(RegistryError::TtlAboveCeiling(
                req.ttl_seconds,
                MAX_TTL_SECONDS,
            ));
        }

        // Parse tools + build the canonical 64-bit capability_word.
        let mut parsed_tools = Vec::with_capacity(req.allowed_tools.len());
        for tok in &req.allowed_tools {
            let t = parse_tool(tok)
                .ok_or_else(|| RegistryError::UnknownTool(tok.clone(), valid_tools_csv()))?;
            parsed_tools.push(t);
        }
        let mut word = CapabilityWord::empty();
        for t in &parsed_tools {
            word.allow_tool(*t);
        }
        word.set_trust_level(trust_ring_numeric(req.trust_ring))
            .map_err(|e| RegistryError::WordBuild(format!("{e:?}")))?;
        let capability_word = word.to_hex();

        let issued_at = now.format(&Rfc3339)?;
        let expires = now + time::Duration::seconds(i64::from(req.ttl_seconds));
        let expires_at = expires.format(&Rfc3339)?;

        // Canonicalize allowed_tools to the kebab-case wire form so the
        // entry's `allowed_tools` mirrors the bits exactly.
        let allowed_tools = parsed_tools
            .iter()
            .map(|t| tool_token(*t).to_string())
            .collect();

        let entry = CapabilityEntry {
            token_id: token_id.to_string(),
            capability_word,
            actor: req.actor.clone(),
            profile: req.profile.clone(),
            trust_ring: req.trust_ring,
            authority_level: req.authority_level,
            allowed_tools,
            sandbox_tier: req.sandbox_tier.clone(),
            issued_at,
            expires_at,
            ttl_seconds: req.ttl_seconds,
            state: TokenState::Pending,
            trace_id: trace_id.to_string(),
            parent_token_id: req.parent_token_id.clone(),
            signature: req.signature.clone(),
        };
        self.snapshot.tokens.push(entry);
        self.recompute(now)?;
        Ok(token_id.to_string())
    }

    /// Transition a Pending token to Active. Returns true if a matching
    /// token was transitioned.
    pub fn activate(&mut self, token_id: &str, now: OffsetDateTime) -> Result<bool, RegistryError> {
        self.set_state(token_id, TokenState::Active, now)
    }

    /// Revoke a token (operator-forced or drift).
    pub fn revoke(&mut self, token_id: &str, now: OffsetDateTime) -> Result<bool, RegistryError> {
        self.set_state(token_id, TokenState::Revoked, now)
    }

    /// Mark every Active/Pending token whose `expires_at` is past `now`
    /// as Expired. Presentation-time lifecycle hygiene — the daemon
    /// export runs this each tick.
    pub fn expire_due(&mut self, now: OffsetDateTime) -> Result<usize, RegistryError> {
        let mut changed = 0usize;
        for t in &mut self.snapshot.tokens {
            if matches!(t.state, TokenState::Active | TokenState::Pending) {
                if let Ok(exp) = OffsetDateTime::parse(&t.expires_at, &Rfc3339) {
                    if exp <= now {
                        t.state = TokenState::Expired;
                        changed += 1;
                    }
                }
            }
        }
        if changed > 0 {
            self.recompute(now)?;
        }
        Ok(changed)
    }

    fn set_state(
        &mut self,
        token_id: &str,
        state: TokenState,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        let found = self
            .snapshot
            .tokens
            .iter_mut()
            .find(|t| t.token_id == token_id);
        match found {
            Some(t) => {
                t.state = state;
                self.recompute(now)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Recompute per-ring summaries + stamp `captured_at`.
    fn recompute(&mut self, now: OffsetDateTime) -> Result<(), RegistryError> {
        self.snapshot.summaries = self.snapshot.recompute_summaries();
        self.snapshot.captured_at = now.format(&Rfc3339)?;
        Ok(())
    }

    /// Current published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &CapabilityMirrorSnapshot {
        &self.snapshot
    }

    /// Live token entries.
    #[must_use]
    pub fn tokens(&self) -> &[CapabilityEntry] {
        &self.snapshot.tokens
    }

    /// Count of tokens currently Active.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.snapshot.active_count()
    }
}

/// Inverse of [`parse_tool`] — canonical kebab-case token for a
/// [`ToolClass`]. Used to canonicalize `allowed_tools` in the issued
/// entry so the bits + tokens never drift.
fn tool_token(t: ToolClass) -> &'static str {
    match t {
        ToolClass::ReadOnlyHost => "read-only-host",
        ToolClass::WriteHost => "write-host",
        ToolClass::Tests => "tests",
        ToolClass::Builds => "builds",
        ToolClass::NetworkEgress => "network-egress",
        ToolClass::GpuCompute => "gpu-compute",
        ToolClass::VmSpawn => "vm-spawn",
        ToolClass::Browser => "browser",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn req(tools: &[&str], ring: TrustRing) -> CapabilityRequest {
        CapabilityRequest {
            actor: "operator-fp".into(),
            profile: "careful".into(),
            allowed_tools: tools.iter().map(|s| (*s).to_string()).collect(),
            trust_ring: ring,
            authority_level: AuthorityLevel::L4Execute,
            sandbox_tier: "A".into(),
            parent_token_id: String::new(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn new_is_empty_and_schema_pinned() {
        let r = CapabilityRegistry::new();
        assert!(r.tokens().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn issue_appends_pending_with_word_and_trust_level() {
        let mut r = CapabilityRegistry::new();
        r.issue(
            &req(&["read-only-host", "tests"], TrustRing::Ring2),
            "tok-1",
            "tr-1",
            now(),
        )
        .unwrap();
        let t = &r.tokens()[0];
        assert_eq!(t.state, TokenState::Pending);
        assert_eq!(t.trust_ring, TrustRing::Ring2);
        assert_eq!(t.allowed_tools, vec!["read-only-host", "tests"]);
        // capability_word: byte 0 = tool bits (ReadOnlyHost=bit0, Tests=bit2)
        // → 0b0000_0101 = 0x05. byte 6 = trust_level Ring2 = 2.
        let word = CapabilityWord::from_hex(&t.capability_word).unwrap();
        assert!(word.has_tool(ToolClass::ReadOnlyHost));
        assert!(word.has_tool(ToolClass::Tests));
        assert!(!word.has_tool(ToolClass::WriteHost));
        assert_eq!(word.trust_level().unwrap(), 2);
        // ring-2 pending count = 1
        let s = r
            .snapshot()
            .summaries
            .iter()
            .find(|s| s.ring == TrustRing::Ring2)
            .unwrap();
        assert_eq!(s.pending, 1);
    }

    #[test]
    fn issue_rejects_unsigned() {
        let mut r = CapabilityRegistry::new();
        let mut bad = req(&["read-only-host"], TrustRing::Ring0);
        bad.signature = String::new();
        assert!(matches!(
            r.issue(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::Unsigned
        ));
    }

    #[test]
    fn issue_rejects_empty_tools() {
        let mut r = CapabilityRegistry::new();
        let bad = req(&[], TrustRing::Ring0);
        assert!(matches!(
            r.issue(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::EmptyTools
        ));
    }

    #[test]
    fn issue_rejects_unknown_tool() {
        let mut r = CapabilityRegistry::new();
        let bad = req(&["godmode"], TrustRing::Ring0);
        assert!(matches!(
            r.issue(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::UnknownTool(t, _) if t == "godmode"
        ));
    }

    #[test]
    fn issue_rejects_bad_sandbox_tier() {
        let mut r = CapabilityRegistry::new();
        let mut bad = req(&["tests"], TrustRing::Ring0);
        bad.sandbox_tier = "Z".into();
        assert!(matches!(
            r.issue(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::InvalidSandboxTier(s) if s == "Z"
        ));
    }

    #[test]
    fn issue_rejects_ttl_zero_and_above_ceiling() {
        let mut r = CapabilityRegistry::new();
        let mut z = req(&["tests"], TrustRing::Ring0);
        z.ttl_seconds = 0;
        assert!(matches!(
            r.issue(&z, "x", "t", now()).unwrap_err(),
            RegistryError::TtlZero
        ));
        let mut big = req(&["tests"], TrustRing::Ring0);
        big.ttl_seconds = MAX_TTL_SECONDS + 1;
        assert!(matches!(
            r.issue(&big, "x", "t", now()).unwrap_err(),
            RegistryError::TtlAboveCeiling(_, MAX_TTL_SECONDS)
        ));
    }

    #[test]
    fn activate_then_revoke_transitions_state() {
        let mut r = CapabilityRegistry::new();
        r.issue(&req(&["tests"], TrustRing::Ring2), "tok-1", "t1", now())
            .unwrap();
        assert!(r.activate("tok-1", now()).unwrap());
        assert_eq!(r.tokens()[0].state, TokenState::Active);
        assert_eq!(r.active_count(), 1);
        assert!(r.revoke("tok-1", now()).unwrap());
        assert_eq!(r.tokens()[0].state, TokenState::Revoked);
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn expire_due_marks_past_ttl_tokens() {
        let mut r = CapabilityRegistry::new();
        let mut q = req(&["tests"], TrustRing::Ring0);
        q.ttl_seconds = 60;
        r.issue(&q, "tok-1", "t1", now()).unwrap();
        r.activate("tok-1", now()).unwrap();
        let later = now() + time::Duration::seconds(61);
        assert_eq!(r.expire_due(later).unwrap(), 1);
        assert_eq!(r.tokens()[0].state, TokenState::Expired);
        assert_eq!(r.expire_due(later).unwrap(), 0); // idempotent
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capability-tokens.json");
        let mut r = CapabilityRegistry::new();
        r.issue(
            &req(&["gpu-compute"], TrustRing::Ring3),
            "tok-1",
            "t1",
            now(),
        )
        .unwrap();
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        let back = CapabilityRegistry::load(&path).unwrap();
        assert_eq!(back.tokens().len(), 1);
        assert_eq!(back.tokens()[0].trust_ring, TrustRing::Ring3);
        back.snapshot().validate_schema().unwrap();
    }

    #[test]
    fn load_absent_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = CapabilityRegistry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.tokens().is_empty());
    }

    #[test]
    fn parent_token_id_carries_through() {
        let mut r = CapabilityRegistry::new();
        let mut child = req(&["tests"], TrustRing::Ring2);
        child.parent_token_id = "tok-parent".into();
        r.issue(&child, "tok-child", "t", now()).unwrap();
        assert_eq!(r.tokens()[0].parent_token_id, "tok-parent");
    }

    /// All 8 tool tokens round-trip through parse + canonicalize.
    #[test]
    fn all_tool_tokens_round_trip() {
        for tok in [
            "read-only-host",
            "write-host",
            "tests",
            "builds",
            "network-egress",
            "gpu-compute",
            "vm-spawn",
            "browser",
        ] {
            let t = parse_tool(tok).unwrap();
            assert_eq!(tool_token(t), tok);
        }
    }

    /// All 5 trust rings map to their MS039 numeric and round-trip
    /// through capability_word.
    #[test]
    fn trust_ring_numeric_round_trips_through_word() {
        for (ring, expected) in [
            (TrustRing::Ring0, 0u8),
            (TrustRing::Ring1, 1),
            (TrustRing::Ring2, 2),
            (TrustRing::Ring3, 3),
            (TrustRing::Ring4, 4),
        ] {
            assert_eq!(trust_ring_numeric(ring), expected);
            let mut r = CapabilityRegistry::new();
            r.issue(
                &req(&["tests"], ring),
                &format!("tok-{expected}"),
                "t",
                now(),
            )
            .unwrap();
            let word =
                CapabilityWord::from_hex(&r.tokens().last().unwrap().capability_word).unwrap();
            assert_eq!(word.trust_level().unwrap(), expected);
        }
    }
}
