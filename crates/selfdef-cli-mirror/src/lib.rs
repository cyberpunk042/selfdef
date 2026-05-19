//! `selfdef-cli-mirror` — MS007 typed-mirror crate exposing the
//! `selfdefctl` CLI subcommand schema (50+ commands) READ-ONLY for
//! sovereign-os IPS-operator-surface introspection, completion
//! generation, and dashboard "how do I do X" cross-links.
//!
//! Per MS043 R10281 + R10297, mirrors expose schema read-only; the
//! daemon owns subcommand registration. Consumers MUST NOT synthesize
//! invocations beyond the published schema.
//!
//! Doctrinal preservation — verbatim per MS043 R10297, dump 581:
//!
//! > "Fullstack at the edges"
//!
//! Composes with:
//! - MS043 IPS operator surface (CLI + TUI + dashboard mirror trio)
//! - MS003 every subcommand requires MS003 signature when mutating
//! - MS039 authority levels gate per-subcommand effect class
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Operator doctrine preserved verbatim per MS043 R10297. Surfaced
/// publicly so consumers can render it in their own UX.
pub const DOCTRINE_FULLSTACK_AT_THE_EDGES: &str = "Fullstack at the edges";

/// Effect class — categorizes the side-effect surface of a subcommand.
/// Maps to MS039 authority levels for gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// Read-only — observes state, no side effects (MS039 L0 Observe).
    ReadOnly,
    /// Diagnostic — runs probes, no persisted change (MS039 L1 Suggest).
    Diagnostic,
    /// Simulate — dry-run with side-effect equivalence (MS039 L2 Simulate).
    Simulate,
    /// Prepare — stages durable change, awaits commit (MS039 L3 Prepare).
    Prepare,
    /// Execute — ephemeral side effect (process kill, sandbox start) (MS039 L4 Execute).
    Execute,
    /// Commit — durable change with receipt (MS039 L5 Commit).
    Commit,
    /// Persist — change survives reboot + replication (MS039 L6 Persist).
    Persist,
    /// Destructive — irreversible (forfeit, purge, rollback-apply); operator confirm required.
    Destructive,
}

/// Argument kind for a subcommand argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgKind {
    /// Positional required argument.
    Positional,
    /// `--flag` boolean.
    Flag,
    /// `--name=value` option taking a value.
    Option,
    /// Repeated `--multi value` option.
    MultiOption,
}

/// Single argument descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArgSpec {
    /// Argument name (canonical, no leading dashes).
    pub name: String,
    /// Argument kind.
    pub kind: ArgKind,
    /// Whether it is required.
    pub required: bool,
    /// Short single-line help text.
    pub help: String,
    /// Default value as a canonical-JSON string, if any.
    pub default: Option<String>,
    /// Allowed values (closed set), if applicable.
    pub allowed_values: Vec<String>,
}

/// Single subcommand schema entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubcommandEntry {
    /// Canonical path, dot-separated, e.g. `grant.list`, `sandbox.allocate`.
    pub path: String,
    /// Single-line help, suitable for `--help` summary.
    pub help_summary: String,
    /// Multi-line help (long form), preserved verbatim.
    pub help_long: String,
    /// Effect class — gates which authority level is needed.
    pub effect_class: EffectClass,
    /// MS039 authority level minimum to invoke (l0_observe..l6_persist).
    pub min_authority: String,
    /// Argument specifications (ordered).
    pub args: Vec<ArgSpec>,
    /// Mirror crate this subcommand operates against, if any.
    /// Example values: "selfdef-grants-mirror", "selfdef-rules-mirror", "".
    pub mirror: String,
    /// Whether invocation requires MS003 operator signature.
    pub requires_signature: bool,
    /// p95 latency target in milliseconds per R10286.
    pub p95_target_ms: u32,
    /// MS003 signature over the entry envelope (hex).
    pub signature: String,
}

/// Aggregate counts per effect class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectSummary {
    /// Effect class.
    pub effect: EffectClass,
    /// Count of subcommands in this class.
    pub count: u32,
}

/// Top-level mirror snapshot consumed by sovereign-os for CLI introspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// `selfdefctl` build version that emitted this schema (e.g. "0.42.1").
    pub cli_build_version: String,
    /// Doctrine surface — MUST equal [`DOCTRINE_FULLSTACK_AT_THE_EDGES`].
    /// Per R10297 verbatim preservation requirement.
    pub doctrine: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-effect-class summaries.
    pub summaries: Vec<EffectSummary>,
    /// Full subcommand list.
    pub subcommands: Vec<SubcommandEntry>,
    /// MS003 signature over the canonical-JSON encoding.
    pub signature: String,
}

/// Errors a consumer may surface when reading this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected version.
        expected: String,
        /// Observed version.
        actual: String,
    },
    /// MS003 signature verification failed.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Snapshot was empty when consumer expected populated data.
    #[error("snapshot is empty (publisher may be initializing)")]
    EmptySnapshot,
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
    /// Doctrine surface tampered with (R10297 verbatim requirement).
    #[error("doctrine surface tampered: expected verbatim \"{expected}\", got \"{actual}\"")]
    DoctrineTampered {
        /// Expected canonical doctrine.
        expected: String,
        /// Observed (tampered) value.
        actual: String,
    },
    /// Subcommand count is below the MS043 50+ surface requirement.
    #[error("subcommand count {0} below MS043 50+ minimum")]
    SubcommandCountLow(usize),
}

impl CliMirrorSnapshot {
    /// Validate schema version. Same-major bumps OK per M061 R10297.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        let snap_major = self.schema_version.split('.').next().unwrap_or("");
        let exp_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
        if snap_major != exp_major {
            return Err(MirrorError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }

    /// Validate doctrine surface verbatim per R10297.
    pub fn validate_doctrine(&self) -> Result<(), MirrorError> {
        if self.doctrine != DOCTRINE_FULLSTACK_AT_THE_EDGES {
            return Err(MirrorError::DoctrineTampered {
                expected: DOCTRINE_FULLSTACK_AT_THE_EDGES.into(),
                actual: self.doctrine.clone(),
            });
        }
        Ok(())
    }

    /// Validate the surface has 50+ subcommands per MS043 R10282 partner spec.
    /// Returns Err if below threshold.
    pub fn validate_surface_size(&self) -> Result<(), MirrorError> {
        if self.subcommands.len() < 50 {
            return Err(MirrorError::SubcommandCountLow(self.subcommands.len()));
        }
        Ok(())
    }

    /// Lookup a subcommand by canonical path.
    pub fn find(&self, path: &str) -> Option<&SubcommandEntry> {
        self.subcommands.iter().find(|s| s.path == path)
    }

    /// Aggregate by effect class.
    pub fn recompute_summaries(&self) -> Vec<EffectSummary> {
        use std::collections::HashMap;
        let mut m: HashMap<EffectClass, u32> = HashMap::new();
        for s in &self.subcommands {
            *m.entry(s.effect_class).or_insert(0) += 1;
        }
        let mut out: Vec<EffectSummary> = m.into_iter()
            .map(|(effect, count)| EffectSummary { effect, count })
            .collect();
        out.sort_by_key(|s| match s.effect {
            EffectClass::ReadOnly => 0,
            EffectClass::Diagnostic => 1,
            EffectClass::Simulate => 2,
            EffectClass::Prepare => 3,
            EffectClass::Execute => 4,
            EffectClass::Commit => 5,
            EffectClass::Persist => 6,
            EffectClass::Destructive => 7,
        });
        out
    }

    /// Find subcommands that require an MS003 signature.
    pub fn signature_required_paths(&self) -> Vec<&str> {
        self.subcommands.iter()
            .filter(|s| s.requires_signature)
            .map(|s| s.path.as_str())
            .collect()
    }

    /// Find subcommands targeting a given mirror crate.
    pub fn for_mirror<'a>(&'a self, mirror_name: &str) -> Vec<&'a SubcommandEntry> {
        self.subcommands.iter()
            .filter(|s| s.mirror == mirror_name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_sub(path: &str, effect: EffectClass, requires_sig: bool, mirror: &str) -> SubcommandEntry {
        SubcommandEntry {
            path: path.into(),
            help_summary: format!("test help for {path}"),
            help_long: format!("Long help for {path}\nMultiple lines preserved verbatim."),
            effect_class: effect,
            min_authority: match effect {
                EffectClass::ReadOnly => "l0_observe",
                EffectClass::Diagnostic => "l1_suggest",
                EffectClass::Simulate => "l2_simulate",
                EffectClass::Prepare => "l3_prepare",
                EffectClass::Execute => "l4_execute",
                EffectClass::Commit => "l5_commit",
                EffectClass::Persist => "l6_persist",
                EffectClass::Destructive => "l5_commit",
            }.into(),
            args: vec![],
            mirror: mirror.into(),
            requires_signature: requires_sig,
            p95_target_ms: 100,
            signature: format!("sig-{path}"),
        }
    }

    fn mk_snap_with(subs: Vec<SubcommandEntry>) -> CliMirrorSnapshot {
        CliMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            cli_build_version: "0.42.1".into(),
            doctrine: DOCTRINE_FULLSTACK_AT_THE_EDGES.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            subcommands: subs,
            signature: String::new(),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        mk_snap_with(vec![]).validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let mut s = mk_snap_with(vec![]);
        s.schema_version = "2.0.0".into();
        assert!(matches!(s.validate_schema().unwrap_err(), MirrorError::SchemaMismatch { .. }));
    }

    #[test]
    fn doctrine_verbatim_preservation() {
        let s = mk_snap_with(vec![]);
        s.validate_doctrine().unwrap();
    }

    #[test]
    fn doctrine_tamper_is_caught() {
        let mut s = mk_snap_with(vec![]);
        s.doctrine = "Fullstack at the middle".into();
        match s.validate_doctrine().unwrap_err() {
            MirrorError::DoctrineTampered { expected, actual } => {
                assert_eq!(expected, "Fullstack at the edges");
                assert_eq!(actual, "Fullstack at the middle");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn surface_size_threshold_at_50() {
        let small = mk_snap_with(vec![mk_sub("grant.list", EffectClass::ReadOnly, false, "selfdef-grants-mirror")]);
        assert!(matches!(small.validate_surface_size().unwrap_err(), MirrorError::SubcommandCountLow(1)));

        let big: Vec<SubcommandEntry> = (0..50).map(|i| mk_sub(&format!("ns.cmd{i}"), EffectClass::ReadOnly, false, "")).collect();
        mk_snap_with(big).validate_surface_size().unwrap();
    }

    #[test]
    fn find_by_path() {
        let snap = mk_snap_with(vec![
            mk_sub("grant.list", EffectClass::ReadOnly, false, "selfdef-grants-mirror"),
            mk_sub("token.mint", EffectClass::Commit, true, "selfdef-capability-mirror"),
        ]);
        assert_eq!(snap.find("token.mint").unwrap().requires_signature, true);
        assert!(snap.find("nonexistent").is_none());
    }

    #[test]
    fn recompute_summaries_groups_by_effect() {
        let snap = mk_snap_with(vec![
            mk_sub("a", EffectClass::ReadOnly, false, ""),
            mk_sub("b", EffectClass::ReadOnly, false, ""),
            mk_sub("c", EffectClass::Commit, true, ""),
            mk_sub("d", EffectClass::Destructive, true, ""),
        ]);
        let s = snap.recompute_summaries();
        let ro = s.iter().find(|x| x.effect == EffectClass::ReadOnly).unwrap();
        assert_eq!(ro.count, 2);
        let dst = s.iter().find(|x| x.effect == EffectClass::Destructive).unwrap();
        assert_eq!(dst.count, 1);
    }

    #[test]
    fn signature_required_paths_filter() {
        let snap = mk_snap_with(vec![
            mk_sub("grant.list", EffectClass::ReadOnly, false, ""),
            mk_sub("grant.approve", EffectClass::Commit, true, ""),
            mk_sub("grant.revoke", EffectClass::Destructive, true, ""),
        ]);
        let paths = snap.signature_required_paths();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"grant.approve"));
        assert!(paths.contains(&"grant.revoke"));
    }

    #[test]
    fn for_mirror_filters_by_mirror_target() {
        let snap = mk_snap_with(vec![
            mk_sub("grant.list", EffectClass::ReadOnly, false, "selfdef-grants-mirror"),
            mk_sub("grant.approve", EffectClass::Commit, true, "selfdef-grants-mirror"),
            mk_sub("token.list", EffectClass::ReadOnly, false, "selfdef-capability-mirror"),
        ]);
        let grant_subs = snap.for_mirror("selfdef-grants-mirror");
        assert_eq!(grant_subs.len(), 2);
        let cap_subs = snap.for_mirror("selfdef-capability-mirror");
        assert_eq!(cap_subs.len(), 1);
    }

    #[test]
    fn subcommand_serde_roundtrip_preserves_help_long() {
        let original = SubcommandEntry {
            path: "rollback.apply".into(),
            help_summary: "Apply a rollback to a ZFS snapshot.".into(),
            help_long: "WARNING: destructive operation.\nRequires MS003 operator signature.\nReverts MS041 commits between HEAD and snapshot.".into(),
            effect_class: EffectClass::Destructive,
            min_authority: "l5_commit".into(),
            args: vec![
                ArgSpec {
                    name: "to".into(),
                    kind: ArgKind::Option,
                    required: true,
                    help: "Target ZFS snapshot id".into(),
                    default: None,
                    allowed_values: vec![],
                },
                ArgSpec {
                    name: "confirm".into(),
                    kind: ArgKind::Flag,
                    required: true,
                    help: "Confirm destructive action".into(),
                    default: None,
                    allowed_values: vec![],
                },
            ],
            mirror: String::new(),
            requires_signature: true,
            p95_target_ms: 500,
            signature: "sig-rollback".into(),
        };
        let j = serde_json::to_string(&original).unwrap();
        let back: SubcommandEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
        // verify multi-line help preserved
        assert!(back.help_long.contains("\n"));
        assert!(back.help_long.contains("MS003 operator signature"));
    }

    #[test]
    fn effect_class_serde_uses_snake_case() {
        let j = serde_json::to_string(&EffectClass::ReadOnly).unwrap();
        assert_eq!(j, "\"read_only\"");
    }

    #[test]
    fn arg_kind_serde_uses_snake_case() {
        let j = serde_json::to_string(&ArgKind::MultiOption).unwrap();
        assert_eq!(j, "\"multi_option\"");
    }

    #[test]
    fn doctrine_constant_exposed_publicly() {
        assert_eq!(DOCTRINE_FULLSTACK_AT_THE_EDGES, "Fullstack at the edges");
    }
}
