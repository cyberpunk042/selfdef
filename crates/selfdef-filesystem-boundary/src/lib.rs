//! `selfdef-filesystem-boundary` — MS037 explicit-exchange directory discipline.
//!
//! Per MS037 + E0371-E0376 + dump 3550-3593:
//!
//! **3-dir exchange** (E0372 dump 3556-3558):
//! - `/ai-exchange/inbox` — host → VM input drop (M00942)
//! - `/ai-exchange/outbox` — VM → host output drop (M00943)
//! - `/ai-exchange/artifacts` — binary artifacts / model outputs (M00944)
//!
//! **6-step host import pipeline** (E0374 dump 3566-3572):
//! 1. parse → 2. scan → 3. diff → 4. policy-check → 5. oracle-review (conditional) → 6. commit
//!
//! **5-field patch schema** (E0375 dump 3578-3584):
//! - unified diff / metadata / declared files touched / test notes / risk flags
//!
//! **6-check application predicates** (E0376 dump 3588-3594):
//! - paths inside workspace / no forbidden files / diff parses /
//!   policy allows writes / branch budget permits / user approval if required
//!
//! Doctrines preserved verbatim per E0371 + E0373:
//!
//! > "Use explicit exchange directories"
//!
//! > "VM writes proposals, not final state"
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine verbatim per E0371 dump 3552.
pub const DOCTRINE_EXPLICIT_EXCHANGE: &str = "Use explicit exchange directories";

/// Doctrine verbatim per E0373 dump 3562.
pub const DOCTRINE_VM_WRITES_PROPOSALS: &str = "VM writes proposals, not final state";

/// Canonical exchange-directory tags per M00942-M00944.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExchangeDir {
    /// host → VM input drop.
    Inbox,
    /// VM → host output drop.
    Outbox,
    /// binary artifacts / model outputs / blobs.
    Artifacts,
}

impl ExchangeDir {
    /// Canonical absolute path per E0372 dump 3556-3558.
    pub fn canonical_path(self) -> &'static str {
        match self {
            ExchangeDir::Inbox => "/ai-exchange/inbox",
            ExchangeDir::Outbox => "/ai-exchange/outbox",
            ExchangeDir::Artifacts => "/ai-exchange/artifacts",
        }
    }
}

/// 6-step host import pipeline per E0374 dump 3566-3572.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportStep {
    /// 1. Parse (must fail-closed per F04360).
    Parse,
    /// 2. Scan (antivirus / yara / sigma per F04361-F04362).
    Scan,
    /// 3. Diff (file-path validation against workspace per F04363-F04364).
    Diff,
    /// 4. Policy-check (M049 Policy Fabric 7-decision per F04365-F04366).
    PolicyCheck,
    /// 5. Oracle-review (Blackwell verification per F04367-F04368).
    OracleReview,
    /// 6. Commit (atomic write per F04369).
    Commit,
}

impl ImportStep {
    /// 1..6 step position per the pipeline.
    pub fn position(self) -> u8 {
        match self {
            ImportStep::Parse => 1,
            ImportStep::Scan => 2,
            ImportStep::Diff => 3,
            ImportStep::PolicyCheck => 4,
            ImportStep::OracleReview => 5,
            ImportStep::Commit => 6,
        }
    }
    /// Next step in the pipeline; None after Commit.
    pub fn next(self) -> Option<Self> {
        match self {
            ImportStep::Parse => Some(ImportStep::Scan),
            ImportStep::Scan => Some(ImportStep::Diff),
            ImportStep::Diff => Some(ImportStep::PolicyCheck),
            ImportStep::PolicyCheck => Some(ImportStep::OracleReview),
            ImportStep::OracleReview => Some(ImportStep::Commit),
            ImportStep::Commit => None,
        }
    }
}

/// 5-field code patch envelope per E0375 dump 3578-3584.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchEnvelope {
    /// Wire-stable schema version.
    pub schema_version: String,
    /// Field 1 — unified diff content.
    pub unified_diff: String,
    /// Field 2 — patch metadata (author / commit message / branch).
    pub metadata: String,
    /// Field 3 — declared files touched (canonicalised paths).
    pub declared_files: Vec<String>,
    /// Field 4 — test notes (which tests cover the patch).
    pub test_notes: String,
    /// Field 5 — risk flags (CVE / privacy / kernel / etc.).
    pub risk_flags: Vec<String>,
    /// MS003 signature over canonical-JSON encoding.
    pub signature: String,
}

/// Result of the 6-check application predicates per E0376 dump 3588-3594.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PredicateChecks {
    /// Check 1 — paths inside workspace.
    pub paths_inside_workspace: bool,
    /// Check 2 — no forbidden files.
    pub no_forbidden_files: bool,
    /// Check 3 — diff parses successfully.
    pub diff_parses: bool,
    /// Check 4 — policy allows writes (M049 result).
    pub policy_allows_writes: bool,
    /// Check 5 — branch budget permits the change.
    pub branch_budget_permits: bool,
    /// Check 6 — user approval present if required.
    pub user_approval_if_required: bool,
}

impl PredicateChecks {
    /// True iff ALL 6 checks passed (no minimisation).
    pub fn all_pass(&self) -> bool {
        self.paths_inside_workspace
            && self.no_forbidden_files
            && self.diff_parses
            && self.policy_allows_writes
            && self.branch_budget_permits
            && self.user_approval_if_required
    }

    /// Names of failing checks (for operator-readable summary).
    pub fn failures(&self) -> Vec<&'static str> {
        let mut v = vec![];
        if !self.paths_inside_workspace {
            v.push("paths_inside_workspace");
        }
        if !self.no_forbidden_files {
            v.push("no_forbidden_files");
        }
        if !self.diff_parses {
            v.push("diff_parses");
        }
        if !self.policy_allows_writes {
            v.push("policy_allows_writes");
        }
        if !self.branch_budget_permits {
            v.push("branch_budget_permits");
        }
        if !self.user_approval_if_required {
            v.push("user_approval_if_required");
        }
        v
    }
}

/// Errors.
#[derive(Debug, Error)]
pub enum FsBoundaryError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Path escapes workspace root.
    #[error("path escapes workspace: {0}")]
    PathEscapesWorkspace(String),
    /// Patch envelope missing MS003 signature.
    #[error("patch envelope unsigned (MS003 signature required)")]
    PatchUnsigned,
    /// Declared files differ from diff-touched files.
    #[error("declared files mismatch diff (declared {declared:?}, diff touched {touched:?})")]
    DeclaredMismatch {
        /// Declared list.
        declared: Vec<String>,
        /// Files actually touched by the diff (parsed).
        touched: Vec<String>,
    },
    /// One of the 6 predicates failed; halt at host application boundary.
    #[error("predicate check(s) failed: {0:?}")]
    PredicateFailed(Vec<&'static str>),
    /// Pipeline attempted to skip a step.
    #[error("import pipeline skip: {from:?} → {to:?} (must be next step)")]
    PipelineSkip {
        /// Current.
        from: ImportStep,
        /// Requested.
        to: ImportStep,
    },
    /// Pipeline attempted to advance past Commit.
    #[error("import pipeline already at terminal Commit step")]
    PipelineTerminal,
    /// Doctrine surface tampered.
    #[error("doctrine surface tampered: expected verbatim \"{expected}\", got \"{actual}\"")]
    DoctrineTampered {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
}

/// Verify a candidate absolute path lies inside the given workspace root.
/// Rejects `..` traversal + path escapes.
pub fn assert_path_inside_workspace(
    workspace: &str,
    candidate: &str,
) -> Result<(), FsBoundaryError> {
    if candidate.contains("/../") || candidate.starts_with("../") || candidate.ends_with("/..") {
        return Err(FsBoundaryError::PathEscapesWorkspace(candidate.into()));
    }
    if !candidate.starts_with(workspace) {
        return Err(FsBoundaryError::PathEscapesWorkspace(candidate.into()));
    }
    Ok(())
}

/// Validate a patch envelope.
pub fn validate_patch(env: &PatchEnvelope, workspace: &str) -> Result<(), FsBoundaryError> {
    if env.schema_version != SCHEMA_VERSION {
        return Err(FsBoundaryError::SchemaMismatch {
            expected: SCHEMA_VERSION.into(),
            actual: env.schema_version.clone(),
        });
    }
    if env.signature.is_empty() {
        return Err(FsBoundaryError::PatchUnsigned);
    }
    for path in &env.declared_files {
        assert_path_inside_workspace(workspace, path)?;
    }
    Ok(())
}

/// Advance the import pipeline by exactly one step.
pub fn advance_step(
    current: ImportStep,
    target: ImportStep,
) -> Result<ImportStep, FsBoundaryError> {
    let next = current.next().ok_or(FsBoundaryError::PipelineTerminal)?;
    if next != target {
        return Err(FsBoundaryError::PipelineSkip {
            from: current,
            to: target,
        });
    }
    Ok(target)
}

/// Apply the 6-check application predicates; refuses commit if any fails.
pub fn assert_application_ready(checks: &PredicateChecks) -> Result<(), FsBoundaryError> {
    if !checks.all_pass() {
        return Err(FsBoundaryError::PredicateFailed(checks.failures()));
    }
    Ok(())
}

/// Validate the doctrine constants are intact.
pub fn assert_doctrines_intact(explicit: &str, vm_writes: &str) -> Result<(), FsBoundaryError> {
    if explicit != DOCTRINE_EXPLICIT_EXCHANGE {
        return Err(FsBoundaryError::DoctrineTampered {
            expected: DOCTRINE_EXPLICIT_EXCHANGE.into(),
            actual: explicit.into(),
        });
    }
    if vm_writes != DOCTRINE_VM_WRITES_PROPOSALS {
        return Err(FsBoundaryError::DoctrineTampered {
            expected: DOCTRINE_VM_WRITES_PROPOSALS.into(),
            actual: vm_writes.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_env() -> PatchEnvelope {
        PatchEnvelope {
            schema_version: SCHEMA_VERSION.into(),
            unified_diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n".into(),
            metadata: "author: operator\nbranch: main".into(),
            declared_files: vec!["/workspace/x".into()],
            test_notes: "passes existing suite".into(),
            risk_flags: vec![],
            signature: "ms003-sig".into(),
        }
    }
    fn ok_checks() -> PredicateChecks {
        PredicateChecks {
            paths_inside_workspace: true,
            no_forbidden_files: true,
            diff_parses: true,
            policy_allows_writes: true,
            branch_budget_permits: true,
            user_approval_if_required: true,
        }
    }

    // --- 3-dir exchange ---

    #[test]
    fn exchange_dir_paths_canonical() {
        assert_eq!(ExchangeDir::Inbox.canonical_path(), "/ai-exchange/inbox");
        assert_eq!(ExchangeDir::Outbox.canonical_path(), "/ai-exchange/outbox");
        assert_eq!(
            ExchangeDir::Artifacts.canonical_path(),
            "/ai-exchange/artifacts"
        );
    }

    #[test]
    fn exchange_dir_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&ExchangeDir::Artifacts).unwrap(),
            "\"artifacts\""
        );
    }

    // --- 6-step import pipeline ---

    #[test]
    fn import_steps_positioned_1_to_6() {
        let order = [
            (ImportStep::Parse, 1),
            (ImportStep::Scan, 2),
            (ImportStep::Diff, 3),
            (ImportStep::PolicyCheck, 4),
            (ImportStep::OracleReview, 5),
            (ImportStep::Commit, 6),
        ];
        for (s, p) in order {
            assert_eq!(s.position(), p);
        }
    }

    #[test]
    fn pipeline_advance_one_step() {
        assert_eq!(
            advance_step(ImportStep::Parse, ImportStep::Scan).unwrap(),
            ImportStep::Scan
        );
    }

    #[test]
    fn pipeline_skip_refused() {
        let err = advance_step(ImportStep::Parse, ImportStep::Commit).unwrap_err();
        assert!(matches!(err, FsBoundaryError::PipelineSkip { .. }));
    }

    #[test]
    fn pipeline_past_commit_refused() {
        assert!(matches!(
            advance_step(ImportStep::Commit, ImportStep::Parse).unwrap_err(),
            FsBoundaryError::PipelineTerminal
        ));
    }

    #[test]
    fn full_pipeline_walk_six_steps() {
        let mut s = ImportStep::Parse;
        let mut count = 1;
        while let Some(n) = s.next() {
            s = n;
            count += 1;
        }
        assert_eq!(count, 6);
        assert_eq!(s, ImportStep::Commit);
    }

    // --- 5-field patch ---

    #[test]
    fn ok_patch_validates() {
        validate_patch(&ok_env(), "/workspace").unwrap();
    }

    #[test]
    fn unsigned_patch_refused() {
        let mut e = ok_env();
        e.signature = String::new();
        assert!(matches!(
            validate_patch(&e, "/workspace").unwrap_err(),
            FsBoundaryError::PatchUnsigned
        ));
    }

    #[test]
    fn schema_drift_refused() {
        let mut e = ok_env();
        e.schema_version = "9.9.9".into();
        assert!(matches!(
            validate_patch(&e, "/workspace").unwrap_err(),
            FsBoundaryError::SchemaMismatch { .. }
        ));
    }

    // --- Path-inside-workspace ---

    #[test]
    fn path_inside_workspace_accepted() {
        assert_path_inside_workspace("/workspace", "/workspace/src/x.rs").unwrap();
    }

    #[test]
    fn path_escape_via_dotdot_refused() {
        for bad in [
            "/workspace/../etc/passwd",
            "../outside",
            "/workspace/sub/..",
        ] {
            let err = assert_path_inside_workspace("/workspace", bad).unwrap_err();
            assert!(
                matches!(err, FsBoundaryError::PathEscapesWorkspace(_)),
                "bad: {bad}"
            );
        }
    }

    #[test]
    fn path_outside_workspace_refused() {
        let err = assert_path_inside_workspace("/workspace", "/etc/passwd").unwrap_err();
        assert!(matches!(err, FsBoundaryError::PathEscapesWorkspace(_)));
    }

    // --- 6-check predicates ---

    #[test]
    fn all_predicates_pass_application_ready() {
        assert_application_ready(&ok_checks()).unwrap();
    }

    #[test]
    fn any_predicate_failure_halts() {
        let mut c = ok_checks();
        c.policy_allows_writes = false;
        let err = assert_application_ready(&c).unwrap_err();
        match err {
            FsBoundaryError::PredicateFailed(v) => {
                assert_eq!(v, vec!["policy_allows_writes"]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn multiple_predicate_failures_listed() {
        let c = PredicateChecks {
            paths_inside_workspace: false,
            no_forbidden_files: true,
            diff_parses: false,
            policy_allows_writes: true,
            branch_budget_permits: true,
            user_approval_if_required: false,
        };
        let err = assert_application_ready(&c).unwrap_err();
        match err {
            FsBoundaryError::PredicateFailed(v) => {
                assert_eq!(v.len(), 3);
                assert!(v.contains(&"paths_inside_workspace"));
                assert!(v.contains(&"diff_parses"));
                assert!(v.contains(&"user_approval_if_required"));
            }
            _ => panic!(),
        }
    }

    // --- Doctrines ---

    #[test]
    fn doctrines_verbatim() {
        assert_eq!(
            DOCTRINE_EXPLICIT_EXCHANGE,
            "Use explicit exchange directories"
        );
        assert_eq!(
            DOCTRINE_VM_WRITES_PROPOSALS,
            "VM writes proposals, not final state"
        );
        assert_doctrines_intact(
            "Use explicit exchange directories",
            "VM writes proposals, not final state",
        )
        .unwrap();
    }

    #[test]
    fn doctrine_tamper_caught() {
        let err =
            assert_doctrines_intact("WRONG", "VM writes proposals, not final state").unwrap_err();
        assert!(matches!(err, FsBoundaryError::DoctrineTampered { .. }));
        let err2 =
            assert_doctrines_intact("Use explicit exchange directories", "WRONG").unwrap_err();
        assert!(matches!(err2, FsBoundaryError::DoctrineTampered { .. }));
    }

    // --- Serde ---

    #[test]
    fn patch_envelope_serde_roundtrip() {
        let original = ok_env();
        let j = serde_json::to_string(&original).unwrap();
        let back: PatchEnvelope = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn predicate_checks_serde() {
        let c = ok_checks();
        let j = serde_json::to_string(&c).unwrap();
        let back: PredicateChecks = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn import_step_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ImportStep::OracleReview).unwrap(),
            "\"oracle-review\""
        );
        assert_eq!(
            serde_json::to_string(&ImportStep::PolicyCheck).unwrap(),
            "\"policy-check\""
        );
    }
}
