//! `GET /v1/filesystem-boundary` — MS037 / SDD-045 D-2 schema
//! discovery surface.
//!
//! Returns the static filesystem-boundary doctrine as JSON.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct FilesystemBoundarySchema {
    pub exchange_dirs: &'static [DirDescriptor],
    pub import_pipeline: &'static [&'static str],
    pub patch_schema_fields: &'static [&'static str],
    pub application_predicates: &'static [&'static str],
    pub doctrines: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub(crate) struct DirDescriptor {
    pub path: &'static str,
    pub direction: &'static str,
    pub source_id: &'static str,
}

const EXCHANGE_DIRS: &[DirDescriptor] = &[
    DirDescriptor {
        path: "/ai-exchange/inbox",
        direction: "host → VM",
        source_id: "M00942",
    },
    DirDescriptor {
        path: "/ai-exchange/outbox",
        direction: "VM → host",
        source_id: "M00943",
    },
    DirDescriptor {
        path: "/ai-exchange/artifacts",
        direction: "VM → host",
        source_id: "M00944",
    },
];

const IMPORT_PIPELINE: &[&str] = &[
    "Parse",
    "Scan",
    "Diff",
    "PolicyCheck",
    "OracleReview",
    "Commit",
];

const PATCH_SCHEMA_FIELDS: &[&str] = &[
    "unified_diff",
    "metadata",
    "declared_files_touched",
    "test_notes",
    "risk_flags",
];

const APPLICATION_PREDICATES: &[&str] = &[
    "paths_inside_workspace",
    "no_forbidden_files",
    "diff_parses",
    "policy_allows_writes",
    "branch_budget_permits",
    "user_approval_required + user_approval_granted",
];

const DOCTRINES: &[&str] = &[
    "Use explicit exchange directories",
    "VM writes proposals, not final state",
];

pub(crate) async fn show() -> Json<FilesystemBoundarySchema> {
    Json(FilesystemBoundarySchema {
        exchange_dirs: EXCHANGE_DIRS,
        import_pipeline: IMPORT_PIPELINE,
        patch_schema_fields: PATCH_SCHEMA_FIELDS,
        application_predicates: APPLICATION_PREDICATES,
        doctrines: DOCTRINES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_045() {
        assert_eq!(EXCHANGE_DIRS.len(), 3);
        assert_eq!(IMPORT_PIPELINE.len(), 6);
        assert_eq!(PATCH_SCHEMA_FIELDS.len(), 5);
        assert_eq!(APPLICATION_PREDICATES.len(), 6);
        assert_eq!(DOCTRINES.len(), 2);
    }
}
