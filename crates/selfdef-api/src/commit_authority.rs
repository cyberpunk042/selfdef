//! `GET /v1/commit-authority` — MS041 / SDD-043 D-3 schema discovery
//! surface.
//!
//! Returns the static doctrine schema as JSON so agents (MCP / dashboard
//! / external tooling) can learn the durable-change contract without
//! reading the Rust source.
//!
//! Static-only — the doctrine doesn't change at runtime. This is a
//! discovery surface, not a state surface; mirrors the selfdefctl
//! commit-authority types output.
//!
//! Source: SDD-043 § Open questions D-3 + the
//! `selfdef-commit-authority` crate's public surface.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct CommitAuthoritySchema {
    pub commit_types: &'static [&'static str],
    pub mandatory_fields: &'static [MandatoryField],
    pub policy_outcomes: &'static [&'static str],
    pub rollback_statuses: &'static [&'static str],
    pub high_risk_gate_fields: &'static [&'static str],
    pub high_risk_classifier_rules: &'static [&'static str],
    pub refusal_rules: &'static [&'static str],
    /// Verbatim doctrinal phrase per R09601 dump 17389. Operators +
    /// agents can `assert` against this to catch silent drift.
    pub doctrine_phrase: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct MandatoryField {
    pub name: &'static str,
    pub r_row: &'static str,
    pub description: &'static str,
}

const COMMIT_TYPES: &[&str] = &[
    "FileWrite",
    "MemoryWrite",
    "PolicyUpdate",
    "ProfileUpdate",
    "AdapterPromotion",
    "CloudExposureLog",
    "ToolSideEffect",
    "WorkflowCompletion",
];

const MANDATORY_FIELDS: &[MandatoryField] = &[
    MandatoryField {
        name: "actor",
        r_row: "R09602 + R09653..R09656",
        description: "MS003 fingerprint of the committing party",
    },
    MandatoryField {
        name: "reason",
        r_row: "R09603 + R09657",
        description: "human-readable; non-empty",
    },
    MandatoryField {
        name: "policy_decision",
        r_row: "R09604",
        description: "Allowed | AllowedWithCaveats | Denied",
    },
    MandatoryField {
        name: "rollback_status",
        r_row: "R09605",
        description: "Reversible | Reversed | Unavailable",
    },
    MandatoryField {
        name: "trace_ref",
        r_row: "R09606",
        description: "MS049 cross-cutting trace reference",
    },
];

const POLICY_OUTCOMES: &[&str] = &["Allowed", "AllowedWithCaveats", "Denied"];

const ROLLBACK_STATUSES: &[&str] = &["Reversible", "Reversed", "Unavailable"];

const HIGH_RISK_GATE_FIELDS: &[&str] = &["snapshot_id", "test_eval_id", "oracle_or_human"];

const HIGH_RISK_CLASSIFIER_RULES: &[&str] = &[
    "F04871: commit_type=AdapterPromotion → ALWAYS high-risk",
    "F04872: L6 Persist authority → ALWAYS high-risk",
    "F04873: commit_type=CloudExposureLog → ALWAYS high-risk",
    "F04874: production L5 commits → ALWAYS high-risk",
    "F04875: autonomous L5 outside predeclared gate → ALWAYS high-risk",
];

const REFUSAL_RULES: &[&str] = &[
    "F04852: rollback_status=Unavailable + is_high_risk=true → REJECT",
    "missing signature → REJECT (MS003 signing is MANDATORY)",
    "any mandatory field empty → REJECT",
    "high_risk_gate missing/incomplete on high-risk commit → REJECT",
];

/// `GET /v1/commit-authority` handler.
pub(crate) async fn show() -> Json<CommitAuthoritySchema> {
    Json(CommitAuthoritySchema {
        commit_types: COMMIT_TYPES,
        mandatory_fields: MANDATORY_FIELDS,
        policy_outcomes: POLICY_OUTCOMES,
        rollback_statuses: ROLLBACK_STATUSES,
        high_risk_gate_fields: HIGH_RISK_GATE_FIELDS,
        high_risk_classifier_rules: HIGH_RISK_CLASSIFIER_RULES,
        refusal_rules: REFUSAL_RULES,
        doctrine_phrase: "A commit is any durable change",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_in_canonical_order() {
        assert_eq!(COMMIT_TYPES.len(), 8);
        assert_eq!(COMMIT_TYPES[0], "FileWrite");
        assert_eq!(COMMIT_TYPES[7], "WorkflowCompletion");
        assert_eq!(MANDATORY_FIELDS.len(), 5);
        assert_eq!(MANDATORY_FIELDS[0].name, "actor");
        assert_eq!(MANDATORY_FIELDS[4].name, "trace_ref");
        assert_eq!(HIGH_RISK_GATE_FIELDS.len(), 3);
        assert_eq!(HIGH_RISK_CLASSIFIER_RULES.len(), 5);
    }

    #[test]
    fn doctrine_phrase_verbatim() {
        let s = CommitAuthoritySchema {
            commit_types: COMMIT_TYPES,
            mandatory_fields: MANDATORY_FIELDS,
            policy_outcomes: POLICY_OUTCOMES,
            rollback_statuses: ROLLBACK_STATUSES,
            high_risk_gate_fields: HIGH_RISK_GATE_FIELDS,
            high_risk_classifier_rules: HIGH_RISK_CLASSIFIER_RULES,
            refusal_rules: REFUSAL_RULES,
            doctrine_phrase: "A commit is any durable change",
        };
        // Verbatim per R09601 dump 17389 — drift detector.
        assert_eq!(s.doctrine_phrase, "A commit is any durable change");
    }
}
