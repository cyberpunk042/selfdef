//! `GET /v1/capability-tokens` — MS035 / SDD-044 D-2 schema discovery
//! surface.
//!
//! Returns the static capability-tokens doctrine as JSON. Mutation
//! surface (issue / revoke) NOT exposed — the store is in-memory per
//! SDD-044 D-3 and operator-token minting goes through MS003-signed
//! config + the CommitAuthority high-risk classifier per SDD-044 D-4.
//!
//! Source: SDD-044 § Open questions D-2 + `selfdefctl
//! capability-tokens schema` (CLI variant).

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct CapabilityTokensSchema {
    pub verdicts: &'static [VerdictDescriptor],
    pub token_shape: &'static [&'static str],
    pub companion_crates: &'static [CrateDescriptor],
    pub caller_contract: &'static [&'static str],
    pub refusal_rules: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub(crate) struct VerdictDescriptor {
    pub variant: &'static str,
    pub semantics: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CrateDescriptor {
    pub name: &'static str,
    pub role: &'static str,
}

const VERDICTS: &[VerdictDescriptor] = &[
    VerdictDescriptor { variant: "Ok",           semantics: "token present + active + not revoked + carries the requested scope" },
    VerdictDescriptor { variant: "Expired",      semantics: "token present but now_ms > expires_at_ms" },
    VerdictDescriptor { variant: "Revoked",      semantics: "token present but revoked == true" },
    VerdictDescriptor { variant: "Unknown",      semantics: "no token registered under this id" },
    VerdictDescriptor { variant: "MissingScope", semantics: "token Ok-otherwise but does not carry the requested scope" },
];

const TOKEN_SHAPE: &[&str] = &[
    "id            — operator-chosen identifier",
    "holder        — MS003 fingerprint of holder actor",
    "scopes        — BTreeSet<String>; canonical names from selfdef-capability-word",
    "expires_at_ms — mandatory; bounded TTL per SDD-044 goal 3",
    "revoked       — bool; surgical revocation per SDD-044 goal 4",
];

const COMPANION_CRATES: &[CrateDescriptor] = &[
    CrateDescriptor { name: "selfdef-capability-token-store",  role: "215 LOC, 9 tests — issue + revoke + check primitives" },
    CrateDescriptor { name: "selfdef-capability-word",         role: "496 LOC — canonical scope vocabulary (drift-prevention)" },
    CrateDescriptor { name: "selfdef-capability-mirror",       role: "416 LOC — cross-repo state projection (MS007 typed-mirror)" },
    CrateDescriptor { name: "selfdef-tool-capability-policy",  role: "12 tests — per-tool scope requirements (consumes scopes)" },
    CrateDescriptor { name: "selfdef-profile-authority-gate",  role: "660 LOC — gates profile transitions on holder scopes" },
];

const CALLER_CONTRACT: &[&str] = &[
    "1. Determine required scope from selfdef-capability-word",
    "2. Read token id from operator-presented header / config",
    "3. Call store.check(id, scope, now_ms)",
    "4a. Ok → proceed; SDD-043 commit envelope",
    "4b. Expired / Revoked / Unknown / MissingScope → refuse + audit",
];

const REFUSAL_RULES: &[&str] = &[
    "Non-Ok CheckVerdict → REFUSE (operator-readable error citing verdict)",
    "Issue without scope present in selfdef-capability-word → REJECT (drift defense)",
];

pub(crate) async fn show() -> Json<CapabilityTokensSchema> {
    Json(CapabilityTokensSchema {
        verdicts: VERDICTS,
        token_shape: TOKEN_SHAPE,
        companion_crates: COMPANION_CRATES,
        caller_contract: CALLER_CONTRACT,
        refusal_rules: REFUSAL_RULES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_044() {
        assert_eq!(VERDICTS.len(), 5);
        assert_eq!(VERDICTS[0].variant, "Ok");
        assert_eq!(VERDICTS[4].variant, "MissingScope");
        assert_eq!(TOKEN_SHAPE.len(), 5);
        assert_eq!(COMPANION_CRATES.len(), 5);
        assert_eq!(CALLER_CONTRACT.len(), 5);
    }
}
