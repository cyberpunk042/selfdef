//! `GET /v1/sandbox-tiers` — MS032 / SDD-047 D-2 schema discovery.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct SandboxTiersSchema {
    pub tiers: &'static [TierDescriptor],
    pub promotion_gates: &'static [GateDescriptor],
    pub companion_crates: &'static [CrateDescriptor],
}

#[derive(Debug, Serialize)]
pub(crate) struct TierDescriptor {
    pub name: &'static str,
    pub scope: &'static str,
    pub subprocess_allowed: bool,
    pub network_allowed: bool,
    pub persistent_allowed: bool,
    pub host_fs_readable: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct GateDescriptor {
    pub name: &'static str,
    pub semantics: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CrateDescriptor {
    pub name: &'static str,
    pub role: &'static str,
}

const TIERS: &[TierDescriptor] = &[
    TierDescriptor {
        name: "Tier0",
        scope: "pure read-only observe; no side effects",
        subprocess_allowed: false,
        network_allowed: false,
        persistent_allowed: false,
        host_fs_readable: false,
    },
    TierDescriptor {
        name: "Tier1",
        scope: "minimal — limited capabilities",
        subprocess_allowed: false,
        network_allowed: false,
        persistent_allowed: false,
        host_fs_readable: false,
    },
    TierDescriptor {
        name: "Tier2",
        scope: "chroot + read-only host FS mount; no network",
        subprocess_allowed: true,
        network_allowed: false,
        persistent_allowed: false,
        host_fs_readable: true,
    },
    TierDescriptor {
        name: "Tier3",
        scope: "controlled network egress (per SDD-046 NetworkProfile)",
        subprocess_allowed: true,
        network_allowed: true,
        persistent_allowed: false,
        host_fs_readable: true,
    },
    TierDescriptor {
        name: "Tier4",
        scope: "full sandbox with persistent state",
        subprocess_allowed: true,
        network_allowed: true,
        persistent_allowed: true,
        host_fs_readable: true,
    },
];

const PROMOTION_GATES: &[GateDescriptor] = &[
    GateDescriptor {
        name: "Routine",
        semantics: "no extra check (typically demotion)",
    },
    GateDescriptor {
        name: "SingleOperator",
        semantics: "single MS003-signed approval",
    },
    GateDescriptor {
        name: "DoubleOperator",
        semantics: "two distinct MS003 signatures (high-tier)",
    },
    GateDescriptor {
        name: "Forbidden",
        semantics: "transition refused unconditionally",
    },
];

const COMPANION_CRATES: &[CrateDescriptor] = &[
    CrateDescriptor {
        name: "selfdef-sandbox-tier-policy",
        role: "272 LOC, 15 tests — enum + capability tuples + gates",
    },
    CrateDescriptor {
        name: "selfdef-sandbox-dispatcher",
        role: "269 LOC, 14 tests — route-by-tier semantics",
    },
    CrateDescriptor {
        name: "selfdef-sandbox-fs-isolation",
        role: "227 LOC — per-tier filesystem mount strategy",
    },
    CrateDescriptor {
        name: "selfdef-sandbox-network-isolation",
        role: "188 LOC — per-tier network namespace strategy",
    },
    CrateDescriptor {
        name: "selfdef-sandbox-mirror",
        role: "441 LOC — cross-repo state projection (MS007)",
    },
];

pub(crate) async fn show() -> Json<SandboxTiersSchema> {
    Json(SandboxTiersSchema {
        tiers: TIERS,
        promotion_gates: PROMOTION_GATES,
        companion_crates: COMPANION_CRATES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_047() {
        assert_eq!(TIERS.len(), 5);
        assert_eq!(TIERS[0].name, "Tier0");
        assert_eq!(TIERS[4].name, "Tier4");
        assert_eq!(PROMOTION_GATES.len(), 4);
        assert_eq!(COMPANION_CRATES.len(), 5);
    }
}
