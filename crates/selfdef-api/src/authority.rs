//! `GET /v1/authority` — MS039 + MS040 / SDD-049 D-2 schema discovery.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct AuthoritySchema {
    pub authority_levels: &'static [LevelDescriptor],
    pub trust_rings: &'static [RingDescriptor],
    pub profile_envelopes: &'static [ProfileDescriptor],
    pub transition_gates: &'static [GateDescriptor],
    pub authority_crates: &'static [CrateDescriptor],
}

#[derive(Debug, Serialize)]
pub(crate) struct LevelDescriptor {
    pub level: &'static str,
    pub scope: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct RingDescriptor {
    pub ring: &'static str,
    pub scope: &'static str,
    pub level_cap: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProfileDescriptor {
    pub profile: &'static str,
    pub max_level: &'static str,
    pub ring_cap: &'static str,
    pub sandbox_requirement: &'static str,
    pub gate: &'static str,
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

const LEVELS: &[LevelDescriptor] = &[
    LevelDescriptor {
        level: "L0",
        scope: "observe-only (no side effects)",
    },
    LevelDescriptor {
        level: "L1",
        scope: "local in-process state (no FS / network / subprocess)",
    },
    LevelDescriptor {
        level: "L2",
        scope: "local FS reads, NO writes (R09202)",
    },
    LevelDescriptor {
        level: "L3",
        scope: "local FS writes within workspace (per SDD-045)",
    },
    LevelDescriptor {
        level: "L4",
        scope: "external network egress (per SDD-046)",
    },
    LevelDescriptor {
        level: "L5",
        scope: "external state mutation (cloud APIs, write-acked)",
    },
    LevelDescriptor {
        level: "L6",
        scope: "persistent durable changes (every commit through SDD-043)",
    },
];

const RINGS: &[RingDescriptor] = &[
    RingDescriptor {
        ring: "Ring0",
        scope: "operator-direct (cockpit + console)",
        level_cap: "L6",
    },
    RingDescriptor {
        ring: "Ring1",
        scope: "daemon-internal",
        level_cap: "L5",
    },
    RingDescriptor {
        ring: "Ring2",
        scope: "operator-sandboxed agent",
        level_cap: "L4",
    },
    RingDescriptor {
        ring: "Ring3",
        scope: "third-party tool plugin",
        level_cap: "L3",
    },
    RingDescriptor {
        ring: "Ring4",
        scope: "external untrusted code",
        level_cap: "L1",
    },
];

const PROFILES: &[ProfileDescriptor] = &[
    ProfileDescriptor {
        profile: "private",
        max_level: "L1",
        ring_cap: "Ring 2",
        sandbox_requirement: "Tier A",
        gate: "operator approval",
    },
    ProfileDescriptor {
        profile: "fast",
        max_level: "L4",
        ring_cap: "Ring 2",
        sandbox_requirement: "Tier A",
        gate: "TTL ≤ 60s default",
    },
    ProfileDescriptor {
        profile: "careful",
        max_level: "L5",
        ring_cap: "Ring 2",
        sandbox_requirement: "Tier A or B",
        gate: "oracle + tests + sim",
    },
    ProfileDescriptor {
        profile: "paranoid",
        max_level: "L4",
        ring_cap: "Ring 1",
        sandbox_requirement: "Tier A",
        gate: "double-operator",
    },
    ProfileDescriptor {
        profile: "production",
        max_level: "L6",
        ring_cap: "Ring 0",
        sandbox_requirement: "Tier B",
        gate: "full commit-authority",
    },
    ProfileDescriptor {
        profile: "experimental",
        max_level: "L5",
        ring_cap: "Ring 3",
        sandbox_requirement: "Tier C",
        gate: "high cycle budget",
    },
];

const TRANSITION_GATES: &[GateDescriptor] = &[
    GateDescriptor {
        name: "Routine",
        semantics: "no extra gate",
    },
    GateDescriptor {
        name: "DirectShift",
        semantics: "explicit operator acknowledgement",
    },
    GateDescriptor {
        name: "SnapshotRequired",
        semantics: "ZFS snapshot evidence required",
    },
    GateDescriptor {
        name: "Forbidden",
        semantics: "refused unconditionally",
    },
];

const AUTHORITY_CRATES: &[CrateDescriptor] = &[
    CrateDescriptor {
        name: "selfdef-mode-transition-authority",
        role: "227 LOC — 4-gate matrix",
    },
    CrateDescriptor {
        name: "selfdef-toggle-audit-authority",
        role: "270 LOC — toggle policy",
    },
    CrateDescriptor {
        name: "selfdef-config-mutation-authority",
        role: "225 LOC — config gating",
    },
    CrateDescriptor {
        name: "selfdef-recovery-snapshot-authority",
        role: "257 LOC — snapshot gate",
    },
    CrateDescriptor {
        name: "selfdef-profile-authority-gate",
        role: "660 LOC — 6-profile matrix",
    },
];

pub(crate) async fn show() -> Json<AuthoritySchema> {
    Json(AuthoritySchema {
        authority_levels: LEVELS,
        trust_rings: RINGS,
        profile_envelopes: PROFILES,
        transition_gates: TRANSITION_GATES,
        authority_crates: AUTHORITY_CRATES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_049() {
        assert_eq!(LEVELS.len(), 7);
        assert_eq!(LEVELS[0].level, "L0");
        assert_eq!(LEVELS[6].level, "L6");
        assert_eq!(RINGS.len(), 5);
        assert_eq!(RINGS[0].ring, "Ring0");
        assert_eq!(RINGS[0].level_cap, "L6");
        assert_eq!(PROFILES.len(), 6);
        assert_eq!(TRANSITION_GATES.len(), 4);
        assert_eq!(AUTHORITY_CRATES.len(), 5);
    }
}
