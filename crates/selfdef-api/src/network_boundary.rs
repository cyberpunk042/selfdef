//! `GET /v1/network-boundary` — MS038 / SDD-046 D-2 schema discovery
//! surface. Returns the 5-profile NetworkProfile ladder.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct NetworkBoundarySchema {
    pub profiles: &'static [ProfileDescriptor],
    pub cross_cycle_bindings: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub(crate) struct ProfileDescriptor {
    pub name: &'static str,
    pub bits: u8,
    pub scope: &'static str,
}

const PROFILES: &[ProfileDescriptor] = &[
    ProfileDescriptor {
        name: "Offline",
        bits: 0b0000_0000,
        scope: "no egress",
    },
    ProfileDescriptor {
        name: "PackageRegistries",
        bits: 0b0000_0001,
        scope: "npm / PyPI / crates.io / …",
    },
    ProfileDescriptor {
        name: "DocsOnly",
        bits: 0b0000_0011,
        scope: "+ read-only documentation hosts",
    },
    ProfileDescriptor {
        name: "ArbitraryWeb",
        bits: 0b0000_0111,
        scope: "+ general egress",
    },
    ProfileDescriptor {
        name: "AuthenticatedBrowser",
        bits: 0b0000_1111,
        scope: "+ logged-in session websites",
    },
];

const CROSS_CYCLE_BINDINGS: &[&str] = &[
    "F04527 — Tier A=offline / Tier B=package-registries / Tier C=docs+arbitrary / Tier D=authenticated-browser",
    "F04526 — capability_word bits 16..23 encode the 5 profile values",
    "F04528 — composes with MS039 authority-graded egress (Ring 0-4)",
];

pub(crate) async fn show() -> Json<NetworkBoundarySchema> {
    Json(NetworkBoundarySchema {
        profiles: PROFILES,
        cross_cycle_bindings: CROSS_CYCLE_BINDINGS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_046() {
        assert_eq!(PROFILES.len(), 5);
        assert_eq!(PROFILES[0].name, "Offline");
        assert_eq!(PROFILES[0].bits, 0);
        assert_eq!(PROFILES[4].name, "AuthenticatedBrowser");
        assert_eq!(PROFILES[4].bits, 15);
        assert_eq!(CROSS_CYCLE_BINDINGS.len(), 3);
    }
}
