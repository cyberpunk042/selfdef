//! `GET /v1/trust-scores` — MS042 / SDD-064 D-064.1 schema discovery surface.
//!
//! Returns the static per-tool trust-score model as JSON so agents (MCP /
//! dashboard / external tooling / the sovereign-os D-18 mirror) can learn the
//! trust-score contract without reading the Rust source.
//!
//! Trust accumulates from declaration-fidelity over time and decays
//! asymmetrically on mismatch history (MS042 M01095, F05030-F05034). The score
//! is persisted, factored into MS040 profile evaluation, and exposed via the
//! MS007 typed mirror for sovereign-os D-18.
//!
//! Static-only — the MODEL doesn't change at runtime (the live per-tool scores
//! do). Score reset is MS003-signed CLI-only (D-064.2); this surface is
//! read-only.
//!
//! Source: SDD-064 + MS042 (M01095, F05030-F05034).

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct TrustScoreSchema {
    pub model: &'static str,
    pub score_range: [f64; 2],
    pub seed_score: f64,
    pub bands: &'static [TrustBand],
    pub dimensions: &'static [&'static str],
    pub decay_rule: &'static str,
    pub persistence_path: &'static str,
    pub profile_integration: &'static str,
    pub mirror_export: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct TrustBand {
    pub name: &'static str,
    pub min: f64,
    pub max: f64,
    pub posture: &'static str,
}

// 4 trust bands (SDD-064 Surface 2). [min, max) half-open except the top band.
const BANDS: &[TrustBand] = &[
    TrustBand {
        name: "trusted",
        min: 0.85,
        max: 1.0,
        posture: "default gates",
    },
    TrustBand {
        name: "watched",
        min: 0.6,
        max: 0.85,
        posture: "extra observation, no gate change",
    },
    TrustBand {
        name: "suspect",
        min: 0.3,
        max: 0.6,
        posture: "stricter gates in Careful/Production",
    },
    TrustBand {
        name: "quarantined",
        min: 0.0,
        max: 0.3,
        posture: "blocked pending operator review",
    },
];

// What feeds the score (MS042 F05030 declaration-fidelity over time).
const DIMENSIONS: &[&str] = &[
    "declaration-fidelity (clean call → credit; mismatch → debit)",
    "mismatch-recency (recent mismatches weighted heavier)",
    "mismatch-severity (which of the 7 declaration fields drifted)",
    "call-volume (more clean calls → slower drift toward neutral)",
];

const MODEL: &str = "per-tool score accumulated from declaration-fidelity over time; \
     a clean declaration-vs-observed match credits a small amount, a mismatch \
     debits a larger amount (asymmetric, conservative posture per F05033)";
const DECAY_RULE: &str = "asymmetric: mismatch debits faster than clean-call credits recover \
     (a tool loses trust faster than it regains it) — F05033";
const SEED_SCORE: f64 = 0.5; // neutral seed for a newly-declared tool
const PERSISTENCE_PATH: &str = "/var/lib/selfdef/tool-trust/";
const PROFILE_INTEGRATION: &str = "score factored into MS040 profile evaluation — low-trust tools face \
     stricter gates in Careful/Production profiles (F05032)";
const MIRROR_EXPORT: &str =
    "exposed via the MS007 typed mirror for the sovereign-os D-18 dashboard (F05034)";

/// `GET /v1/trust-scores` handler.
pub(crate) async fn show() -> Json<TrustScoreSchema> {
    Json(TrustScoreSchema {
        model: MODEL,
        score_range: [0.0, 1.0],
        seed_score: SEED_SCORE,
        bands: BANDS,
        dimensions: DIMENSIONS,
        decay_rule: DECAY_RULE,
        persistence_path: PERSISTENCE_PATH,
        profile_integration: PROFILE_INTEGRATION,
        mirror_export: MIRROR_EXPORT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_match_sdd_064() {
        assert_eq!(BANDS.len(), 4);
        assert_eq!(BANDS[0].name, "trusted");
        assert_eq!(BANDS[3].name, "quarantined");
        assert_eq!(DIMENSIONS.len(), 4);
        assert!(PERSISTENCE_PATH.starts_with("/var/lib/selfdef/"));
    }

    #[test]
    fn bands_cover_0_to_1_contiguously() {
        // bands are listed high→low; their [min,max) must tile [0,1] with no gap
        let mut expected_top = 1.0_f64;
        for b in BANDS {
            assert!(
                (b.max - expected_top).abs() < 1e-9,
                "band {} max {} != {}",
                b.name,
                b.max,
                expected_top
            );
            assert!(b.min < b.max, "band {} min must be < max", b.name);
            expected_top = b.min;
        }
        assert!(
            (expected_top - 0.0).abs() < 1e-9,
            "bands must bottom out at 0.0"
        );
    }

    #[test]
    fn seed_is_neutral_within_range() {
        assert_eq!(SEED_SCORE, 0.5);
        assert!(SEED_SCORE > BANDS[2].min && SEED_SCORE < BANDS[1].max);
    }
}
