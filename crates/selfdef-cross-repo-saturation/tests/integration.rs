//! Cross-repo typed-mirror SATURATION invariant on the selfdef side.
//!
//! Sister to sovereign-os R473
//! (`tests/lint/test_cross_repo_saturation_invariant.py`).

use selfdef_cross_repo_saturation::{CROSS_REPO_BINDING_IDS, CROSS_REPO_CRATES};

// Re-import each mirror crate's verbatim-order const at module level.
// The mere fact that the workspace builds with `[dependencies]`
// listing all 8 crates is itself the first saturation check — if any
// of these `use` lines fail to resolve, the saturation invariant is
// broken and `cargo build -p selfdef-cross-repo-saturation` fails
// before tests even run.
use selfdef_audit_manifest::PATTERN_IDS;
use selfdef_auth_tier::TIER_NAMES;
use selfdef_bashrc_install::{
    BLOCK_BEGIN_SENTINEL, BLOCK_END_SENTINEL, COMPLETION_TOP_VERBS, INSTALLER_REL_PATH,
    SHIPPED_ALIASES,
};
use selfdef_dashboard_manifest::{AUTH_TIERS, SURFACES};
use selfdef_doc_manifest::DOC_KINDS;
use selfdef_history_sink::{ENV_MODULES_LOG, STATUSES};
use selfdef_surface_manifest::SURFACE_TAXONOMY;
use selfdef_ux_checklist::UX_DIMENSIONS;

#[test]
fn saturation_a_count_floor() {
    // SATURATION-A: 8 cross-repo mirror crates (the count claimed in
    // SDD-038 + R473). Future additions can grow this; this is a
    // floor against accidental regression.
    assert_eq!(CROSS_REPO_CRATES.len(), 8);
    assert_eq!(CROSS_REPO_BINDING_IDS.len(), 8);
}

#[test]
fn saturation_b_each_crate_name_unique() {
    let mut seen = std::collections::HashSet::new();
    for &c in &CROSS_REPO_CRATES {
        assert!(seen.insert(c), "duplicate crate name {c:?}");
    }
}

#[test]
fn saturation_c_each_binding_id_unique() {
    let mut seen = std::collections::HashSet::new();
    for &id in &CROSS_REPO_BINDING_IDS {
        assert!(seen.insert(id), "duplicate binding ID {id:?}");
    }
}

#[test]
fn saturation_d_taxonomy_array_lengths_match_sovereign_os_counts() {
    // Every operator-named taxonomy ships with a hand-pinned length.
    // Drift on either side fails this test.
    assert_eq!(TIER_NAMES.len(), 6, "6-tier auth ladder");
    assert_eq!(SURFACE_TAXONOMY.len(), 8, "§1g 8-surface taxonomy");
    assert_eq!(UX_DIMENSIONS.len(), 6, "6 UX-quality dimensions");
    assert_eq!(PATTERN_IDS.len(), 8, "8 minimization patterns");
    assert_eq!(DOC_KINDS.len(), 6, "6 doc-surface kinds");
    assert_eq!(STATUSES.len(), 5, "5 event-status states");
    assert_eq!(SURFACES.len(), 8, "dashboard manifest surfaces (= §1g 8)");
    assert_eq!(
        AUTH_TIERS.len(),
        6,
        "dashboard manifest auth tiers (= 6-tier)"
    );
}

#[test]
fn saturation_e_dashboard_manifest_aliases_match_auth_tier() {
    // The dashboard-manifest crate re-exports auth-tier's TIER_NAMES
    // as AUTH_TIERS. They MUST be identical arrays in identical order.
    assert_eq!(
        AUTH_TIERS, TIER_NAMES,
        "AUTH_TIERS (dashboard-manifest) != TIER_NAMES (auth-tier); \
         cross-crate alias drift"
    );
}

#[test]
fn saturation_f_bashrc_constants_present() {
    // bashrc-install ships installer-path + sentinel-pair + alias list
    // + top-verb completion list. All four are stable contract.
    assert!(!INSTALLER_REL_PATH.is_empty());
    assert!(INSTALLER_REL_PATH.ends_with("selfdefctl-bashrc-install.sh"));
    assert!(BLOCK_BEGIN_SENTINEL.contains("SD-R-BASHRC-1"));
    assert!(BLOCK_END_SENTINEL.contains("SD-R-BASHRC-1"));
    assert!(SHIPPED_ALIASES.len() >= 8, "≥8 operator aliases");
    assert!(COMPLETION_TOP_VERBS.len() >= 10, "≥10 top verbs");
}

#[test]
fn saturation_g_history_sink_env_name_matches_sovereign_os() {
    // The env-name binding is the cross-repo wire format for the
    // event-stream consumer (R448/R465). MUST match sovereign-os
    // global-history.py's SOVEREIGN_OS_MODULES_LOG.
    assert_eq!(ENV_MODULES_LOG, "SOVEREIGN_OS_MODULES_LOG");
}

#[test]
fn saturation_h_taxonomies_have_kebab_case_entries() {
    // Cross-repo wire format is TOML which uses kebab-case naming.
    // Quick sanity check: every taxonomy entry is lowercase
    // alphanumeric + hyphen (no spaces, no underscores). Drift catches:
    // operator-named identifier accidentally renamed to snake_case.
    for taxonomy in [
        TIER_NAMES.as_slice(),
        SURFACE_TAXONOMY.as_slice(),
        UX_DIMENSIONS.as_slice(),
        PATTERN_IDS.as_slice(),
        DOC_KINDS.as_slice(),
        STATUSES.as_slice(),
    ] {
        for &entry in taxonomy {
            assert!(
                entry
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "taxonomy entry {entry:?} contains non-kebab-case chars; \
                 cross-repo wire format requires lowercase + digits + hyphens"
            );
            assert!(!entry.is_empty());
        }
    }
}

#[test]
fn saturation_i_taxonomies_no_duplicate_entries() {
    // Each taxonomy is a SET semantically; duplicate entries =
    // ambiguity at the parse-time selector.
    for (name, taxonomy) in [
        ("TIER_NAMES", TIER_NAMES.as_slice()),
        ("SURFACE_TAXONOMY", SURFACE_TAXONOMY.as_slice()),
        ("UX_DIMENSIONS", UX_DIMENSIONS.as_slice()),
        ("PATTERN_IDS", PATTERN_IDS.as_slice()),
        ("DOC_KINDS", DOC_KINDS.as_slice()),
        ("STATUSES", STATUSES.as_slice()),
    ] {
        let mut seen = std::collections::HashSet::new();
        for &entry in taxonomy {
            assert!(seen.insert(entry), "{name}: duplicate entry {entry:?}");
        }
    }
}

#[test]
fn saturation_j_binding_id_format() {
    // Every binding ID follows the pattern SD-R-<NAME>-<N>.
    for &id in &CROSS_REPO_BINDING_IDS {
        assert!(id.starts_with("SD-R-"), "binding ID {id:?} missing prefix");
        assert!(
            id.chars().last().is_some_and(|c| c.is_ascii_digit()),
            "binding ID {id:?} should end with a version digit"
        );
    }
}
