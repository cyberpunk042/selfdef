//! # `selfdef-cross-repo-saturation`
//!
//! SD-R-SATURATION-1 — sister of sovereign-os R473.
//!
//! Cross-repo typed-mirror SATURATION invariant on the selfdef side.
//! This crate is a meta-test: it depends on every cross-repo
//! typed-mirror crate and asserts (via the integration test) that:
//!
//! 1. Every claimed mirror crate exists in the workspace (the
//!    `Cargo.toml` `[dependencies]` block here is the source of truth
//!    — if a crate is renamed or removed, `cargo build` fails here
//!    BEFORE the integration test runs).
//!
//! 2. Every mirror crate exports its named verbatim-order const
//!    (TIER_NAMES / SURFACE_TAXONOMY / UX_DIMENSIONS / PATTERN_IDS /
//!    DOC_KINDS / STATUSES) with the correct array length.
//!
//! 3. Cross-crate aliases match (e.g., `selfdef-dashboard-manifest`
//!    re-exports `selfdef-auth-tier`'s TIER_NAMES as `AUTH_TIERS`).
//!
//! The cross-repo doctrine lives at
//! `docs/sdd/038-cross-repo-binding-doctrine.md` (sovereign-os repo).
//!
//! ## What this crate does NOT do
//!
//! - It does NOT re-verify the verbatim-order match against
//!   sovereign-os source-of-truth — that's already the responsibility
//!   of each individual mirror crate's own `*_matches_sovereign_os_*`
//!   unit test (the drift-detection sentinel pattern).
//! - It does NOT verify the `packaging/bash/selfdefctl-bashrc-install.sh`
//!   file exists — that's `selfdef-bashrc-install`'s
//!   `installer_script_exists_and_is_executable` integration test.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The 8 cross-repo typed-mirror crates this saturation invariant
/// covers. Order matches `tests/lint/test_cross_repo_saturation_invariant.py`
/// in the sovereign-os repo (SDD-038 Way-forward table order).
pub const CROSS_REPO_CRATES: [&str; 8] = [
    "selfdef-bashrc-install",
    "selfdef-history-sink",
    "selfdef-auth-tier",
    "selfdef-dashboard-manifest",
    "selfdef-surface-manifest",
    "selfdef-ux-checklist",
    "selfdef-audit-manifest",
    "selfdef-doc-manifest",
];

/// The 8 sovereign-os cross-repo binding IDs corresponding to
/// [`CROSS_REPO_CRATES`].
pub const CROSS_REPO_BINDING_IDS: [&str; 8] = [
    "SD-R-BASHRC-1",
    "SD-R-EVENT-LOG-1",
    "SD-R-AUTH-TIER-1",
    "SD-R-DASHBOARD-MANIFEST-1",
    "SD-R-MULTI-SURFACE-AUDIT-1",
    "SD-R-UX-CHECKLIST-1",
    "SD-R-AUDIT-1",
    "SD-R-DOC-MANIFEST-1",
];
