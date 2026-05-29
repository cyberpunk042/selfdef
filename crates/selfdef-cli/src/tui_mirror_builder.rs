//! `selfdef-tui-mirror` PRODUCER (CLI side) — thin shim over the
//! canonical builder that now lives inside the `selfdef-tui-mirror`
//! crate itself ([`selfdef_tui_mirror::canonical_snapshot`]).
//!
//! Keeping the canonical layout INSIDE the mirror crate means both
//! `selfdefctl` (this shim) and `selfdef-daemon` (the mirror-export
//! loop) project the SAME shape with zero parallel hand-built layout
//! — drift is structurally impossible.
//!
//! Per MS043 R10298 (verbatim):
//!
//! > "A dashboard should not show vanity graphs"

use selfdef_tui_mirror::{TuiMirrorSnapshot, canonical_snapshot};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Build the canonical TuiMirrorSnapshot for the `selfdefctl` binary.
/// Delegates to the mirror crate's canonical builder — see
/// [`selfdef_tui_mirror::canonical_snapshot`] for the layout doctrine.
#[must_use]
pub(crate) fn build_snapshot() -> TuiMirrorSnapshot {
    canonical_snapshot(env!("CARGO_PKG_VERSION"), &now_rfc3339())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_tui_mirror::{DOCTRINE_NO_VANITY_GRAPHS, PanelKind, Quadrant, SCHEMA_VERSION};

    #[test]
    fn snapshot_carries_schema_version_and_doctrine_verbatim() {
        let s = build_snapshot();
        assert_eq!(s.schema_version, SCHEMA_VERSION);
        assert_eq!(s.doctrine, DOCTRINE_NO_VANITY_GRAPHS);
        assert!(!s.tui_build_version.is_empty());
        assert!(s.captured_at.contains('T'));
        assert!(s.captured_at.ends_with('Z'));
    }

    #[test]
    fn snapshot_has_exactly_four_canonical_panels() {
        let s = build_snapshot();
        assert_eq!(s.panels.len(), 4);
        let kinds: Vec<PanelKind> = s.panels.iter().map(|p| p.kind).collect();
        assert!(kinds.contains(&PanelKind::Rules));
        assert!(kinds.contains(&PanelKind::Grants));
        assert!(kinds.contains(&PanelKind::Quarantine));
        assert!(kinds.contains(&PanelKind::Authority));
    }

    #[test]
    fn each_panel_in_distinct_quadrant() {
        let s = build_snapshot();
        use std::collections::HashSet;
        let qs: HashSet<Quadrant> = s.panels.iter().map(|p| p.quadrant).collect();
        assert_eq!(qs.len(), 4);
    }

    #[test]
    fn no_panel_keybinding_is_mutating_per_r10212() {
        let s = build_snapshot();
        for p in &s.panels {
            for kb in &p.key_bindings {
                assert!(!kb.mutating, "panel {:?} kb {} mutating", p.kind, kb.key);
            }
        }
    }

    #[test]
    fn validate_schema_doctrine_layout_pass_on_built_snapshot() {
        let s = build_snapshot();
        s.validate_schema().unwrap();
        s.validate_doctrine().unwrap();
        s.validate_layout().unwrap();
    }
}
