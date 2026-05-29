//! MS007 selfdef-tui-mirror — canonical 4-panel TUI layout read surface.
//!
//! - `GET /v1/tui/snapshot` — full TuiMirrorSnapshot 1.0.0 with the
//!   canonical 4-panel layout (rules / grants / quarantine / authority)
//!   per MS043 R10141 + F05081 + R10298 ("a dashboard should not show
//!   vanity graphs").
//!
//! Static-shape surface: the layout is FIXED by doctrine — the handler
//! always returns the canonical projection, with `captured_at` set to
//! the time of the HTTP request and `tui_build_version` set to the
//! selfdef-api crate version. No daemon-resident store is consulted
//! (unlike the other 8 mirrors); the canonical layout lives entirely
//! inside `selfdef-tui-mirror::canonical_snapshot`.
//!
//! No mutation endpoints: TUI layout is READ-ONLY by doctrine. The
//! 4 panels are forbidden from expanding per R10141; the panel
//! keybindings themselves are clipboard-copy verbs of selfdefctl
//! (R10212 lock — TUI/web NEVER mutates IPS state directly).

use axum::Json;
use selfdef_tui_mirror::{TuiMirrorSnapshot, canonical_snapshot};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// `GET /v1/tui/snapshot` — emit the canonical 4-panel TuiMirrorSnapshot.
///
/// Returns 200 + the snapshot JSON. Cannot fail: the canonical layout
/// is a pure function of static doctrine + the current time.
pub(crate) async fn snapshot() -> Json<TuiMirrorSnapshot> {
    let captured_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    Json(canonical_snapshot(env!("CARGO_PKG_VERSION"), &captured_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_tui_mirror::{DOCTRINE_NO_VANITY_GRAPHS, PanelKind, Quadrant, SCHEMA_VERSION};

    #[tokio::test]
    async fn snapshot_handler_returns_canonical_4_panel_layout() {
        let Json(snap) = snapshot().await;
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
        assert_eq!(snap.doctrine, DOCTRINE_NO_VANITY_GRAPHS);
        assert_eq!(snap.panels.len(), 4);
        let kinds: Vec<PanelKind> = snap.panels.iter().map(|p| p.kind).collect();
        assert!(kinds.contains(&PanelKind::Rules));
        assert!(kinds.contains(&PanelKind::Grants));
        assert!(kinds.contains(&PanelKind::Quarantine));
        assert!(kinds.contains(&PanelKind::Authority));
        // Each panel in a distinct quadrant — no collision.
        use std::collections::HashSet;
        let qs: HashSet<Quadrant> = snap.panels.iter().map(|p| p.quadrant).collect();
        assert_eq!(qs.len(), 4);
    }

    #[tokio::test]
    async fn snapshot_validates_schema_doctrine_layout() {
        let Json(snap) = snapshot().await;
        snap.validate_schema().unwrap();
        snap.validate_doctrine().unwrap();
        snap.validate_layout().unwrap();
    }

    #[tokio::test]
    async fn snapshot_has_non_empty_build_version_and_capture_time() {
        let Json(snap) = snapshot().await;
        assert!(!snap.tui_build_version.is_empty());
        assert!(snap.captured_at.contains('T'));
        assert!(snap.captured_at.ends_with('Z'));
    }

    #[tokio::test]
    async fn r10212_no_panel_keybinding_is_mutating() {
        // TUI/web NEVER mutates IPS state. Every panel keybinding must
        // be clipboard-copy of selfdefctl (mutating: false).
        let Json(snap) = snapshot().await;
        for p in &snap.panels {
            for kb in &p.key_bindings {
                assert!(!kb.mutating, "panel {:?} kb {} mutating", p.kind, kb.key);
            }
        }
    }
}
