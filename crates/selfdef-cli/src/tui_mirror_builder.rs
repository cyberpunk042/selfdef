//! `selfdef-tui-mirror` PRODUCER — emits the canonical 4-panel
//! [`TuiMirrorSnapshot`] per MS043 R10141 + F05081 + R10298, ready for
//! the sovereign-os minimal-web mirroring path (R10170 "same 4-panel
//! layout as TUI") + IPS-operator-surface introspection.
//!
//! Per MS043 R10298 (verbatim):
//!
//! > "A dashboard should not show vanity graphs"
//!
//! The 4 panels are FIXED per R10141 — adding panels is forbidden by
//! doctrine. Columns + keybindings + min_authority per panel are
//! derived from each panel's underlying mirror crate (rules /
//! grants / quarantine / authority) to keep them in sync with the
//! actual data shapes the TUI renders.

use selfdef_tui_mirror::{
    ColumnSpec, DOCTRINE_NO_VANITY_GRAPHS, KeyBinding, PanelEntry, PanelKind, Quadrant,
    SCHEMA_VERSION, TuiMirrorSnapshot,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Build the canonical TuiMirrorSnapshot per R10141 + F05081.
///
/// Layout (counter-clockwise from top-left, per F05081 dump 3299):
///   TL: Rules       TR: Grants
///   BL: Quarantine  BR: Authority
///
/// Each panel's columns mirror the first N stable fields of its
/// source mirror crate (so TUI columns = mirror schema by construction).
#[must_use]
pub(crate) fn build_snapshot() -> TuiMirrorSnapshot {
    TuiMirrorSnapshot {
        schema_version: SCHEMA_VERSION.into(),
        tui_build_version: env!("CARGO_PKG_VERSION").into(),
        doctrine: DOCTRINE_NO_VANITY_GRAPHS.into(),
        captured_at: now_rfc3339(),
        panels: vec![
            rules_panel(),
            grants_panel(),
            quarantine_panel(),
            authority_panel(),
        ],
        global_keys: global_keys(),
        // Signature filled by daemon-side signer (MS003 verify-only —
        // operators sign externally with minisign).
        signature: String::new(),
    }
}

fn rules_panel() -> PanelEntry {
    PanelEntry {
        kind: PanelKind::Rules,
        quadrant: Quadrant::TopLeft,
        title: "Rules · Ring 0..4 · selfdef-rules-mirror".into(),
        source_mirror: "selfdef-rules-mirror".into(),
        columns: vec![
            ColumnSpec {
                header: "ring".into(),
                field: "ring".into(),
                width: 12,
                right_align: false,
            },
            ColumnSpec {
                header: "table".into(),
                field: "table".into(),
                width: 14,
                right_align: false,
            },
            ColumnSpec {
                header: "chain".into(),
                field: "chain".into(),
                width: 22,
                right_align: false,
            },
            ColumnSpec {
                header: "match".into(),
                field: "match_expr".into(),
                width: 0,
                right_align: false,
            },
            ColumnSpec {
                header: "dispo".into(),
                field: "disposition".into(),
                width: 8,
                right_align: false,
            },
            ColumnSpec {
                header: "packets".into(),
                field: "packets".into(),
                width: 10,
                right_align: true,
            },
            ColumnSpec {
                header: "bytes".into(),
                field: "bytes".into(),
                width: 12,
                right_align: true,
            },
        ],
        key_bindings: vec![
            KeyBinding {
                key: "j/k".into(),
                action: "cursor down/up".into(),
                mutating: false,
            },
            KeyBinding {
                key: "Enter".into(),
                action: "show full match_expr".into(),
                mutating: false,
            },
            KeyBinding {
                key: "/".into(),
                action: "filter rules (search)".into(),
                mutating: false,
            },
            KeyBinding {
                key: "r".into(),
                action: "filter by ring (0..4)".into(),
                mutating: false,
            },
        ],
        min_authority: "l0_observe".into(),
        refresh_ms: 30_000,
        signature: String::new(),
    }
}

fn grants_panel() -> PanelEntry {
    PanelEntry {
        kind: PanelKind::Grants,
        quadrant: Quadrant::TopRight,
        title: "Grants · MS035 + MS037 + MS038 · selfdef-grants-mirror".into(),
        source_mirror: "selfdef-grants-mirror".into(),
        columns: vec![
            ColumnSpec {
                header: "grant_id".into(),
                field: "grant_id".into(),
                width: 14,
                right_align: false,
            },
            ColumnSpec {
                header: "kind".into(),
                field: "kind".into(),
                width: 12,
                right_align: false,
            },
            ColumnSpec {
                header: "scope".into(),
                field: "scope".into(),
                width: 0,
                right_align: false,
            },
            ColumnSpec {
                header: "actor".into(),
                field: "actor".into(),
                width: 14,
                right_align: false,
            },
            ColumnSpec {
                header: "state".into(),
                field: "state".into(),
                width: 10,
                right_align: false,
            },
            ColumnSpec {
                header: "expires".into(),
                field: "expires_at".into(),
                width: 20,
                right_align: false,
            },
        ],
        key_bindings: vec![
            KeyBinding {
                key: "j/k".into(),
                action: "cursor down/up".into(),
                mutating: false,
            },
            KeyBinding {
                key: "i".into(),
                action: "copy `selfdefctl grants issue ...`".into(),
                mutating: false,
            },
            KeyBinding {
                key: "r".into(),
                action: "copy `selfdefctl grants revoke <id>`".into(),
                mutating: false,
            },
            KeyBinding {
                key: "Enter".into(),
                action: "inspect grant detail".into(),
                mutating: false,
            },
        ],
        min_authority: "l0_observe".into(),
        refresh_ms: 5_000,
        signature: String::new(),
    }
}

fn quarantine_panel() -> PanelEntry {
    PanelEntry {
        kind: PanelKind::Quarantine,
        quadrant: Quadrant::BottomLeft,
        title: "Quarantine · MS042 declaration-vs-observed · selfdef-quarantine-mirror".into(),
        source_mirror: "selfdef-quarantine-mirror".into(),
        columns: vec![
            ColumnSpec {
                header: "quarantine_id".into(),
                field: "quarantine_id".into(),
                width: 16,
                right_align: false,
            },
            ColumnSpec {
                header: "tool".into(),
                field: "tool".into(),
                width: 14,
                right_align: false,
            },
            ColumnSpec {
                header: "severity".into(),
                field: "max_severity".into(),
                width: 12,
                right_align: false,
            },
            ColumnSpec {
                header: "state".into(),
                field: "state".into(),
                width: 12,
                right_align: false,
            },
            ColumnSpec {
                header: "mismatches".into(),
                field: "mismatches".into(),
                width: 0,
                right_align: false,
            },
            ColumnSpec {
                header: "blocked".into(),
                field: "blocked_at".into(),
                width: 20,
                right_align: false,
            },
        ],
        key_bindings: vec![
            KeyBinding {
                key: "j/k".into(),
                action: "cursor down/up".into(),
                mutating: false,
            },
            KeyBinding {
                key: "Enter".into(),
                action: "show per-field mismatch detail".into(),
                mutating: false,
            },
            KeyBinding {
                key: "R".into(),
                action: "copy `selfdefctl quarantine release <id> --confirm`".into(),
                mutating: false,
            },
            KeyBinding {
                key: "F".into(),
                action: "copy `selfdefctl quarantine forfeit <id> --confirm`".into(),
                mutating: false,
            },
            KeyBinding {
                key: "T".into(),
                action: "copy `selfdefctl quarantine trace <id>`".into(),
                mutating: false,
            },
        ],
        min_authority: "l0_observe".into(),
        refresh_ms: 5_000,
        signature: String::new(),
    }
}

fn authority_panel() -> PanelEntry {
    PanelEntry {
        kind: PanelKind::Authority,
        quadrant: Quadrant::BottomRight,
        title: "Authority · MS039 L0..L6 + MS040 profile · selfdef-profile-mirror".into(),
        source_mirror: "selfdef-profile-mirror".into(),
        columns: vec![
            ColumnSpec {
                header: "field".into(),
                field: "field".into(),
                width: 20,
                right_align: false,
            },
            ColumnSpec {
                header: "value".into(),
                field: "value".into(),
                width: 0,
                right_align: false,
            },
        ],
        key_bindings: vec![
            KeyBinding {
                key: "j/k".into(),
                action: "cursor down/up".into(),
                mutating: false,
            },
            KeyBinding {
                key: "p".into(),
                action: "copy `selfdefctl flex-profile switch <name>`".into(),
                mutating: false,
            },
            KeyBinding {
                key: "h".into(),
                action: "show transition history".into(),
                mutating: false,
            },
            KeyBinding {
                key: "Enter".into(),
                action: "show full MS040 authority envelope (L0..L6)".into(),
                mutating: false,
            },
        ],
        min_authority: "l0_observe".into(),
        refresh_ms: 30_000,
        signature: String::new(),
    }
}

fn global_keys() -> Vec<KeyBinding> {
    vec![
        KeyBinding {
            key: "Tab".into(),
            action: "focus next panel (clockwise)".into(),
            mutating: false,
        },
        KeyBinding {
            key: "S-Tab".into(),
            action: "focus prev panel (counter-CW)".into(),
            mutating: false,
        },
        KeyBinding {
            key: "1..4".into(),
            action: "focus panel by quadrant index".into(),
            mutating: false,
        },
        KeyBinding {
            key: "?".into(),
            action: "toggle help overlay".into(),
            mutating: false,
        },
        KeyBinding {
            key: "q".into(),
            action: "quit".into(),
            mutating: false,
        },
        KeyBinding {
            key: "Ctrl-r".into(),
            action: "force refresh all panels".into(),
            mutating: false,
        },
        KeyBinding {
            key: ":".into(),
            action: "command palette (copies selfdefctl)".into(),
            mutating: false,
        },
    ]
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(qs.len(), 4); // no collisions
    }

    #[test]
    fn rules_panel_top_left_with_rules_mirror_source() {
        let s = build_snapshot();
        let p = s
            .panels
            .iter()
            .find(|p| p.kind == PanelKind::Rules)
            .unwrap();
        assert_eq!(p.quadrant, Quadrant::TopLeft);
        assert_eq!(p.source_mirror, "selfdef-rules-mirror");
        // Columns must reflect Ring 0..4 + disposition (R10141 + MS024).
        let fields: Vec<&str> = p.columns.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"ring"));
        assert!(fields.contains(&"disposition"));
        assert!(fields.contains(&"packets"));
    }

    #[test]
    fn grants_panel_top_right_with_grants_mirror_source() {
        let s = build_snapshot();
        let p = s
            .panels
            .iter()
            .find(|p| p.kind == PanelKind::Grants)
            .unwrap();
        assert_eq!(p.quadrant, Quadrant::TopRight);
        assert_eq!(p.source_mirror, "selfdef-grants-mirror");
        let fields: Vec<&str> = p.columns.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"grant_id"));
        assert!(fields.contains(&"state"));
    }

    #[test]
    fn quarantine_panel_bottom_left_with_quarantine_mirror_source() {
        let s = build_snapshot();
        let p = s
            .panels
            .iter()
            .find(|p| p.kind == PanelKind::Quarantine)
            .unwrap();
        assert_eq!(p.quadrant, Quadrant::BottomLeft);
        assert_eq!(p.source_mirror, "selfdef-quarantine-mirror");
        let fields: Vec<&str> = p.columns.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"quarantine_id"));
        assert!(fields.contains(&"max_severity"));
    }

    #[test]
    fn authority_panel_bottom_right_with_profile_mirror_source() {
        let s = build_snapshot();
        let p = s
            .panels
            .iter()
            .find(|p| p.kind == PanelKind::Authority)
            .unwrap();
        assert_eq!(p.quadrant, Quadrant::BottomRight);
        assert_eq!(p.source_mirror, "selfdef-profile-mirror");
    }

    #[test]
    fn no_panel_keybinding_is_mutating_per_r10212() {
        // Web/TUI mirror NEVER mutates IPS state — all panel verbs are
        // clipboard-copy of selfdefctl + MS003 (R10122 + R10212).
        let s = build_snapshot();
        for p in &s.panels {
            for kb in &p.key_bindings {
                assert!(
                    !kb.mutating,
                    "TUI panel {:?} keybinding {} should be non-mutating (R10212)",
                    p.kind, kb.key
                );
            }
        }
    }

    #[test]
    fn global_keys_include_help_quit_palette() {
        let s = build_snapshot();
        let keys: Vec<&str> = s.global_keys.iter().map(|kb| kb.key.as_str()).collect();
        assert!(keys.contains(&"?"));
        assert!(keys.contains(&"q"));
        assert!(keys.contains(&":"));
        assert!(keys.contains(&"Tab"));
    }

    #[test]
    fn all_panels_min_authority_l0_observe() {
        // Panels are READ-ONLY views — observer authority sufficient.
        let s = build_snapshot();
        for p in &s.panels {
            assert_eq!(p.min_authority, "l0_observe", "panel {:?}", p.kind);
        }
    }

    #[test]
    fn validate_schema_doctrine_layout_pass_on_built_snapshot() {
        let s = build_snapshot();
        s.validate_schema().unwrap();
        s.validate_doctrine().unwrap();
        s.validate_layout().unwrap();
    }

    #[test]
    fn snapshot_is_deterministic_modulo_timestamp() {
        let a = build_snapshot();
        let b = build_snapshot();
        assert_eq!(a.schema_version, b.schema_version);
        assert_eq!(a.doctrine, b.doctrine);
        assert_eq!(a.panels, b.panels);
        assert_eq!(a.global_keys, b.global_keys);
    }

    #[test]
    fn each_panel_has_at_least_one_keybinding() {
        let s = build_snapshot();
        for p in &s.panels {
            assert!(
                !p.key_bindings.is_empty(),
                "panel {:?} has no key bindings",
                p.kind
            );
        }
    }
}
