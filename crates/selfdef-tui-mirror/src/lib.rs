//! `selfdef-tui-mirror` — MS007 typed-mirror crate exposing selfdef TUI
//! panel schema READ-ONLY for sovereign-os IPS-operator-surface
//! introspection + minimal-web mirroring (R10170 "same 4-panel layout
//! as TUI").
//!
//! Per MS043 R10282 + R10298, mirrors expose schema read-only; the
//! daemon owns panel registration. Consumers MUST NOT add panels
//! beyond the 4-panel canonical layout.
//!
//! Doctrinal preservation — verbatim per MS043 R10298, dump 3299:
//!
//! > "A dashboard should not show vanity graphs"
//!
//! 4-panel layout per R10141 + F05081:
//! - rules (selfdef-tui-rules-panel · M01111 · MS024+MS038)
//! - grants (selfdef-tui-grants-panel · M01112 · MS035+MS037+MS038)
//! - quarantine (selfdef-tui-quarantine-panel · M01113 · MS042)
//! - authority (selfdef-tui-authority-panel · M01115 · MS039+MS040)
//!
//! Composes with:
//! - MS043 IPS operator surface (CLI + TUI + dashboard mirror trio)
//! - MS039 authority levels (panel content filtered by L0..L6)
//! - MS040 six profiles (panel keyboard hints follow active profile)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Operator doctrine preserved verbatim per MS043 R10298. Surfaced
/// publicly so consumers can render it in their own UX.
pub const DOCTRINE_NO_VANITY_GRAPHS: &str = "A dashboard should not show vanity graphs";

/// The 4 canonical TUI panels per R10141. Adding panels is forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelKind {
    /// Rules panel — selfdef-tui-rules-panel (MS024 + MS038).
    Rules,
    /// Grants panel — selfdef-tui-grants-panel (MS035 + MS037 + MS038).
    Grants,
    /// Quarantine panel — selfdef-tui-quarantine-panel (MS042).
    Quarantine,
    /// Authority panel — selfdef-tui-authority-panel (MS039 + MS040).
    Authority,
}

/// Layout position of a panel within the 4-quadrant TUI grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quadrant {
    /// Top-left quadrant.
    TopLeft,
    /// Top-right quadrant.
    TopRight,
    /// Bottom-left quadrant.
    BottomLeft,
    /// Bottom-right quadrant.
    BottomRight,
}

/// Keyboard binding for a panel action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyBinding {
    /// Key sequence string (e.g. "j", "k", "?", "Enter", "Ctrl-r").
    pub key: String,
    /// Action description (single-line).
    pub action: String,
    /// Whether the action is mutating (requires MS003 signature).
    pub mutating: bool,
}

/// Column definition for a panel that renders tabular data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnSpec {
    /// Column header.
    pub header: String,
    /// Source field name from the underlying mirror.
    pub field: String,
    /// Display width (characters). 0 = flex.
    pub width: u16,
    /// Whether the column right-aligns (numeric).
    pub right_align: bool,
}

/// Single panel descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PanelEntry {
    /// Panel discriminator.
    pub kind: PanelKind,
    /// Layout position.
    pub quadrant: Quadrant,
    /// Panel title (header line).
    pub title: String,
    /// Mirror crate name this panel renders.
    pub source_mirror: String,
    /// Column definitions for tabular rendering.
    pub columns: Vec<ColumnSpec>,
    /// Keyboard bindings active when this panel has focus.
    pub key_bindings: Vec<KeyBinding>,
    /// MS039 minimum authority required to view this panel.
    pub min_authority: String,
    /// Refresh interval in milliseconds (publisher hint).
    pub refresh_ms: u32,
    /// MS003 signature over the panel envelope (hex).
    pub signature: String,
}

/// Top-level mirror snapshot consumed for TUI / minimal-web introspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TuiMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// TUI build version that emitted this schema.
    pub tui_build_version: String,
    /// Doctrine surface — MUST equal [`DOCTRINE_NO_VANITY_GRAPHS`].
    /// Per R10298 verbatim preservation requirement.
    pub doctrine: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// The 4 panels, in canonical order: rules / grants / quarantine / authority.
    pub panels: Vec<PanelEntry>,
    /// Global keyboard bindings (active regardless of focused panel).
    pub global_keys: Vec<KeyBinding>,
    /// MS003 signature over the canonical-JSON encoding.
    pub signature: String,
}

/// Errors a consumer may surface when reading this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected version.
        expected: String,
        /// Observed version.
        actual: String,
    },
    /// MS003 signature verification failed.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Snapshot was empty when consumer expected populated data.
    #[error("snapshot is empty (publisher may be initializing)")]
    EmptySnapshot,
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
    /// Doctrine surface tampered (R10298 verbatim requirement).
    #[error("doctrine surface tampered: expected verbatim \"{expected}\", got \"{actual}\"")]
    DoctrineTampered {
        /// Expected canonical doctrine.
        expected: String,
        /// Observed (tampered) value.
        actual: String,
    },
    /// Panel count is not exactly 4 (canonical layout violation).
    #[error("panel count {0} != 4 canonical layout (R10141)")]
    PanelCountInvalid(usize),
    /// A required panel kind is missing from the layout.
    #[error("required panel kind missing from layout: {0:?}")]
    PanelKindMissing(PanelKind),
    /// Two panels occupy the same quadrant.
    #[error("quadrant collision: {0:?} occupied twice")]
    QuadrantCollision(Quadrant),
}

impl TuiMirrorSnapshot {
    /// Validate schema version. Same-major bumps OK per M061 R10297.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        let snap_major = self.schema_version.split('.').next().unwrap_or("");
        let exp_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
        if snap_major != exp_major {
            return Err(MirrorError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }

    /// Validate doctrine surface verbatim per R10298.
    pub fn validate_doctrine(&self) -> Result<(), MirrorError> {
        if self.doctrine != DOCTRINE_NO_VANITY_GRAPHS {
            return Err(MirrorError::DoctrineTampered {
                expected: DOCTRINE_NO_VANITY_GRAPHS.into(),
                actual: self.doctrine.clone(),
            });
        }
        Ok(())
    }

    /// Validate the 4-panel canonical layout per R10141:
    /// - exactly 4 panels
    /// - all 4 PanelKind variants present
    /// - no quadrant collision
    pub fn validate_layout(&self) -> Result<(), MirrorError> {
        if self.panels.len() != 4 {
            return Err(MirrorError::PanelCountInvalid(self.panels.len()));
        }
        for required in [PanelKind::Rules, PanelKind::Grants, PanelKind::Quarantine, PanelKind::Authority] {
            if !self.panels.iter().any(|p| p.kind == required) {
                return Err(MirrorError::PanelKindMissing(required));
            }
        }
        use std::collections::HashSet;
        let mut seen: HashSet<Quadrant> = HashSet::new();
        for p in &self.panels {
            if !seen.insert(p.quadrant) {
                return Err(MirrorError::QuadrantCollision(p.quadrant));
            }
        }
        Ok(())
    }

    /// Lookup a panel by kind.
    pub fn find_panel(&self, kind: PanelKind) -> Option<&PanelEntry> {
        self.panels.iter().find(|p| p.kind == kind)
    }

    /// Collect all mutating key bindings across panels + globals.
    /// Mutating bindings require MS003 signature on invocation.
    pub fn mutating_keys(&self) -> Vec<(&str, &KeyBinding)> {
        let mut out: Vec<(&str, &KeyBinding)> = Vec::new();
        for p in &self.panels {
            for k in &p.key_bindings {
                if k.mutating {
                    out.push((panel_name(p.kind), k));
                }
            }
        }
        for k in &self.global_keys {
            if k.mutating {
                out.push(("global", k));
            }
        }
        out
    }
}

fn panel_name(k: PanelKind) -> &'static str {
    match k {
        PanelKind::Rules => "rules",
        PanelKind::Grants => "grants",
        PanelKind::Quarantine => "quarantine",
        PanelKind::Authority => "authority",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_panel(kind: PanelKind, q: Quadrant, mirror: &str) -> PanelEntry {
        PanelEntry {
            kind,
            quadrant: q,
            title: format!("{:?}", kind),
            source_mirror: mirror.into(),
            columns: vec![
                ColumnSpec { header: "id".into(), field: "id".into(), width: 12, right_align: false },
                ColumnSpec { header: "state".into(), field: "state".into(), width: 0, right_align: false },
            ],
            key_bindings: vec![
                KeyBinding { key: "j".into(), action: "next row".into(), mutating: false },
                KeyBinding { key: "k".into(), action: "prev row".into(), mutating: false },
                KeyBinding { key: "Enter".into(), action: "inspect".into(), mutating: false },
                KeyBinding { key: "x".into(), action: "destructive action".into(), mutating: true },
            ],
            min_authority: "l0_observe".into(),
            refresh_ms: 5000,
            signature: format!("sig-{:?}", kind),
        }
    }

    fn canonical_snap() -> TuiMirrorSnapshot {
        TuiMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            tui_build_version: "0.42.1".into(),
            doctrine: DOCTRINE_NO_VANITY_GRAPHS.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            panels: vec![
                mk_panel(PanelKind::Rules,      Quadrant::TopLeft,     "selfdef-rules-mirror"),
                mk_panel(PanelKind::Grants,     Quadrant::TopRight,    "selfdef-grants-mirror"),
                mk_panel(PanelKind::Quarantine, Quadrant::BottomLeft,  "selfdef-quarantine-mirror"),
                mk_panel(PanelKind::Authority,  Quadrant::BottomRight, "selfdef-capability-mirror"),
            ],
            global_keys: vec![
                KeyBinding { key: "?".into(), action: "help".into(), mutating: false },
                KeyBinding { key: "q".into(), action: "quit".into(), mutating: false },
                KeyBinding { key: "Tab".into(), action: "cycle focus".into(), mutating: false },
            ],
            signature: String::new(),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        canonical_snap().validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let mut s = canonical_snap();
        s.schema_version = "2.0.0".into();
        assert!(matches!(s.validate_schema().unwrap_err(), MirrorError::SchemaMismatch { .. }));
    }

    #[test]
    fn doctrine_verbatim_preservation() {
        canonical_snap().validate_doctrine().unwrap();
    }

    #[test]
    fn doctrine_tamper_is_caught() {
        let mut s = canonical_snap();
        s.doctrine = "A dashboard should show vanity graphs".into();  // tampered
        match s.validate_doctrine().unwrap_err() {
            MirrorError::DoctrineTampered { expected, actual } => {
                assert_eq!(expected, "A dashboard should not show vanity graphs");
                assert!(actual.contains("should show vanity"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn layout_validates_canonical_4_panels() {
        canonical_snap().validate_layout().unwrap();
    }

    #[test]
    fn layout_rejects_missing_panel_kind() {
        let mut s = canonical_snap();
        s.panels.remove(0); // remove rules
        // need to keep 4 panels for count check first — add a duplicate
        s.panels.push(mk_panel(PanelKind::Grants, Quadrant::TopLeft, "selfdef-grants-mirror"));
        match s.validate_layout().unwrap_err() {
            MirrorError::PanelKindMissing(PanelKind::Rules) => {},
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn layout_rejects_wrong_panel_count() {
        let mut s = canonical_snap();
        s.panels.pop();
        match s.validate_layout().unwrap_err() {
            MirrorError::PanelCountInvalid(3) => {},
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn layout_rejects_quadrant_collision() {
        let mut s = canonical_snap();
        // Change one panel to collide with another
        s.panels[0].quadrant = Quadrant::TopRight;
        match s.validate_layout().unwrap_err() {
            MirrorError::QuadrantCollision(Quadrant::TopRight) => {},
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn find_panel_lookup() {
        let s = canonical_snap();
        assert_eq!(s.find_panel(PanelKind::Authority).unwrap().source_mirror, "selfdef-capability-mirror");
        assert!(s.find_panel(PanelKind::Rules).is_some());
    }

    #[test]
    fn mutating_keys_collected_with_panel_name() {
        let s = canonical_snap();
        let muts = s.mutating_keys();
        // each panel has 1 mutating binding ("x")
        assert_eq!(muts.len(), 4);
        assert!(muts.iter().any(|(n, _)| *n == "rules"));
        assert!(muts.iter().any(|(n, _)| *n == "authority"));
    }

    #[test]
    fn panel_serde_roundtrip() {
        let original = mk_panel(PanelKind::Quarantine, Quadrant::BottomLeft, "selfdef-quarantine-mirror");
        let j = serde_json::to_string(&original).unwrap();
        let back: PanelEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
        assert_eq!(back.key_bindings.len(), 4);
    }

    #[test]
    fn panel_kind_serde_uses_snake_case() {
        let j = serde_json::to_string(&PanelKind::Authority).unwrap();
        assert_eq!(j, "\"authority\"");
    }

    #[test]
    fn quadrant_serde_uses_snake_case() {
        let j = serde_json::to_string(&Quadrant::BottomRight).unwrap();
        assert_eq!(j, "\"bottom_right\"");
    }

    #[test]
    fn doctrine_constant_exposed_publicly() {
        assert_eq!(DOCTRINE_NO_VANITY_GRAPHS, "A dashboard should not show vanity graphs");
    }
}
