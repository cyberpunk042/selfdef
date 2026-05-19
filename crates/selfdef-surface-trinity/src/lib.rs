//! `selfdef-surface-trinity` — MS043 IPS operator-surface composite check.
//!
//! Per MS043 R10281 + R10282 + R10168-R10170:
//! - CLI subcommand schema published via selfdef-cli-mirror
//! - TUI panel schema published via selfdef-tui-mirror
//! - minimal-web 4-panel layout matching TUI
//!
//! Verifies all 3 surfaces share consistent schemas at boot.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_cli_mirror::CliMirrorSnapshot;
use selfdef_tui_mirror::{PanelKind, TuiMirrorSnapshot};
use selfdef_web::{PANEL_ROUTES, WebConfig};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Surface check categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceCheck {
    /// MS043 R10281 — CLI subcommand schema published + 50+ commands.
    CliSurface,
    /// MS043 R10282 — TUI 4-panel layout published + doctrine verbatim.
    TuiSurface,
    /// MS043 R10170 — minimal-web 4-panel matches TUI canonical 4.
    WebSurface,
    /// Cross-surface consistency — TUI panels == web routes.
    CrossSurfaceConsistency,
}

/// One check result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    /// Check.
    pub check: SurfaceCheck,
    /// Passed.
    pub passed: bool,
    /// Reason (empty when passed).
    pub reason: String,
}

/// 4-check trinity report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrinityReport {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 capture timestamp.
    pub captured_at: String,
    /// 4 check results.
    pub results: Vec<CheckResult>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TrinityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// One or more checks failed.
    #[error("trinity checks failed: {0:?}")]
    ChecksFailed(Vec<SurfaceCheck>),
}

impl TrinityReport {
    /// Run all 4 checks against the supplied snapshots.
    pub fn run(
        cli: &CliMirrorSnapshot,
        tui: &TuiMirrorSnapshot,
        web: &WebConfig,
    ) -> Self {
        let mut results = Vec::with_capacity(4);

        // 1. CLI surface (schema valid + 50+ subcommands).
        let cli_check = match cli.validate_schema()
            .and_then(|_| cli.validate_surface_size())
        {
            Ok(()) => CheckResult { check: SurfaceCheck::CliSurface, passed: true, reason: String::new() },
            Err(e) => CheckResult { check: SurfaceCheck::CliSurface, passed: false, reason: e.to_string() },
        };
        results.push(cli_check);

        // 2. TUI surface (4-panel layout + doctrine verbatim).
        let tui_check = match tui.validate_schema()
            .and_then(|_| tui.validate_doctrine())
            .and_then(|_| tui.validate_layout())
        {
            Ok(()) => CheckResult { check: SurfaceCheck::TuiSurface, passed: true, reason: String::new() },
            Err(e) => CheckResult { check: SurfaceCheck::TuiSurface, passed: false, reason: e.to_string() },
        };
        results.push(tui_check);

        // 3. Web surface config validates.
        let web_check = match web.validate() {
            Ok(()) => CheckResult { check: SurfaceCheck::WebSurface, passed: true, reason: String::new() },
            Err(e) => CheckResult { check: SurfaceCheck::WebSurface, passed: false, reason: e.to_string() },
        };
        results.push(web_check);

        // 4. Cross-surface: every PANEL_ROUTES kind appears in TUI snapshot.
        let mut missing: Vec<PanelKind> = vec![];
        for route in PANEL_ROUTES.iter() {
            if tui.find_panel(route.kind).is_none() {
                missing.push(route.kind);
            }
        }
        let cross_check = if missing.is_empty() {
            CheckResult { check: SurfaceCheck::CrossSurfaceConsistency, passed: true, reason: String::new() }
        } else {
            CheckResult {
                check: SurfaceCheck::CrossSurfaceConsistency,
                passed: false,
                reason: format!("web panel kinds missing from TUI: {missing:?}"),
            }
        };
        results.push(cross_check);

        Self {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            results,
        }
    }

    /// True iff all 4 checks passed.
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Failed checks.
    pub fn failed(&self) -> Vec<SurfaceCheck> {
        self.results.iter().filter(|r| !r.passed).map(|r| r.check).collect()
    }

    /// Assert all 4 checks passed (daemon-boot gate).
    pub fn assert_all_passed(&self) -> Result<(), TrinityError> {
        if !self.all_passed() {
            return Err(TrinityError::ChecksFailed(self.failed()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_cli_mirror::{CliMirrorSnapshot, DOCTRINE_FULLSTACK_AT_THE_EDGES, EffectClass, SubcommandEntry};
    use selfdef_tui_mirror::{ColumnSpec, DOCTRINE_NO_VANITY_GRAPHS, KeyBinding, PanelEntry, Quadrant};

    fn ok_cli() -> CliMirrorSnapshot {
        let subs: Vec<SubcommandEntry> = (0..50).map(|i| SubcommandEntry {
            path: format!("ns.cmd{i}"),
            help_summary: format!("cmd {i}"),
            help_long: format!("Long {i}"),
            effect_class: EffectClass::ReadOnly,
            min_authority: "l0_observe".into(),
            args: vec![],
            mirror: String::new(),
            requires_signature: false,
            p95_target_ms: 100,
            signature: format!("sig-{i}"),
        }).collect();
        CliMirrorSnapshot {
            schema_version: "1.0.0".into(),
            cli_build_version: "0.42.1".into(),
            doctrine: DOCTRINE_FULLSTACK_AT_THE_EDGES.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            subcommands: subs,
            signature: String::new(),
        }
    }

    fn ok_tui_panel(kind: PanelKind, q: Quadrant) -> PanelEntry {
        PanelEntry {
            kind,
            quadrant: q,
            title: format!("{kind:?}"),
            source_mirror: format!("selfdef-{kind:?}-mirror"),
            columns: vec![ColumnSpec { header: "id".into(), field: "id".into(), width: 12, right_align: false }],
            key_bindings: vec![KeyBinding { key: "j".into(), action: "next".into(), mutating: false }],
            min_authority: "l0_observe".into(),
            refresh_ms: 5000,
            signature: format!("sig-{kind:?}"),
        }
    }

    fn ok_tui() -> TuiMirrorSnapshot {
        TuiMirrorSnapshot {
            schema_version: "1.0.0".into(),
            tui_build_version: "0.42.1".into(),
            doctrine: DOCTRINE_NO_VANITY_GRAPHS.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            panels: vec![
                ok_tui_panel(PanelKind::Rules, Quadrant::TopLeft),
                ok_tui_panel(PanelKind::Grants, Quadrant::TopRight),
                ok_tui_panel(PanelKind::Quarantine, Quadrant::BottomLeft),
                ok_tui_panel(PanelKind::Authority, Quadrant::BottomRight),
            ],
            global_keys: vec![],
            signature: String::new(),
        }
    }

    fn ok_web() -> WebConfig { WebConfig::default() }

    #[test]
    fn all_passed_when_canonical() {
        let r = TrinityReport::run(&ok_cli(), &ok_tui(), &ok_web());
        assert!(r.all_passed());
        r.assert_all_passed().unwrap();
    }

    #[test]
    fn cli_failure_caught() {
        let mut bad = ok_cli();
        bad.subcommands.truncate(10);  // below 50
        let r = TrinityReport::run(&bad, &ok_tui(), &ok_web());
        assert!(!r.all_passed());
        assert!(r.failed().contains(&SurfaceCheck::CliSurface));
    }

    #[test]
    fn tui_failure_caught() {
        let mut bad = ok_tui();
        bad.doctrine = "tampered".into();
        let r = TrinityReport::run(&ok_cli(), &bad, &ok_web());
        assert!(!r.all_passed());
        assert!(r.failed().contains(&SurfaceCheck::TuiSurface));
    }

    #[test]
    fn web_failure_caught() {
        let mut bad = ok_web();
        bad.host = "0.0.0.0".into();
        let r = TrinityReport::run(&ok_cli(), &ok_tui(), &bad);
        assert!(!r.all_passed());
        assert!(r.failed().contains(&SurfaceCheck::WebSurface));
    }

    #[test]
    fn cross_surface_consistency_caught() {
        let mut bad = ok_tui();
        // Remove Rules panel — web PANEL_ROUTES still requires it
        bad.panels.retain(|p| p.kind != PanelKind::Rules);
        bad.panels.push(ok_tui_panel(PanelKind::Grants, Quadrant::TopLeft));
        let r = TrinityReport::run(&ok_cli(), &bad, &ok_web());
        // Either TuiSurface (layout invariant violated) or CrossSurfaceConsistency fires
        assert!(!r.all_passed());
    }

    #[test]
    fn assert_all_passed_refuses_on_failure() {
        let mut bad = ok_web();
        bad.host = "0.0.0.0".into();
        let r = TrinityReport::run(&ok_cli(), &ok_tui(), &bad);
        assert!(matches!(r.assert_all_passed().unwrap_err(), TrinityError::ChecksFailed(_)));
    }

    #[test]
    fn report_serde_roundtrip() {
        let r = TrinityReport::run(&ok_cli(), &ok_tui(), &ok_web());
        let j = serde_json::to_string(&r).unwrap();
        let back: TrinityReport = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn surface_check_serde_kebab() {
        assert_eq!(serde_json::to_string(&SurfaceCheck::CliSurface).unwrap(), "\"cli-surface\"");
        assert_eq!(serde_json::to_string(&SurfaceCheck::CrossSurfaceConsistency).unwrap(), "\"cross-surface-consistency\"");
    }
}
