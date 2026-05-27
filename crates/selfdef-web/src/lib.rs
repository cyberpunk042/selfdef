//! `selfdef-web` — MS043 minimal local web surface (localhost:7575).
//!
//! Per MS043 R10166-R10173 + R10212 + R10220:
//! - HTTPS server on localhost:7575 (fallback when TUI unavailable)
//! - 4-panel layout matching the TUI (rules / grants / quarantine /
//!   authority) — schema mirrored from `selfdef-tui-mirror`
//! - Read-only views accessible without operator key
//! - Mutations require operator MS003 key upload (R10171 + R10212)
//! - SSE auto-refresh every 2s (R10173)
//! - Offline survivability: works without sovereign-os (R10220)
//!
//! This crate currently exposes the **panel registry + asset bundle**
//! (HTML/CSS/JS embedded via include_str!) + a config struct. The
//! actual HTTPS server bring-up (hyper/axum) is gated behind a future
//! `server` feature flag so the registry can be linked + lint-checked
//! without pulling the async stack.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_tui_mirror::{PanelKind, Quadrant};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version of the minimal-web configuration surface.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical bind port per MS043 R10166.
pub const DEFAULT_PORT: u16 = 7575;

/// Canonical bind host (loopback only — per R10166).
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// SSE refresh interval in milliseconds per R10173.
pub const SSE_REFRESH_MS: u32 = 2000;

/// Minimal-web configuration. Serialised via TOML on disk; deserialised
/// by the daemon on boot. Schema bumps follow [`SCHEMA_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebConfig {
    /// Schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// Bind host. Defaults to loopback per R10166.
    pub host: String,
    /// Bind port. Defaults to [`DEFAULT_PORT`].
    pub port: u16,
    /// TLS certificate path. Empty = self-signed bootstrap cert.
    pub tls_cert_path: String,
    /// TLS key path. Empty = self-signed bootstrap key.
    pub tls_key_path: String,
    /// SSE refresh interval in milliseconds. Defaults to 2000 per R10173.
    pub sse_refresh_ms: u32,
    /// When true, panels render read-only; operator MS003 key upload
    /// must precede any mutation route per R10171.
    pub read_only_default: bool,
    /// Operator's MS003 minisign public key (hex). Empty when no
    /// operator key has been uploaded yet.
    pub operator_public_key_hex: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            host: DEFAULT_HOST.into(),
            port: DEFAULT_PORT,
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            sse_refresh_ms: SSE_REFRESH_MS,
            read_only_default: true,
            operator_public_key_hex: String::new(),
        }
    }
}

/// Configuration errors.
#[derive(Debug, Error)]
pub enum WebError {
    /// Schema version drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema version.
        expected: String,
        /// Observed schema version.
        actual: String,
    },
    /// Non-loopback host (security regression).
    #[error("non-loopback host refused for minimal-web: {0}")]
    NonLoopbackHost(String),
    /// Refresh interval below 100ms minimum.
    #[error("sse_refresh_ms {0} below 100ms floor")]
    RefreshFloor(u32),
    /// Mutation attempted without operator key upload (R10171).
    #[error("mutation refused: operator MS003 key not uploaded (R10171)")]
    OperatorKeyMissing,
    /// Panel kind absent from canonical 4-panel layout.
    #[error("unknown panel kind: {0:?}")]
    UnknownPanel(PanelKind),
}

impl WebConfig {
    /// Validate config.
    pub fn validate(&self) -> Result<(), WebError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WebError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.host != "127.0.0.1" && self.host != "localhost" && self.host != "::1" {
            return Err(WebError::NonLoopbackHost(self.host.clone()));
        }
        if self.sse_refresh_ms < 100 {
            return Err(WebError::RefreshFloor(self.sse_refresh_ms));
        }
        Ok(())
    }

    /// True if the operator key has been uploaded + accepted.
    pub fn has_operator_key(&self) -> bool {
        !self.operator_public_key_hex.is_empty()
    }

    /// Assert that the caller may invoke a mutation route. Errors
    /// with [`WebError::OperatorKeyMissing`] when no operator key is loaded.
    pub fn assert_mutation_allowed(&self) -> Result<(), WebError> {
        if self.read_only_default && !self.has_operator_key() {
            return Err(WebError::OperatorKeyMissing);
        }
        Ok(())
    }
}

/// 4-panel layout entry per R10170. Mirrors the canonical TUI assignment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PanelRoute {
    /// Panel kind discriminator.
    pub kind: PanelKind,
    /// Quadrant in the 4-pane layout (matches TUI).
    pub quadrant: Quadrant,
    /// HTTP path for the panel's HTML view.
    pub html_path: &'static str,
    /// SSE event stream path.
    pub sse_path: &'static str,
}

/// Canonical 4-panel route table per R10170.
pub const PANEL_ROUTES: [PanelRoute; 4] = [
    PanelRoute {
        kind: PanelKind::Rules,
        quadrant: Quadrant::TopLeft,
        html_path: "/panels/rules",
        sse_path: "/sse/rules",
    },
    PanelRoute {
        kind: PanelKind::Grants,
        quadrant: Quadrant::TopRight,
        html_path: "/panels/grants",
        sse_path: "/sse/grants",
    },
    PanelRoute {
        kind: PanelKind::Quarantine,
        quadrant: Quadrant::BottomLeft,
        html_path: "/panels/quarantine",
        sse_path: "/sse/quarantine",
    },
    PanelRoute {
        kind: PanelKind::Authority,
        quadrant: Quadrant::BottomRight,
        html_path: "/panels/authority",
        sse_path: "/sse/authority",
    },
];

/// Find the route for a given panel kind.
pub fn route_for(kind: PanelKind) -> Result<PanelRoute, WebError> {
    PANEL_ROUTES
        .iter()
        .find(|r| r.kind == kind)
        .copied()
        .ok_or(WebError::UnknownPanel(kind))
}

/// Embedded asset bundle. Single-file vanilla HTML+CSS+JS per the
/// sovereignty-clean UX doctrine (no framework, no CDN, no external fonts).
pub mod assets {
    /// Root index page. Renders 4-panel layout grid.
    pub const INDEX_HTML: &str = include_str!("../static/index.html");

    /// Shared CSS bundle (monospace, monochrome palette).
    pub const APP_CSS: &str = include_str!("../static/app.css");

    /// Shared JS bundle (SSE wiring, keyboard nav, web→CLI clipboard).
    pub const APP_JS: &str = include_str!("../static/app.js");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        WebConfig::default().validate().unwrap();
    }

    #[test]
    fn non_loopback_host_refused() {
        let mut c = WebConfig::default();
        c.host = "0.0.0.0".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            WebError::NonLoopbackHost(_)
        ));
        c.host = "192.168.1.1".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            WebError::NonLoopbackHost(_)
        ));
    }

    #[test]
    fn ipv6_loopback_accepted() {
        let mut c = WebConfig::default();
        c.host = "::1".into();
        c.validate().unwrap();
    }

    #[test]
    fn refresh_floor_enforced() {
        let mut c = WebConfig::default();
        c.sse_refresh_ms = 50;
        assert!(matches!(
            c.validate().unwrap_err(),
            WebError::RefreshFloor(50)
        ));
    }

    #[test]
    fn read_only_default_blocks_mutations_without_key() {
        let c = WebConfig::default();
        assert!(c.read_only_default);
        assert!(!c.has_operator_key());
        assert!(matches!(
            c.assert_mutation_allowed().unwrap_err(),
            WebError::OperatorKeyMissing
        ));
    }

    #[test]
    fn operator_key_upload_unblocks_mutations() {
        let mut c = WebConfig::default();
        c.operator_public_key_hex = "deadbeefcafe1234".into();
        assert!(c.has_operator_key());
        c.assert_mutation_allowed().unwrap();
    }

    #[test]
    fn schema_drift_caught() {
        let mut c = WebConfig::default();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            WebError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn four_canonical_routes_present() {
        assert_eq!(PANEL_ROUTES.len(), 4);
        for kind in [
            PanelKind::Rules,
            PanelKind::Grants,
            PanelKind::Quarantine,
            PanelKind::Authority,
        ] {
            assert!(route_for(kind).is_ok());
        }
    }

    #[test]
    fn each_route_has_unique_quadrant() {
        use std::collections::HashSet;
        let qs: HashSet<Quadrant> = PANEL_ROUTES.iter().map(|r| r.quadrant).collect();
        assert_eq!(qs.len(), 4);
    }

    #[test]
    fn each_route_has_unique_sse_path() {
        use std::collections::HashSet;
        let paths: HashSet<&str> = PANEL_ROUTES.iter().map(|r| r.sse_path).collect();
        assert_eq!(paths.len(), 4);
    }

    #[test]
    fn assets_index_html_non_empty() {
        assert!(!assets::INDEX_HTML.is_empty());
        // Sovereignty-clean UX doctrine — no framework, no CDN.
        assert!(!assets::INDEX_HTML.contains("cdn."));
        assert!(!assets::INDEX_HTML.contains("fonts.googleapis"));
    }

    #[test]
    fn assets_css_and_js_non_empty() {
        assert!(!assets::APP_CSS.is_empty());
        assert!(!assets::APP_JS.is_empty());
    }

    #[test]
    fn default_port_is_canonical_7575() {
        assert_eq!(DEFAULT_PORT, 7575);
    }
}
