//! `GET /v1/audit-chains` — MS009 audit-cycles HTTP surface.
//!
//! Runs the 3 watchdog audit-chain checks (perimeter, guardian,
//! scheduler) and returns the structured result. Mirrors the CLI's
//! `selfdefctl <watchdog> audit-cycle replay` verbs but surfaces them
//! as one composite read so dashboards + monitoring agents can probe
//! all chains in a single HTTP call.
//!
//! Each watchdog's `audit_chain_check(path)` returns:
//!   `Ok(usize)` — number of events successfully verified (chain intact)
//!   `Err(_)`    — chain break at a specific position with detail
//!
//! Response shape:
//! ```json
//! {
//!   "worst": "ok" | "critical",
//!   "chains": [
//!     {
//!       "watchdog": "perimeter",
//!       "path": "/var/log/selfdef/perimeter.ocsf.jsonl",
//!       "events_verified": 1234,
//!       "ok": true,
//!       "error": null
//!     },
//!     {
//!       "watchdog": "guardian",
//!       "path": "/mnt/vault/context/security_audit.log",
//!       "events_verified": 0,
//!       "ok": false,
//!       "error": "chain break at line 4567: prev_event_sha256 mismatch"
//!     },
//!     ...
//!   ]
//! }
//! ```
//!
//! Source: MS009 catalog rows + the 3 per-watchdog `audit_chain_check`
//! public functions in selfdef-{perimeter,guardian,scheduler}.

use std::path::PathBuf;

use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChainCheck {
    /// `"perimeter" | "guardian" | "scheduler"`.
    pub watchdog: &'static str,
    /// Path to the OCSF JSONL file the check ran against.
    pub path: PathBuf,
    /// Number of events successfully verified when ok=true; 0 when
    /// the chain broke (the verifier exits at the first inconsistency).
    pub events_verified: usize,
    /// True iff `audit_chain_check` returned Ok(_).
    pub ok: bool,
    /// Human-readable error message when ok=false; `None` otherwise.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditChainsResponse {
    /// `"ok"` iff every chain verified; `"critical"` if any chain broke.
    pub worst: &'static str,
    pub chains: Vec<ChainCheck>,
}

fn check_one(
    watchdog: &'static str,
    path: PathBuf,
    check: impl FnOnce(&std::path::Path) -> Result<usize, String>,
) -> ChainCheck {
    match check(&path) {
        Ok(events_verified) => ChainCheck {
            watchdog,
            path,
            events_verified,
            ok: true,
            error: None,
        },
        Err(e) => ChainCheck {
            watchdog,
            path,
            events_verified: 0,
            ok: false,
            error: Some(e),
        },
    }
}

/// `GET /v1/audit-chains` handler.
pub(crate) async fn show() -> Json<AuditChainsResponse> {
    let perimeter_path = PathBuf::from(selfdef_perimeter::DEFAULT_OCSF_PATH);
    let guardian_path = PathBuf::from(selfdef_guardian::DEFAULT_AUDIT_LOG_PATH);
    let scheduler_path = PathBuf::from(selfdef_scheduler::DEFAULT_AUDIT_LOG_PATH);
    let chains = vec![
        check_one("perimeter", perimeter_path.clone(), |p| {
            selfdef_perimeter::audit_chain_check(p).map_err(|e| e.to_string())
        }),
        check_one("guardian", guardian_path.clone(), |p| {
            selfdef_guardian::audit_chain_check(p).map_err(|e| e.to_string())
        }),
        check_one("scheduler", scheduler_path.clone(), |p| {
            selfdef_scheduler::audit_chain_check(p).map_err(|e| e.to_string())
        }),
    ];
    let worst: &'static str = if chains.iter().all(|c| c.ok) {
        "ok"
    } else {
        "critical"
    };
    Json(AuditChainsResponse { worst, chains })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_one_returns_ok_on_success() {
        let path = PathBuf::from("/no/such/path");
        let result = check_one("test", path.clone(), |_p| Ok(42));
        assert!(result.ok);
        assert_eq!(result.events_verified, 42);
        assert_eq!(result.path, path);
        assert!(result.error.is_none());
    }

    #[test]
    fn check_one_returns_err_on_failure() {
        let path = PathBuf::from("/no/such/path");
        let result = check_one("test", path.clone(), |_p| {
            Err("chain break at line 42".to_string())
        });
        assert!(!result.ok);
        assert_eq!(result.events_verified, 0);
        assert_eq!(result.error.as_deref(), Some("chain break at line 42"));
    }
}
