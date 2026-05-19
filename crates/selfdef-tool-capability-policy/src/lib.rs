//! `selfdef-tool-capability-policy` — IPS authority over operator-callable tools.
//!
//! 8 canonical tool ids: Shell / FsRead / FsWrite / WebFetch /
//! ModelInference / McpBridge / ReplayControl / CliBridge. For each
//! tool, this policy declares the set of `(ExecutionMode, Profile)`
//! pairs the IPS authorizes. The runtime cockpit tool catalog
//! consumes this; selfdef refuses any call where (mode, profile)
//! isn't in the authorized set.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_execution_mode_policy::ExecutionMode;
use selfdef_profile_authority_gate::Profile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 8 canonical tool ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolId {
    /// Subprocess shell.
    Shell,
    /// Filesystem read.
    FsRead,
    /// Filesystem write.
    FsWrite,
    /// HTTPS fetch.
    WebFetch,
    /// Model inference call.
    ModelInference,
    /// MCP bridge.
    McpBridge,
    /// Replay step / pause / seek.
    ReplayControl,
    /// Bridge to selfdef CLI.
    CliBridge,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CapabilityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Tool not authorized in this context.
    #[error("tool {tool:?} not authorized in mode {mode:?} profile {profile:?}")]
    NotAuthorized {
        /// Tool.
        tool: ToolId,
        /// Mode.
        mode: ExecutionMode,
        /// Profile.
        profile: Profile,
    },
}

impl ToolId {
    /// All 8 tools.
    pub const ALL: [ToolId; 8] = [
        ToolId::Shell, ToolId::FsRead, ToolId::FsWrite, ToolId::WebFetch,
        ToolId::ModelInference, ToolId::McpBridge, ToolId::ReplayControl,
        ToolId::CliBridge,
    ];
}

/// IPS-authoritative permission check.
///
/// Rules (operator-curated):
/// - `FsRead`         — every mode + every profile (universally read-allowed)
/// - `ModelInference` — every mode + every profile (always model-bound)
/// - `CliBridge`      — every mode + non-Private profile
/// - `FsWrite`        — mode in {Sandbox, Execute, Debug} + non-Private
/// - `Shell`          — mode in {Sandbox, Execute, Debug} + Careful/Autonomous/Production
/// - `WebFetch`       — mode in {DryRun, Shadow, Execute, Debug} + non-Private
/// - `McpBridge`      — mode in {DryRun, Shadow, Execute, Debug} + non-Private
/// - `ReplayControl`  — mode in {Replay, Debug} + non-Private
pub fn is_authorized(tool: ToolId, mode: ExecutionMode, profile: Profile) -> bool {
    use ExecutionMode::*;
    use Profile::*;
    match tool {
        ToolId::FsRead => true,
        ToolId::ModelInference => true,
        ToolId::CliBridge => profile != Private,
        ToolId::FsWrite => {
            profile != Private && matches!(mode, Sandbox | Execute | Debug)
        }
        ToolId::Shell => {
            matches!(profile, Careful | Autonomous | Production)
                && matches!(mode, Sandbox | Execute | Debug)
        }
        ToolId::WebFetch => {
            profile != Private && matches!(mode, DryRun | Shadow | Execute | Debug)
        }
        ToolId::McpBridge => {
            profile != Private && matches!(mode, DryRun | Shadow | Execute | Debug)
        }
        ToolId::ReplayControl => {
            profile != Private && matches!(mode, Replay | Debug)
        }
    }
}

/// Refuse with descriptive error if not authorized.
pub fn require_authorized(
    tool: ToolId, mode: ExecutionMode, profile: Profile,
) -> Result<(), CapabilityError> {
    if is_authorized(tool, mode, profile) {
        Ok(())
    } else {
        Err(CapabilityError::NotAuthorized { tool, mode, profile })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExecutionMode::*;
    use Profile::*;

    #[test]
    fn fs_read_authorized_everywhere() {
        for m in ExecutionMode::ALL {
            for p in [Private, Fast, Careful, Autonomous, Experimental, Production] {
                assert!(is_authorized(ToolId::FsRead, m, p), "fs-read denied in {m:?}/{p:?}");
            }
        }
    }

    #[test]
    fn model_inference_authorized_everywhere() {
        assert!(is_authorized(ToolId::ModelInference, Plan, Private));
        assert!(is_authorized(ToolId::ModelInference, Execute, Production));
    }

    #[test]
    fn fs_write_blocked_in_plan() {
        assert!(!is_authorized(ToolId::FsWrite, Plan, Careful));
        assert!(!is_authorized(ToolId::FsWrite, DryRun, Careful));
    }

    #[test]
    fn fs_write_blocked_in_private() {
        assert!(!is_authorized(ToolId::FsWrite, Sandbox, Private));
        assert!(!is_authorized(ToolId::FsWrite, Execute, Private));
    }

    #[test]
    fn fs_write_permitted_sandbox_execute_debug() {
        for m in [Sandbox, Execute, Debug] {
            assert!(is_authorized(ToolId::FsWrite, m, Careful));
        }
    }

    #[test]
    fn shell_only_in_careful_autonomous_production() {
        for p in [Fast, Experimental] {
            assert!(!is_authorized(ToolId::Shell, Sandbox, p));
        }
        for p in [Careful, Autonomous, Production] {
            assert!(is_authorized(ToolId::Shell, Execute, p));
        }
    }

    #[test]
    fn web_fetch_blocked_in_private_and_plan() {
        assert!(!is_authorized(ToolId::WebFetch, DryRun, Private));
        assert!(!is_authorized(ToolId::WebFetch, Plan, Careful));
    }

    #[test]
    fn web_fetch_allowed_dry_run_careful() {
        assert!(is_authorized(ToolId::WebFetch, DryRun, Careful));
        assert!(is_authorized(ToolId::WebFetch, Shadow, Careful));
        assert!(is_authorized(ToolId::WebFetch, Execute, Careful));
    }

    #[test]
    fn replay_control_only_in_replay_or_debug() {
        assert!(is_authorized(ToolId::ReplayControl, Replay, Careful));
        assert!(is_authorized(ToolId::ReplayControl, Debug, Careful));
        assert!(!is_authorized(ToolId::ReplayControl, Execute, Careful));
        assert!(!is_authorized(ToolId::ReplayControl, Plan, Careful));
    }

    #[test]
    fn require_authorized_emits_error() {
        let err = require_authorized(ToolId::FsWrite, Plan, Careful).unwrap_err();
        match err {
            CapabilityError::NotAuthorized { tool, mode, profile } => {
                assert_eq!(tool, ToolId::FsWrite);
                assert_eq!(mode, Plan);
                assert_eq!(profile, Careful);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn require_authorized_passes_when_allowed() {
        require_authorized(ToolId::FsWrite, Execute, Careful).unwrap();
    }

    #[test]
    fn tool_id_serde_kebab() {
        assert_eq!(serde_json::to_string(&ToolId::FsRead).unwrap(), "\"fs-read\"");
        assert_eq!(serde_json::to_string(&ToolId::ModelInference).unwrap(), "\"model-inference\"");
        assert_eq!(serde_json::to_string(&ToolId::ReplayControl).unwrap(), "\"replay-control\"");
    }
}
