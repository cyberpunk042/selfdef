//! `selfdef-routing-decision-authority` — IPS gate over provider routing.
//!
//! For every (Profile, ExecutionMode) tuple, declares which
//! `ProviderClass` (Local / Cloud / Synthetic) values the router may
//! pick. Private profile forbids Cloud; Replay mode allows only
//! Synthetic; Sandbox + Plan modes allow Synthetic and Local. The
//! runtime router asks `authorize_route` before issuing any model
//! call.
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

/// 3 provider classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderClass {
    /// Local runtime (Ollama / vLLM).
    Local,
    /// External cloud.
    Cloud,
    /// Synthetic (mock).
    Synthetic,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RoutingAuthorityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Route not authorized.
    #[error("route not authorized: class={class:?} profile={profile:?} mode={mode:?} reason={reason}")]
    NotAuthorized {
        /// class.
        class: ProviderClass,
        /// profile.
        profile: Profile,
        /// mode.
        mode: ExecutionMode,
        /// reason.
        reason: &'static str,
    },
}

/// IPS-authoritative gate.
pub fn authorize_route(
    class: ProviderClass,
    profile: Profile,
    mode: ExecutionMode,
) -> Result<(), RoutingAuthorityError> {
    use ExecutionMode::*;
    use Profile::*;
    // Replay mode: only Synthetic admissible.
    if mode == Replay && class != ProviderClass::Synthetic {
        return Err(RoutingAuthorityError::NotAuthorized {
            class, profile, mode, reason: "replay-mode-allows-synthetic-only",
        });
    }
    // Private profile: never Cloud.
    if profile == Private && class == ProviderClass::Cloud {
        return Err(RoutingAuthorityError::NotAuthorized {
            class, profile, mode, reason: "private-profile-forbids-cloud",
        });
    }
    // Plan mode forbids Cloud (no live network in pure planning).
    if mode == Plan && class == ProviderClass::Cloud {
        return Err(RoutingAuthorityError::NotAuthorized {
            class, profile, mode, reason: "plan-mode-forbids-cloud",
        });
    }
    // Sandbox forbids Cloud (network is off per mode policy).
    if mode == Sandbox && class == ProviderClass::Cloud {
        return Err(RoutingAuthorityError::NotAuthorized {
            class, profile, mode, reason: "sandbox-mode-forbids-cloud",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExecutionMode::*;
    use Profile::*;

    #[test]
    fn replay_only_synthetic() {
        authorize_route(ProviderClass::Synthetic, Careful, Replay).unwrap();
        assert!(authorize_route(ProviderClass::Local, Careful, Replay).is_err());
        assert!(authorize_route(ProviderClass::Cloud, Careful, Replay).is_err());
    }

    #[test]
    fn private_forbids_cloud() {
        assert!(authorize_route(ProviderClass::Cloud, Private, Execute).is_err());
        authorize_route(ProviderClass::Local, Private, Execute).unwrap();
        authorize_route(ProviderClass::Synthetic, Private, Execute).unwrap();
    }

    #[test]
    fn plan_forbids_cloud() {
        assert!(authorize_route(ProviderClass::Cloud, Careful, Plan).is_err());
        authorize_route(ProviderClass::Local, Careful, Plan).unwrap();
        authorize_route(ProviderClass::Synthetic, Careful, Plan).unwrap();
    }

    #[test]
    fn sandbox_forbids_cloud() {
        assert!(authorize_route(ProviderClass::Cloud, Careful, Sandbox).is_err());
        authorize_route(ProviderClass::Local, Careful, Sandbox).unwrap();
    }

    #[test]
    fn execute_careful_allows_all_classes() {
        for class in [ProviderClass::Local, ProviderClass::Cloud, ProviderClass::Synthetic] {
            authorize_route(class, Careful, Execute).unwrap();
        }
    }

    #[test]
    fn dry_run_allows_cloud_in_careful_profile() {
        authorize_route(ProviderClass::Cloud, Careful, DryRun).unwrap();
    }

    #[test]
    fn dry_run_private_forbids_cloud() {
        assert!(authorize_route(ProviderClass::Cloud, Private, DryRun).is_err());
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&ProviderClass::Local).unwrap(), "\"local\"");
        assert_eq!(serde_json::to_string(&ProviderClass::Cloud).unwrap(), "\"cloud\"");
        assert_eq!(serde_json::to_string(&ProviderClass::Synthetic).unwrap(), "\"synthetic\"");
    }
}
