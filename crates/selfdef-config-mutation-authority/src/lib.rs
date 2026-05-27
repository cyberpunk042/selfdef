//! `selfdef-config-mutation-authority` — IPS gate over config mutations.
//!
//! Each `ConfigNamespace` declares the minimum `Profile` required to
//! flip any key under it. The cockpit consults `permitted` before
//! applying an operator-issued config change.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_profile_authority_gate::Profile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical config namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigNamespace {
    /// `boundary.*` — IPS rule packs.
    Boundary,
    /// `notifier.*` — channel routing.
    Notifier,
    /// `theme.*` — cockpit theme.
    Theme,
    /// `density.*` — cockpit density.
    Density,
    /// `locale.*` — operator locale.
    Locale,
    /// `provider.*` — model providers.
    Provider,
    /// `eval.*` — eval suite registration.
    Eval,
    /// `replay.*` — replay sources.
    Replay,
}

/// Per-namespace mutation policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationPolicy {
    /// Namespace.
    pub namespace: ConfigNamespace,
    /// Minimum profile to mutate any key under this namespace.
    pub min_profile: Profile,
}

/// Authority envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigMutationAuthority {
    /// Schema version.
    pub schema_version: String,
    /// 8 namespace policies.
    pub policies: Vec<MutationPolicy>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ConfigMutationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("policy count {0} != 8 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing namespace: {0:?}")]
    Missing(ConfigNamespace),
    /// Profile below requirement.
    #[error(
        "mutation forbidden in namespace {namespace:?}: actor profile {actor_profile:?} below required {required:?}"
    )]
    BelowMinimum {
        /// namespace.
        namespace: ConfigNamespace,
        /// actor profile.
        actor_profile: Profile,
        /// required.
        required: Profile,
    },
}

const REQUIRED: [ConfigNamespace; 8] = [
    ConfigNamespace::Boundary,
    ConfigNamespace::Notifier,
    ConfigNamespace::Theme,
    ConfigNamespace::Density,
    ConfigNamespace::Locale,
    ConfigNamespace::Provider,
    ConfigNamespace::Eval,
    ConfigNamespace::Replay,
];

/// Numeric rank for Profile authority ordering (higher = more authority).
fn profile_rank(p: Profile) -> u8 {
    match p {
        Profile::Private => 0,
        Profile::Fast => 1,
        Profile::Experimental => 2,
        Profile::Careful => 3,
        Profile::Autonomous => 4,
        Profile::Production => 5,
    }
}

impl ConfigMutationAuthority {
    /// Canonical policy.
    pub fn canonical() -> Self {
        let policies = vec![
            MutationPolicy {
                namespace: ConfigNamespace::Boundary,
                min_profile: Profile::Production,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Notifier,
                min_profile: Profile::Careful,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Theme,
                min_profile: Profile::Private,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Density,
                min_profile: Profile::Private,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Locale,
                min_profile: Profile::Private,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Provider,
                min_profile: Profile::Careful,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Eval,
                min_profile: Profile::Careful,
            },
            MutationPolicy {
                namespace: ConfigNamespace::Replay,
                min_profile: Profile::Careful,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            policies,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ConfigMutationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfigMutationError::SchemaMismatch);
        }
        if self.policies.len() != 8 {
            return Err(ConfigMutationError::CountInvalid(self.policies.len()));
        }
        for n in REQUIRED {
            if !self.policies.iter().any(|p| p.namespace == n) {
                return Err(ConfigMutationError::Missing(n));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, ns: ConfigNamespace) -> Option<&MutationPolicy> {
        self.policies.iter().find(|p| p.namespace == ns)
    }

    /// IPS-authoritative admission check.
    pub fn permitted(
        &self,
        namespace: ConfigNamespace,
        actor_profile: Profile,
    ) -> Result<(), ConfigMutationError> {
        let req = self
            .get(namespace)
            .ok_or(ConfigMutationError::Missing(namespace))?;
        if profile_rank(actor_profile) < profile_rank(req.min_profile) {
            return Err(ConfigMutationError::BelowMinimum {
                namespace,
                actor_profile,
                required: req.min_profile,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ConfigMutationAuthority::canonical().validate().unwrap();
    }

    #[test]
    fn theme_anyone_can_mutate() {
        let a = ConfigMutationAuthority::canonical();
        a.permitted(ConfigNamespace::Theme, Profile::Private)
            .unwrap();
        a.permitted(ConfigNamespace::Theme, Profile::Production)
            .unwrap();
    }

    #[test]
    fn boundary_requires_production() {
        let a = ConfigMutationAuthority::canonical();
        assert!(
            a.permitted(ConfigNamespace::Boundary, Profile::Private)
                .is_err()
        );
        assert!(
            a.permitted(ConfigNamespace::Boundary, Profile::Careful)
                .is_err()
        );
        a.permitted(ConfigNamespace::Boundary, Profile::Production)
            .unwrap();
    }

    #[test]
    fn notifier_requires_careful() {
        let a = ConfigMutationAuthority::canonical();
        assert!(
            a.permitted(ConfigNamespace::Notifier, Profile::Fast)
                .is_err()
        );
        a.permitted(ConfigNamespace::Notifier, Profile::Careful)
            .unwrap();
        a.permitted(ConfigNamespace::Notifier, Profile::Production)
            .unwrap();
    }

    #[test]
    fn replay_requires_careful() {
        let a = ConfigMutationAuthority::canonical();
        assert!(
            a.permitted(ConfigNamespace::Replay, Profile::Private)
                .is_err()
        );
        a.permitted(ConfigNamespace::Replay, Profile::Careful)
            .unwrap();
    }

    #[test]
    fn count_invalid_caught() {
        let mut a = ConfigMutationAuthority::canonical();
        a.policies.pop();
        assert!(matches!(
            a.validate().unwrap_err(),
            ConfigMutationError::CountInvalid(7)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = ConfigMutationAuthority::canonical();
        a.schema_version = "9.9.9".into();
        assert!(matches!(
            a.validate().unwrap_err(),
            ConfigMutationError::SchemaMismatch
        ));
    }

    #[test]
    fn namespace_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ConfigNamespace::Boundary).unwrap(),
            "\"boundary\""
        );
        assert_eq!(
            serde_json::to_string(&ConfigNamespace::Provider).unwrap(),
            "\"provider\""
        );
    }

    #[test]
    fn authority_serde_roundtrip() {
        let a = ConfigMutationAuthority::canonical();
        let j = serde_json::to_string(&a).unwrap();
        let back: ConfigMutationAuthority = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
