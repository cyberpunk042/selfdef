//! `selfdef-rule-pack-version` — 8 versioned rule packs the daemon loads.
//!
//! Each `RulePack` declares: id (kind), semver, MS003 signature, ISO-8601
//! `loaded_at`. The manifest is validated against a `pinned_floor` semver
//! per pack — if any pack's semver < floor or its signature is empty,
//! the daemon refuses boot.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 8 rule-pack kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackKind {
    /// MS037 filesystem boundary rules.
    Filesystem,
    /// MS038 network boundary rules.
    Network,
    /// MS035 capability rules.
    Capability,
    /// MS036 sandbox rules.
    Sandbox,
    /// MS034 communication boundary rules.
    Communication,
    /// Collector budget thresholds.
    CollectorBudget,
    /// Quarantine policy.
    Quarantine,
    /// MS041 commit authority gates.
    CommitAuthority,
}

/// Semver triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemVer {
    /// Major.
    pub major: u16,
    /// Minor.
    pub minor: u16,
    /// Patch.
    pub patch: u16,
}

impl SemVer {
    /// Parse "x.y.z".
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts[2].parse().ok()?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }
    /// "x.y.z".
    pub fn to_string_dotted(self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One rule pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePack {
    /// Kind.
    pub kind: PackKind,
    /// Semver as "x.y.z".
    pub semver: String,
    /// MS003 signature (non-empty).
    pub signature: String,
    /// ISO-8601 UTC.
    pub loaded_at: String,
}

/// Manifest envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePackManifest {
    /// Schema version.
    pub schema_version: String,
    /// 8 packs.
    pub packs: Vec<RulePack>,
}

/// Per-pack pinned semver floor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedFloors {
    /// One floor per kind.
    pub floors: Vec<(PackKind, SemVer)>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PackError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("pack count {0} != 8 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing pack: {0:?}")]
    Missing(PackKind),
    /// Bad semver string.
    #[error("pack {kind:?} bad semver: {semver}")]
    BadSemver {
        /// kind.
        kind: PackKind,
        /// semver.
        semver: String,
    },
    /// Empty signature.
    #[error("pack {0:?} unsigned")]
    Unsigned(PackKind),
    /// Empty loaded_at.
    #[error("pack {0:?} missing loaded_at")]
    MissingLoadedAt(PackKind),
    /// Semver below pinned floor.
    #[error("pack {kind:?} semver {got} below floor {floor}")]
    BelowFloor {
        /// kind.
        kind: PackKind,
        /// got.
        got: String,
        /// floor.
        floor: String,
    },
    /// Floor missing for a kind.
    #[error("floor missing for kind: {0:?}")]
    NoFloor(PackKind),
}

const REQUIRED_KINDS: [PackKind; 8] = [
    PackKind::Filesystem,
    PackKind::Network,
    PackKind::Capability,
    PackKind::Sandbox,
    PackKind::Communication,
    PackKind::CollectorBudget,
    PackKind::Quarantine,
    PackKind::CommitAuthority,
];

impl RulePackManifest {
    /// Lookup.
    pub fn get(&self, k: PackKind) -> Option<&RulePack> {
        self.packs.iter().find(|p| p.kind == k)
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<(), PackError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PackError::SchemaMismatch);
        }
        if self.packs.len() != 8 {
            return Err(PackError::CountInvalid(self.packs.len()));
        }
        for k in REQUIRED_KINDS {
            if !self.packs.iter().any(|p| p.kind == k) {
                return Err(PackError::Missing(k));
            }
        }
        for p in &self.packs {
            if SemVer::parse(&p.semver).is_none() {
                return Err(PackError::BadSemver {
                    kind: p.kind,
                    semver: p.semver.clone(),
                });
            }
            if p.signature.is_empty() {
                return Err(PackError::Unsigned(p.kind));
            }
            if p.loaded_at.is_empty() {
                return Err(PackError::MissingLoadedAt(p.kind));
            }
        }
        Ok(())
    }

    /// Validate against pinned floors.
    pub fn validate_floors(&self, floors: &PinnedFloors) -> Result<(), PackError> {
        self.validate()?;
        for p in &self.packs {
            let floor = floors
                .floors
                .iter()
                .find(|(k, _)| *k == p.kind)
                .map(|(_, v)| *v)
                .ok_or(PackError::NoFloor(p.kind))?;
            let got = SemVer::parse(&p.semver).expect("validated above");
            if got < floor {
                return Err(PackError::BelowFloor {
                    kind: p.kind,
                    got: got.to_string_dotted(),
                    floor: floor.to_string_dotted(),
                });
            }
        }
        Ok(())
    }
}

impl PinnedFloors {
    /// Canonical floors — 1.0.0 for everything by default.
    pub fn canonical() -> Self {
        Self {
            floors: REQUIRED_KINDS
                .iter()
                .map(|k| {
                    (
                        *k,
                        SemVer {
                            major: 1,
                            minor: 0,
                            patch: 0,
                        },
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(k: PackKind, semver: &str) -> RulePack {
        RulePack {
            kind: k,
            semver: semver.into(),
            signature: "ms003-sig".into(),
            loaded_at: "2026-05-19T03:00:00Z".into(),
        }
    }

    fn canonical_manifest() -> RulePackManifest {
        RulePackManifest {
            schema_version: SCHEMA_VERSION.into(),
            packs: REQUIRED_KINDS.iter().map(|k| pack(*k, "1.2.3")).collect(),
        }
    }

    #[test]
    fn canonical_validates() {
        canonical_manifest().validate().unwrap();
    }

    #[test]
    fn floors_pass() {
        canonical_manifest()
            .validate_floors(&PinnedFloors::canonical())
            .unwrap();
    }

    #[test]
    fn missing_pack_caught() {
        let mut m = canonical_manifest();
        m.packs.retain(|p| p.kind != PackKind::Network);
        m.packs.push(pack(PackKind::Filesystem, "1.2.3")); // wrong shape: still 8 but two Filesystem
        match m.validate().unwrap_err() {
            PackError::Missing(k) => assert_eq!(k, PackKind::Network),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn count_invalid_caught() {
        let mut m = canonical_manifest();
        m.packs.pop();
        assert!(matches!(
            m.validate().unwrap_err(),
            PackError::CountInvalid(7)
        ));
    }

    #[test]
    fn unsigned_caught() {
        let mut m = canonical_manifest();
        m.packs[0].signature = String::new();
        match m.validate().unwrap_err() {
            PackError::Unsigned(k) => assert_eq!(k, m.packs[0].kind),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn bad_semver_caught() {
        let mut m = canonical_manifest();
        m.packs[0].semver = "1.2".into();
        assert!(matches!(
            m.validate().unwrap_err(),
            PackError::BadSemver { .. }
        ));
    }

    #[test]
    fn below_floor_caught() {
        let mut m = canonical_manifest();
        m.packs[0].semver = "0.9.0".into();
        match m.validate_floors(&PinnedFloors::canonical()).unwrap_err() {
            PackError::BelowFloor { kind, got, floor } => {
                assert_eq!(kind, m.packs[0].kind);
                assert_eq!(got, "0.9.0");
                assert_eq!(floor, "1.0.0");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn semver_parse_and_string() {
        let v = SemVer::parse("3.4.5").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 3,
                minor: 4,
                patch: 5
            }
        );
        assert_eq!(v.to_string_dotted(), "3.4.5");
        assert!(SemVer::parse("1.2").is_none());
        assert!(SemVer::parse("abc").is_none());
    }

    #[test]
    fn semver_ordering() {
        let a = SemVer {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let b = SemVer {
            major: 1,
            minor: 0,
            patch: 1,
        };
        let c = SemVer {
            major: 2,
            minor: 0,
            patch: 0,
        };
        assert!(a < b && b < c);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = canonical_manifest();
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate().unwrap_err(),
            PackError::SchemaMismatch
        ));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&PackKind::CollectorBudget).unwrap(),
            "\"collector-budget\""
        );
        assert_eq!(
            serde_json::to_string(&PackKind::CommitAuthority).unwrap(),
            "\"commit-authority\""
        );
        assert_eq!(
            serde_json::to_string(&PackKind::Sandbox).unwrap(),
            "\"sandbox\""
        );
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = canonical_manifest();
        let j = serde_json::to_string(&m).unwrap();
        let back: RulePackManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
