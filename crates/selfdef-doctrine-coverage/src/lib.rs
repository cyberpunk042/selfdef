//! `selfdef-doctrine-coverage` — cross-crate coverage summary.
//!
//! Composes 3 composite registries:
//! - selfdef-functional-modules (14 IPS modules)
//! - selfdef-boundary-summary (5 boundaries: MS034-MS038)
//! - selfdef-doctrinal-preservation (10 verbatim doctrines)
//!
//! Returns a single `IntegrityReport` per the post-boot integrity check
//! the daemon runs against itself.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_boundary_summary::BoundarySummary;
use selfdef_doctrinal_preservation::DoctrineRegistry;
use selfdef_functional_modules::IpsModuleCatalog;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Coverage check categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageCategory {
    /// MS006 14 functional modules.
    FunctionalModules,
    /// MS034-MS038 5 boundaries.
    FiveBoundaries,
    /// 10 doctrine strings preserved verbatim.
    DoctrineRegistry,
}

/// One coverage category result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryResult {
    /// Category.
    pub category: CoverageCategory,
    /// Whether the embedded composite validated cleanly.
    pub valid: bool,
    /// Inner-error reason (empty when valid).
    pub reason: String,
    /// Count of items in the composite (modules / boundaries / doctrines).
    pub item_count: u32,
}

/// Integrity report — the daemon's post-boot self-check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 UTC.
    pub captured_at: String,
    /// 3 category results.
    pub categories: Vec<CategoryResult>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CoverageError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// One of the 3 categories failed.
    #[error("integrity report failure: {failures:?}")]
    IntegrityFailed {
        /// Categories that failed.
        failures: Vec<CoverageCategory>,
    },
}

impl IntegrityReport {
    /// Run the post-boot integrity check across the 3 composites.
    pub fn run(
        modules: &IpsModuleCatalog,
        boundaries: &BoundarySummary,
        doctrines: &DoctrineRegistry,
    ) -> Self {
        let mod_res = match modules.validate() {
            Ok(()) => CategoryResult {
                category: CoverageCategory::FunctionalModules,
                valid: true,
                reason: String::new(),
                item_count: modules.entries.len() as u32,
            },
            Err(e) => CategoryResult {
                category: CoverageCategory::FunctionalModules,
                valid: false,
                reason: e.to_string(),
                item_count: modules.entries.len() as u32,
            },
        };
        let bd_res = match boundaries.validate() {
            Ok(()) => CategoryResult {
                category: CoverageCategory::FiveBoundaries,
                valid: true,
                reason: String::new(),
                item_count: boundaries.boundaries.len() as u32,
            },
            Err(e) => CategoryResult {
                category: CoverageCategory::FiveBoundaries,
                valid: false,
                reason: e.to_string(),
                item_count: boundaries.boundaries.len() as u32,
            },
        };
        let dc_res = match doctrines.validate() {
            Ok(()) => CategoryResult {
                category: CoverageCategory::DoctrineRegistry,
                valid: true,
                reason: String::new(),
                item_count: doctrines.records.len() as u32,
            },
            Err(e) => CategoryResult {
                category: CoverageCategory::DoctrineRegistry,
                valid: false,
                reason: e.to_string(),
                item_count: doctrines.records.len() as u32,
            },
        };
        Self {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            categories: vec![mod_res, bd_res, dc_res],
        }
    }

    /// True iff all 3 categories validated cleanly.
    pub fn all_clean(&self) -> bool {
        self.categories.iter().all(|r| r.valid)
    }

    /// Categories that failed.
    pub fn failures(&self) -> Vec<CoverageCategory> {
        self.categories
            .iter()
            .filter(|r| !r.valid)
            .map(|r| r.category)
            .collect()
    }

    /// Assert clean — refuses daemon bring-up if any composite invalid.
    pub fn assert_clean(&self) -> Result<(), CoverageError> {
        if !self.all_clean() {
            return Err(CoverageError::IntegrityFailed {
                failures: self.failures(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_functional_modules::IpsModule;

    fn modules() -> IpsModuleCatalog {
        IpsModuleCatalog::empty_canonical()
    }
    fn boundaries() -> BoundarySummary {
        BoundarySummary::empty_canonical()
    }
    fn doctrines() -> DoctrineRegistry {
        DoctrineRegistry::canonical()
    }

    #[test]
    fn ok_report_all_clean() {
        let r = IntegrityReport::run(&modules(), &boundaries(), &doctrines());
        assert!(r.all_clean());
        r.assert_clean().unwrap();
    }

    #[test]
    fn three_categories_present() {
        let r = IntegrityReport::run(&modules(), &boundaries(), &doctrines());
        assert_eq!(r.categories.len(), 3);
        assert!(
            r.categories
                .iter()
                .any(|c| c.category == CoverageCategory::FunctionalModules)
        );
        assert!(
            r.categories
                .iter()
                .any(|c| c.category == CoverageCategory::FiveBoundaries)
        );
        assert!(
            r.categories
                .iter()
                .any(|c| c.category == CoverageCategory::DoctrineRegistry)
        );
    }

    #[test]
    fn module_failure_reflected() {
        let mut bad = modules();
        // Make detect-host Absent → substrate-not-active per IpsModuleCatalog::validate.
        for e in bad.entries.iter_mut() {
            if e.module == IpsModule::DetectHost {
                e.state = selfdef_functional_modules::ModuleState::Absent;
            }
        }
        let r = IntegrityReport::run(&bad, &boundaries(), &doctrines());
        assert!(!r.all_clean());
        assert!(r.failures().contains(&CoverageCategory::FunctionalModules));
    }

    #[test]
    fn boundary_failure_reflected() {
        let mut bad = boundaries();
        bad.doctrine = "wrong".into();
        let r = IntegrityReport::run(&modules(), &bad, &doctrines());
        assert!(!r.all_clean());
        assert!(r.failures().contains(&CoverageCategory::FiveBoundaries));
    }

    #[test]
    fn doctrine_failure_reflected() {
        let mut bad = doctrines();
        bad.records[0].text = "tampered".into();
        let r = IntegrityReport::run(&modules(), &boundaries(), &bad);
        assert!(!r.all_clean());
        assert!(r.failures().contains(&CoverageCategory::DoctrineRegistry));
    }

    #[test]
    fn assert_clean_refuses_on_failure() {
        let mut bad = doctrines();
        bad.records[0].text = "tampered".into();
        let r = IntegrityReport::run(&modules(), &boundaries(), &bad);
        assert!(matches!(
            r.assert_clean().unwrap_err(),
            CoverageError::IntegrityFailed { .. }
        ));
    }

    #[test]
    fn item_counts_match_compositions() {
        let r = IntegrityReport::run(&modules(), &boundaries(), &doctrines());
        let m = r
            .categories
            .iter()
            .find(|c| c.category == CoverageCategory::FunctionalModules)
            .unwrap();
        assert_eq!(m.item_count, 14);
        let b = r
            .categories
            .iter()
            .find(|c| c.category == CoverageCategory::FiveBoundaries)
            .unwrap();
        assert_eq!(b.item_count, 5);
        let d = r
            .categories
            .iter()
            .find(|c| c.category == CoverageCategory::DoctrineRegistry)
            .unwrap();
        assert_eq!(d.item_count, 10);
    }

    #[test]
    fn coverage_category_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&CoverageCategory::FunctionalModules).unwrap(),
            "\"functional-modules\""
        );
        assert_eq!(
            serde_json::to_string(&CoverageCategory::FiveBoundaries).unwrap(),
            "\"five-boundaries\""
        );
        assert_eq!(
            serde_json::to_string(&CoverageCategory::DoctrineRegistry).unwrap(),
            "\"doctrine-registry\""
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let r = IntegrityReport::run(&modules(), &boundaries(), &doctrines());
        let j = serde_json::to_string(&r).unwrap();
        let back: IntegrityReport = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
