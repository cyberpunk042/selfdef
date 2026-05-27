//! `selfdef-quarantine-engine` — MS042 decision engine for the
//! 3-step block + quarantine + trace protocol.
//!
//! Per MS042 + E0429-E0430 + dump 17422-17445 + F04871-F04875 high-risk
//! classifier sibling: given a mismatch report, this engine decides one
//! of 4 dispositions:
//!
//! 1. **Observe** — no response (informational-only mismatch).
//! 2. **Block** — terminate process + emit OCSF 2004.
//! 3. **Quarantine** — block + escalate to operator queue for triage.
//! 4. **Forfeit** — irreversible (purge image, ban fingerprint).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_quarantine_mirror::{MismatchDetail, MismatchField, MismatchSeverity, QuarantineState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision outcome per E0430.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// Observe-only — no enforcement.
    Observe,
    /// Block — SIGKILL the offending process.
    Block,
    /// Quarantine — block + queue for operator triage.
    Quarantine,
    /// Forfeit — irreversible removal.
    Forfeit,
}

/// Mismatch report input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MismatchReport {
    /// Tool that mismatched.
    pub tool: String,
    /// Declarer fingerprint.
    pub declarer: String,
    /// One or more mismatch details.
    pub mismatches: Vec<MismatchDetail>,
    /// Recidivism count — how many times this tool has been quarantined before.
    pub prior_quarantine_count: u32,
    /// Whether the operator has whitelisted this tool.
    pub operator_whitelisted: bool,
    /// Recent state of the tool (if any).
    pub current_state: Option<QuarantineState>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Mismatch list empty.
    #[error("mismatch list empty — nothing to decide")]
    EmptyMismatches,
    /// Tool name empty.
    #[error("tool name empty")]
    EmptyTool,
}

/// Decide disposition from a mismatch report.
pub fn decide(report: &MismatchReport) -> Result<Disposition, EngineError> {
    if report.tool.is_empty() {
        return Err(EngineError::EmptyTool);
    }
    if report.mismatches.is_empty() {
        return Err(EngineError::EmptyMismatches);
    }

    fn rank(s: MismatchSeverity) -> u8 {
        match s {
            MismatchSeverity::Informational => 0,
            MismatchSeverity::Minor => 1,
            MismatchSeverity::Major => 2,
            MismatchSeverity::Critical => 3,
        }
    }
    // Highest severity in the report drives the base disposition.
    let max_sev = report
        .mismatches
        .iter()
        .map(|m| m.severity)
        .max_by_key(|s| rank(*s))
        .unwrap_or(MismatchSeverity::Informational);

    // Whitelist override: only escalates above Block to Quarantine, never to Forfeit.
    if report.operator_whitelisted {
        return Ok(match max_sev {
            MismatchSeverity::Informational | MismatchSeverity::Minor => Disposition::Observe,
            MismatchSeverity::Major | MismatchSeverity::Critical => Disposition::Quarantine,
        });
    }

    // Recidivism: 3+ prior quarantines → Forfeit candidate.
    if report.prior_quarantine_count >= 3 {
        return Ok(Disposition::Forfeit);
    }

    // Default per-severity decision matrix.
    let base = match max_sev {
        MismatchSeverity::Informational => Disposition::Observe,
        MismatchSeverity::Minor => Disposition::Block,
        MismatchSeverity::Major => Disposition::Quarantine,
        MismatchSeverity::Critical => {
            if report.prior_quarantine_count >= 1 {
                Disposition::Forfeit
            } else {
                Disposition::Quarantine
            }
        }
    };

    // Secret-access mismatch ALWAYS escalates to at least Quarantine.
    if report
        .mismatches
        .iter()
        .any(|m| m.field == MismatchField::SecretAccess)
    {
        let escalated = match base {
            Disposition::Observe | Disposition::Block => Disposition::Quarantine,
            other => other,
        };
        return Ok(escalated);
    }

    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(field: MismatchField, severity: MismatchSeverity) -> MismatchDetail {
        MismatchDetail {
            field,
            severity,
            declared: "x".into(),
            observed: "y".into(),
            first_observed_at: "2026-05-19T03:00:00Z".into(),
        }
    }
    fn report(details: Vec<MismatchDetail>) -> MismatchReport {
        MismatchReport {
            tool: "tool-x".into(),
            declarer: "ext".into(),
            mismatches: details,
            prior_quarantine_count: 0,
            operator_whitelisted: false,
            current_state: None,
        }
    }

    // --- Severity-driven base disposition ---

    #[test]
    fn informational_yields_observe() {
        assert_eq!(
            decide(&report(vec![detail(
                MismatchField::ReadPaths,
                MismatchSeverity::Informational
            )]))
            .unwrap(),
            Disposition::Observe
        );
    }

    #[test]
    fn minor_yields_block() {
        assert_eq!(
            decide(&report(vec![detail(
                MismatchField::ReadPaths,
                MismatchSeverity::Minor
            )]))
            .unwrap(),
            Disposition::Block
        );
    }

    #[test]
    fn major_yields_quarantine() {
        assert_eq!(
            decide(&report(vec![detail(
                MismatchField::NetworkDomains,
                MismatchSeverity::Major
            )]))
            .unwrap(),
            Disposition::Quarantine
        );
    }

    #[test]
    fn critical_yields_quarantine_first_time() {
        assert_eq!(
            decide(&report(vec![detail(
                MismatchField::WritePaths,
                MismatchSeverity::Critical
            )]))
            .unwrap(),
            Disposition::Quarantine
        );
    }

    #[test]
    fn critical_with_prior_yields_forfeit() {
        let mut r = report(vec![detail(
            MismatchField::WritePaths,
            MismatchSeverity::Critical,
        )]);
        r.prior_quarantine_count = 1;
        assert_eq!(decide(&r).unwrap(), Disposition::Forfeit);
    }

    #[test]
    fn three_prior_yields_forfeit_regardless() {
        let mut r = report(vec![detail(
            MismatchField::ReadPaths,
            MismatchSeverity::Minor,
        )]);
        r.prior_quarantine_count = 3;
        assert_eq!(decide(&r).unwrap(), Disposition::Forfeit);
    }

    // --- Whitelist override ---

    #[test]
    fn whitelisted_informational_observes() {
        let mut r = report(vec![detail(
            MismatchField::ReadPaths,
            MismatchSeverity::Informational,
        )]);
        r.operator_whitelisted = true;
        assert_eq!(decide(&r).unwrap(), Disposition::Observe);
    }

    #[test]
    fn whitelisted_critical_still_quarantines() {
        let mut r = report(vec![detail(
            MismatchField::WritePaths,
            MismatchSeverity::Critical,
        )]);
        r.operator_whitelisted = true;
        r.prior_quarantine_count = 5; // whitelist trumps recidivism
        assert_eq!(decide(&r).unwrap(), Disposition::Quarantine);
    }

    // --- SecretAccess escalator ---

    #[test]
    fn secret_access_minor_escalates_to_quarantine() {
        // Minor base → Block, then SecretAccess escalates to Quarantine.
        let r = report(vec![detail(
            MismatchField::SecretAccess,
            MismatchSeverity::Minor,
        )]);
        assert_eq!(decide(&r).unwrap(), Disposition::Quarantine);
    }

    #[test]
    fn secret_access_informational_escalates_to_quarantine() {
        let r = report(vec![detail(
            MismatchField::SecretAccess,
            MismatchSeverity::Informational,
        )]);
        assert_eq!(decide(&r).unwrap(), Disposition::Quarantine);
    }

    #[test]
    fn secret_access_critical_stays_critical_path() {
        let r = report(vec![detail(
            MismatchField::SecretAccess,
            MismatchSeverity::Critical,
        )]);
        // First time → Quarantine (already escalated, no change).
        assert_eq!(decide(&r).unwrap(), Disposition::Quarantine);
    }

    // --- Highest-severity-wins ---

    #[test]
    fn mixed_severity_picks_highest() {
        let r = report(vec![
            detail(MismatchField::ReadPaths, MismatchSeverity::Minor),
            detail(MismatchField::NetworkDomains, MismatchSeverity::Major),
            detail(MismatchField::EnvVars, MismatchSeverity::Informational),
        ]);
        assert_eq!(decide(&r).unwrap(), Disposition::Quarantine); // Major drives it
    }

    // --- Errors ---

    #[test]
    fn empty_tool_rejected() {
        let mut r = report(vec![detail(
            MismatchField::ReadPaths,
            MismatchSeverity::Minor,
        )]);
        r.tool = String::new();
        assert!(matches!(decide(&r).unwrap_err(), EngineError::EmptyTool));
    }

    #[test]
    fn empty_mismatches_rejected() {
        let r = report(vec![]);
        assert!(matches!(
            decide(&r).unwrap_err(),
            EngineError::EmptyMismatches
        ));
    }

    // --- Serde ---

    #[test]
    fn disposition_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&Disposition::Quarantine).unwrap(),
            "\"quarantine\""
        );
        assert_eq!(
            serde_json::to_string(&Disposition::Forfeit).unwrap(),
            "\"forfeit\""
        );
        assert_eq!(
            serde_json::to_string(&Disposition::Observe).unwrap(),
            "\"observe\""
        );
    }
}
