//! `GET /v1/cpu` — MS011 Z-4 CPU mode state surface.
//!
//! Reports the host's current CPU mode (scaling governor + SMT
//! state) classified into one of the named modes SDD-026 Z-4 defines:
//!
//! - `ultra-low-power`  — governor=powersave, SMT off
//! - `balanced`         — governor=schedutil OR ondemand, SMT on
//! - `sustained-burst`  — governor=performance, SMT on
//! - `peak-inference`   — governor=performance, SMT off (consistent
//!   pinning, max single-thread cache footprint)
//! - `custom`           — anything else (operator has hand-tuned
//!   outside the named-mode set)
//!
//! Read-only for this round. The POST surface that *sets* a mode
//! (per Z-4 "dashboard radio-button switches between them") will
//! land in a follow-up: it requires privileged writes to
//! `/sys/devices/system/cpu/*/cpufreq/scaling_governor` and the SMT
//! control file, which the daemon's existing IPC boundaries don't
//! currently expose.
//!
//! Source: MS011 catalog row M00275 area + SDD-026 Z-4.

use std::path::Path;

use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CpuModeResponse {
    /// `"ultra-low-power" | "balanced" | "sustained-burst" |
    /// "peak-inference" | "custom"`.
    pub mode: &'static str,
    /// Concatenation of all per-cpu scaling_governor values — useful
    /// for operators debugging "why isn't my mode what I expect".
    pub governors: Vec<String>,
    /// True iff SMT (hyperthreading) is enabled.
    pub smt_enabled: bool,
    /// True iff we successfully read every per-cpu governor file.
    /// False on systems without cpufreq support (containers, some
    /// virtualization) — then `governors` is empty and `mode` is
    /// `"custom"` (vacuous; operator should treat as unknown).
    pub cpufreq_present: bool,
    /// Whether the SMT-state file was readable. False on systems
    /// without SMT control (some virtualization).
    pub smt_present: bool,
}

const CPUFREQ_ROOT: &str = "/sys/devices/system/cpu";
const SMT_CONTROL: &str = "/sys/devices/system/cpu/smt/control";
const SMT_ACTIVE: &str = "/sys/devices/system/cpu/smt/active";

/// Read every `cpuN/cpufreq/scaling_governor` under
/// `/sys/devices/system/cpu/`. Returns the sorted-by-index list of
/// governor strings (one per CPU). Missing files / unreadable
/// system → empty vec.
fn read_governors(root: &Path) -> Vec<String> {
    let mut indexed: Vec<(u32, String)> = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Match `cpuN` where N is digits.
        let Some(rest) = name.strip_prefix("cpu") else {
            continue;
        };
        let Ok(idx) = rest.parse::<u32>() else {
            continue;
        };
        let gov_path = entry.path().join("cpufreq").join("scaling_governor");
        if let Ok(text) = std::fs::read_to_string(&gov_path) {
            indexed.push((idx, text.trim().to_string()));
        }
    }
    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, g)| g).collect()
}

fn read_smt() -> (bool, bool) {
    // First try smt/active (1 = on, 0 = off; integer-only).
    if let Ok(text) = std::fs::read_to_string(SMT_ACTIVE) {
        let active = text.trim() == "1";
        return (active, true);
    }
    // Fall back to smt/control which is a string (`on`, `off`,
    // `forceoff`, `notsupported`).
    if let Ok(text) = std::fs::read_to_string(SMT_CONTROL) {
        let val = text.trim();
        let on = matches!(val, "on");
        let present = !matches!(val, "notsupported");
        return (on, present);
    }
    (false, false)
}

/// Classify the host's CPU state into one of the SDD-026 Z-4 modes.
/// All governors must agree on a single name for the named modes to
/// apply; mismatched per-CPU governors → `custom` (operator has
/// hand-tuned a subset).
fn classify(governors: &[String], smt_enabled: bool, cpufreq_present: bool) -> &'static str {
    if !cpufreq_present || governors.is_empty() {
        return "custom";
    }
    let first = &governors[0];
    if !governors.iter().all(|g| g == first) {
        return "custom";
    }
    match (first.as_str(), smt_enabled) {
        ("powersave", false) => "ultra-low-power",
        ("schedutil", true) | ("ondemand", true) => "balanced",
        ("performance", true) => "sustained-burst",
        ("performance", false) => "peak-inference",
        _ => "custom",
    }
}

pub(crate) fn probe() -> CpuModeResponse {
    let governors = read_governors(Path::new(CPUFREQ_ROOT));
    let cpufreq_present = !governors.is_empty();
    let (smt_enabled, smt_present) = read_smt();
    let mode = classify(&governors, smt_enabled, cpufreq_present);
    CpuModeResponse {
        mode,
        governors,
        smt_enabled,
        cpufreq_present,
        smt_present,
    }
}

/// `GET /v1/cpu` handler.
pub(crate) async fn show() -> Json<CpuModeResponse> {
    Json(probe())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_powersave_no_smt_is_ultra_low_power() {
        let govs = vec!["powersave".to_string(); 8];
        assert_eq!(classify(&govs, false, true), "ultra-low-power");
    }

    #[test]
    fn classify_schedutil_smt_on_is_balanced() {
        let govs = vec!["schedutil".to_string(); 16];
        assert_eq!(classify(&govs, true, true), "balanced");
    }

    #[test]
    fn classify_ondemand_smt_on_is_balanced() {
        let govs = vec!["ondemand".to_string(); 16];
        assert_eq!(classify(&govs, true, true), "balanced");
    }

    #[test]
    fn classify_performance_smt_on_is_sustained_burst() {
        let govs = vec!["performance".to_string(); 16];
        assert_eq!(classify(&govs, true, true), "sustained-burst");
    }

    #[test]
    fn classify_performance_smt_off_is_peak_inference() {
        let govs = vec!["performance".to_string(); 8];
        assert_eq!(classify(&govs, false, true), "peak-inference");
    }

    #[test]
    fn classify_mixed_governors_is_custom() {
        let govs = vec![
            "performance".to_string(),
            "powersave".to_string(),
            "schedutil".to_string(),
        ];
        assert_eq!(classify(&govs, true, true), "custom");
    }

    #[test]
    fn classify_no_cpufreq_is_custom() {
        let govs: Vec<String> = Vec::new();
        assert_eq!(classify(&govs, true, false), "custom");
    }

    #[test]
    fn classify_unknown_governor_is_custom() {
        let govs = vec!["userspace".to_string(); 4];
        assert_eq!(classify(&govs, true, true), "custom");
    }

    #[test]
    fn read_governors_returns_sorted_list_from_tempdir() {
        let tmp = std::env::temp_dir().join(format!(
            "selfdef-cpu-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        // Intentionally out-of-order on disk: cpu2, cpu0, cpu1.
        for (i, gov) in [(2u32, "performance"), (0, "schedutil"), (1, "schedutil")] {
            let p = tmp.join(format!("cpu{i}")).join("cpufreq");
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("scaling_governor"), gov).unwrap();
        }
        // Non-cpu entry that the parser should skip.
        std::fs::create_dir_all(tmp.join("cpufreq")).unwrap();
        let govs = read_governors(&tmp);
        assert_eq!(govs, vec!["schedutil", "schedutil", "performance"]);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
