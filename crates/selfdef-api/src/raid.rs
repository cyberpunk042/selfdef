//! `GET /v1/raid` — MS011 Z-9 software RAID state surface.
//!
//! Per-array state for every Linux MD (multiple-disk) software RAID
//! array on the host. SDD-026 Z-9 explicitly rules out direct
//! manipulation of the array — selfdef NEVER touches mdadm to assemble,
//! create, or modify; this surface is read-only state visibility for
//! the operator dashboard + alert pipeline.
//!
//! Probe path:
//! 1. Parse `/proc/mdstat` for per-array name + level + members +
//!    "UU__" health string.
//! 2. For each array, classify state:
//!    - `green` — all members healthy (all U bits)
//!    - `yellow` — at least one member missing/spare/rebuilding
//!    - `red` — array is failed or has fewer working members than
//!      its level requires (e.g. raid5 with ≥2 missing)
//!
//! Missing /proc/mdstat (no MD support / not Linux) → empty arrays
//! list with state `unknown` so the dashboard can render a clear
//! "no software RAID on this host" rather than an error.
//!
//! Source: MS011 catalog row M00276/M00277 area + SDD-026 § Z-9.

use std::path::Path;

use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RaidArray {
    /// `"md0"`, `"md1"`, …
    pub name: String,
    /// `"raid0"`, `"raid1"`, `"raid5"`, `"raid6"`, `"raid10"`,
    /// `"linear"`, or `"unknown"`.
    pub level: String,
    /// Block device members (`"sda1"`, `"nvme0n1p1"`, …) with the
    /// in-array index (the `[N]` suffix mdstat shows).
    pub members: Vec<String>,
    /// The `UU__`-style health string from mdstat. `U` = present;
    /// `_` = missing.
    pub health: String,
    /// `"green"` / `"yellow"` / `"red"`.
    pub state: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RaidResponse {
    /// Worst-state across arrays (`red > yellow > green`). When no
    /// arrays are present, this is `"green"` (vacuously healthy) and
    /// `mdstat_present` is false so the dashboard can distinguish
    /// "no RAID configured" from "RAID is fine".
    pub worst: &'static str,
    /// True iff `/proc/mdstat` exists. False on hosts without MD
    /// kernel support.
    pub mdstat_present: bool,
    pub arrays: Vec<RaidArray>,
}

fn classify_health(health: &str, level: &str) -> &'static str {
    if health.is_empty() {
        return "yellow";
    }
    let missing = health.chars().filter(|c| *c == '_').count();
    if missing == 0 {
        return "green";
    }
    // Tolerance bound per level. Conservative: any missing on
    // raid0/linear → red (no redundancy at all). raid1/raid5/raid10
    // tolerate 1 missing → yellow; 2+ → red. raid6 tolerates 2 → red
    // only at 3+. Unknown level treats any missing as yellow (we
    // don't know the tolerance bound, so signal the operator but
    // don't escalate to red).
    match level {
        "raid0" | "linear" => "red",
        "raid1" | "raid5" | "raid10" => {
            if missing >= 2 {
                "red"
            } else {
                "yellow"
            }
        }
        "raid6" => {
            if missing >= 3 {
                "red"
            } else {
                "yellow"
            }
        }
        _ => "yellow",
    }
}

fn worst_arrays(arrays: &[RaidArray]) -> &'static str {
    let mut worst = "green";
    for a in arrays {
        match (worst, a.state) {
            (_, "red") => return "red",
            ("green", "yellow") => worst = "yellow",
            _ => {}
        }
    }
    worst
}

/// Parse the body of `/proc/mdstat`. The format is:
///
/// ```text
/// Personalities : [raid1] [raid6]
/// md0 : active raid1 sda1[0] sdb1[1]
///       104320 blocks [2/2] [UU]
///
/// md1 : active raid6 sdc1[0] sdd1[1] sde1[2] sdf1[3]
///       3907018752 blocks level 6, 512k chunk, algorithm 2 [4/4] [UUUU]
///
/// unused devices: <none>
/// ```
///
/// We pair each "mdN : active LEVEL members…" line with its
/// following "blocks …" line that carries the `[UU…]` health
/// indicator.
pub(crate) fn parse_mdstat(body: &str) -> Vec<RaidArray> {
    let mut out = Vec::new();
    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        // "mdN : active LEVEL member member …"  (also matches "inactive")
        if let Some(colon) = line.find(" : ") {
            let name = &line[..colon];
            if name.starts_with("md") && name.len() >= 3 {
                let after = &line[colon + 3..];
                let mut tokens = after.split_whitespace();
                let _status = tokens.next(); // "active" / "inactive" / "auto-read-only"
                let level = tokens.next().unwrap_or("unknown").to_string();
                let members: Vec<String> = tokens.map(|t| t.to_string()).collect();
                // Look for the next non-empty indented line — the
                // "blocks …" continuation that contains the [UU…]
                // health bracket.
                let mut health = String::new();
                let mut j = i + 1;
                while j < lines.len() {
                    let lj = lines[j];
                    if lj.trim().is_empty() {
                        break;
                    }
                    if !lj.starts_with(char::is_whitespace) {
                        break;
                    }
                    if let Some(lb) = lj.rfind('[') {
                        let rest = &lj[lb + 1..];
                        if let Some(rb) = rest.find(']') {
                            let candidate = &rest[..rb];
                            if !candidate.is_empty()
                                && candidate.chars().all(|c| c == 'U' || c == '_')
                            {
                                health = candidate.to_string();
                                break;
                            }
                        }
                    }
                    j += 1;
                }
                let state = classify_health(&health, &level);
                out.push(RaidArray {
                    name: name.to_string(),
                    level,
                    members,
                    health,
                    state,
                });
            }
        }
        i += 1;
    }
    out
}

pub(crate) fn probe() -> RaidResponse {
    let path = Path::new("/proc/mdstat");
    if !path.exists() {
        return RaidResponse {
            worst: "green",
            mdstat_present: false,
            arrays: Vec::new(),
        };
    }
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => {
            return RaidResponse {
                worst: "green",
                mdstat_present: false,
                arrays: Vec::new(),
            };
        }
    };
    let arrays = parse_mdstat(&body);
    let worst = worst_arrays(&arrays);
    RaidResponse {
        worst,
        mdstat_present: true,
        arrays,
    }
}

/// `GET /v1/raid` handler.
pub(crate) async fn show() -> Json<RaidResponse> {
    Json(probe())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_health_all_present_is_green() {
        assert_eq!(classify_health("UU", "raid1"), "green");
        assert_eq!(classify_health("UUUUUU", "raid6"), "green");
    }

    #[test]
    fn classify_health_raid1_one_missing_is_yellow() {
        assert_eq!(classify_health("U_", "raid1"), "yellow");
    }

    #[test]
    fn classify_health_raid1_both_missing_is_red() {
        assert_eq!(classify_health("__", "raid1"), "red");
    }

    #[test]
    fn classify_health_raid0_any_missing_is_red() {
        assert_eq!(classify_health("U_", "raid0"), "red");
    }

    #[test]
    fn classify_health_raid6_two_missing_is_yellow() {
        assert_eq!(classify_health("UU__", "raid6"), "yellow");
    }

    #[test]
    fn classify_health_raid6_three_missing_is_red() {
        assert_eq!(classify_health("U___", "raid6"), "red");
    }

    #[test]
    fn classify_health_unknown_level_one_missing_is_yellow() {
        assert_eq!(classify_health("U_", "raid42"), "yellow");
    }

    #[test]
    fn parse_mdstat_extracts_arrays() {
        let body = "\
Personalities : [raid1] [raid6]
md0 : active raid1 sda1[0] sdb1[1]
      104320 blocks [2/2] [UU]

md1 : active raid6 sdc1[0] sdd1[1] sde1[2] sdf1[3]
      3907018752 blocks level 6, 512k chunk, algorithm 2 [4/4] [UUUU]

unused devices: <none>
";
        let arrays = parse_mdstat(body);
        assert_eq!(arrays.len(), 2);

        let md0 = &arrays[0];
        assert_eq!(md0.name, "md0");
        assert_eq!(md0.level, "raid1");
        assert_eq!(md0.members, vec!["sda1[0]", "sdb1[1]"]);
        assert_eq!(md0.health, "UU");
        assert_eq!(md0.state, "green");

        let md1 = &arrays[1];
        assert_eq!(md1.name, "md1");
        assert_eq!(md1.level, "raid6");
        assert_eq!(md1.health, "UUUU");
        assert_eq!(md1.state, "green");
        assert_eq!(md1.members.len(), 4);
    }

    #[test]
    fn parse_mdstat_degraded_raid1_is_yellow() {
        let body = "\
Personalities : [raid1]
md0 : active raid1 sda1[0]
      104320 blocks [2/1] [U_]

unused devices: <none>
";
        let arrays = parse_mdstat(body);
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].state, "yellow");
        assert_eq!(arrays[0].health, "U_");
    }

    #[test]
    fn worst_arrays_red_dominates() {
        let arrays = vec![
            RaidArray {
                name: "md0".into(),
                level: "raid1".into(),
                members: vec![],
                health: "UU".into(),
                state: "green",
            },
            RaidArray {
                name: "md1".into(),
                level: "raid0".into(),
                members: vec![],
                health: "U_".into(),
                state: "red",
            },
        ];
        assert_eq!(worst_arrays(&arrays), "red");
    }

    #[test]
    fn parse_mdstat_empty_body_returns_empty_arrays() {
        let arrays = parse_mdstat("");
        assert!(arrays.is_empty());
    }
}
