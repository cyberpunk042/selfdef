//! `selfdefctl m060-doctor` — operator surface for verifying the M060
//! cross-repo mirror chain from the **selfdef-host** side.
//!
//! Sister command to sovereign-os's `sovereign-osctl m060-doctor` (which
//! verifies the chain from the consumer side via HTTP). This one
//! verifies the **producer** side via filesystem state — no daemon
//! process required, so it works whether or not `selfdefd` is running.
//!
//! Checks (per domain × 6):
//!   1. Resident store at the canonical `/var/lib/selfdef/<domain>.json`
//!      (or the `SELFDEF_<DOMAIN>_PATH` env override).
//!   2. Published mirror file at `<selfdef_mirror_dir>/<domain>.json`
//!      (only when `[deployment].selfdef_mirror_dir` is set).
//!
//! Reports per-domain state + the M060 chain prerequisites
//! (selfdef.toml [deployment].selfdef_mirror_dir, /var/lib/selfdef,
//! /run/sovereign-os/selfdef-mirror).
//!
//! Read-only — never mutates anything.

use std::env;
use std::path::{Path, PathBuf};

use anyhow::Result;

/// One M060 domain — its resident store + its published mirror filename.
struct Domain {
    id: &'static str,
    label: &'static str,
    resident_env: &'static str,
    resident_default: &'static str,
    published_file: &'static str,
}

const DOMAINS: &[Domain] = &[
    Domain {
        id: "D-02",
        label: "active-profile",
        resident_env: "SELFDEF_FLEX_PROFILE_PATH",
        resident_default: "/var/lib/selfdef/flex-profile.json",
        published_file: "active-profile.json",
    },
    Domain {
        id: "D-13",
        label: "grants",
        resident_env: "SELFDEF_GRANTS_PATH",
        resident_default: "/var/lib/selfdef/grants.json",
        published_file: "grants.json",
    },
    Domain {
        id: "D-14",
        label: "capability-tokens",
        resident_env: "SELFDEF_CAPABILITY_TOKENS_PATH",
        resident_default: "/var/lib/selfdef/capability-tokens.json",
        published_file: "capability-tokens.json",
    },
    Domain {
        id: "D-15",
        label: "sandboxes",
        resident_env: "SELFDEF_SANDBOXES_PATH",
        resident_default: "/var/lib/selfdef/sandboxes.json",
        published_file: "sandboxes.json",
    },
    Domain {
        id: "D-17",
        label: "quarantine",
        resident_env: "SELFDEF_QUARANTINE_PATH",
        resident_default: "/var/lib/selfdef/quarantine.json",
        published_file: "quarantine.json",
    },
    Domain {
        id: "D-18",
        label: "trust-scores",
        resident_env: "SELFDEF_TRUST_SCORES_PATH",
        resident_default: "/var/lib/selfdef/trust-scores.json",
        published_file: "trust-scores.json",
    },
];

/// Read `[deployment].selfdef_mirror_dir` from the canonical config path
/// without parsing the full TOML — just enough to surface the knob's
/// state. Returns `Ok(Some(path))` when set + non-empty, `Ok(None)`
/// when unset / empty / config absent.
fn read_mirror_dir_from_config(config_path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let mut in_deployment = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_deployment = line == "[deployment]";
            continue;
        }
        if !in_deployment {
            continue;
        }
        if let Some(rest) = line.strip_prefix("selfdef_mirror_dir") {
            let val = rest.trim_start_matches([' ', '\t', '=']);
            let val = val.trim().trim_matches('"').trim_matches('\'');
            if val.is_empty() {
                return None;
            }
            return Some(PathBuf::from(val));
        }
    }
    None
}

fn domain_resident_path(d: &Domain) -> PathBuf {
    env::var(d.resident_env)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(d.resident_default))
}

/// Run the M060 doctor against the operator's host. Returns 0 if every
/// per-domain state is internally consistent (resident-present implies
/// published-present when mirror_dir is set); 1 if any inconsistency
/// found (and reports it).
pub(crate) fn run(json: bool, config_path: Option<&Path>) -> Result<i32> {
    let cfg = config_path
        .map(PathBuf::from)
        .or_else(|| env::var("SELFDEF_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/selfdef/selfdef.toml"));

    let mirror_dir = read_mirror_dir_from_config(&cfg);

    let mut rows: Vec<(String, String, bool, bool, String)> = Vec::new();
    let mut inconsistencies: usize = 0;

    for d in DOMAINS {
        let resident_path = domain_resident_path(d);
        let resident_exists = resident_path.is_file();
        let (published_exists, published_path_display) = match &mirror_dir {
            Some(dir) => {
                let p = dir.join(d.published_file);
                (p.is_file(), p.display().to_string())
            }
            None => (false, String::from("(mirror_dir unset)")),
        };
        let note = match (resident_exists, mirror_dir.is_some(), published_exists) {
            (false, _, _) => "no resident store — domain offline (operator hasn't issued/seeded)".to_string(),
            (true, false, _) => {
                "resident store present but [deployment].selfdef_mirror_dir unset — daemon export disabled".to_string()
            }
            (true, true, true) => "resident → published OK".to_string(),
            (true, true, false) => {
                inconsistencies += 1;
                "resident PRESENT but NOT YET PUBLISHED — selfdefd not running, or export loop hasn't ticked yet".to_string()
            }
        };
        rows.push((
            d.id.to_string(),
            d.label.to_string(),
            resident_exists,
            published_exists,
            format!(
                "resident={} published={} · {}",
                resident_path.display(),
                published_path_display,
                note
            ),
        ));
    }

    if json {
        let mut entries = Vec::with_capacity(rows.len());
        for (id, label, res, pub_, note) in &rows {
            entries.push(format!(
                "{{\"id\":\"{}\",\"label\":\"{}\",\"resident_present\":{},\"published_present\":{},\"note\":\"{}\"}}",
                id,
                label,
                res,
                pub_,
                note.replace('"', "\\\"")
            ));
        }
        println!(
            "{{\"config_path\":\"{}\",\"mirror_dir\":{},\"inconsistencies\":{},\"domains\":[{}]}}",
            cfg.display(),
            mirror_dir
                .as_ref()
                .map(|p| format!("\"{}\"", p.display()))
                .unwrap_or_else(|| "null".to_string()),
            inconsistencies,
            entries.join(",")
        );
    } else {
        println!("selfdef M060 cross-repo mirror chain (host-side)");
        println!("  config:     {}", cfg.display());
        println!(
            "  mirror_dir: {}",
            mirror_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(unset — daemon export disabled)".to_string())
        );
        println!();
        println!("  {:<6} {:<20} state", "domain", "label");
        println!(
            "  {:<6} {:<20} {}",
            "------",
            "--------------------",
            "-".repeat(60)
        );
        for (id, label, _res, _pub, note) in &rows {
            println!("  {id:<6} {label:<20} {note}");
        }
        println!();
        let present_count = rows.iter().filter(|r| r.2).count();
        let published_count = rows.iter().filter(|r| r.3).count();
        println!(
            "  summary: {present_count}/6 resident stores present · {published_count}/6 published · {inconsistencies} inconsistencies"
        );
    }

    if inconsistencies > 0 { Ok(1) } else { Ok(0) }
}
