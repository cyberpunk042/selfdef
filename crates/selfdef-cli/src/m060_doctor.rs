//! `selfdefctl m060-doctor` — operator surface for verifying the M060
//! cross-repo mirror chain from the **selfdef-host** side.
//!
//! Sister command to sovereign-os's `sovereign-osctl m060-doctor` (which
//! verifies the chain from the consumer side via HTTP). This one
//! verifies the **producer** side via filesystem state — no daemon
//! process required, so it works whether or not `selfdefd` is running.
//!
//! Checks (per domain × 8):
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
        id: "D-12",
        label: "rules",
        resident_env: "SELFDEF_RULES_PATH",
        resident_default: "/var/lib/selfdef/rules.json",
        published_file: "rules.json",
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
        id: "D-16",
        label: "audit-chain",
        resident_env: "SELFDEF_AUDIT_PATH",
        resident_default: "/var/lib/selfdef/audit.json",
        published_file: "audit.json",
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

/// Escape a Prometheus label value per the textfile exposition format:
/// backslash, double-quote, and newline must be backslash-escaped.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            ch => out.push(ch),
        }
    }
    out
}

/// Per-domain state used by both the operator-readable table and the
/// textfile emitter. Severity classification:
///   0 (pass)  — resident present + (mirror_dir unset OR published present)
///   1 (warn)  — resident absent (operator hasn't onboarded; honest offline)
///   2 (fail)  — resident present + mirror_dir set + published ABSENT
///               (inconsistency — daemon export wedged)
#[derive(Debug, Clone)]
pub(crate) struct DomainState {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) resident_present: bool,
    pub(crate) published_present: bool,
    pub(crate) severity: u8,
    pub(crate) note: String,
}

/// Render the per-domain DomainState set as a node_exporter-compatible
/// textfile. Same metric naming convention as selfdef_cli_mirror_doctor_*
/// (different prefix + labels for cross-cutting chain). Emitted series:
///
///   selfdef_m060_doctor_severity{domain, label}            0/1/2
///   selfdef_m060_doctor_resident_present{domain, label}    0/1
///   selfdef_m060_doctor_published_present{domain, label}   0/1
///   selfdef_m060_doctor_domain_info{domain, label, note}   1
///   selfdef_m060_doctor_worst_severity                     0/1/2
///   selfdef_m060_doctor_last_run_unix                      epoch seconds
///
/// The worst-severity rollup pairs with the same Prometheus alert
/// pattern the cli-mirror doctor already wires.
pub(crate) fn render_textfile(states: &[DomainState]) -> String {
    let worst = states.iter().map(|s| s.severity).max().unwrap_or(0);
    let mut body = String::new();
    body.push_str(
        "# HELP selfdef_m060_doctor_severity Per-domain severity \
         (0=pass 1=warn 2=fail). One series per M060 mirror domain.\n",
    );
    body.push_str("# TYPE selfdef_m060_doctor_severity gauge\n");
    for s in states {
        body.push_str(&format!(
            "selfdef_m060_doctor_severity{{domain=\"{}\",label=\"{}\"}} {}\n",
            escape_label(&s.id),
            escape_label(&s.label),
            s.severity,
        ));
    }
    body.push_str(
        "# HELP selfdef_m060_doctor_resident_present 1 when the \
         daemon-resident registry store exists for the domain.\n",
    );
    body.push_str("# TYPE selfdef_m060_doctor_resident_present gauge\n");
    for s in states {
        body.push_str(&format!(
            "selfdef_m060_doctor_resident_present{{domain=\"{}\",label=\"{}\"}} {}\n",
            escape_label(&s.id),
            escape_label(&s.label),
            u8::from(s.resident_present),
        ));
    }
    body.push_str(
        "# HELP selfdef_m060_doctor_published_present 1 when the \
         daemon's mirror_export_loop has actually published the artifact \
         to <selfdef_mirror_dir>/<domain>.json.\n",
    );
    body.push_str("# TYPE selfdef_m060_doctor_published_present gauge\n");
    for s in states {
        body.push_str(&format!(
            "selfdef_m060_doctor_published_present{{domain=\"{}\",label=\"{}\"}} {}\n",
            escape_label(&s.id),
            escape_label(&s.label),
            u8::from(s.published_present),
        ));
    }
    body.push_str(
        "# HELP selfdef_m060_doctor_domain_info Per-domain operator-readable \
         note (always value=1). Carries the same triage text the JSON \
         output's `note` field carries.\n",
    );
    body.push_str("# TYPE selfdef_m060_doctor_domain_info gauge\n");
    for s in states {
        body.push_str(&format!(
            "selfdef_m060_doctor_domain_info{{domain=\"{}\",label=\"{}\",note=\"{}\"}} 1\n",
            escape_label(&s.id),
            escape_label(&s.label),
            escape_label(&s.note),
        ));
    }
    body.push_str(
        "# HELP selfdef_m060_doctor_worst_severity Worst severity across \
         all M060 mirror domains. Alert rules fire on > 0 (warn) and \
         > 1 (fail).\n",
    );
    body.push_str("# TYPE selfdef_m060_doctor_worst_severity gauge\n");
    body.push_str(&format!("selfdef_m060_doctor_worst_severity {worst}\n"));
    body.push_str(
        "# HELP selfdef_m060_doctor_last_run_unix Unix timestamp of the \
         last doctor invocation. Lets the alert pipeline detect a \
         wedged systemd timer (no recent writes).\n",
    );
    body.push_str("# TYPE selfdef_m060_doctor_last_run_unix gauge\n");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    body.push_str(&format!("selfdef_m060_doctor_last_run_unix {now}\n"));
    body
}

/// Atomically write the rendered exposition to `path`. Tempfile in the
/// same dir + rename — same shape as every other M060 producer.
///
/// # Errors
/// Returns I/O errors on dir-create / tempfile-write / rename.
fn write_textfile(path: &Path, states: &[DomainState]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "m060-doctor.prom".to_string()),
        std::process::id()
    ));
    let body = render_textfile(states);
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Compute the per-domain DomainState set for the host. Shared between
/// the printable table, the JSON emitter, and the textfile emitter so
/// all three surfaces classify identically.
pub(crate) fn compute_states(cfg: &Path) -> (Option<PathBuf>, Vec<DomainState>) {
    let mirror_dir = read_mirror_dir_from_config(cfg);
    let mut states = Vec::with_capacity(DOMAINS.len());
    for d in DOMAINS {
        let resident_path = domain_resident_path(d);
        let resident_present = resident_path.is_file();
        let (published_present, published_display) = match &mirror_dir {
            Some(dir) => {
                let p = dir.join(d.published_file);
                (p.is_file(), p.display().to_string())
            }
            None => (false, String::from("(mirror_dir unset)")),
        };
        let (severity, note_inner) =
            match (resident_present, mirror_dir.is_some(), published_present) {
                (false, _, _) => (
                    1u8,
                    "no resident store — domain offline (operator hasn't issued/seeded)"
                        .to_string(),
                ),
                (true, false, _) => (
                    1u8,
                    "resident store present but [deployment].selfdef_mirror_dir unset — daemon export disabled"
                        .to_string(),
                ),
                (true, true, true) => (0u8, "resident → published OK".to_string()),
                (true, true, false) => (
                    2u8,
                    "resident PRESENT but NOT YET PUBLISHED — selfdefd not running, or export loop hasn't ticked yet"
                        .to_string(),
                ),
            };
        let note = format!(
            "resident={} published={} · {}",
            resident_path.display(),
            published_display,
            note_inner
        );
        states.push(DomainState {
            id: d.id.to_string(),
            label: d.label.to_string(),
            resident_present,
            published_present,
            severity,
            note,
        });
    }
    (mirror_dir, states)
}

/// Run the M060 doctor against the operator's host. Returns 0 if every
/// per-domain state is internally consistent (resident-present implies
/// published-present when mirror_dir is set); 1 if any inconsistency
/// found (and reports it). When `textfile` is set, also writes a
/// node_exporter-compatible exposition.
pub(crate) fn run(json: bool, config_path: Option<&Path>, textfile: Option<&Path>) -> Result<i32> {
    let cfg = config_path
        .map(PathBuf::from)
        .or_else(|| env::var("SELFDEF_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/selfdef/selfdef.toml"));

    let (mirror_dir, states) = compute_states(&cfg);

    if let Some(p) = textfile {
        write_textfile(p, &states)?;
    }

    let mut rows: Vec<(String, String, bool, bool, String)> = Vec::with_capacity(states.len());
    let mut inconsistencies: usize = 0;
    for s in &states {
        if s.severity == 2 {
            inconsistencies += 1;
        }
        rows.push((
            s.id.clone(),
            s.label.clone(),
            s.resident_present,
            s.published_present,
            s.note.clone(),
        ));
    }
    // The existing body below builds `rows` then prints. Keep the
    // same render path for backwards-compatibility with parsers that
    // grew up on it.
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
        let total = DOMAINS.len();
        println!(
            "  summary: {present_count}/{total} resident stores present · {published_count}/{total} published · {inconsistencies} inconsistencies"
        );
    }

    if inconsistencies > 0 { Ok(1) } else { Ok(0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state(id: &str, label: &str, severity: u8, note: &str) -> DomainState {
        DomainState {
            id: id.into(),
            label: label.into(),
            resident_present: severity == 0 || severity == 2,
            published_present: severity == 0,
            severity,
            note: note.into(),
        }
    }

    #[test]
    fn escape_label_handles_quote_backslash_newline() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("with \"quote\""), "with \\\"quote\\\"");
        assert_eq!(escape_label("with\\backslash"), "with\\\\backslash");
        assert_eq!(escape_label("with\nnewline"), "with\\nnewline");
    }

    #[test]
    fn render_textfile_emits_one_severity_per_domain() {
        let states = vec![
            sample_state("D-02", "active-profile", 0, "ok"),
            sample_state("D-13", "grants", 1, "absent"),
            sample_state("D-17", "quarantine", 2, "wedged"),
        ];
        let body = render_textfile(&states);
        assert!(
            body.contains(
                "selfdef_m060_doctor_severity{domain=\"D-02\",label=\"active-profile\"} 0"
            )
        );
        assert!(body.contains("selfdef_m060_doctor_severity{domain=\"D-13\",label=\"grants\"} 1"));
        assert!(
            body.contains("selfdef_m060_doctor_severity{domain=\"D-17\",label=\"quarantine\"} 2")
        );
    }

    #[test]
    fn render_textfile_worst_severity_picks_max_across_domains() {
        let mixed = vec![
            sample_state("D-02", "active-profile", 0, "ok"),
            sample_state("D-13", "grants", 1, "absent"),
            sample_state("D-17", "quarantine", 2, "wedged"),
        ];
        let body = render_textfile(&mixed);
        assert!(body.contains("selfdef_m060_doctor_worst_severity 2"));

        let all_ok = vec![sample_state("D-02", "active-profile", 0, "ok")];
        assert!(render_textfile(&all_ok).contains("selfdef_m060_doctor_worst_severity 0"));

        let all_warn = vec![sample_state("D-13", "grants", 1, "absent")];
        assert!(render_textfile(&all_warn).contains("selfdef_m060_doctor_worst_severity 1"));

        let empty: Vec<DomainState> = vec![];
        assert!(render_textfile(&empty).contains("selfdef_m060_doctor_worst_severity 0"));
    }

    #[test]
    fn render_textfile_emits_help_and_type_lines_for_every_metric() {
        let body = render_textfile(&[sample_state("D-02", "active-profile", 0, "ok")]);
        for metric in [
            "selfdef_m060_doctor_severity",
            "selfdef_m060_doctor_resident_present",
            "selfdef_m060_doctor_published_present",
            "selfdef_m060_doctor_domain_info",
            "selfdef_m060_doctor_worst_severity",
            "selfdef_m060_doctor_last_run_unix",
        ] {
            assert!(
                body.contains(&format!("# HELP {metric}")),
                "missing HELP for {metric}; body:\n{body}"
            );
            assert!(
                body.contains(&format!("# TYPE {metric} gauge")),
                "missing TYPE for {metric}; body:\n{body}"
            );
        }
    }

    #[test]
    fn render_textfile_domain_info_carries_note() {
        let body = render_textfile(&[sample_state(
            "D-17",
            "quarantine",
            2,
            "resident PRESENT but NOT YET PUBLISHED",
        )]);
        assert!(body.contains(
            "selfdef_m060_doctor_domain_info{domain=\"D-17\",label=\"quarantine\",\
             note=\"resident PRESENT but NOT YET PUBLISHED\"} 1"
        ));
    }

    #[test]
    fn render_textfile_resident_and_published_gauges_track_state() {
        let body = render_textfile(&[
            sample_state("D-02", "active-profile", 0, "ok"),
            sample_state("D-13", "grants", 1, "absent"),
            sample_state("D-17", "quarantine", 2, "wedged"),
        ]);
        // severity=0 → both present
        assert!(body.contains(
            "selfdef_m060_doctor_resident_present{domain=\"D-02\",label=\"active-profile\"} 1"
        ));
        assert!(body.contains(
            "selfdef_m060_doctor_published_present{domain=\"D-02\",label=\"active-profile\"} 1"
        ));
        // severity=1 → neither present (operator hasn't onboarded)
        assert!(
            body.contains(
                "selfdef_m060_doctor_resident_present{domain=\"D-13\",label=\"grants\"} 0"
            )
        );
        // severity=2 → resident present, published missing (the wedge case)
        assert!(body.contains(
            "selfdef_m060_doctor_resident_present{domain=\"D-17\",label=\"quarantine\"} 1"
        ));
        assert!(body.contains(
            "selfdef_m060_doctor_published_present{domain=\"D-17\",label=\"quarantine\"} 0"
        ));
    }

    #[test]
    fn write_textfile_is_atomic_no_leftover_tmp() {
        let dir = std::env::temp_dir().join(format!("m060-doctor-textfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("selfdef-m060.prom");
        write_textfile(&path, &[sample_state("D-02", "active-profile", 0, "ok")]).unwrap();
        assert!(path.exists());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "tempfile must be renamed away; leftovers: {leftovers:?}"
        );
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("selfdef_m060_doctor_severity"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compute_states_emits_one_per_domain_with_severity_1_when_offline() {
        let dir = std::env::temp_dir().join(format!("m060-doctor-compute-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("selfdef.toml");
        std::fs::write(&cfg, b"").unwrap();
        let (mirror_dir, states) = compute_states(&cfg);
        assert!(mirror_dir.is_none());
        assert_eq!(states.len(), DOMAINS.len());
        // All offline → all severity=1 (operator hasn't onboarded)
        for s in &states {
            assert_eq!(s.severity, 1, "{} severity should be 1; got {:?}", s.id, s);
            assert!(!s.resident_present);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pin the full 8-domain M060 cross-repo mirror chain. Future
    /// silent removal of a domain (e.g., the bug that left D-12
    /// rules + D-16 audit out of the doctor verb for several releases)
    /// fails fast here. The IDs must match the M060 wire contract
    /// the sovereign-os consumer side expects.
    #[test]
    fn domains_cover_full_m060_wire_contract() {
        let ids: Vec<&str> = DOMAINS.iter().map(|d| d.id).collect();
        let expected = [
            "D-02", // active-profile
            "D-12", // rules           (added — was silently missing)
            "D-13", // grants
            "D-14", // capability-tokens
            "D-15", // sandboxes
            "D-16", // audit-chain     (added — was silently missing)
            "D-17", // quarantine
            "D-18", // trust-scores
        ];
        assert_eq!(
            ids, expected,
            "M060 doctor domain set must match the wire contract \
             (sovereign-os consumer expects all 8 mirrors). Silent \
             removal here means the operator's m060-doctor triage \
             verb will skip a domain; mirror wedge will go unseen."
        );
    }

    /// Pin the resident-path defaults so a future rename in a
    /// registry crate doesn't silently desync the doctor from the
    /// daemon. The resident store is the source-of-truth the daemon
    /// publishes from; the doctor inspects the same path.
    #[test]
    fn domains_resident_defaults_match_daemon_canonical_paths() {
        use std::collections::HashMap;
        let expected: HashMap<&str, &str> = [
            ("D-02", "/var/lib/selfdef/flex-profile.json"),
            ("D-12", "/var/lib/selfdef/rules.json"),
            ("D-13", "/var/lib/selfdef/grants.json"),
            ("D-14", "/var/lib/selfdef/capability-tokens.json"),
            ("D-15", "/var/lib/selfdef/sandboxes.json"),
            ("D-16", "/var/lib/selfdef/audit.json"),
            ("D-17", "/var/lib/selfdef/quarantine.json"),
            ("D-18", "/var/lib/selfdef/trust-scores.json"),
        ]
        .into_iter()
        .collect();
        for d in DOMAINS {
            let want = expected
                .get(d.id)
                .unwrap_or_else(|| panic!("unexpected domain id {}", d.id));
            assert_eq!(d.resident_default, *want, "{} resident_default drift", d.id);
        }
    }
}
