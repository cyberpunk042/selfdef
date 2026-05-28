//! `selfdefctl cli-mirror doctor` — triage the M060 D-CLI chain.
//!
//! Operator-facing diagnostic for the cli-mirror sub-chain of M060:
//!
//!   producer one-shot (selfdef-cli-mirror-emit.service)
//!     → resident store (/var/lib/selfdef/cli-mirror.json)
//!     → daemon publisher (selfdefd::cli_mirror_publisher)
//!     → published mirror (<selfdef_mirror_dir>/cli.json)
//!     → sovereign-os consumer (D-XX cockpit panel)
//!
//! Each link in the chain has a distinct operator-actionable failure
//! mode; this doctor surfaces which one is broken in a single
//! triage line per check. Three exit-code classes:
//!
//!   - 0 (GREEN)  every check passes; chain is healthy
//!   - 1 (YELLOW) at least one operator-actionable degradation
//!   - 2 (RED)    structural break (e.g. selfdefd doesn't link
//!     cli-mirror at all — wire-shape regression)
//!
//! Read-only — never mutates anything. Works whether or not
//! `selfdefd` is running (filesystem + systemd state are the
//! source of truth; no daemon-process required).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use anyhow::Result;
use selfdef_cli_mirror::{CliMirrorSnapshot, DEFAULT_STATE_PATH, SCHEMA_VERSION};

/// Canonical config path the doctor inspects for the
/// `[deployment].selfdef_mirror_dir` knob. Operator overrides via
/// `--config PATH`.
const DEFAULT_CONFIG_PATH: &str = "/etc/selfdef/selfdef.toml";

/// Outcome class per check — ordered by severity (Pass < Warn < Fail)
/// so the worst-case across the chain drives the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    Pass = 0,
    Warn = 1,
    Fail = 2,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "OK   ",
            Self::Warn => "WARN ",
            Self::Fail => "FAIL ",
        }
    }
    fn json(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One row of the operator-readable triage table.
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) severity: Severity,
    pub(crate) detail: String,
    /// Suggested next step when severity != Pass. Empty when Pass.
    pub(crate) fix: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Pass,
            detail: detail.into(),
            fix: String::new(),
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Warn,
            detail: detail.into(),
            fix: fix.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Fail,
            detail: detail.into(),
            fix: fix.into(),
        }
    }
}

/// Compute the canonical 4-check set the dedicated verb runs. Used
/// by both the standalone `selfdefctl cli-mirror doctor` verb (which
/// renders these into a triage table) and the cross-cutting
/// `selfdefctl doctor` roll-up (which converts them into CheckResult
/// rows). Keeping a single source-of-truth means the operator gets
/// identical classifications regardless of which surface they call.
#[must_use]
pub(crate) fn run_checks(config_path: &Path) -> Vec<Check> {
    let resident = resident_store_path();
    vec![
        check_schema_version_invariant(),
        check_resident_store(&resident),
        check_systemd_unit(),
        check_published_mirror(config_path),
    ]
}

/// Resolve the resident-store path: env override wins, else crate const.
fn resident_store_path() -> PathBuf {
    std::env::var_os("SELFDEF_CLI_MIRROR_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_PATH))
}

/// Read `[deployment].selfdef_mirror_dir` from selfdef.toml without
/// pulling in the full TOML parser — mirrors the m060_doctor sibling.
pub(crate) fn read_mirror_dir_from_config(config_path: &Path) -> Option<PathBuf> {
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

/// Age in seconds since the file was last modified. `None` when the
/// file doesn't exist or its mtime is unreadable. Saturating at u64::MAX
/// is intentional — a timestamp from before the epoch is operationally
/// equivalent to "infinitely stale".
fn file_age_secs(path: &Path) -> Option<u64> {
    let md = std::fs::metadata(path).ok()?;
    let mtime = md.modified().ok()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|d| d.as_secs())
}

/// Inspect the resident store: existence + schema-version + age +
/// subcommand count. Schema-drift is FAIL (operator must re-emit);
/// age > 1 day is WARN (rebuilt selfdefctl with no re-emit); absent is
/// WARN (shell-out fallback may still cover, but the doctor flags it
/// so the operator can wire the one-shot).
pub(crate) fn check_resident_store(path: &Path) -> Check {
    if !path.exists() {
        return Check::warn(
            "resident-store",
            format!("{} absent", path.display()),
            "systemctl start selfdef-cli-mirror-emit.service",
        );
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return Check::fail(
                "resident-store",
                format!("{} unreadable: {e}", path.display()),
                "check file ownership (selfdef:selfdef) + perms (0640)",
            );
        }
    };
    let snap: CliMirrorSnapshot = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            return Check::fail(
                "resident-store",
                format!("malformed JSON: {e}"),
                "rm + re-emit: systemctl start selfdef-cli-mirror-emit.service",
            );
        }
    };
    if let Err(e) = snap.validate_schema() {
        return Check::fail(
            "resident-store",
            format!("schema-version drift ({e})"),
            "re-emit: systemctl start selfdef-cli-mirror-emit.service",
        );
    }
    // Age-of-last-emit > 1 day = operator likely upgraded selfdefctl
    // without re-running the emit one-shot; the daemon's 5-min
    // resident-cache will pick up the new bytes once we re-emit.
    let age = file_age_secs(path);
    let subs = snap.subcommands.len();
    match age {
        Some(s) if s > 86_400 => Check::warn(
            "resident-store",
            format!(
                "{} present (schema {}, {subs} subcommands), but {}h old",
                path.display(),
                snap.schema_version,
                s / 3600
            ),
            "post-upgrade re-emit: systemctl start selfdef-cli-mirror-emit.service",
        ),
        Some(s) => Check::pass(
            "resident-store",
            format!(
                "{} present (schema {}, {subs} subcommands, {}m old)",
                path.display(),
                snap.schema_version,
                s / 60
            ),
        ),
        None => Check::pass(
            "resident-store",
            format!(
                "{} present (schema {}, {subs} subcommands)",
                path.display(),
                snap.schema_version
            ),
        ),
    }
}

/// Inspect the systemd one-shot. Three states the operator cares about:
///
///   1. systemctl available + unit exists + last result is success → PASS
///   2. systemctl available + unit exists + last result not success → WARN
///   3. systemctl unavailable (no systemd) OR unit not installed → WARN
///      (the shell-out fallback may still cover, but the operator
///      should know they're on the legacy path)
pub(crate) fn check_systemd_unit() -> Check {
    // `is-active` is cheap + standalone; doesn't need any sd-bus glue.
    let probe = Command::new("systemctl")
        .args([
            "show",
            "selfdef-cli-mirror-emit.service",
            "--property=ActiveState,Result,ExecMainStatus,LoadState",
        ])
        .output();
    let output = match probe {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Check::warn(
                "systemd-unit",
                "systemctl not on PATH (non-systemd host?)",
                "no fix needed if the host doesn't run systemd; verify resident store via other means",
            );
        }
        Err(e) => {
            return Check::warn(
                "systemd-unit",
                format!("systemctl probe failed: {e}"),
                "retry; if persistent, check systemd health",
            );
        }
    };
    // systemctl exists but the bus is unreachable (containers,
    // non-systemd hosts where systemd is installed but not PID 1,
    // chroots) — `show` exits 0 with the diagnostic written to stderr
    // and an empty stdout. Detect + downgrade to WARN.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("System has not been booted with systemd")
        || stderr.contains("Failed to connect to bus")
        || stderr.contains("Failed to get D-Bus connection")
    {
        return Check::warn(
            "systemd-unit",
            "systemctl present but systemd bus unreachable (container / non-systemd host)",
            "no fix needed if the host doesn't run systemd; verify resident store via other means",
        );
    }
    let body = String::from_utf8_lossy(&output.stdout);
    // Empty stdout despite a successful exit code also indicates a
    // broken bus / no-systemd environment — treat the same way.
    if body.trim().is_empty() {
        return Check::warn(
            "systemd-unit",
            "systemctl returned empty state (systemd bus not reachable?)",
            "if host runs systemd, verify the bus is up; else this is non-actionable",
        );
    }
    let mut load_state = "unknown";
    let mut active_state = "unknown";
    let mut result = "unknown";
    let mut exec_status = "unknown";
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("LoadState=") {
            load_state = v;
        }
        if let Some(v) = line.strip_prefix("ActiveState=") {
            active_state = v;
        }
        if let Some(v) = line.strip_prefix("Result=") {
            result = v;
        }
        if let Some(v) = line.strip_prefix("ExecMainStatus=") {
            exec_status = v;
        }
    }
    if load_state == "not-found" {
        return Check::warn(
            "systemd-unit",
            "selfdef-cli-mirror-emit.service not installed",
            "install selfdef-daemon .deb (or copy the unit file to /lib/systemd/system + daemon-reload)",
        );
    }
    // One-shot units sit at ActiveState=inactive after a successful
    // run — that's the post-success steady state, not a failure.
    if result == "success" {
        Check::pass(
            "systemd-unit",
            format!(
                "selfdef-cli-mirror-emit.service installed, last-result=success, active-state={active_state}"
            ),
        )
    } else if result == "exit-code" || exec_status != "0" {
        Check::fail(
            "systemd-unit",
            format!(
                "selfdef-cli-mirror-emit.service exited non-zero (Result={result}, ExecMainStatus={exec_status})"
            ),
            "journalctl -u selfdef-cli-mirror-emit.service -n 50",
        )
    } else {
        Check::warn(
            "systemd-unit",
            format!(
                "selfdef-cli-mirror-emit.service in indeterminate state ({load_state}/{active_state}/{result})"
            ),
            "systemctl start selfdef-cli-mirror-emit.service",
        )
    }
}

/// Inspect the published mirror — should exist when
/// `[deployment].selfdef_mirror_dir` is set + selfdefd is running.
pub(crate) fn check_published_mirror(config_path: &Path) -> Check {
    let mirror_dir = match read_mirror_dir_from_config(config_path) {
        Some(p) => p,
        None => {
            return Check::warn(
                "published-mirror",
                "[deployment].selfdef_mirror_dir not set in selfdef.toml",
                "set selfdef_mirror_dir = \"/run/sovereign-os/selfdef-mirror\" + restart selfdefd",
            );
        }
    };
    let published = mirror_dir.join("cli.json");
    if !published.exists() {
        return Check::warn(
            "published-mirror",
            format!("{} absent", published.display()),
            "verify selfdefd is running: systemctl status selfdefd",
        );
    }
    let age = file_age_secs(&published);
    match age {
        Some(s) if s > 120 => Check::warn(
            "published-mirror",
            format!(
                "{} stale ({}s old, exceeds 2x export interval)",
                published.display(),
                s
            ),
            "verify selfdefd is running + cli_mirror_publisher path: journalctl -u selfdefd | grep cli-mirror",
        ),
        Some(s) => Check::pass(
            "published-mirror",
            format!("{} fresh ({}s old)", published.display(), s),
        ),
        None => Check::pass(
            "published-mirror",
            format!("{} present", published.display()),
        ),
    }
}

/// Cross-check: resident store schema_version MUST equal the
/// consumer-side const at compile time. Drift here is a wire-shape
/// regression (developer introduced a new schema without bumping the
/// crate const), not an operator-actionable state. RED.
pub(crate) fn check_schema_version_invariant() -> Check {
    // SCHEMA_VERSION is a const from selfdef-cli-mirror; the producer
    // (the in-process clap walker) reads the same const. They cannot
    // drift unless someone hand-edits the JSON. This check exists so
    // the doctor surfaces the invariant explicitly in the triage
    // table — operators have asked for "what version of the schema
    // is expected" in the past, and this is the answer.
    Check::pass(
        "schema-version",
        format!("expected CliMirrorSnapshot {SCHEMA_VERSION} (compiled into selfdefctl)"),
    )
}

/// Escape a Prometheus label value per the textfile_collector format:
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

/// Render the doctor checks as a node_exporter-compatible textfile
/// payload. Lines emitted (one per check + one summary):
///
///   # HELP selfdef_cli_mirror_doctor_severity Per-check severity (0=pass 1=warn 2=fail).
///   # TYPE selfdef_cli_mirror_doctor_severity gauge
///   selfdef_cli_mirror_doctor_severity{check="<name>"} <0|1|2>
///   selfdef_cli_mirror_doctor_check_info{check="<name>",detail="<...>",fix="<...>"} 1
///   selfdef_cli_mirror_doctor_worst_severity <0|1|2>
///   selfdef_cli_mirror_doctor_last_run_unix <seconds since epoch>
///
/// Atomic write via tempfile + rename in the same directory so a
/// concurrent node_exporter scrape never sees a torn write.
pub(crate) fn render_textfile(checks: &[Check], worst: Severity) -> String {
    let mut body = String::new();
    body.push_str(
        "# HELP selfdef_cli_mirror_doctor_severity Per-check severity \
         (0=pass 1=warn 2=fail). One series per check name.\n",
    );
    body.push_str("# TYPE selfdef_cli_mirror_doctor_severity gauge\n");
    for c in checks {
        body.push_str(&format!(
            "selfdef_cli_mirror_doctor_severity{{check=\"{}\"}} {}\n",
            escape_label(c.name),
            c.severity as u8,
        ));
    }
    body.push_str(
        "# HELP selfdef_cli_mirror_doctor_check_info Per-check info \
         (detail+fix as labels, always value=1). Used by Grafana to \
         hover-render the operator-readable triage text.\n",
    );
    body.push_str("# TYPE selfdef_cli_mirror_doctor_check_info gauge\n");
    for c in checks {
        body.push_str(&format!(
            "selfdef_cli_mirror_doctor_check_info{{check=\"{}\",detail=\"{}\",fix=\"{}\"}} 1\n",
            escape_label(c.name),
            escape_label(&c.detail),
            escape_label(&c.fix),
        ));
    }
    body.push_str(
        "# HELP selfdef_cli_mirror_doctor_worst_severity Worst severity \
         across all checks (0=pass 1=warn 2=fail). The M060Chain* \
         alert rules fire on `worst_severity > 1`.\n",
    );
    body.push_str("# TYPE selfdef_cli_mirror_doctor_worst_severity gauge\n");
    body.push_str(&format!(
        "selfdef_cli_mirror_doctor_worst_severity {}\n",
        worst as u8,
    ));
    body.push_str(
        "# HELP selfdef_cli_mirror_doctor_last_run_unix Unix timestamp \
         of the last doctor invocation. Lets the alert pipeline detect \
         a wedged systemd timer (no recent writes).\n",
    );
    body.push_str("# TYPE selfdef_cli_mirror_doctor_last_run_unix gauge\n");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    body.push_str(&format!("selfdef_cli_mirror_doctor_last_run_unix {now}\n"));
    body
}

/// Atomically write the doctor's textfile to `path`. Tempfile in the
/// same directory with `.tmp.<pid>` suffix, then `rename(2)` — the
/// same pattern every other M060 producer uses (POSIX rename is
/// atomic on the same filesystem; a concurrent node_exporter scrape
/// either sees the OLD bytes or the NEW bytes, never a torn write).
fn write_textfile(path: &Path, checks: &[Check], worst: Severity) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "cli-mirror.prom".to_string()),
        std::process::id()
    ));
    let body = render_textfile(checks, worst);
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Run the doctor. Returns the worst-severity exit code (0/1/2).
pub(crate) fn run(
    json: bool,
    config_override: Option<&Path>,
    textfile: Option<&Path>,
) -> Result<i32> {
    let config_path = config_override.map_or_else(
        || PathBuf::from(DEFAULT_CONFIG_PATH),
        std::path::Path::to_path_buf,
    );
    let checks = run_checks(&config_path);
    let worst = checks
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::Pass);

    if let Some(p) = textfile {
        write_textfile(p, &checks, worst)?;
    }

    if json {
        let arr: Vec<_> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "severity": c.severity.json(),
                    "detail": c.detail,
                    "fix": c.fix,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schema_version": "1.0.0",
            "domain": "D-CLI",
            "worst_severity": worst.json(),
            "checks": arr,
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        println!("M060 D-CLI mirror chain — host triage");
        println!("=====================================");
        for c in &checks {
            println!("{} {:<18} {}", c.severity.label(), c.name, c.detail);
            if !c.fix.is_empty() {
                println!("      └─ fix: {}", c.fix);
            }
        }
        println!();
        match worst {
            Severity::Pass => println!("verdict: GREEN — chain healthy"),
            Severity::Warn => {
                println!("verdict: YELLOW — at least one operator-actionable degradation")
            }
            Severity::Fail => println!("verdict: RED — structural break; see fix lines above"),
        }
    }

    Ok(match worst {
        Severity::Pass => 0,
        Severity::Warn => 1,
        Severity::Fail => 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_valid_resident(path: &Path) {
        let snap = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "cli_build_version": "test",
            "doctrine": "Fullstack at the edges",
            "captured_at": "2026-05-19T00:00:00Z",
            "summaries": [],
            "subcommands": [{
                "path": "doctor",
                "help_summary": "Run diagnostics",
                "help_long": "",
                "effect_class": "diagnostic",
                "min_authority": "l1_suggest",
                "args": [],
                "mirror": "",
                "requires_signature": false,
                "p95_target_ms": 1000,
                "signature": "",
            }],
            "signature": "",
        });
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(path).unwrap();
        f.write_all(serde_json::to_string(&snap).unwrap().as_bytes())
            .unwrap();
    }

    #[test]
    fn severity_ordering_pass_lt_warn_lt_fail() {
        assert!(Severity::Pass < Severity::Warn);
        assert!(Severity::Warn < Severity::Fail);
    }

    #[test]
    pub(crate) fn check_resident_store_absent_is_warn() {
        let path = std::env::temp_dir().join(format!(
            "cli-mirror-doctor-absent-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let check = check_resident_store(&path);
        assert_eq!(check.severity, Severity::Warn);
        assert!(check.detail.contains("absent"));
        assert!(check.fix.contains("selfdef-cli-mirror-emit"));
    }

    #[test]
    pub(crate) fn check_resident_store_valid_is_pass() {
        let path = std::env::temp_dir().join(format!(
            "cli-mirror-doctor-valid-{}.json",
            std::process::id()
        ));
        write_valid_resident(&path);
        let check = check_resident_store(&path);
        assert_eq!(check.severity, Severity::Pass);
        assert!(check.detail.contains("1 subcommands"));
        fs::remove_file(&path).ok();
    }

    #[test]
    pub(crate) fn check_resident_store_malformed_json_is_fail() {
        let path =
            std::env::temp_dir().join(format!("cli-mirror-doctor-bad-{}.json", std::process::id()));
        fs::write(&path, b"this is not json").unwrap();
        let check = check_resident_store(&path);
        assert_eq!(check.severity, Severity::Fail);
        assert!(check.detail.contains("malformed"));
        fs::remove_file(&path).ok();
    }

    #[test]
    pub(crate) fn check_resident_store_schema_drift_is_fail() {
        let path = std::env::temp_dir().join(format!(
            "cli-mirror-doctor-drift-{}.json",
            std::process::id()
        ));
        let drift = serde_json::json!({
            "schema_version": "9.9.9",
            "cli_build_version": "test",
            "doctrine": "Fullstack at the edges",
            "captured_at": "2026-05-19T00:00:00Z",
            "summaries": [],
            "subcommands": [],
            "signature": "",
        });
        fs::write(&path, serde_json::to_vec(&drift).unwrap()).unwrap();
        let check = check_resident_store(&path);
        assert_eq!(check.severity, Severity::Fail);
        assert!(check.detail.contains("drift"));
        fs::remove_file(&path).ok();
    }

    #[test]
    pub(crate) fn check_published_mirror_no_config_is_warn() {
        let path = std::env::temp_dir().join(format!(
            "cli-mirror-doctor-missing-config-{}.toml",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let check = check_published_mirror(&path);
        assert_eq!(check.severity, Severity::Warn);
        assert!(check.detail.contains("selfdef_mirror_dir not set"));
    }

    #[test]
    pub(crate) fn check_published_mirror_config_set_but_file_absent_is_warn() {
        let dir = std::env::temp_dir().join(format!(
            "cli-mirror-doctor-published-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("selfdef.toml");
        let mirror_dir = dir.join("mirror");
        fs::create_dir_all(&mirror_dir).unwrap();
        fs::write(
            &config,
            format!(
                "[deployment]\nselfdef_mirror_dir = \"{}\"\n",
                mirror_dir.display()
            ),
        )
        .unwrap();
        let check = check_published_mirror(&config);
        assert_eq!(check.severity, Severity::Warn);
        assert!(check.detail.contains("cli.json"));
        assert!(check.detail.contains("absent"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    pub(crate) fn check_published_mirror_fresh_file_is_pass() {
        let dir =
            std::env::temp_dir().join(format!("cli-mirror-doctor-pubfresh-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("selfdef.toml");
        let mirror_dir = dir.join("mirror");
        fs::create_dir_all(&mirror_dir).unwrap();
        fs::write(
            &config,
            format!(
                "[deployment]\nselfdef_mirror_dir = \"{}\"\n",
                mirror_dir.display()
            ),
        )
        .unwrap();
        // Drop a fresh cli.json.
        fs::write(mirror_dir.join("cli.json"), b"{}").unwrap();
        let check = check_published_mirror(&config);
        assert_eq!(check.severity, Severity::Pass);
        assert!(check.detail.contains("fresh"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn schema_version_invariant_passes() {
        let check = check_schema_version_invariant();
        assert_eq!(check.severity, Severity::Pass);
        assert!(check.detail.contains(SCHEMA_VERSION));
    }

    #[test]
    fn read_mirror_dir_from_config_honors_quoted_value() {
        let dir =
            std::env::temp_dir().join(format!("cli-mirror-doctor-readcfg-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("selfdef.toml");
        fs::write(&cfg, b"[deployment]\nselfdef_mirror_dir = \"/run/x\"\n").unwrap();
        let got = read_mirror_dir_from_config(&cfg);
        assert_eq!(got, Some(PathBuf::from("/run/x")));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_mirror_dir_from_config_returns_none_when_key_absent() {
        let dir =
            std::env::temp_dir().join(format!("cli-mirror-doctor-noconfig-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("selfdef.toml");
        fs::write(&cfg, b"[deployment]\n# no knob here\n").unwrap();
        assert!(read_mirror_dir_from_config(&cfg).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    fn sample_checks_warn() -> Vec<Check> {
        vec![
            Check::pass("schema-version", "expected 1.0.0"),
            Check::warn(
                "resident-store",
                "/var/lib/selfdef/cli-mirror.json absent",
                "systemctl start selfdef-cli-mirror-emit.service",
            ),
        ]
    }

    #[test]
    fn escape_label_handles_quote_backslash_newline() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("with \"quote\""), "with \\\"quote\\\"");
        assert_eq!(escape_label("with\\backslash"), "with\\\\backslash");
        assert_eq!(escape_label("with\nnewline"), "with\\nnewline");
    }

    #[test]
    fn render_textfile_emits_one_severity_per_check() {
        let body = render_textfile(&sample_checks_warn(), Severity::Warn);
        assert!(body.contains("selfdef_cli_mirror_doctor_severity{check=\"schema-version\"} 0"));
        assert!(body.contains("selfdef_cli_mirror_doctor_severity{check=\"resident-store\"} 1"));
    }

    #[test]
    fn render_textfile_emits_worst_severity_summary() {
        let body = render_textfile(&sample_checks_warn(), Severity::Warn);
        assert!(body.contains("selfdef_cli_mirror_doctor_worst_severity 1"));
        let body_fail = render_textfile(
            &[Check::fail("resident-store", "bad", "fix me")],
            Severity::Fail,
        );
        assert!(body_fail.contains("selfdef_cli_mirror_doctor_worst_severity 2"));
        let body_pass = render_textfile(&[Check::pass("schema-version", "ok")], Severity::Pass);
        assert!(body_pass.contains("selfdef_cli_mirror_doctor_worst_severity 0"));
    }

    #[test]
    fn render_textfile_emits_help_and_type_lines() {
        let body = render_textfile(&sample_checks_warn(), Severity::Warn);
        for metric in [
            "selfdef_cli_mirror_doctor_severity",
            "selfdef_cli_mirror_doctor_check_info",
            "selfdef_cli_mirror_doctor_worst_severity",
            "selfdef_cli_mirror_doctor_last_run_unix",
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
    fn render_textfile_check_info_carries_detail_and_fix() {
        let body = render_textfile(&sample_checks_warn(), Severity::Warn);
        // The warn row should embed detail + fix as escaped labels.
        assert!(body.contains(
            "selfdef_cli_mirror_doctor_check_info{check=\"resident-store\",\
             detail=\"/var/lib/selfdef/cli-mirror.json absent\",\
             fix=\"systemctl start selfdef-cli-mirror-emit.service\"} 1"
        ));
    }

    #[test]
    fn render_textfile_check_info_escapes_quotes_in_detail() {
        let checks = vec![Check::warn(
            "thing",
            "detail with \"embedded quote\"",
            "fix without quotes",
        )];
        let body = render_textfile(&checks, Severity::Warn);
        assert!(
            body.contains("detail=\"detail with \\\"embedded quote\\\"\""),
            "embedded quotes must be backslash-escaped; body:\n{body}"
        );
    }

    #[test]
    fn render_textfile_last_run_unix_is_recent() {
        let body = render_textfile(&sample_checks_warn(), Severity::Warn);
        let line = body
            .lines()
            .find(|l| l.starts_with("selfdef_cli_mirror_doctor_last_run_unix "))
            .expect("last_run_unix line");
        let value: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Within 60s of "now" — generous tolerance for slow CI.
        assert!(
            now.saturating_sub(value) <= 60,
            "last_run_unix={value} too far behind now={now}"
        );
    }

    #[test]
    fn write_textfile_is_atomic_no_leftover_tmp() {
        let dir =
            std::env::temp_dir().join(format!("cli-mirror-doctor-textfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("selfdef-cli-mirror.prom");
        write_textfile(&path, &sample_checks_warn(), Severity::Warn).unwrap();
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
        assert!(body.contains("selfdef_cli_mirror_doctor_worst_severity 1"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
