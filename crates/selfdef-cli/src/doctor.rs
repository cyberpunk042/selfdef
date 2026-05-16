//! `selfdefctl doctor` — holistic operator health-check.
//!
//! Cross-cutting checks that don't fit any single `modules check`
//! script. Each post-audit security feature has an opt-in knob
//! whose "is this actually working?" state lives across multiple
//! files — the API token file's mode, the eventstream JSONL
//! ownership, every rule file's `.minisig` sidecar, the
//! agent-guard pod-label scope's RBAC dependency. Operators
//! shouldn't have to remember to spot-check each one.
//!
//! Doctor runs the cross-cutting checks; per-module check.sh
//! lives in `selfdefctl modules check`. The two are
//! complementary — neither subsumes the other.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use selfdef_config::Config;

/// Outcome of one doctor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckStatus {
    /// Check passed; everything as expected.
    Ok,
    /// Check passed but with a non-blocking observation.
    Warn,
    /// Check failed; operator action needed.
    Fail,
    /// Check not applicable to this deployment (e.g. signing
    /// disabled, agent-guard not using pod-label scope).
    Skipped,
}

impl CheckStatus {
    fn label(&self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Skipped => "skip",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CheckResult {
    /// Bucket name: `"signing" | "api" | "eventstream" | "rbac"`.
    pub category: String,
    /// Human-readable check name.
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// Run every doctor check against `cfg`. Returns the results
/// and a suggested exit code (0 if no `Fail`, 1 otherwise).
pub(crate) fn run(cfg: &Config) -> Vec<CheckResult> {
    let mut out = Vec::new();
    out.extend(check_rule_signing(cfg));
    out.extend(check_api_token(cfg));
    out.extend(check_eventstream(cfg));
    out.extend(check_rbac_posture(cfg));
    out.extend(check_deployment_target(cfg));
    out
}

/// Render a human-readable report (one line per check, summary
/// at the end). Returns the suggested exit code.
pub(crate) fn render_human(results: &[CheckResult]) -> (String, i32) {
    let mut buf = String::new();
    writeln!(&mut buf, "# selfdefctl doctor").unwrap();
    writeln!(&mut buf).unwrap();

    let mut by_cat: std::collections::BTreeMap<&str, Vec<&CheckResult>> =
        std::collections::BTreeMap::new();
    for r in results {
        by_cat.entry(r.category.as_str()).or_default().push(r);
    }
    for (cat, items) in &by_cat {
        writeln!(&mut buf, "## {cat}").unwrap();
        for r in items {
            writeln!(
                &mut buf,
                "  [{:>4}] {}: {}",
                r.status.label(),
                r.name,
                r.detail
            )
            .unwrap();
        }
        writeln!(&mut buf).unwrap();
    }

    let n_ok = results
        .iter()
        .filter(|r| r.status == CheckStatus::Ok)
        .count();
    let n_warn = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    let n_fail = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let n_skip = results
        .iter()
        .filter(|r| r.status == CheckStatus::Skipped)
        .count();
    writeln!(
        &mut buf,
        "summary: {n_ok} ok, {n_warn} warn, {n_fail} fail, {n_skip} skip ({} total)",
        results.len()
    )
    .unwrap();

    let exit = if n_fail > 0 { 1 } else { 0 };
    (buf, exit)
}

/// Render as JSON-lines, one object per check. Mostly for CI
/// integration; the human report is the primary surface.
pub(crate) fn render_json(results: &[CheckResult]) -> Result<(String, i32)> {
    let mut buf = String::new();
    for r in results {
        let obj = serde_json::json!({
            "category": r.category,
            "name": r.name,
            "status": r.status.label(),
            "detail": r.detail,
        });
        writeln!(&mut buf, "{obj}").context("writing doctor JSON line")?;
    }
    let n_fail = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let exit = if n_fail > 0 { 1 } else { 0 };
    Ok((buf, exit))
}

// --- checks ----------------------------------------------------

/// Rule signing — when `[security].require_signed_rules = true`,
/// verify the public key loads + every rule in
/// `cfg.correlator.rules_dir` has a sibling `.minisig` that
/// validates. Mirrors what the daemon does on startup but as
/// an ahead-of-time check so operators don't discover the
/// problem after a restart.
fn check_rule_signing(cfg: &Config) -> Vec<CheckResult> {
    if !cfg.security.require_signed_rules {
        return vec![CheckResult {
            category: "signing".into(),
            name: "rule signing".into(),
            status: CheckStatus::Skipped,
            detail: "[security].require_signed_rules = false".into(),
        }];
    }
    let Some(key_path) = cfg.security.signing_public_key_file.clone() else {
        return vec![CheckResult {
            category: "signing".into(),
            name: "public key".into(),
            status: CheckStatus::Fail,
            detail: "[security].require_signed_rules = true but \
                 signing_public_key_file is unset"
                .into(),
        }];
    };
    let verifier = match selfdef_signing::Verifier::load(&key_path) {
        Ok(v) => v,
        Err(e) => {
            return vec![CheckResult {
                category: "signing".into(),
                name: "public key".into(),
                status: CheckStatus::Fail,
                detail: format!("loading {}: {e}", key_path.display()),
            }];
        }
    };
    let mut out = vec![CheckResult {
        category: "signing".into(),
        name: "public key".into(),
        status: CheckStatus::Ok,
        detail: format!("loaded {}", key_path.display()),
    }];
    let rules_dir = &cfg.correlator.rules_dir;
    if !rules_dir.exists() {
        out.push(CheckResult {
            category: "signing".into(),
            name: "rules directory".into(),
            status: CheckStatus::Warn,
            detail: format!("does not exist: {}", rules_dir.display()),
        });
        return out;
    }
    let mut checked = 0usize;
    let mut failed = Vec::new();
    walk_yaml_files(rules_dir, &mut |p| {
        checked += 1;
        if let Err(e) = verifier.verify_detached_file(p) {
            failed.push(format!("{}: {e}", p.display()));
        }
    });
    if failed.is_empty() {
        out.push(CheckResult {
            category: "signing".into(),
            name: "rule sidecars".into(),
            status: CheckStatus::Ok,
            detail: format!("{checked} rule file(s) verify"),
        });
    } else {
        out.push(CheckResult {
            category: "signing".into(),
            name: "rule sidecars".into(),
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {checked} rule file(s) failed: {}",
                failed.len(),
                failed.join("; ")
            ),
        });
    }
    out
}

/// API token file: when `[api].token_file` is configured, verify
/// the file exists and is mode 0600. Catches the
/// `selfdefctl api rotate-token` happy path drifting (e.g. an
/// operator-managed file with `chmod 0644`).
fn check_api_token(cfg: &Config) -> Vec<CheckResult> {
    use std::os::unix::fs::PermissionsExt as _;
    if !cfg.api.enabled || cfg.api.token_file.trim().is_empty() {
        return vec![CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Skipped,
            detail: "[api] disabled or token_file unset".into(),
        }];
    }
    let path = std::path::PathBuf::from(&cfg.api.token_file);
    let md = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            return vec![CheckResult {
                category: "api".into(),
                name: "token file".into(),
                status: CheckStatus::Fail,
                detail: format!("{} unreadable: {e}", path.display()),
            }];
        }
    };
    let mode = md.permissions().mode() & 0o777;
    let mut out = Vec::new();
    if mode == 0o600 {
        out.push(CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Ok,
            detail: format!("{} mode 0600", path.display()),
        });
    } else {
        out.push(CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Fail,
            detail: format!(
                "{} mode {:o} (expected 0600 — see selfdefctl api rotate-token)",
                path.display(),
                mode
            ),
        });
    }
    if md.len() == 0 {
        out.push(CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Fail,
            detail: format!("{} is empty", path.display()),
        });
    }
    out
}

/// Eventstream integrity: when
/// `[collectors.eventstream].integrity_check = true`, verify
/// every configured path passes the same checks the collector
/// will run at startup (not world-writable, owned by an
/// allowed UID).
fn check_eventstream(cfg: &Config) -> Vec<CheckResult> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !cfg.collectors.eventstream.enabled || !cfg.collectors.eventstream.integrity_check {
        return vec![CheckResult {
            category: "eventstream".into(),
            name: "integrity".into(),
            status: CheckStatus::Skipped,
            detail: "[collectors.eventstream] disabled or integrity_check = false".into(),
        }];
    }
    let mut out = Vec::new();
    let allowed = &cfg.collectors.eventstream.allowed_owners;
    for path in &cfg.collectors.eventstream.paths {
        let md = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                out.push(CheckResult {
                    category: "eventstream".into(),
                    name: path.display().to_string(),
                    status: CheckStatus::Warn,
                    detail: format!("unreadable: {e}"),
                });
                continue;
            }
        };
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o002 != 0 {
            out.push(CheckResult {
                category: "eventstream".into(),
                name: path.display().to_string(),
                status: CheckStatus::Fail,
                detail: format!("world-writable (mode {mode:o})"),
            });
            continue;
        }
        let uid = md.uid();
        if uid != 0 && !allowed.contains(&uid) {
            out.push(CheckResult {
                category: "eventstream".into(),
                name: path.display().to_string(),
                status: CheckStatus::Fail,
                detail: format!(
                    "owner uid {uid} not in [collectors.eventstream].allowed_owners and not root"
                ),
            });
            continue;
        }
        out.push(CheckResult {
            category: "eventstream".into(),
            name: path.display().to_string(),
            status: CheckStatus::Ok,
            detail: format!("mode {mode:o}, owner {uid}"),
        });
    }
    out
}

/// RBAC posture summary. We don't probe the cluster here — that's
/// `selfdefctl rbac check --probe`. Doctor just reports whether
/// the rbac surface applies + points at the dedicated verb.
fn check_rbac_posture(_cfg: &Config) -> Vec<CheckResult> {
    // F-2027-018: `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` is the
    // test-only env override that lets the integration suite stage
    // a fake agent-guard config in a tempdir without polluting
    // /etc. Production callers leave this unset; the verb's
    // `--help` and `docs/dev/operator-health-check.md` both
    // document it explicitly so an operator chasing a doctor bug
    // can reproduce against a staged config.
    // F-2027-017: pull the default path from `crate::paths` so
    // every CLI verb sees the same canonical layout.
    let ag_path = std::env::var_os("SELFDEF_DOCTOR_AGENT_GUARD_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(crate::paths::AGENT_GUARD_CONFIG));
    if !ag_path.exists() {
        return vec![CheckResult {
            category: "rbac".into(),
            name: "agent-guard scope".into(),
            status: CheckStatus::Skipped,
            detail: format!(
                "{} not present — agent-guard not installed",
                ag_path.display()
            ),
        }];
    }
    let body = match std::fs::read_to_string(&ag_path) {
        Ok(s) => s,
        Err(e) => {
            return vec![CheckResult {
                category: "rbac".into(),
                name: "agent-guard scope".into(),
                status: CheckStatus::Warn,
                detail: format!("{} unreadable: {e}", ag_path.display()),
            }];
        }
    };
    let scope = extract_toml_scalar_line(&body, "scope").unwrap_or_else(|| "container".into());
    if scope == "pod-label" {
        // F-2027-008: previously emitted `Warn` for pod-label
        // scope. Doctor never probes the cluster (deliberate —
        // probing is `selfdefctl rbac check --probe`'s job).
        // The `warn:` line was inflating the doctor's
        // top-level summary count, suggesting something was
        // wrong when actually nothing was — just that the
        // RBAC posture hadn't been verified yet. Flip to
        // `Skipped` (which doesn't contribute to the warn or
        // fail count) with explicit "not verified" wording.
        vec![CheckResult {
            category: "rbac".into(),
            name: "agent-guard scope".into(),
            status: CheckStatus::Skipped,
            detail:
                "scope = \"pod-label\" — posture not verified here; run `selfdefctl rbac check --probe` to verify the cluster's RBAC matches"
                    .into(),
        }]
    } else {
        vec![CheckResult {
            category: "rbac".into(),
            name: "agent-guard scope".into(),
            status: CheckStatus::Skipped,
            detail: format!("scope = \"{scope}\" — RBAC posture not gating"),
        }]
    }
}

// ---------------------------------------------------------------- deployment target (SDD-013)

/// SDD-013 § 6: deployment-target sanity checks.
///
/// Surfaces likely-misconfigured deployments where the operator's
/// `target` value and on-disk state disagree:
///
/// - `target = "sain01"` but `/mnt/vault/` doesn't exist
///   → WARN: operator probably forgot to set up ZFS / mount the dataset
///     before starting the daemon; the daemon will fail to write state.
/// - `target = "generic"` but `/mnt/vault/context/selfdef-*` exists
///   → WARN: state-fork hazard — operator likely flipped from sain01
///     back to generic without migrating files (Q13-C).
///
/// Both are non-blocking (WARN, not FAIL): doctor surfaces the
/// inconsistency; the operator decides whether the state is intentional
/// (mid-migration) or a bug. The daemon's own Q13-C check ENFORCES
/// the same invariant at startup with a hard refusal.
fn check_deployment_target(cfg: &Config) -> Vec<CheckResult> {
    use selfdef_config::{state_dir, DeploymentTarget};

    let target = cfg.deployment.target;
    let mut out = Vec::new();

    // Always surface the active target — operators grep for this.
    out.push(CheckResult {
        category: "deployment".into(),
        name: "deployment.target".into(),
        status: CheckStatus::Ok,
        detail: format!(
            "target = \"{}\"; state_dir = {}",
            target,
            state_dir(target).display()
        ),
    });

    match target {
        DeploymentTarget::Sain01 => {
            // SAIN-01 needs /mnt/vault present (the ZFS pool mountpoint).
            let mnt_vault = Path::new("/mnt/vault");
            if !mnt_vault.exists() {
                out.push(CheckResult {
                    category: "deployment".into(),
                    name: "sain01 vault mountpoint".into(),
                    status: CheckStatus::Warn,
                    detail: "target=sain01 but /mnt/vault/ doesn't exist; \
                             run sovereign-os scripts/hooks/during-install/zfs-datasets-create.sh \
                             first (the daemon will fail to write state without it)"
                        .into(),
                });
            } else {
                out.push(CheckResult {
                    category: "deployment".into(),
                    name: "sain01 vault mountpoint".into(),
                    status: CheckStatus::Ok,
                    detail: "/mnt/vault/ present".into(),
                });
            }
        }
        DeploymentTarget::Generic => {
            // Generic: warn if SAIN-01 state files are present in
            // /mnt/vault/context — likely operator flipped target back
            // to generic without migrating state (state-fork hazard).
            let sain_state_dir = Path::new("/mnt/vault/context");
            if sain_state_dir.exists() {
                let sain_audit =
                    sain_state_dir.join("selfdef-audit.jsonl");
                let sain_esc =
                    sain_state_dir.join("selfdef-escalations.sqlite");
                if sain_audit.exists() || sain_esc.exists() {
                    out.push(CheckResult {
                        category: "deployment".into(),
                        name: "generic state-fork hazard".into(),
                        status: CheckStatus::Warn,
                        detail: "target=generic but selfdef state files \
                                 exist at /mnt/vault/context/; likely operator \
                                 flipped target back without migrating. Run \
                                 `selfdefctl init config --target=sain01 --force` \
                                 OR migrate /mnt/vault/context/selfdef-* to \
                                 /var/lib/selfdef/ before next daemon restart"
                            .into(),
                    });
                }
            }
        }
    }

    out
}

/// Minimal TOML scalar reader: finds `<key> = "value"` (one per
/// line, scalar string only). Used by the rbac check; the
/// agent-guard config has a fixed flat shape so this is enough.
fn extract_toml_scalar_line(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start().strip_prefix('"')?;
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    None
}

/// Walk a directory recursively and call `visit` for every
/// `*.yml`/`*.yaml` file that isn't a `.tests.yaml` fixture.
fn walk_yaml_files(root: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_yaml_files(&path, visit);
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".tests.yaml") || name.ends_with(".tests.yml") {
            continue;
        }
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            visit(&path);
        }
    }
}

#[cfg(test)]
mod sdd_013_tests {
    //! SDD-013 § 6 doctor checks.
    use super::*;
    use selfdef_config::{Config, DeploymentConfig, DeploymentTarget};

    fn cfg_with_target(t: DeploymentTarget) -> Config {
        Config {
            deployment: DeploymentConfig { target: t },
            ..Config::default()
        }
    }

    /// Both targets always surface a deployment.target row so
    /// operators grepping doctor output see the active posture.
    #[test]
    fn doctor_always_surfaces_active_target() {
        for t in [DeploymentTarget::Generic, DeploymentTarget::Sain01] {
            let cfg = cfg_with_target(t);
            let results = check_deployment_target(&cfg);
            let row = results
                .iter()
                .find(|r| r.name == "deployment.target")
                .expect("deployment.target row must surface");
            assert_eq!(row.status, CheckStatus::Ok);
            assert!(row.detail.contains(&format!("target = \"{t}\"")));
        }
    }

    /// Generic target on a host without /mnt/vault/ produces NO
    /// state-fork hazard row (no /mnt/vault/context state files).
    #[test]
    fn doctor_generic_on_clean_host_no_warn() {
        // We can't reliably control whether /mnt/vault/context exists
        // on the test host, so we test the predicate: if the dir
        // doesn't exist OR doesn't contain selfdef state, no warn row
        // appears.
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = check_deployment_target(&cfg);
        // The deployment.target row always exists; the hazard row
        // only appears when state files are present in /mnt/vault/context.
        // On the test runner with no such files, only the active-target
        // row appears.
        let hazard = results
            .iter()
            .find(|r| r.name == "generic state-fork hazard");
        let sain_state = Path::new("/mnt/vault/context");
        if !sain_state.exists()
            || (!sain_state.join("selfdef-audit.jsonl").exists()
                && !sain_state.join("selfdef-escalations.sqlite").exists())
        {
            assert!(
                hazard.is_none(),
                "no hazard row on clean host"
            );
        }
    }

    /// SAIN-01 target on a host without /mnt/vault/ warns about the
    /// missing mountpoint.
    #[test]
    fn doctor_sain01_without_vault_warns() {
        let cfg = cfg_with_target(DeploymentTarget::Sain01);
        let results = check_deployment_target(&cfg);
        let mount_row = results
            .iter()
            .find(|r| r.name == "sain01 vault mountpoint")
            .expect("vault mountpoint row must surface for sain01");
        let mnt = Path::new("/mnt/vault");
        if mnt.exists() {
            assert_eq!(mount_row.status, CheckStatus::Ok);
        } else {
            assert_eq!(mount_row.status, CheckStatus::Warn);
            assert!(mount_row.detail.contains("zfs-datasets-create.sh"));
        }
    }

    /// Doctor's main run() wires the deployment check in; results
    /// include at least one "deployment" category row.
    #[test]
    fn doctor_run_includes_deployment_category() {
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = run(&cfg);
        assert!(
            results.iter().any(|r| r.category == "deployment"),
            "doctor::run() must surface deployment checks"
        );
    }
}
