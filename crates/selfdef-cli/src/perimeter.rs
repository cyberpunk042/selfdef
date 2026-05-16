//! `selfdefctl perimeter` — Tetragon perimeter coexistence (SDD-015).
//!
//! On SAIN-01 deployments (`[deployment].target = "sain01"`), selfdef
//! and sovereign-os both author TracingPolicy YAMLs that load into the
//! same Tetragon daemon. This module ships the operator-facing tooling
//! that ensures their authorities don't overlap:
//!
//! - sovereign-os authors `sovereign-kernel-fence.yaml` — HOST-SCOPED
//!   `sys_execve` allowlist (a 4-binary whitelist of container-runtime
//!   processes; SIGKILL on anything else).
//! - selfdef authors `agent-guard-*.yaml` — CONTAINER-SCOPED policies
//!   using `matchNamespaces: [container]` selectors to govern
//!   container-internal behavior.
//!
//! **Non-overlap invariant** (SDD-015 § 1): no `agent-guard` policy
//! should EVER assert on `sys_execve` host-wide. If it does,
//! `check-overlap` flags it with the precise fix.
//!
//! Subverbs:
//! - `selfdefctl perimeter check-overlap` — overlap detector (exit 0
//!   on pass, 1 on overlap)
//! - `selfdefctl perimeter status` — show coexistence state +
//!   per-policy summary
//!
//! Each subverb is pure-Rust + reads only YAML files on disk
//! (per SDD-015 Q15-A — no Tetragon socket dep yet; `diff` lands
//! when the socket-query path is wired). Operator can run any of these
//! safely on a host without Tetragon installed; they'll just report
//! "no policies present" cleanly.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::warn;

/// Selfdef-authored policy filename prefix. Used as the
/// `policy_name` discriminator in Tetragon events (SDD-015 § 5):
/// events whose `policy_name` starts with this prefix are routed to
/// selfdef's audit pipeline; everything else is sovereign-os's
/// guardian-core's responsibility.
pub(crate) const SELFDEF_POLICY_PREFIX: &str = "agent-guard-";

/// Filename-stem prefix for sovereign-os policies (currently only
/// `sovereign-kernel-fence`, but we use a prefix to future-proof for
/// additional sovereign-os-authored policies).
pub(crate) const SOVEREIGN_POLICY_PREFIX: &str = "sovereign-";

/// Syscalls considered HIGH-SENSITIVITY for the boundary check.
/// A selfdef policy that asserts on these without container-scope
/// would overlap with sovereign-kernel-fence — and gets flagged.
const HOST_SCOPED_SYSCALLS: &[&str] = &["sys_execve", "sys_execveat", "tcp_connect", "tcp_sendmsg"];

/// SDD-015 § 5: policy_name → discriminator. selfdef daemon should
/// only emit shared-audit-summary lines for events whose
/// `policy_name` starts with [`SELFDEF_POLICY_PREFIX`]. Sovereign-os's
/// guardian-core handles the rest. Returns `true` iff selfdef should
/// claim ownership of an event with this `policy_name`.
/// Exposed for the daemon's audit-log filter — gets wired up when the
/// Tetragon event-stream subscriber lands (Stage-2+ post SDD-016).
#[must_use]
#[allow(dead_code)]
pub(crate) fn is_selfdef_policy(policy_name: &str) -> bool {
    policy_name.starts_with(SELFDEF_POLICY_PREFIX)
}

// ---------------------------------------------------------------- yaml schema

/// Minimal TracingPolicy YAML representation — only the fields needed
/// for overlap detection. Tetragon's full schema is much richer; we
/// deserialize just what we need and ignore the rest via serde's
/// default-on-missing behavior.
#[derive(Debug, Clone, Deserialize)]
struct TracingPolicyDoc {
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    spec: Spec,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Spec {
    #[serde(default)]
    kprobes: Vec<Kprobe>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Kprobe {
    #[serde(default)]
    call: String,
    #[serde(default)]
    selectors: Vec<Selector>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Selector {
    #[serde(default, rename = "matchNamespaces")]
    match_namespaces: Vec<MatchNamespace>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MatchNamespace {
    #[serde(default)]
    operator: String,
    #[serde(default)]
    values: Vec<String>,
}

// ---------------------------------------------------------------- summary

/// Operator-readable summary of one policy. Built from a parsed YAML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicySummary {
    /// Filename on disk (relative to the policies dir).
    pub(crate) filename: String,
    /// `metadata.name` from the YAML — Tetragon's unique-id field.
    pub(crate) metadata_name: String,
    /// Author classification: "selfdef" | "sovereign-os" | "third-party".
    pub(crate) author: String,
    /// One line per kprobe with classified scope.
    pub(crate) kprobes: Vec<KprobeSummary>,
}

/// One kprobe's effective scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KprobeSummary {
    /// Syscall name (e.g. `sys_execve`).
    pub(crate) call: String,
    /// `host` or `container` based on the selectors' matchNamespaces.
    pub(crate) scope: PolicyScope,
}

/// Effective scope of a kprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyScope {
    /// No `matchNamespaces` selector or no `container` value — fires
    /// host-wide.
    Host,
    /// Has at least one selector with `matchNamespaces.values = [container]`
    /// (operator In) — fires only inside containers.
    Container,
}

impl PolicyScope {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Container => "container",
        }
    }
}

impl std::fmt::Display for PolicyScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Overlap-check finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OverlapFinding {
    /// Two policies share the same `metadata.name` — Tetragon would
    /// reject one or load both with non-deterministic ordering.
    DuplicateMetadataName { name: String, files: Vec<String> },
    /// A selfdef policy declares a host-scoped kprobe on a syscall
    /// that sovereign-os also fences. Operator must add a
    /// `matchNamespaces: { operator: In, values: [container] }`
    /// selector to scope it.
    SelfdefHostScopedOnFencedSyscall {
        filename: String,
        metadata_name: String,
        syscall: String,
    },
    /// SDD-015 Q15-D: a third-party policy (neither selfdef- nor
    /// sovereign-os-authored) was observed. Emitted at WARN severity
    /// by default; promoted to FAIL when
    /// [perimeter] third_party_policy_stance = "block".
    ThirdPartyPolicyObserved {
        filename: String,
        metadata_name: String,
    },
    /// SDD-015 Q15-D + § 1: a third-party policy declares a
    /// host-scoped kprobe on a fenced syscall. Same shape as
    /// SelfdefHostScopedOnFencedSyscall but distinguished by author.
    /// Emitted iff `third_party_policy_stance == "block"`.
    ThirdPartyHostScopedOnFencedSyscall {
        filename: String,
        metadata_name: String,
        syscall: String,
    },
}

impl OverlapFinding {
    /// Operator-readable one-line render.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        match self {
            Self::DuplicateMetadataName { name, files } => format!(
                "duplicate metadata.name {name:?}: appears in {}",
                files.join(", ")
            ),
            Self::SelfdefHostScopedOnFencedSyscall {
                filename,
                metadata_name,
                syscall,
            } => format!(
                "{filename} ({metadata_name}) asserts on {syscall} without matchNamespaces=container scope — \
                 would conflict with sovereign-kernel-fence's host-wide allowlist. \
                 Fix: add 'matchNamespaces: {{ operator: In, values: [container] }}' to the selector"
            ),
            Self::ThirdPartyPolicyObserved {
                filename,
                metadata_name,
            } => format!(
                "third-party policy observed: {filename} ({metadata_name}) — \
                 author is neither selfdef nor sovereign-os; \
                 treating as opaque per [perimeter] third_party_policy_stance"
            ),
            Self::ThirdPartyHostScopedOnFencedSyscall {
                filename,
                metadata_name,
                syscall,
            } => format!(
                "{filename} ({metadata_name}) is a third-party policy asserting on {syscall} host-wide — \
                 [perimeter] third_party_policy_stance = \"block\" treats this as conflict. \
                 Either scope to container, or set stance = \"warn\" (default) / \"ignore\""
            ),
        }
    }
}

// ---------------------------------------------------------------- core API

/// Parse all `*.yaml` / `*.yml` policy files in `dir`. Returns one
/// [`PolicySummary`] per file. Bad YAML is logged + skipped (operator
/// gets a WARN; the overlap check proceeds with what parses).
pub(crate) fn read_policies_dir(dir: &Path) -> Result<Vec<PolicySummary>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.ends_with(".yaml") || name.ends_with(".yml")) {
            continue;
        }
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "policy file unreadable; skipping");
                continue;
            }
        };
        match parse_policy(name, &body) {
            Ok(summary) => out.push(summary),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "policy YAML parse failed; skipping");
            }
        }
    }
    // Deterministic order for operator-facing output.
    out.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(out)
}

/// Parse a single policy YAML body. `filename` is just the display
/// name used in summaries — the YAML body is the source of truth for
/// metadata.name + spec.
pub(crate) fn parse_policy(filename: &str, body: &str) -> Result<PolicySummary> {
    let doc: TracingPolicyDoc = serde_yaml_ng::from_str(body).context("parse YAML")?;
    let author = classify_author(filename);
    let kprobes = doc
        .spec
        .kprobes
        .into_iter()
        .map(|k| KprobeSummary {
            call: k.call.clone(),
            scope: classify_scope(&k),
        })
        .collect();
    Ok(PolicySummary {
        filename: filename.to_owned(),
        metadata_name: doc.metadata.name,
        author,
        kprobes,
    })
}

fn classify_author(filename: &str) -> String {
    if filename.starts_with(SELFDEF_POLICY_PREFIX) {
        "selfdef".to_owned()
    } else if filename.starts_with(SOVEREIGN_POLICY_PREFIX) {
        "sovereign-os".to_owned()
    } else {
        "third-party".to_owned()
    }
}

/// SDD-015 § 1 verbatim: a kprobe is container-scoped iff at least
/// one selector has `matchNamespaces` with `operator: In` and
/// `container` in `values`. Anything else fires host-wide.
fn classify_scope(k: &Kprobe) -> PolicyScope {
    for sel in &k.selectors {
        for mn in &sel.match_namespaces {
            if mn.operator == "In" && mn.values.iter().any(|v| v == "container") {
                return PolicyScope::Container;
            }
        }
    }
    PolicyScope::Host
}

/// SDD-015 § 2 + § 1: detect overlap findings across a set of policies.
///
/// Reports:
/// - Duplicate `metadata.name`s across files
/// - Selfdef-authored policies that declare a HOST-scoped kprobe on a
///   syscall sovereign-kernel-fence governs
/// - Third-party policies are NOT flagged (use [`check_overlap_with_stance`]
///   to handle them per Q15-D).
///
/// Kept as a backwards-compat shim around
/// [`check_overlap_with_stance`] with `stance = "ignore"` — historical
/// callers + tests that don't care about the third-party axis stay
/// stable.
#[allow(dead_code)]
pub(crate) fn check_overlap(policies: &[PolicySummary]) -> Vec<OverlapFinding> {
    check_overlap_with_stance(policies, "ignore")
}

/// SDD-015 Q15-D: like [`check_overlap`] but honors a third-party
/// stance. `stance` ∈ {"warn", "ignore", "block"}:
///   - `"ignore"` — third-party policies never produce findings.
///   - `"warn"` (default) — emit a [`OverlapFinding::ThirdPartyPolicyObserved`]
///     informational finding per third-party policy. The render layer
///     treats these as WARN, not FAIL — operator's discretion.
///   - `"block"` — third-party policies are subject to the same
///     host-scoped-fenced-syscall check as selfdef policies, and the
///     existence of one emits both
///     [`OverlapFinding::ThirdPartyPolicyObserved`] (WARN) AND
///     [`OverlapFinding::ThirdPartyHostScopedOnFencedSyscall`] (FAIL)
///     when relevant.
pub(crate) fn check_overlap_with_stance(
    policies: &[PolicySummary],
    stance: &str,
) -> Vec<OverlapFinding> {
    let mut findings = Vec::new();

    // 1. Duplicate metadata.name
    use std::collections::HashMap;
    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
    for p in policies {
        if p.metadata_name.is_empty() {
            continue;
        }
        by_name
            .entry(p.metadata_name.clone())
            .or_default()
            .push(p.filename.clone());
    }
    let mut dup_names: Vec<(String, Vec<String>)> =
        by_name.into_iter().filter(|(_, fs)| fs.len() > 1).collect();
    dup_names.sort();
    for (name, mut files) in dup_names {
        files.sort();
        findings.push(OverlapFinding::DuplicateMetadataName { name, files });
    }

    // 2. Selfdef host-scoped on fenced syscalls
    for p in policies {
        if p.author != "selfdef" {
            continue;
        }
        for kp in &p.kprobes {
            if kp.scope == PolicyScope::Host && HOST_SCOPED_SYSCALLS.contains(&kp.call.as_str()) {
                findings.push(OverlapFinding::SelfdefHostScopedOnFencedSyscall {
                    filename: p.filename.clone(),
                    metadata_name: p.metadata_name.clone(),
                    syscall: kp.call.clone(),
                });
            }
        }
    }

    // 3. SDD-015 Q15-D: third-party policy stance handling.
    if stance != "ignore" {
        for p in policies {
            if p.author != "third-party" {
                continue;
            }
            // Always emit the observation (warn-class) when stance != ignore.
            findings.push(OverlapFinding::ThirdPartyPolicyObserved {
                filename: p.filename.clone(),
                metadata_name: p.metadata_name.clone(),
            });
            // Promote to host-scoped-block when stance == block.
            if stance == "block" {
                for kp in &p.kprobes {
                    if kp.scope == PolicyScope::Host
                        && HOST_SCOPED_SYSCALLS.contains(&kp.call.as_str())
                    {
                        findings.push(OverlapFinding::ThirdPartyHostScopedOnFencedSyscall {
                            filename: p.filename.clone(),
                            metadata_name: p.metadata_name.clone(),
                            syscall: kp.call.clone(),
                        });
                    }
                }
            }
        }
    }

    findings
}

/// SDD-015 Q15-D: classify a finding as blocking (FAIL → exit 1) vs
/// advisory (WARN → exit 0). Default `check_overlap` returns the
/// blocking-only subset; `check_overlap_with_stance` may produce
/// advisory findings (third-party observations under stance=warn).
#[must_use]
pub(crate) fn finding_is_blocking(f: &OverlapFinding) -> bool {
    matches!(
        f,
        OverlapFinding::DuplicateMetadataName { .. }
            | OverlapFinding::SelfdefHostScopedOnFencedSyscall { .. }
            | OverlapFinding::ThirdPartyHostScopedOnFencedSyscall { .. }
    )
}

// ---------------------------------------------------------------- rendering

/// Render the check-overlap report. Returns `(text, exit_code)`.
pub(crate) fn render_check_overlap_report(
    policies: &[PolicySummary],
    findings: &[OverlapFinding],
) -> (String, i32) {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(&mut buf, "# selfdefctl perimeter check-overlap (SDD-015)").unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Loaded policies").unwrap();
    if policies.is_empty() {
        writeln!(&mut buf, "  (no policies present)").unwrap();
    } else {
        for p in policies {
            writeln!(
                &mut buf,
                "  {:<48} author={:<13} metadata.name={}",
                p.filename, p.author, p.metadata_name
            )
            .unwrap();
            for kp in &p.kprobes {
                writeln!(&mut buf, "      kprobe call={} scope={}", kp.call, kp.scope).unwrap();
            }
        }
    }
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Findings").unwrap();
    if findings.is_empty() {
        writeln!(&mut buf, "  PASS — no host-wide kprobe overlap detected").unwrap();
        writeln!(
            &mut buf,
            "  PASS — all policies have distinct metadata.name"
        )
        .unwrap();
        (buf, 0)
    } else {
        // SDD-015 Q15-D: split into WARN (advisory) + FAIL (blocking).
        let mut blocking_count = 0usize;
        for f in findings {
            if finding_is_blocking(f) {
                blocking_count += 1;
                writeln!(&mut buf, "  FAIL — {}", f.render()).unwrap();
            } else {
                writeln!(&mut buf, "  WARN — {}", f.render()).unwrap();
            }
        }
        writeln!(&mut buf).unwrap();
        if blocking_count == 0 {
            writeln!(
                &mut buf,
                "Exit 0. {} advisory finding(s); no blocking overlap.",
                findings.len()
            )
            .unwrap();
            (buf, 0)
        } else {
            writeln!(
                &mut buf,
                "Exit 1. {blocking_count} blocking finding(s). Fix the FAIL items \
                 above, or set `[perimeter] overlap_warn_only = true` to downgrade."
            )
            .unwrap();
            (buf, 1)
        }
    }
}

// ---------------------------------------------------------------- entry point

/// Top-level `selfdefctl perimeter check-overlap` dispatch. Reads
/// `[perimeter]` config, scans the policies dir, runs overlap check,
/// renders + prints, returns exit code.
pub(crate) fn run_check_overlap(cfg: &selfdef_config::Config) -> Result<i32> {
    let target = cfg.deployment.target;
    if matches!(target, selfdef_config::DeploymentTarget::Generic)
        && !selfdef_config::resolve_perimeter_check_overlap(cfg)
    {
        println!(
            "# selfdefctl perimeter check-overlap (SDD-015)\n\
             \n\
             skip — deployment.target = generic and [perimeter] check_overlap_on_apply not set;\n\
             coexistence is not assumed on non-SAIN-01 deployments (SDD-012 Q-G honored).\n\
             To force the check on a generic deployment, set:\n\
             [perimeter]\n\
             check_overlap_on_apply = true\n"
        );
        return Ok(0);
    }
    let dir = &cfg.perimeter.policies_dir;
    let policies = read_policies_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    let stance = cfg.perimeter.third_party_policy_stance.as_str();
    let findings = check_overlap_with_stance(&policies, stance);

    if !findings.is_empty() && cfg.perimeter.overlap_warn_only {
        // Q15-B: warn-only mode emits findings but exits 0.
        let (mut text, _exit) = render_check_overlap_report(&policies, &findings);
        text.push_str(
            "\n[perimeter] overlap_warn_only = true — overlaps treated as WARN; exit 0.\n",
        );
        print!("{text}");
        return Ok(0);
    }
    let (text, exit) = render_check_overlap_report(&policies, &findings);
    print!("{text}");
    Ok(exit)
}

/// `selfdefctl perimeter status` — concise coexistence state.
pub(crate) fn run_status(cfg: &selfdef_config::Config) -> Result<i32> {
    let target = cfg.deployment.target;
    let check_active = selfdef_config::resolve_perimeter_check_overlap(cfg);
    println!("# selfdefctl perimeter status (SDD-015)");
    println!();
    println!("  deployment.target:          {target}");
    println!("  check-overlap on apply:     {check_active}");
    println!(
        "  policies_dir:               {}",
        cfg.perimeter.policies_dir.display()
    );
    println!(
        "  sovereign_kernel_fence:     {}",
        cfg.perimeter.sovereign_kernel_fence_path.display()
    );
    println!(
        "  overlap_warn_only:          {}",
        cfg.perimeter.overlap_warn_only
    );
    let policies = read_policies_dir(&cfg.perimeter.policies_dir).unwrap_or_default();
    let selfdef_count = policies.iter().filter(|p| p.author == "selfdef").count();
    let sovereign_count = policies
        .iter()
        .filter(|p| p.author == "sovereign-os")
        .count();
    let third_party_count = policies
        .iter()
        .filter(|p| p.author == "third-party")
        .count();
    println!();
    println!(
        "  policies on disk:  selfdef={selfdef_count}  sovereign-os={sovereign_count}  third-party={third_party_count}"
    );
    Ok(0)
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_config::{Config, DeploymentConfig, DeploymentTarget, PerimeterConfig};
    use tempfile::tempdir;

    const AGENT_GUARD_SHELL_EXEC: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: agent-guard-shell-exec
spec:
  kprobes:
    - call: sys_execve
      selectors:
        - matchNamespaces:
            - operator: In
              values: [container]
"#;

    const AGENT_GUARD_HOST_WIDE: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: agent-guard-bad
spec:
  kprobes:
    - call: sys_execve
"#;

    const SOVEREIGN_KERNEL_FENCE: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sovereign-kernel-fence
spec:
  kprobes:
    - call: sys_execve
"#;

    const AGENT_GUARD_DUP_A: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: agent-guard-etc-write
spec:
  kprobes:
    - call: sys_openat
      selectors:
        - matchNamespaces:
            - operator: In
              values: [container]
"#;

    const AGENT_GUARD_DUP_B: &str = AGENT_GUARD_DUP_A;

    /// SDD-015 § 1: a properly-scoped agent-guard policy passes.
    #[test]
    fn sdd_015_no_overlap_passes() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("sovereign-kernel-fence.yaml"),
            SOVEREIGN_KERNEL_FENCE,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("agent-guard-shell-exec.yaml"),
            AGENT_GUARD_SHELL_EXEC,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        assert_eq!(policies.len(), 2);
        let findings = check_overlap(&policies);
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    /// SDD-015 § 7: host-scoped agent-guard sys_execve fails the boundary.
    #[test]
    fn sdd_015_host_scoped_sys_execve_in_agent_guard_fails_overlap() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("agent-guard-bad.yaml"),
            AGENT_GUARD_HOST_WIDE,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        let findings = check_overlap(&policies);
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            OverlapFinding::SelfdefHostScopedOnFencedSyscall { syscall, .. } => {
                assert_eq!(syscall, "sys_execve");
            }
            other => panic!("expected host-scoped finding, got {other:?}"),
        }
    }

    /// SDD-015 § 7: two policies sharing metadata.name flagged.
    #[test]
    fn sdd_015_duplicate_metadata_name_fails() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("agent-guard-etc-write-a.yaml"),
            AGENT_GUARD_DUP_A,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("agent-guard-etc-write-b.yaml"),
            AGENT_GUARD_DUP_B,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        assert_eq!(policies.len(), 2);
        let findings = check_overlap(&policies);
        let dup = findings
            .iter()
            .find(|f| matches!(f, OverlapFinding::DuplicateMetadataName { .. }));
        assert!(dup.is_some(), "expected duplicate-name finding");
    }

    /// SDD-015 § 7: check_overlap is a no-op on Generic when the
    /// resolver returns false (skip path).
    #[test]
    fn sdd_015_check_overlap_skipped_on_generic_target() {
        let cfg = Config::default(); // Generic
        let result = run_check_overlap(&cfg).unwrap();
        assert_eq!(result, 0);
    }

    /// SDD-015 § 5: policy_name prefix filter — selfdef claims
    /// `agent-guard-*` events; sovereign-os claims the rest.
    #[test]
    fn sdd_015_audit_log_filter_by_policy_name_prefix() {
        assert!(is_selfdef_policy("agent-guard-shell-exec"));
        assert!(is_selfdef_policy("agent-guard-bad"));
        assert!(!is_selfdef_policy("sovereign-kernel-fence"));
        assert!(!is_selfdef_policy("third-party-policy"));
        assert!(!is_selfdef_policy(""));
    }

    /// Scope classifier: explicit container scope detected.
    #[test]
    fn sdd_015_scope_container_via_match_namespaces() {
        let policy = parse_policy("agent-guard-shell-exec.yaml", AGENT_GUARD_SHELL_EXEC).unwrap();
        assert_eq!(policy.kprobes.len(), 1);
        assert_eq!(policy.kprobes[0].scope, PolicyScope::Container);
    }

    /// Scope classifier: no selector = host scope.
    #[test]
    fn sdd_015_scope_host_when_no_match_namespaces() {
        let policy = parse_policy("agent-guard-bad.yaml", AGENT_GUARD_HOST_WIDE).unwrap();
        assert_eq!(policy.kprobes.len(), 1);
        assert_eq!(policy.kprobes[0].scope, PolicyScope::Host);
    }

    /// classify_author distinguishes selfdef / sovereign-os / third-party.
    #[test]
    fn sdd_015_classify_author_by_filename_prefix() {
        assert_eq!(classify_author("agent-guard-shell-exec.yaml"), "selfdef");
        assert_eq!(
            classify_author("sovereign-kernel-fence.yaml"),
            "sovereign-os"
        );
        assert_eq!(classify_author("custom-thing.yaml"), "third-party");
    }

    /// Empty dir → no policies, no findings.
    #[test]
    fn sdd_015_empty_dir_no_policies() {
        let dir = tempdir().unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        assert!(policies.is_empty());
        let findings = check_overlap(&policies);
        assert!(findings.is_empty());
    }

    /// Missing dir → no error (operators without Tetragon installed
    /// don't get a hard fail from `selfdefctl perimeter` invocations).
    #[test]
    fn sdd_015_missing_dir_no_error() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("not-a-real-subdir");
        let policies = read_policies_dir(&nonexistent).unwrap();
        assert!(policies.is_empty());
    }

    /// Bad YAML is logged + skipped; check_overlap continues with what
    /// parses (operator gets WARN in journald + a partial report).
    #[test]
    fn sdd_015_bad_yaml_is_skipped() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("bad.yaml"), "this is: not: valid: yaml: [[").unwrap();
        std::fs::write(
            dir.path().join("agent-guard-shell-exec.yaml"),
            AGENT_GUARD_SHELL_EXEC,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        // Bad file skipped; good one present.
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].filename, "agent-guard-shell-exec.yaml");
    }

    /// Render produces operator-readable output with PASS/FAIL markers.
    #[test]
    fn sdd_015_render_report_on_pass_and_fail() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("agent-guard-bad.yaml"),
            AGENT_GUARD_HOST_WIDE,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        let findings = check_overlap(&policies);
        let (text, exit) = render_check_overlap_report(&policies, &findings);
        assert_eq!(exit, 1);
        assert!(text.contains("FAIL"));
        assert!(text.contains("matchNamespaces"));
        assert!(text.contains("agent-guard-bad.yaml"));
        // Pass-path
        let empty: Vec<PolicySummary> = Vec::new();
        let (text_ok, exit_ok) = render_check_overlap_report(&empty, &[]);
        assert_eq!(exit_ok, 0);
        assert!(text_ok.contains("PASS"));
    }

    /// SDD-015 § 4 + Q15-B: overlap_warn_only=true downgrades FAIL→WARN
    /// (exit 0 with findings printed).
    #[test]
    fn sdd_015_overlap_warn_only_downgrades_exit() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("agent-guard-bad.yaml"),
            AGENT_GUARD_HOST_WIDE,
        )
        .unwrap();
        let cfg = Config {
            deployment: DeploymentConfig {
                target: DeploymentTarget::Sain01,
            },
            perimeter: PerimeterConfig {
                policies_dir: dir.path().to_path_buf(),
                overlap_warn_only: true,
                ..PerimeterConfig::default()
            },
            ..Config::default()
        };
        let exit = run_check_overlap(&cfg).unwrap();
        assert_eq!(exit, 0, "warn-only mode must exit 0 despite findings");
    }

    // ----------------------------------------------------------------
    // SDD-015 Q15-D third-party stance tests (SD-R6)
    // ----------------------------------------------------------------

    const THIRD_PARTY_CONTAINER_SCOPED: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: third-party-policy
spec:
  kprobes:
    - call: sys_openat
      selectors:
        - matchNamespaces:
            - operator: In
              values: [container]
"#;

    const THIRD_PARTY_HOST_SCOPED_EXECVE: &str = r#"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: third-party-bad
spec:
  kprobes:
    - call: sys_execve
"#;

    /// Q15-D: ignore stance — no third-party findings, ever.
    #[test]
    fn q15d_third_party_stance_ignore_emits_nothing() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("custom-third.yaml"),
            THIRD_PARTY_CONTAINER_SCOPED,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("custom-bad.yaml"),
            THIRD_PARTY_HOST_SCOPED_EXECVE,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        let findings = check_overlap_with_stance(&policies, "ignore");
        assert!(
            findings.is_empty(),
            "ignore stance must emit nothing for third-party: got {findings:?}"
        );
    }

    /// Q15-D: warn stance (default) — third-party observation emitted
    /// per file, NOT blocking. Render reports exit 0.
    #[test]
    fn q15d_third_party_stance_warn_emits_observation_non_blocking() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("custom-third.yaml"),
            THIRD_PARTY_CONTAINER_SCOPED,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        let findings = check_overlap_with_stance(&policies, "warn");
        // One ThirdPartyPolicyObserved, no blocking.
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0],
            OverlapFinding::ThirdPartyPolicyObserved { .. }
        ));
        assert!(!finding_is_blocking(&findings[0]));
        // Render reports exit 0 because no FAIL findings.
        let (_text, exit) = render_check_overlap_report(&policies, &findings);
        assert_eq!(exit, 0, "warn-only third-party → exit 0");
    }

    /// Q15-D: block stance — host-scoped third-party syscall is FAIL.
    #[test]
    fn q15d_third_party_stance_block_fails_on_host_scoped() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("custom-bad.yaml"),
            THIRD_PARTY_HOST_SCOPED_EXECVE,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        let findings = check_overlap_with_stance(&policies, "block");
        // Observation + host-scoped-block finding (2 findings).
        assert_eq!(findings.len(), 2);
        let has_block = findings.iter().any(|f| {
            matches!(
                f,
                OverlapFinding::ThirdPartyHostScopedOnFencedSyscall { .. }
            )
        });
        assert!(has_block);
        let blocking_count = findings.iter().filter(|f| finding_is_blocking(f)).count();
        assert_eq!(blocking_count, 1);
        let (_text, exit) = render_check_overlap_report(&policies, &findings);
        assert_eq!(exit, 1, "block stance + host-scoped third-party → exit 1");
    }

    /// Q15-D: block stance + container-scoped third-party syscall is
    /// observation-only (no block).
    #[test]
    fn q15d_third_party_stance_block_allows_container_scoped() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("custom-third.yaml"),
            THIRD_PARTY_CONTAINER_SCOPED,
        )
        .unwrap();
        let policies = read_policies_dir(dir.path()).unwrap();
        let findings = check_overlap_with_stance(&policies, "block");
        // Just the observation (container-scoped is not a fence overlap).
        assert_eq!(findings.len(), 1);
        assert!(!finding_is_blocking(&findings[0]));
    }

    /// SDD-015: finding_is_blocking classifies findings correctly.
    #[test]
    fn q15d_finding_is_blocking_taxonomy() {
        assert!(finding_is_blocking(
            &OverlapFinding::DuplicateMetadataName {
                name: "x".into(),
                files: vec![],
            }
        ));
        assert!(finding_is_blocking(
            &OverlapFinding::SelfdefHostScopedOnFencedSyscall {
                filename: "x".into(),
                metadata_name: "x".into(),
                syscall: "sys_execve".into(),
            }
        ));
        assert!(finding_is_blocking(
            &OverlapFinding::ThirdPartyHostScopedOnFencedSyscall {
                filename: "x".into(),
                metadata_name: "x".into(),
                syscall: "sys_execve".into(),
            }
        ));
        assert!(!finding_is_blocking(
            &OverlapFinding::ThirdPartyPolicyObserved {
                filename: "x".into(),
                metadata_name: "x".into(),
            }
        ));
    }
}
