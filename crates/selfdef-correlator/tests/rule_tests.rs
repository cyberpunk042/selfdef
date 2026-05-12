//! Detection-as-code: every rule with a sibling `.tests.yaml` file is
//! exercised. Failures here block merges in CI.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

use selfdef_core::Event;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_correlator::sigma::{Engine, RawRule, compile_rule};
use serde::Deserialize;

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../..")
}

#[derive(Debug, Deserialize)]
struct TestFile {
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    name: String,
    events: Vec<EventSpec>,
    expected_findings: usize,
}

/// Partial event spec. Required fields default sensibly; all observables
/// optional so tests are terse.
#[derive(Debug, Default, Clone, Deserialize)]
struct EventSpec {
    #[serde(default)]
    class_uid: Option<u32>,
    #[serde(default)]
    activity_id: Option<u32>,
    #[serde(default)]
    severity_id: Option<u32>,
    #[serde(default)]
    status_id: Option<u32>,
    #[serde(default)]
    host_tag: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    actor: Option<Actor>,
    #[serde(default)]
    process: Option<Process>,
    #[serde(default)]
    file: Option<File>,
    #[serde(default)]
    src_endpoint: Option<Endpoint>,
    #[serde(default)]
    dst_endpoint: Option<Endpoint>,
    #[serde(default)]
    raw: Option<serde_json::Value>,
}

fn severity_from_id(id: u32) -> SeverityId {
    match id {
        0 => SeverityId::Unknown,
        1 => SeverityId::Informational,
        2 => SeverityId::Low,
        3 => SeverityId::Medium,
        4 => SeverityId::High,
        5 => SeverityId::Critical,
        6 => SeverityId::Fatal,
        _ => SeverityId::Other,
    }
}

fn status_from_id(id: u32) -> StatusId {
    match id {
        0 => StatusId::Unknown,
        1 => StatusId::Success,
        2 => StatusId::Failure,
        _ => StatusId::Other,
    }
}

impl EventSpec {
    fn into_event(self) -> Event {
        let mut event = Event::new(
            ClassUid::new(self.class_uid.unwrap_or(0)),
            self.activity_id.unwrap_or(0),
            severity_from_id(self.severity_id.unwrap_or(1)),
            self.host_tag.unwrap_or_else(|| "test-host".into()),
            self.source.unwrap_or_else(|| "test".into()),
            0,
        );
        if let Some(sid) = self.status_id {
            event = event.with_status(status_from_id(sid));
        }
        if let Some(m) = self.message {
            event = event.with_message(m);
        }
        if let Some(a) = self.actor {
            event = event.with_actor(a);
        }
        if let Some(p) = self.process {
            event = event.with_process(p);
        }
        if let Some(f) = self.file {
            event = event.with_file(f);
        }
        if let Some(e) = self.src_endpoint {
            event = event.with_src_endpoint(e);
        }
        if let Some(e) = self.dst_endpoint {
            event = event.with_dst_endpoint(e);
        }
        if let Some(r) = self.raw {
            event = event.with_raw(r);
        }
        event
    }
}

fn walk_rule_yaml(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.exists() {
        return out;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // Rules: *.yml or *.yaml that are not *.tests.yaml
            if name.ends_with(".tests.yaml") || name.ends_with(".tests.yml") {
                continue;
            }
            if name.ends_with(".yml") || name.ends_with(".yaml") {
                out.push(path);
            }
        }
    }
    out
}

fn load_single_rule(path: &Path) -> Result<selfdef_correlator::sigma::CompiledRule, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let raw: RawRule = serde_yaml_ng::from_str(&content).map_err(|e| e.to_string())?;
    compile_rule(raw, path.to_path_buf()).map_err(|e| e.to_string())
}

fn run_case(rule_path: &Path, case: &TestCase) -> Result<(), String> {
    let rule = load_single_rule(rule_path)?;
    let engine = Engine::with_rules(vec![rule]);
    let seq = AtomicU64::new(0);

    let mut findings = 0;
    for spec in &case.events {
        let event = spec.clone().into_event();
        findings += engine.process(&event, "test-host", &seq).len();
    }

    if findings != case.expected_findings {
        return Err(format!(
            "expected {} findings, got {}",
            case.expected_findings, findings
        ));
    }
    Ok(())
}

#[test]
fn every_rule_with_tests_passes() {
    let rules_dir = workspace_root().join("rules/sigma");
    let rules = walk_rule_yaml(&rules_dir);

    assert!(
        !rules.is_empty(),
        "no rules discovered in {}",
        rules_dir.display()
    );

    let mut tested_rules = HashSet::new();
    let mut total = 0;
    let mut failures: Vec<(PathBuf, String, String)> = Vec::new();

    for rule_path in &rules {
        let test_path = sibling_tests_path(rule_path);
        if !test_path.exists() {
            continue;
        }
        tested_rules.insert(rule_path.clone());

        let content = std::fs::read_to_string(&test_path)
            .unwrap_or_else(|e| panic!("read {}: {}", test_path.display(), e));
        let tf: TestFile = serde_yaml_ng::from_str(&content)
            .unwrap_or_else(|e| panic!("parse {}: {}", test_path.display(), e));

        for case in &tf.tests {
            total += 1;
            if let Err(e) = run_case(rule_path, case) {
                failures.push((rule_path.clone(), case.name.clone(), e));
            }
        }
    }

    eprintln!(
        "rule-tests: {} cases across {} rules ({} rule files total)",
        total,
        tested_rules.len(),
        rules.len()
    );

    if !failures.is_empty() {
        for (path, name, err) in &failures {
            eprintln!("FAIL  {} :: {} — {}", path.display(), name, err);
        }
        panic!("{} of {} rule tests failed", failures.len(), total);
    }

    // Soft warning: rules without a tests file
    let untested: Vec<_> = rules
        .iter()
        .filter(|p| !tested_rules.contains(*p))
        .collect();
    if !untested.is_empty() {
        eprintln!("WARN: {} rule(s) have no tests yet:", untested.len());
        for p in untested {
            eprintln!("  {}", p.display());
        }
    }
}

fn sibling_tests_path(rule_path: &Path) -> PathBuf {
    // foo.yml → foo.tests.yaml in the same directory.
    let stem = rule_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    rule_path.with_file_name(format!("{stem}.tests.yaml"))
}

#[test]
fn rule_set_passes_lint() {
    let rules_dir = workspace_root().join("rules/sigma");
    let engine = Engine::load_dir(&rules_dir).expect("load");
    let issues = selfdef_correlator::lint::lint_rules(engine.rules());

    let errors: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.severity, selfdef_correlator::lint::Severity::Error))
        .collect();
    let warns: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.severity, selfdef_correlator::lint::Severity::Warn))
        .collect();

    eprintln!(
        "rule-lint: {} errors, {} warnings across {} rules",
        errors.len(),
        warns.len(),
        engine.rule_count()
    );
    for w in &warns {
        eprintln!("  {w}");
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("  {e}");
        }
        panic!("{} lint errors", errors.len());
    }
}

#[test]
fn attack_coverage_report() {
    let rules_dir = workspace_root().join("rules/sigma");
    let engine = Engine::load_dir(&rules_dir).expect("load");
    let coverage = engine.attack_coverage();

    eprintln!("ATT&CK coverage:");
    eprintln!("  techniques: {}", coverage.techniques.len());
    eprintln!("  tactics:    {}", coverage.tactics.len());
    for (tactic, count) in &coverage.rules_per_tactic {
        eprintln!("    {tactic:?}: {count} rules");
    }
    eprintln!("  full technique set:");
    for t in &coverage.techniques {
        eprintln!("    - {t}");
    }

    // Coverage gate: a non-trivial rule set should cover something.
    assert!(
        !coverage.techniques.is_empty(),
        "no ATT&CK techniques covered"
    );
}
