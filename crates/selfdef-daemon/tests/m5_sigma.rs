//! M5 integration test for the Sigma engine.
//!
//! Three scenarios:
//! 1. Replay a JSONL corpus through the engine and count findings.
//! 2. Validate engine handles multiple co-resident rules.
//! 3. Hot reload swaps rules without restarting the correlator.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_core::Event;
use selfdef_correlator::Correlator;
use selfdef_correlator::sigma::Engine;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

const SSH_RULE: &str = r#"
title: SSH Brute Force
id: rule-ssh-brute
tags: [attack.credential_access, attack.t1110]
logsource: { service: auditd }
detection:
  failed:
    class_uid: 3002
    status_id: 2
  timeframe: 60s
  condition: failed | count() by src_endpoint.ip > 2
level: high
"#;

const FAILED_LOGIN_RULE: &str = r#"
title: Any Failed Login
id: rule-any-failed-login
tags: [attack.credential_access]
logsource: { service: auditd }
detection:
  fail:
    class_uid: 3002
    status_id: 2
  condition: fail
level: low
"#;

const SUDOERS_RULE: &str = r#"
title: Sudoers Tamper
id: rule-sudoers-tamper
tags: [attack.persistence, attack.t1098]
logsource: { service: auditd }
detection:
  write:
    class_uid: 1001
    file.path|contains: "/etc/sudoers"
  condition: write
level: high
"#;

#[test]
fn engine_loads_rules_from_directory() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("ssh.yml"), SSH_RULE).unwrap();
    std::fs::write(dir.path().join("login.yml"), FAILED_LOGIN_RULE).unwrap();
    std::fs::write(dir.path().join("sudoers.yml"), SUDOERS_RULE).unwrap();

    let engine = Engine::load_dir(dir.path()).expect("load");
    assert_eq!(engine.rule_count(), 3);
}

#[test]
fn engine_ignores_non_yaml_files() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("ssh.yml"), SSH_RULE).unwrap();
    std::fs::write(dir.path().join("README.md"), "not a rule").unwrap();
    std::fs::write(dir.path().join("config.toml"), "not a rule").unwrap();

    let engine = Engine::load_dir(dir.path()).expect("load");
    assert_eq!(engine.rule_count(), 1);
}

#[test]
fn replay_corpus_produces_expected_findings() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("ssh.yml"), SSH_RULE).unwrap();
    std::fs::write(dir.path().join("sudoers.yml"), SUDOERS_RULE).unwrap();

    let engine = Engine::load_dir(dir.path()).expect("load");
    let seq = AtomicU64::new(0);

    // Load the bundled replay corpus.
    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/replay/auditd/ssh_bruteforce.jsonl");
    let corpus = std::fs::read_to_string(&corpus_path)
        .unwrap_or_else(|e| panic!("read corpus {}: {e}", corpus_path.display()));

    let mut total_findings = 0;
    let mut ssh_brute_findings = 0;
    for line in corpus.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(line).expect("parse corpus event");
        let findings = engine.process(&event, "replay", &seq);
        for f in findings {
            total_findings += 1;
            if f.message
                .as_deref()
                .unwrap_or("")
                .contains("SSH Brute Force")
            {
                ssh_brute_findings += 1;
            }
        }
    }

    // Expectations from tests/replay/auditd/ssh_bruteforce.expected.yaml
    assert_eq!(
        ssh_brute_findings, 1,
        "exactly one SSH brute force finding expected"
    );
    assert_eq!(
        total_findings, 1,
        "no other rules should fire on this corpus"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn correlator_hot_reload_picks_up_new_rules() {
    let dir = tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir(&rules_dir).unwrap();

    let bus = Bus::new(64);
    let publisher = bus.publisher();
    let _sub_keepalive = bus.subscribe(); // keep the broadcast channel from drying out

    let correlator = Correlator::new(publisher, "test-host".into(), rules_dir.clone());

    // Initially: empty.
    correlator.load_rules().expect("load empty");
    assert_eq!(correlator.rule_count(), 0);

    // Drop one rule in and reload.
    std::fs::write(rules_dir.join("ssh.yml"), SSH_RULE).unwrap();
    let n = correlator.load_rules().expect("load one");
    assert_eq!(n, 1);
    assert_eq!(correlator.rule_count(), 1);

    // Drop two more in and reload.
    std::fs::write(rules_dir.join("login.yml"), FAILED_LOGIN_RULE).unwrap();
    std::fs::write(rules_dir.join("sudoers.yml"), SUDOERS_RULE).unwrap();
    let n = correlator.load_rules().expect("load three");
    assert_eq!(n, 3);

    // Spawn the run loop, ensure it stays alive briefly, then cancel.
    let shutdown = CancellationToken::new();
    let sub = bus.subscribe();
    let sd = shutdown.clone();
    let handle = tokio::spawn(async move { correlator.run(sub, sd).await });

    tokio::time::sleep(Duration::from_millis(20)).await;
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
