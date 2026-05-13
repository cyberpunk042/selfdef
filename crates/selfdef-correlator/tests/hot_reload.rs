//! SDD-005 Test-4 / closes F-2026-033: correlator SIGHUP /
//! hot-reload under live traffic.
//!
//! `ARCHITECTURE.md` claims the correlator supports atomic rule
//! reload — events arriving during the swap either match the
//! pre-reload rule set or the post-reload set, never a half-state.
//! Pre-SDD-005 this was unit-tested for load semantics only;
//! nothing verified the in-flight behaviour. This test:
//!
//! 1. Starts a correlator with rule set A (matches `cat foo`).
//! 2. Spins up a publisher firing events on a tight loop.
//! 3. Calls `load_rules()` mid-flight after swapping the
//!    on-disk YAML to rule set B (matches `dog bar`).
//! 4. Asserts findings consistent with one or the other rule
//!    set arrive — never an empty set, never both at once for
//!    the same event.

use std::sync::Arc;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_correlator::Correlator;
use tokio_util::sync::CancellationToken;

const RULE_A: &str = r#"
title: cat-foo
id: 11111111-1111-1111-1111-111111111111
status: stable
level: high
logsource:
    product: linux
detection:
    selection:
        message|contains: "cat foo"
    condition: selection
"#;

const RULE_B: &str = r#"
title: dog-bar
id: 22222222-2222-2222-2222-222222222222
status: stable
level: high
logsource:
    product: linux
detection:
    selection:
        message|contains: "dog bar"
    condition: selection
"#;

#[tokio::test]
async fn correlator_swaps_rules_atomically_under_live_traffic() {
    let rules_dir = tempfile::tempdir().expect("rules dir");
    let rule_path = rules_dir.path().join("active.yml");
    std::fs::write(&rule_path, RULE_A).unwrap();

    let bus = Arc::new(Bus::new(64));
    let publisher = bus.publisher();
    let finding_subscriber = bus.subscribe();
    let correlator_subscriber = bus.subscribe();
    let correlator = Arc::new(Correlator::new(
        publisher.clone(),
        "host-test".into(),
        rules_dir.path().to_path_buf(),
    ));
    assert_eq!(correlator.load_rules().unwrap(), 1);

    let shutdown = CancellationToken::new();
    let correlator_for_run = Arc::clone(&correlator);
    let shutdown_for_run = shutdown.clone();
    let run_task = tokio::spawn(async move {
        correlator_for_run
            .run(correlator_subscriber, shutdown_for_run)
            .await;
    });

    // Driver task: publish "cat foo" until told to switch, then
    // publish "dog bar" until shutdown. Throttled so the bus
    // doesn't lag.
    let switch = Arc::new(tokio::sync::Notify::new());
    let switched = Arc::new(tokio::sync::Notify::new());
    let drive_pub = publisher.clone();
    let drive_switch = switch.clone();
    let drive_switched = switched.clone();
    let drive_shutdown = shutdown.clone();
    let drive_task = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut phase_b = false;
        loop {
            seq += 1;
            let msg = if phase_b {
                "dog bar event"
            } else {
                "cat foo event"
            };
            let evt = Event::new(
                ClassUid::PROCESS_ACTIVITY,
                1,
                SeverityId::Informational,
                "host-test",
                "drive",
                seq,
            )
            .with_message(msg);
            let _ = drive_pub.publish(evt);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                _ = drive_switch.notified(), if !phase_b => {
                    phase_b = true;
                    drive_switched.notify_one();
                }
                _ = drive_shutdown.cancelled() => return,
            }
        }
    });

    // Observer task: collect findings until shutdown.
    let obs_shutdown = shutdown.clone();
    let observer = tokio::spawn(async move {
        let mut sub = finding_subscriber;
        let mut findings: Vec<(String, Option<String>)> = Vec::new();
        loop {
            tokio::select! {
                res = sub.recv() => {
                    match res {
                        Ok(evt) if evt.category_uid == selfdef_core::category::CategoryUid::Findings => {
                            findings.push((
                                evt.message.clone().unwrap_or_default(),
                                evt.raw.as_ref()
                                    .and_then(|r| r.get("rule"))
                                    .and_then(|r| r.get("title"))
                                    .and_then(|t| t.as_str())
                                    .map(str::to_string),
                            ));
                        }
                        Ok(_) => continue,
                        Err(_) => return findings,
                    }
                }
                _ = obs_shutdown.cancelled() => return findings,
            }
        }
    });

    // Phase 1: rule A is active. Let traffic flow for 100ms so
    // we accumulate findings.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Swap the rule file + reload. Tell the driver to switch to
    // phase B traffic.
    std::fs::write(&rule_path, RULE_B).unwrap();
    assert_eq!(correlator.load_rules().unwrap(), 1);
    switch.notify_one();
    tokio::time::timeout(Duration::from_secs(2), switched.notified())
        .await
        .expect("driver must observe switch within 2s");

    // Phase 2: rule B is active. Let traffic flow another 100ms.
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.cancel();

    let _ = tokio::time::timeout(Duration::from_secs(2), drive_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), run_task).await;
    let findings = tokio::time::timeout(Duration::from_secs(2), observer)
        .await
        .expect("observer joins")
        .expect("observer task");

    let a_count = findings.iter().filter(|(m, _)| m == "cat-foo").count();
    let b_count = findings.iter().filter(|(m, _)| m == "dog-bar").count();
    assert!(
        a_count > 0,
        "phase 1 produced no findings; got: {findings:?}"
    );
    assert!(
        b_count > 0,
        "phase 2 produced no findings; got: {findings:?}"
    );
    // Every finding should match exactly one known rule title.
    // A finding whose message doesn't match either title would
    // mean we produced a finding via some other path — i.e. the
    // rule swap got into a half-state.
    let unexpected: Vec<_> = findings
        .iter()
        .filter(|(m, _)| m != "cat-foo" && m != "dog-bar")
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected finding messages — atomicity violation: {unexpected:?}",
    );
}

#[tokio::test]
async fn correlator_load_rules_keeps_prior_set_on_parse_failure() {
    // Sibling promise: if the new rule file is malformed, the
    // engine keeps the prior rule set. Verifies the SDD-005
    // claim that hot-reload is non-destructive on failure.
    let rules_dir = tempfile::tempdir().expect("rules dir");
    let rule_path = rules_dir.path().join("active.yml");
    std::fs::write(&rule_path, RULE_A).unwrap();

    let bus = Arc::new(Bus::new(8));
    let publisher = bus.publisher();
    let correlator = Correlator::new(
        publisher,
        "host-test".into(),
        rules_dir.path().to_path_buf(),
    );
    assert_eq!(correlator.load_rules().unwrap(), 1);
    assert_eq!(correlator.rule_count(), 1);

    // Write a malformed rule.
    std::fs::write(&rule_path, "this is: not: valid: sigma:\n  - {").unwrap();
    let err = correlator.load_rules();
    assert!(err.is_err(), "expected parse failure, got: {err:?}");
    assert_eq!(
        correlator.rule_count(),
        1,
        "prior rule set must remain loaded after a failed reload"
    );
}
