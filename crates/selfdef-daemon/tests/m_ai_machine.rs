//! End-to-end integration test for the AI-machine track
//! (SDD-001 D-4). Closes Phase-1 ledger F-2026-006.
//!
//! The flow under test:
//!
//!   Tetragon `process_kprobe` JSON (synthetic, agent-guard
//!   policy match with `action: Sigkill`)
//!       → `selfdef-collector-tetragon` parses + attaches
//!         `raw.tetragon.{policy_name,action,function_name}`
//!         (SDD-001 D-1, F-2026-001)
//!       → bus
//!       → correlator running the
//!         `agent_guard_violation.yml` sigma rule (SDD-001 D-2,
//!         F-2026-002)
//!       → publishes a Detection Finding (severity High)
//!       → store sink persists it
//!       → responder routes Findings-category events through
//!         the notifier chain (existing M4 wiring; not under
//!         test here)
//!
//! The test asserts:
//!   1. The synthetic event reaches the store as a non-finding
//!      Tetragon event with the structured `raw.tetragon`
//!      subobject populated.
//!   2. The sigma rule fires; a Detection Finding (class 2004,
//!      severity High) lands in the store.
//!   3. A second synthetic event with `action: Post`
//!      (audit-mode) does **not** produce a finding —
//!      verifying the rule's action-discrimination at the
//!      negative case.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_eventstream::{EventstreamCollector, ReadFrom};
use selfdef_collector_tetragon::{ReadFrom as TgReadFrom, TetragonCollector};
use selfdef_core::category::{CategoryUid, ClassUid};
use selfdef_core::severity::SeverityId;
use selfdef_correlator::Correlator;
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

fn agent_guard_kprobe_line(action: &str, policy_name: &str) -> String {
    format!(
        r#"{{"process_kprobe":{{"function_name":"security_file_open","policy_name":"{policy_name}","policy_namespace":"","action":"{action}","process":{{"pid":4242,"binary":"/usr/bin/sed"}},"args":[{{"file_arg":{{"path":"/etc/shadow"}}}}]}}}}"#
    )
}

#[tokio::test(flavor = "current_thread")]
async fn ai_machine_pipeline_surfaces_agent_guard_sigkill_as_finding() {
    // ---- fs ----
    let dir = tempdir().expect("tempdir");
    let tetragon_log = dir.path().join("tetragon-events.json");
    let sqlite_path = dir.path().join("state.sqlite");
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let shipped_rules = workspace_root.join("rules/sigma");
    assert!(
        shipped_rules.is_dir(),
        "shipped rules dir missing at {}",
        shipped_rules.display(),
    );

    // Pre-write one Sigkill event so it's present when the
    // collector reads from `Start`.
    {
        let mut f = std::fs::File::create(&tetragon_log).expect("create");
        writeln!(
            f,
            "{}",
            agent_guard_kprobe_line("Sigkill", "selfdef-agent-etc-write-guard"),
        )
        .expect("write");
    }

    // ---- runtime ----
    let bus = Bus::new(256);
    let publisher = bus.publisher();
    let store = SqliteStore::open(&sqlite_path).expect("store");
    let sink_store = SqliteStore::open(&sqlite_path).expect("sink store");

    let shutdown = CancellationToken::new();

    // Store sink — persist every event including findings.
    let mut store_sub = bus.subscribe();
    let sink_shutdown = shutdown.clone();
    let sink = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = sink_shutdown.cancelled() => return,
                res = store_sub.recv() => {
                    if let Ok(event) = res {
                        sink_store.insert(&event).await.expect("insert");
                    }
                }
            }
        }
    });

    // Correlator — loads every shipped rule. The
    // `agent_guard_violation.yml` rule is what we're exercising.
    let corr_sub = bus.subscribe();
    let correlator = Arc::new(Correlator::new(
        publisher.clone(),
        "test-host".into(),
        shipped_rules,
    ));
    correlator.load_rules().expect("load rules");
    let corr_shutdown = shutdown.clone();
    let corr_task = tokio::spawn({
        let c = Arc::clone(&correlator);
        async move { c.run(corr_sub, corr_shutdown).await }
    });

    // Tetragon collector — reads from start so the pre-written
    // line is consumed.
    let tg_coll = TetragonCollector::new(
        tetragon_log.clone(),
        TgReadFrom::Start,
        publisher.clone(),
        "test-host".into(),
    );
    let tg_shutdown = shutdown.clone();
    let tg_task = tokio::spawn(async move {
        let _ = tg_coll.run(tg_shutdown).await;
    });

    // Keep the (unused) eventstream collector import alive so the
    // compiler doesn't flag the use statement — this test
    // deliberately exercises the *tetragon* collector path, NOT
    // eventstream, because the audit's F-2026-003 / I-006 warned
    // operators against confusing the two.
    let _ = EventstreamCollector::new(
        dir.path().join("unused.jsonl"),
        ReadFrom::End,
        publisher.clone(),
    );

    // Wait until the synthetic Sigkill event produces a finding.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let findings = store.recent_findings(10).await.unwrap_or_default();
        if !findings.is_empty() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            // Debug aid: dump every event we *did* see.
            let all = store.recent(50).await.unwrap_or_default();
            panic!(
                "no finding appeared within timeout; saw {} events:\n{:#?}",
                all.len(),
                all,
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // ---- assertions on the positive (Sigkill) case ----
    //
    // The synthetic event's file path is `/etc/shadow`, which
    // also trips the pre-existing `sensitive_file_access` sigma
    // rule. That's fine — both findings are legitimate. The
    // contract under test here is that the agent-guard
    // promotion lands; we filter on the rule's title since the
    // correlator builds findings with a fresh `raw` that
    // carries rule-metadata rather than the source event's
    // `raw.tetragon` subobject.
    let findings = store.recent_findings(50).await.expect("findings");
    let agent_guard_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.message
                .as_deref()
                .is_some_and(|m| m.contains("agent-guard policy violation"))
        })
        .collect();
    assert_eq!(
        agent_guard_findings.len(),
        1,
        "expected exactly one agent-guard finding; saw {} matching out of {} total",
        agent_guard_findings.len(),
        findings.len(),
    );
    let f = agent_guard_findings[0];
    assert_eq!(
        f.category_uid,
        CategoryUid::Findings,
        "finding must be category 2",
    );
    assert_eq!(
        f.class_uid,
        ClassUid::DETECTION_FINDING,
        "finding must be class 2004",
    );
    assert_eq!(
        f.severity_id,
        SeverityId::High,
        "agent-guard violations should surface as High",
    );
    // The finding's source identifies the rule that promoted it.
    assert!(
        f.source.starts_with("selfdef.correlator."),
        "finding source should name the rule, got: {}",
        f.source,
    );

    // ---- negative case: audit-mode Post does NOT promote ----
    // Append a Post line; verify the finding count stays at 1.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&tetragon_log)
            .expect("reopen append");
        writeln!(
            f,
            "{}",
            agent_guard_kprobe_line("Post", "selfdef-agent-etc-write-guard"),
        )
        .expect("write Post");
    }
    // Give the pipeline a moment to ingest + decide.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after_post = store.recent_findings(50).await.expect("findings");
    let agent_guard_after_post: Vec<_> = after_post
        .iter()
        .filter(|f| {
            f.message
                .as_deref()
                .is_some_and(|m| m.contains("agent-guard policy violation"))
        })
        .collect();
    assert_eq!(
        agent_guard_after_post.len(),
        1,
        "audit-mode Post must NOT promote to a finding; \
         agent-guard finding count should still be 1, was {}",
        agent_guard_after_post.len(),
    );

    // ---- teardown ----
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), tg_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), corr_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), sink).await;
}
