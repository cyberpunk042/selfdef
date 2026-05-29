//! SDD-074 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_process_env_scrub_backend::{
    AuthorityTier, InMemoryBackend, PendingEnvRestore, ProcessEnvScrubBackend,
    ProcessEnvScrubError, ProcessEnvScrubHandle, ScrubEnvRequest, ScrubSignal,
};

fn req(
    pid: i32,
    vars: &[&str],
    dur_secs: u64,
    tier: AuthorityTier,
    signal: ScrubSignal,
    reason: &str,
) -> ScrubEnvRequest {
    let var_strs: Vec<String> = vars.iter().map(|s| (*s).to_string()).collect();
    let idempotency_key = format!("{pid}:{}:{reason}:{tier:?}:{signal:?}", var_strs.join(","));
    ScrubEnvRequest {
        pid,
        vars: var_strs,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        signal,
        idempotency_key,
    }
}

#[tokio::test]
async fn scrub_env_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        &["AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"],
        900,
        AuthorityTier::Operator,
        ScrubSignal::Sigusr2,
        "post-rotation: scrub cached creds",
    );
    let receipt = b.scrub_env(r).await.expect("scrub must succeed");
    assert!(matches!(receipt.handle, ProcessEnvScrubHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    assert_eq!(receipt.vars_scrubbed, 2);
}

#[tokio::test]
async fn invalid_pid_zero_or_negative_is_rejected() {
    let b = InMemoryBackend::new();
    for bad_pid in [0, -1] {
        let r = req(
            bad_pid,
            &["X"],
            60,
            AuthorityTier::Operator,
            ScrubSignal::None,
            "x",
        );
        let err = b
            .scrub_env(r)
            .await
            .expect_err("non-positive pid must error");
        assert!(matches!(err, ProcessEnvScrubError::InvalidRequest(_)));
    }
}

#[tokio::test]
async fn pid_one_init_is_refused() {
    let b = InMemoryBackend::new();
    let r = req(
        1,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "test",
    );
    let err = b.scrub_env(r).await.expect_err("pid 1 must error");
    assert!(matches!(
        err,
        ProcessEnvScrubError::PidRefused { pid: 1, .. }
    ));
}

#[tokio::test]
async fn empty_vars_list_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &[],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "x",
    );
    let err = b.scrub_env(r).await.expect_err("empty vars must error");
    assert!(matches!(err, ProcessEnvScrubError::InvalidRequest(_)));
}

#[tokio::test]
async fn empty_var_name_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["X", ""],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "x",
    );
    let err = b.scrub_env(r).await.expect_err("empty var name must error");
    assert!(matches!(err, ProcessEnvScrubError::InvalidRequest(_)));
}

#[tokio::test]
async fn var_name_with_equals_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["FOO=BAR"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "x",
    );
    let err = b.scrub_env(r).await.expect_err("var with = must error");
    assert!(matches!(err, ProcessEnvScrubError::InvalidRequest(_)));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "",
    );
    let err = b.scrub_env(r).await.expect_err("empty reason must error");
    assert!(matches!(err, ProcessEnvScrubError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["X"],
        60 * 60 * 2,
        AuthorityTier::Autonomous,
        ScrubSignal::None,
        "x",
    );
    let err = b.scrub_env(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        ProcessEnvScrubError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_074_section_4() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(5 * 60)
    );
    assert_eq!(
        AuthorityTier::Responder.max_duration(),
        Duration::from_secs(30 * 60)
    );
    assert_eq!(
        AuthorityTier::Operator.max_duration(),
        Duration::from_secs(2 * 60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(6 * 60 * 60)
    );
}

#[tokio::test]
async fn no_match_yields_no_match_handle_and_zero_scrubbed() {
    let b = InMemoryBackend::with_simulated_vars_matched(0);
    let r = req(
        222,
        &["X", "Y"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "no-match",
    );
    let receipt = b.scrub_env(r).await.unwrap();
    assert!(matches!(receipt.handle, ProcessEnvScrubHandle::NoMatch(_)));
    assert_eq!(receipt.vars_scrubbed, 0);
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn partial_match_yields_active_handle_with_scrubbed_count() {
    let b = InMemoryBackend::with_simulated_vars_matched(1);
    let r = req(
        223,
        &["X", "Y", "Z"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::Sigusr2,
        "partial",
    );
    let receipt = b.scrub_env(r).await.unwrap();
    assert!(matches!(receipt.handle, ProcessEnvScrubHandle::Active(_)));
    assert_eq!(receipt.vars_scrubbed, 1);
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn idempotent_scrub_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        333,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::Sigusr2,
        "t",
    );
    let r2 = req(
        333,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::Sigusr2,
        "t",
    );
    let h1 = b.scrub_env(r1).await.unwrap().handle;
    let h2 = b.scrub_env(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        444,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::None,
        "t",
    );
    let receipt = b.scrub_env(r).await.unwrap();
    let restore = b.restore_env(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::with_simulated_vars_matched(3);
    let r = req(
        555,
        &["A", "B", "C"],
        900,
        AuthorityTier::Responder,
        ScrubSignal::Sigusr2,
        "rotation",
    );
    b.scrub_env(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 555);
    assert_eq!(pending[0].vars_scrubbed, 3);
}

#[tokio::test]
async fn signal_variants_distinct_handles() {
    let b = InMemoryBackend::new();
    let a = req(
        700,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::Sigusr2,
        "t",
    );
    let bb = req(
        700,
        &["X"],
        60,
        AuthorityTier::Operator,
        ScrubSignal::Sighup,
        "t",
    );
    let h1 = b.scrub_env(a).await.unwrap().handle;
    let h2 = b.scrub_env(bb).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn pending_env_restore_serializes_to_json() {
    let p = PendingEnvRestore {
        handle: ProcessEnvScrubHandle::Active("h-1".into()),
        pid: 12345,
        vars: vec!["AWS_SECRET".into(), "DB_PASSWORD".into()],
        original_authority: AuthorityTier::Responder,
        original_reason: "rotated".into(),
        seconds_remaining: 600,
        signal: ScrubSignal::Sigusr2,
        vars_scrubbed: 2,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("12345"));
    assert!(json.contains("AWS_SECRET"));
    assert!(json.contains("\"vars_scrubbed\":2"));
    assert!(json.contains("600"));
}
