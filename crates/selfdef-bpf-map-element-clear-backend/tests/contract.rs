//! SDD-078 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_bpf_map_element_clear_backend::{
    AuthorityTier, BpfMapElementClearBackend, BpfMapElementClearError, ClearHandle, ClearRequest,
    ClearScope, InMemoryBackend, MapSpecKind, PendingMapRestore, parse_key_hex, parse_map_spec,
};

fn req(
    spec: &str,
    scope: ClearScope,
    key_hex: Option<&str>,
    dur_secs: u64,
    tier: AuthorityTier,
    reason: &str,
) -> ClearRequest {
    let idempotency_key = format!("{spec}:{scope:?}:{key_hex:?}:{tier:?}:{reason}");
    ClearRequest {
        map_spec: spec.into(),
        scope,
        key_hex: key_hex.map(String::from),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        idempotency_key,
    }
}

#[tokio::test]
async fn element_clear_returns_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/ip_allow_list",
        ClearScope::Element,
        Some("0a000001"),
        900,
        AuthorityTier::Operator,
        "delete suspect entry",
    );
    let receipt = b.clear(r).await.expect("element clear must succeed");
    assert!(matches!(receipt.handle, ClearHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    assert_eq!(receipt.elements_cleared, 1);
    assert_eq!(receipt.map_spec_kind, MapSpecKind::Path);
}

#[tokio::test]
async fn unparseable_map_spec_rejected() {
    let b = InMemoryBackend::new();
    for bad in [
        "",
        "no-prefix",
        "id:",
        "id:abc",
        "name:",
        "name:with space",
        "/wrong/path",
    ] {
        let r = req(
            bad,
            ClearScope::Element,
            Some("00"),
            60,
            AuthorityTier::Operator,
            "x",
        );
        let err = b
            .clear(r)
            .await
            .expect_err(&format!("malformed map spec {bad:?} must error"));
        assert!(
            matches!(err, BpfMapElementClearError::UnparseableMapSpec { .. }),
            "got {err:?}"
        );
    }
}

#[tokio::test]
async fn id_spec_accepted() {
    let b = InMemoryBackend::new();
    let r = req(
        "id:42",
        ClearScope::Element,
        Some("0a000001"),
        60,
        AuthorityTier::Operator,
        "by-id",
    );
    let receipt = b.clear(r).await.unwrap();
    assert_eq!(receipt.map_spec_kind, MapSpecKind::Id);
}

#[tokio::test]
async fn name_spec_accepted() {
    let b = InMemoryBackend::new();
    let r = req(
        "name:per_pid_budget",
        ClearScope::Element,
        Some("01000000"),
        60,
        AuthorityTier::Operator,
        "by-name",
    );
    let receipt = b.clear(r).await.unwrap();
    assert_eq!(receipt.map_spec_kind, MapSpecKind::Name);
}

#[tokio::test]
async fn element_scope_without_key_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::Element,
        None,
        60,
        AuthorityTier::Operator,
        "missing key",
    );
    let err = b.clear(r).await.unwrap_err();
    assert!(matches!(
        err,
        BpfMapElementClearError::ElementScopeRequiresKey
    ));
}

#[tokio::test]
async fn all_scope_with_key_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::All,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "extra key",
    );
    let err = b.clear(r).await.unwrap_err();
    assert!(matches!(err, BpfMapElementClearError::AllScopeForbidsKey));
}

#[tokio::test]
async fn invalid_key_hex_rejected() {
    let b = InMemoryBackend::new();
    for bad in ["", "f", "fff", "0g", "zz"] {
        let r = req(
            "/sys/fs/bpf/x",
            ClearScope::Element,
            Some(bad),
            60,
            AuthorityTier::Operator,
            "x",
        );
        let err = b.clear(r).await.unwrap_err();
        assert!(
            matches!(err, BpfMapElementClearError::InvalidKeyHex { .. }),
            "{bad:?} → {err:?}"
        );
    }
}

#[tokio::test]
async fn all_scope_requires_operator_tier() {
    let b = InMemoryBackend::new();
    for tier in [AuthorityTier::Autonomous, AuthorityTier::Responder] {
        let r = req(
            "/sys/fs/bpf/x",
            ClearScope::All,
            None,
            60,
            tier,
            "scope All under low tier",
        );
        let err = b.clear(r).await.unwrap_err();
        assert!(
            matches!(
                err,
                BpfMapElementClearError::AllScopeRequiresOperator { .. }
            ),
            "{tier:?} → {err:?}"
        );
    }
}

#[tokio::test]
async fn all_scope_operator_accepted() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::All,
        None,
        60 * 30,
        AuthorityTier::Operator,
        "wipe all",
    );
    let receipt = b.clear(r).await.unwrap();
    assert!(matches!(receipt.handle, ClearHandle::Active(_)));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "",
    );
    let err = b.clear(r).await.unwrap_err();
    assert!(matches!(err, BpfMapElementClearError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::Element,
        Some("00"),
        60 * 60 * 6,
        AuthorityTier::Autonomous,
        "over-tier",
    );
    let err = b.clear(r).await.unwrap_err();
    assert!(matches!(
        err,
        BpfMapElementClearError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_078_table() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(2 * 60)
    );
    assert_eq!(
        AuthorityTier::Responder.max_duration(),
        Duration::from_secs(15 * 60)
    );
    assert_eq!(
        AuthorityTier::Operator.max_duration(),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(4 * 60 * 60)
    );
}

#[tokio::test]
async fn forced_map_not_found_handle() {
    let b = InMemoryBackend::new().force_map_not_found();
    let r = req(
        "/sys/fs/bpf/ghost",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "ghost map",
    );
    let receipt = b.clear(r).await.unwrap();
    assert!(matches!(receipt.handle, ClearHandle::MapNotFound(_)));
    assert_eq!(receipt.elements_cleared, 0);
}

#[tokio::test]
async fn forced_ambiguous_name_handle() {
    let b = InMemoryBackend::new().force_ambiguous_name();
    let r = req(
        "name:shared",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "ambiguous",
    );
    let receipt = b.clear(r).await.unwrap();
    assert!(matches!(receipt.handle, ClearHandle::AmbiguousName(_)));
}

#[tokio::test]
async fn forced_key_size_mismatch_handle() {
    let b = InMemoryBackend::new().force_key_size_mismatch();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "mismatch",
    );
    let receipt = b.clear(r).await.unwrap();
    assert!(matches!(receipt.handle, ClearHandle::KeySizeMismatch(_)));
}

#[tokio::test]
async fn forced_key_not_found_handle_audit_only() {
    let b = InMemoryBackend::new().force_key_not_found();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "race",
    );
    let receipt = b.clear(r).await.unwrap();
    assert!(matches!(receipt.handle, ClearHandle::KeyNotFound(_)));
    assert_eq!(receipt.elements_cleared, 0);
}

#[tokio::test]
async fn forced_access_denied_handle() {
    let b = InMemoryBackend::new().force_access_denied();
    let r = req(
        "/sys/fs/bpf/x",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "denied",
    );
    let receipt = b.clear(r).await.unwrap();
    assert!(matches!(receipt.handle, ClearHandle::BpfMapAccessDenied(_)));
}

#[tokio::test]
async fn idempotent_clear_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        "/sys/fs/bpf/dup",
        ClearScope::Element,
        Some("0102"),
        60,
        AuthorityTier::Operator,
        "t",
    );
    let r2 = req(
        "/sys/fs/bpf/dup",
        ClearScope::Element,
        Some("0102"),
        60,
        AuthorityTier::Operator,
        "t",
    );
    let h1 = b.clear(r1).await.unwrap().handle;
    let h2 = b.clear(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "/sys/fs/bpf/r",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "t",
    );
    let receipt = b.clear(r).await.unwrap();
    let restore = b.restore(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_with_repopulation_flag() {
    let b = InMemoryBackend::with_simulated_elements_cleared(1);
    let r = req(
        "/sys/fs/bpf/ip_allow_list",
        ClearScope::Element,
        Some("0a000001"),
        600,
        AuthorityTier::Responder,
        "responder",
    );
    b.clear(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].map_spec, "/sys/fs/bpf/ip_allow_list");
    assert_eq!(pending[0].elements_cleared, 1);
    assert!(pending[0].requires_owning_program_repopulation);
}

#[tokio::test]
async fn scope_variants_distinct_handles() {
    let b = InMemoryBackend::new();
    let e = req(
        "/sys/fs/bpf/s",
        ClearScope::Element,
        Some("00"),
        60,
        AuthorityTier::Operator,
        "t",
    );
    let a = req(
        "/sys/fs/bpf/s",
        ClearScope::All,
        None,
        60,
        AuthorityTier::Operator,
        "t",
    );
    let h1 = b.clear(e).await.unwrap().handle;
    let h2 = b.clear(a).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn parse_map_spec_accepts_three_shapes() {
    assert_eq!(
        parse_map_spec("/sys/fs/bpf/ip_allow_list"),
        Some((MapSpecKind::Path, "/sys/fs/bpf/ip_allow_list"))
    );
    assert_eq!(parse_map_spec("id:42"), Some((MapSpecKind::Id, "42")));
    assert_eq!(
        parse_map_spec("name:per_pid_budget"),
        Some((MapSpecKind::Name, "per_pid_budget"))
    );
    assert_eq!(
        parse_map_spec("/sys/fs/bpf/nested/dir/map"),
        Some((MapSpecKind::Path, "/sys/fs/bpf/nested/dir/map"))
    );
}

#[test]
fn parse_map_spec_rejects_malformed() {
    assert_eq!(parse_map_spec(""), None);
    assert_eq!(parse_map_spec("no-prefix"), None);
    assert_eq!(parse_map_spec("id:"), None);
    assert_eq!(parse_map_spec("id:abc"), None);
    assert_eq!(parse_map_spec("name:"), None);
    assert_eq!(parse_map_spec("name:with space"), None);
    assert_eq!(parse_map_spec("/wrong/path"), None);
    assert_eq!(parse_map_spec("/sys/fs/bpf/"), None);
}

#[test]
fn parse_map_spec_rejects_parent_traversal() {
    // A bpffs pin path must stay under /sys/fs/bpf/. The '.'/'/' charset
    // otherwise lets a ".." component through, blessing an escaping spec as
    // well-formed and handing a future BPF_OBJ_GET a path resolving outside
    // bpffs. Every parent-traversal form must be rejected.
    assert_eq!(parse_map_spec("/sys/fs/bpf/../../etc/passwd"), None);
    assert_eq!(parse_map_spec("/sys/fs/bpf/a/../../../root"), None);
    assert_eq!(parse_map_spec("/sys/fs/bpf/.."), None);
    assert_eq!(parse_map_spec("/sys/fs/bpf/sub/../map"), None);
    // A single leading dot in a name (not a traversal) is still fine, and
    // legitimately nested pins must keep working.
    assert!(parse_map_spec("/sys/fs/bpf/.hidden_map").is_some());
    assert!(parse_map_spec("/sys/fs/bpf/nested/dir/map").is_some());
}

#[test]
fn parse_key_hex_accepts_even_hex() {
    assert_eq!(parse_key_hex("00"), Some(1));
    assert_eq!(parse_key_hex("0a000001"), Some(4));
    assert_eq!(parse_key_hex("deadbeef"), Some(4));
    assert_eq!(parse_key_hex("0102030405060708090a0b0c0d0e0f10"), Some(16));
}

#[test]
fn parse_key_hex_rejects_malformed() {
    assert_eq!(parse_key_hex(""), None);
    assert_eq!(parse_key_hex("f"), None);
    assert_eq!(parse_key_hex("fff"), None);
    assert_eq!(parse_key_hex("0g"), None);
    assert_eq!(parse_key_hex("zz"), None);
}

#[test]
fn pending_map_restore_serializes_to_json() {
    let p = PendingMapRestore {
        handle: ClearHandle::Active("h-1".into()),
        map_spec: "/sys/fs/bpf/ip_allow_list".into(),
        map_spec_kind: MapSpecKind::Path,
        scope: ClearScope::Element,
        key_hex: Some("0a000001".into()),
        original_authority: AuthorityTier::Responder,
        original_reason: "attacker IP".into(),
        seconds_remaining: 600,
        elements_cleared: 1,
        requires_owning_program_repopulation: true,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("/sys/fs/bpf/ip_allow_list"));
    assert!(json.contains("0a000001"));
    assert!(json.contains("\"requires_owning_program_repopulation\":true"));
    assert!(json.contains("\"elements_cleared\":1"));
}
