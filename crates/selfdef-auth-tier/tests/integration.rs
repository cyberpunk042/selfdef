//! Integration tests for `selfdef-auth-tier`. Cross-repo binding
//! sentinel: drift between this crate's TIER_NAMES and the
//! sovereign-os R450 verbatim 6-tier ladder is a contract violation.

use selfdef_auth_tier::{AuthTier, AuthTierError, TIER_NAMES};

#[test]
fn tier_count_is_exactly_six() {
    assert_eq!(TIER_NAMES.len(), 6);
    assert_eq!(AuthTier::all().len(), 6);
}

#[test]
fn level_zero_is_no_auth_and_five_is_network_level() {
    assert_eq!(AuthTier::NoAuth.level(), 0);
    assert_eq!(AuthTier::NetworkLevel.level(), 5);
}

#[test]
fn warnings_distinct_per_tier() {
    use std::collections::HashSet;
    let warnings: HashSet<_> = AuthTier::all()
        .iter()
        .map(|t| t.operator_named_warning())
        .collect();
    assert_eq!(warnings.len(), 6, "every tier needs its own warning");
}

#[test]
fn requires_distinct_or_subset() {
    // Higher tiers may share some lower-tier requirements, but the
    // operator-§1g intent is that each tier's requirements set is
    // non-empty (except NoAuth).
    for t in AuthTier::all().iter().skip(1) {
        let r = t.requires();
        assert!(!r.is_empty(), "{t:?} should declare requirements");
    }
}

#[test]
fn error_message_lists_the_known_tiers() {
    let err = AuthTier::from_kebab("freeform").unwrap_err();
    let msg = format!("{err}");
    for &name in &TIER_NAMES {
        assert!(
            msg.contains(name),
            "error msg should list {name:?}; got {msg}"
        );
    }
}

#[test]
fn error_pattern_matches_specific_variant() {
    let err = AuthTier::from_kebab("xyz").unwrap_err();
    assert!(matches!(err, AuthTierError::Unknown(_)));
}

#[test]
fn round_trip_all_six_tiers_via_strings() {
    for t in AuthTier::all() {
        assert_eq!(AuthTier::from_kebab(t.as_kebab()).unwrap(), t);
    }
}

#[test]
fn r450_sovereign_os_verbatim_order_preserved_in_tier_names() {
    // Operator §1g VERBATIM sentence: 'no auth at all by default to
    // basic auth to advanced auth to social auth to enterprise auth
    // and network level access'. The order MUST be exactly:
    assert_eq!(TIER_NAMES[0], "no-auth");
    assert_eq!(TIER_NAMES[1], "basic");
    assert_eq!(TIER_NAMES[2], "advanced");
    assert_eq!(TIER_NAMES[3], "social");
    assert_eq!(TIER_NAMES[4], "enterprise");
    assert_eq!(TIER_NAMES[5], "network-level");
}
