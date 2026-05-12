//! Property tests: invariants the schema must always uphold.

use proptest::prelude::*;
use selfdef_core::activity::AuthenticationActivity;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;

// ---------- strategies ----------

fn arb_severity() -> impl Strategy<Value = SeverityId> {
    prop_oneof![
        Just(SeverityId::Unknown),
        Just(SeverityId::Informational),
        Just(SeverityId::Low),
        Just(SeverityId::Medium),
        Just(SeverityId::High),
        Just(SeverityId::Critical),
        Just(SeverityId::Fatal),
        Just(SeverityId::Other),
    ]
}

fn arb_class_uid() -> impl Strategy<Value = ClassUid> {
    prop_oneof![
        Just(ClassUid::AUTHENTICATION),
        Just(ClassUid::PROCESS_ACTIVITY),
        Just(ClassUid::FILE_SYSTEM_ACTIVITY),
        Just(ClassUid::NETWORK_ACTIVITY),
        Just(ClassUid::SSH_ACTIVITY),
        Just(ClassUid::ACCOUNT_CHANGE),
        Just(ClassUid::KERNEL_ACTIVITY),
        (1u32..10_000).prop_map(ClassUid::new),
    ]
}

fn arb_nonempty_string(max: usize) -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_\\-]{1,128}".prop_map(move |s| s[..s.len().min(max)].to_string())
}

fn arb_event() -> impl Strategy<Value = Event> {
    (
        arb_class_uid(),
        0u32..200,
        arb_severity(),
        arb_nonempty_string(64),
        arb_nonempty_string(64),
        0u64..u64::MAX,
    )
        .prop_map(|(class, activity, sev, host, src, seq)| {
            Event::new(class, activity, sev, host, src, seq)
        })
}

// ---------- properties ----------

proptest! {
    /// Any event must serialize and deserialize to an equal-shape event.
    #[test]
    fn json_round_trip(event in arb_event()) {
        let s = serde_json::to_string(&event).expect("serialize");
        let back: Event = serde_json::from_str(&s).expect("deserialize");
        prop_assert_eq!(back.id, event.id);
        prop_assert_eq!(back.class_uid, event.class_uid);
        prop_assert_eq!(back.activity_id, event.activity_id);
        prop_assert_eq!(back.type_uid, event.type_uid);
        prop_assert_eq!(back.severity_id, event.severity_id);
        prop_assert_eq!(back.host_tag, event.host_tag);
        prop_assert_eq!(back.source, event.source);
    }

    /// type_uid must always be derivable from class_uid * 100 + activity_id.
    #[test]
    fn type_uid_invariant(event in arb_event()) {
        prop_assert_eq!(event.type_uid, event.class_uid.type_uid(event.activity_id));
    }

    /// category_uid is determined by the thousands digit of class_uid.
    #[test]
    fn category_matches_class(event in arb_event()) {
        prop_assert_eq!(event.category_uid, event.class_uid.category());
    }

    /// Validation accepts any well-formed event.
    #[test]
    fn validate_accepts_well_formed(event in arb_event()) {
        prop_assert!(event.validate().is_ok());
    }
}

#[test]
fn type_uid_specific_case() {
    // OCSF: Authentication / Logon = 3002 * 100 + 1 = 300201
    let e = Event::new(
        ClassUid::AUTHENTICATION,
        AuthenticationActivity::Logon as u32,
        SeverityId::Medium,
        "h",
        "s",
        0,
    );
    assert_eq!(e.type_uid, 300_201);
}
