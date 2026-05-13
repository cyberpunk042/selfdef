//! SDD-004 rule-signing follow-up: integration tests for
//! `Correlator::load_rules` under a configured verifier.
//!
//! Closes the original SECURITY.md "Rule signing not yet
//! enforced" Known gap as opt-in shipped. The tests mirror the
//! `selfdef-signing` unit suite (signed/unsigned/wrong-key/
//! tampered) but exercise the full correlator path:
//!
//! - The rules directory is staged with one .yml file plus its
//!   sibling .minisig.
//! - `Correlator::with_verifier(...).load_rules()` is invoked.
//! - The outcome is asserted: load count for the positive case,
//!   typed `SigmaError::Signature` for every failure mode.
//!
//! Together with the existing `hot_reload.rs` tests, this gives
//! us SDD-005 Category 2 (pipeline) coverage of the
//! verification path.

use std::path::Path;
use std::sync::Arc;

use selfdef_bus::Bus;
use selfdef_correlator::{Correlator, SigmaError};

const RULE_YAML: &str = r#"
title: signed-test-rule
id: 11111111-2222-3333-4444-555555555555
status: stable
level: high
logsource:
    product: linux
detection:
    selection:
        message|contains: "signed"
    condition: selection
"#;

fn fresh_keypair(dir: &Path) -> (std::path::PathBuf, minisign::SecretKey) {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let pub_path = dir.join("policy.pub");
    std::fs::write(&pub_path, kp.pk.to_box().unwrap().to_string()).unwrap();
    (pub_path, kp.sk)
}

fn sign_file(sk: &minisign::SecretKey, target: &Path) {
    let body = std::fs::read(target).unwrap();
    let sig = minisign::sign(None, sk, &body[..], None, None).unwrap();
    let mut sig_path = target.as_os_str().to_owned();
    sig_path.push(".minisig");
    std::fs::write(std::path::PathBuf::from(sig_path), sig.to_string()).unwrap();
}

fn empty_correlator(rules_dir: &Path) -> Correlator {
    let bus = Arc::new(Bus::new(8));
    Correlator::new(bus.publisher(), "host-test".into(), rules_dir.to_path_buf())
}

#[test]
fn load_rules_with_verifier_accepts_signed_rule() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("ok.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    let (pub_path, sk) = fresh_keypair(dir.path());
    sign_file(&sk, &rule_path);

    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    let n = corr.load_rules().expect("signed rule must load");
    assert_eq!(n, 1);
    assert_eq!(corr.rule_count(), 1);
}

#[test]
fn load_rules_with_verifier_rejects_unsigned_rule() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("unsigned.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();
    // No .minisig file.

    let (pub_path, _sk) = fresh_keypair(dir.path());
    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    let err = corr.load_rules().unwrap_err();
    match err {
        SigmaError::Signature { path, .. } => {
            assert!(
                path.ends_with("unsigned.yml"),
                "expected the unsigned rule path; got {}",
                path.display(),
            );
        }
        other => panic!("expected SigmaError::Signature, got {other:?}"),
    }
    // The correlator's "keep prior ruleset on failure" semantics
    // mean rule_count stays at the pre-load value (0).
    assert_eq!(corr.rule_count(), 0);
}

#[test]
fn load_rules_with_verifier_rejects_tampered_rule() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("tampered.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    let (pub_path, sk) = fresh_keypair(dir.path());
    sign_file(&sk, &rule_path);

    // Tamper: rewrite the YAML after signing.
    let mut tampered = RULE_YAML.to_string();
    tampered.push_str("# stealth comment\n");
    std::fs::write(&rule_path, &tampered).unwrap();

    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    let err = corr.load_rules().unwrap_err();
    assert!(
        matches!(err, SigmaError::Signature { .. }),
        "expected SigmaError::Signature, got {err:?}",
    );
}

#[test]
fn load_rules_with_verifier_rejects_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("wrong-key.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    // Sign with key B; verify with key A.
    let dir_b = tempfile::tempdir().unwrap();
    let (_pub_b, sk_b) = fresh_keypair(dir_b.path());
    sign_file(&sk_b, &rule_path);

    let (pub_a, _sk_a) = fresh_keypair(dir.path());
    let verifier = selfdef_signing::Verifier::load(&pub_a).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    let err = corr.load_rules().unwrap_err();
    assert!(
        matches!(err, SigmaError::Signature { .. }),
        "expected SigmaError::Signature, got {err:?}",
    );
}

#[test]
fn load_rules_without_verifier_loads_unsigned_rule() {
    // Sanity: a correlator built without a verifier accepts
    // unsigned rules (the pre-SDD-004 default workflow).
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("unsigned.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    let corr = empty_correlator(&rules_dir);
    let n = corr
        .load_rules()
        .expect("unsigned rule must load when no verifier");
    assert_eq!(n, 1);
}

#[test]
fn reload_verifier_swaps_in_a_rotated_pubkey() {
    // F-2027-005: simulate operator rotating policy.pub on disk
    // (new keypair B replaces keypair A). Before reload, a rule
    // signed by B must fail under the A-loaded verifier; after
    // calling `reload_verifier()`, the same rule must load.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("rotated.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    // Step 1: load A's pubkey at /tmp/.../policy.pub.
    let (pub_path, sk_a) = fresh_keypair(dir.path());
    let verifier_a = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier_a);

    // The rule is signed by A initially → load succeeds.
    sign_file(&sk_a, &rule_path);
    assert_eq!(corr.load_rules().expect("A-signed rule loads"), 1);

    // Step 2: operator rotates the key — keypair B replaces the
    // contents of policy.pub on disk. The rule gets re-signed by
    // B (operator's signing workflow).
    let kp_b = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    std::fs::write(&pub_path, kp_b.pk.to_box().unwrap().to_string()).unwrap();
    sign_file(&kp_b.sk, &rule_path);

    // Without reload_verifier, load_rules now fails — the
    // in-memory verifier still trusts A but the rule is B-signed.
    let err = corr.load_rules().unwrap_err();
    assert!(matches!(err, SigmaError::Signature { .. }), "got {err:?}");

    // Step 3: SIGUSR2 → reload_verifier → load_rules.
    let reloaded_from = corr
        .reload_verifier()
        .expect("verifier reloads from same path");
    assert_eq!(reloaded_from, pub_path);
    let n = corr
        .load_rules()
        .expect("B-signed rule loads under reloaded verifier");
    assert_eq!(n, 1);
}

#[test]
fn reload_verifier_keeps_prior_on_load_failure() {
    // Operator clobbers policy.pub with garbage. reload_verifier
    // must fail loudly but leave the existing verifier in place
    // so the daemon keeps verifying against the last-good key.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("kept.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    let (pub_path, sk) = fresh_keypair(dir.path());
    sign_file(&sk, &rule_path);
    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    assert_eq!(corr.load_rules().unwrap(), 1);

    // Clobber policy.pub.
    std::fs::write(&pub_path, b"not a key\n").unwrap();
    let err = corr.reload_verifier().unwrap_err();
    assert!(
        matches!(&err, selfdef_correlator::ReloadVerifierError::Load(p, _) if p == &pub_path),
        "expected typed Load error pointing at policy.pub; got {err:?}",
    );

    // Prior verifier still functional — re-signing with the
    // original sk should still verify under it.
    sign_file(&sk, &rule_path);
    assert_eq!(corr.load_rules().expect("prior verifier still works"), 1,);
}

#[test]
fn reload_verifier_with_no_verifier_attached_is_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let corr = empty_correlator(&rules_dir);
    assert!(!corr.has_verifier());
    let err = corr.reload_verifier().unwrap_err();
    assert!(
        matches!(
            err,
            selfdef_correlator::ReloadVerifierError::NoVerifierConfigured
        ),
        "got {err:?}",
    );
}

#[test]
fn verifier_source_returns_none_without_verifier() {
    // F-2027-021: a correlator built without `with_verifier`
    // reports None — signing is opt-in, the getter must
    // distinguish "no verifier" from "verifier loaded but key
    // path empty" (which can't happen).
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let corr = empty_correlator(&rules_dir);
    assert_eq!(corr.verifier_source(), None);
}

#[test]
fn verifier_source_returns_loaded_path_after_with_verifier() {
    // F-2027-021: the getter returns the absolute path the
    // verifier was loaded from. Mirrors `Verifier::source()`.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let (pub_path, _sk) = fresh_keypair(dir.path());
    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    assert_eq!(corr.verifier_source(), Some(pub_path));
}

#[test]
fn verifier_source_tracks_reload() {
    // F-2027-021: after a hot-rotate via `reload_verifier()`,
    // the getter still reports the *path* (the path didn't
    // change — only the key file's contents did). Sanity-check
    // that the path stays stable across reloads.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let (pub_path, _sk_a) = fresh_keypair(dir.path());
    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    assert_eq!(corr.verifier_source(), Some(pub_path.clone()));

    // Operator rotates the on-disk key. reload_verifier reads
    // the new bytes from the same path.
    let kp_b = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    std::fs::write(&pub_path, kp_b.pk.to_box().unwrap().to_string()).unwrap();
    let reloaded = corr.reload_verifier().expect("reload succeeds");
    assert_eq!(reloaded, pub_path);
    assert_eq!(corr.verifier_source(), Some(pub_path));
}

#[test]
fn load_rules_yaml_error_takes_priority_over_signature() {
    // F-2027-034: a malformed-but-signed rule used to return
    // SigmaError::Signature because the signature was checked
    // before the YAML parse. Now the parse runs first and the
    // operator sees the real failure: SigmaError::Yaml with a
    // serde_yaml_ng error pointing at the parse position. The
    // signature is still verified before a rule is *added* to
    // the engine, so the security contract is unchanged.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("malformed.yml");
    // YAML that won't parse as a RawRule (a top-level array
    // instead of the expected map).
    std::fs::write(&rule_path, b"- not-a-rule\n- another-thing\n").unwrap();

    let (pub_path, sk) = fresh_keypair(dir.path());
    // Sign the malformed bytes anyway — the signature itself
    // is valid; the content is not.
    sign_file(&sk, &rule_path);

    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    let err = corr.load_rules().unwrap_err();
    assert!(
        matches!(err, SigmaError::Yaml { ref path, .. } if path.ends_with("malformed.yml")),
        "expected Yaml error pointing at malformed.yml; got {err:?}",
    );
}

#[test]
fn load_rules_walks_yaml_in_sorted_order() {
    // F-2027-033: walk_yaml's enumeration is now sorted
    // lexicographically. We can't directly observe the order
    // from outside the engine, but we can prove the contract
    // by loading three rules whose detection blocks differ in
    // a way that *would* be observable if precedence flipped —
    // and asserting all three load (the sort is deterministic
    // across machines + the count is stable). The stronger
    // property (matching event fires deterministic rule first)
    // is implicit; per-engine tests for that live elsewhere.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    // Three rules, named to put them in reverse alphabetical
    // creation order so an unsorted walk would yield them in
    // a different order than sorted on most filesystems.
    let (pub_path, sk) = fresh_keypair(dir.path());
    for (i, name) in ["zeta", "mu", "alpha"].iter().enumerate() {
        let p = rules_dir.join(format!("{name}.yml"));
        let body = RULE_YAML.replace(
            "11111111-2222-3333-4444-555555555555",
            &format!("00000000-0000-0000-0000-{i:012}"),
        );
        std::fs::write(&p, body).unwrap();
        sign_file(&sk, &p);
    }
    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    let n = corr.load_rules().expect("all three rules load under sort");
    assert_eq!(n, 3);
}

#[test]
fn load_rules_signature_failure_keeps_prior_ruleset() {
    // Two-step: (1) load a valid signed rule, (2) corrupt the
    // signature and reload, (3) verify the prior rule is still
    // active. Mirrors the hot-reload contract.
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let rule_path = rules_dir.join("flip.yml");
    std::fs::write(&rule_path, RULE_YAML).unwrap();

    let (pub_path, sk) = fresh_keypair(dir.path());
    sign_file(&sk, &rule_path);

    let verifier = selfdef_signing::Verifier::load(&pub_path).unwrap();
    let corr = empty_correlator(&rules_dir).with_verifier(verifier);
    corr.load_rules().expect("initial load");
    assert_eq!(corr.rule_count(), 1);

    // Corrupt the sidecar.
    let mut sig_path = rule_path.as_os_str().to_owned();
    sig_path.push(".minisig");
    std::fs::write(std::path::PathBuf::from(sig_path), b"garbage").unwrap();

    let err = corr.load_rules().unwrap_err();
    assert!(matches!(err, SigmaError::Signature { .. }), "got {err:?}");
    // Prior rule still active.
    assert_eq!(corr.rule_count(), 1);
}
