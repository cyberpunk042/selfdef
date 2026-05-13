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
