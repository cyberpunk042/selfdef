//! `selfdef-scheduler::policy_signer` — M01172: Minisign-detached
//! signature VERIFICATION for rotated audit-log generations.
//!
//! Catalog grounding: MS048 module `M01172 selfdef-scheduler-policy-
//! signer (MS003)` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md`. Pairs with the
//! existing `selfdef-signing` crate (verify-only minisign wrapper).
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — Core Law clause
//! "ZFS remembers" + "User chooses" + peace-machine clause
//! "reversible enough to trust". Operator-supervised signing of
//! rotated audit generations is the cryptographic proof that the
//! audit log was NOT tampered with after rotation: tamper-detection
//! is multi-layered:
//!   1. SHA-256 chain (M01170) — detects tampering BEFORE rotation
//!   2. minisign detached signatures (M01172, this module) —
//!      cryptographic proof of rotation-time integrity
//!   3. ZFS send/recv replication (sovereign-os M068) — detects
//!      replication-time corruption
//!
//! ## Architecture
//!
//! Signing happens in an OPERATOR-SUPERVISED process OUTSIDE the
//! scheduler. The scheduler's role is verify-only — by design (per
//! selfdef-signing crate doc): operators sign with the standalone
//! `minisign` CLI (Jedisct1/minisign) which is widely audited; the
//! IPS daemon never holds a private key.
//!
//! Pipeline:
//!
//! 1. `selfdef-scheduler-textfile` (M01174) appends entries to
//!    `/var/log/selfdef/scheduler.driver.audit.jsonl` (M01170).
//! 2. On rotation, `.jsonl` → `.jsonl.1`, etc.
//! 3. Operator-supervised signing process (cron / systemd-timer /
//!    manual) tail-watches for new rotated generations and runs:
//!    `minisign -S -m scheduler.driver.audit.jsonl.1 -s ~/.selfdef-policy.key`
//!    producing `scheduler.driver.audit.jsonl.1.minisig`.
//! 4. M01172 (this module) verifies the signature on demand:
//!    `verify_audit_generation(path, &verifier)` checks the
//!    `.minisig` is valid under the operator's public key.
//! 5. Bulk verification: `verify_all_signed_generations(base_path,
//!    &verifier, max_gens)` walks every rotated generation and
//!    returns aggregate `SignatureStats`.
//!
//! The CURRENT (growing) audit file is intentionally UNSIGNED —
//! signing a growing file is meaningless (file changes per poll;
//! signature would be stale immediately). Signing is per-rotation,
//! per-generation.
//!
//! ## What this module provides
//!
//! 1. `verify_audit_generation(path, verifier)` — verify one
//!    `.minisig` against a single rotated audit file.
//! 2. `verify_all_signed_generations(base_path, verifier, max_gens)`
//!    — walk `.1` ... `.max_gens` and verify each (skipping
//!    missing-signature generations as unsigned, not failed).
//! 3. `SignatureStats` — { signed_ok, unsigned, signature_failed,
//!    first_failure_at }.
//! 4. `SignatureOutcome` — per-generation outcome enum.
//!
//! ## Non-goals
//!
//! - Not a signer. Signing is operator-supervised via standalone
//!   minisign CLI; selfdef never holds a private key.
//! - Not a key-rotation manager. Operator manages key lifecycle.
//! - Not a per-entry inline signer. Detached per-generation
//!   signatures only.
//!
//! Standing rule: We do not minimize anything.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use selfdef_signing::{SigningError, Verifier};

/// Default location for the operator's policy public key
/// (corresponds to `~/.selfdef-policy.key` private key in the
/// operator's key store).
pub const DEFAULT_PUBLIC_KEY_PATH: &str = "/etc/selfdef/keys/policy.pub";

// ============================================================================
// Errors
// ============================================================================

/// Errors raised by M01172 verification.
#[derive(Debug, Error)]
pub enum PolicySignerError {
    /// Path doesn't exist or isn't readable.
    #[error("policy-signer io ({path}): {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Signature verification failed (wrong key, tampered file,
    /// malformed .minisig).
    #[error("policy-signer verify ({path}): {source}")]
    Verify {
        /// Audit file that failed verification.
        path: PathBuf,
        /// Underlying selfdef-signing error.
        #[source]
        source: SigningError,
    },
}

// ============================================================================
// SignatureOutcome + SignatureStats
// ============================================================================

/// Per-generation verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureOutcome {
    /// Audit generation has a valid `.minisig` and it verifies
    /// under the configured public key.
    SignedOk,
    /// Audit generation has no `.minisig` file (operator hasn't
    /// signed it yet, or signing was disabled).
    Unsigned,
    /// `.minisig` exists but signature does not verify (wrong key,
    /// tampered file, corruption). Reason captured for the
    /// audit-failure cockpit panel.
    SignatureFailed {
        /// Human reason.
        reason: String,
    },
}

impl SignatureOutcome {
    /// `true` for [`Self::SignedOk`].
    #[must_use]
    pub const fn is_signed_ok(&self) -> bool {
        matches!(self, Self::SignedOk)
    }

    /// `true` for [`Self::SignatureFailed`].
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::SignatureFailed { .. })
    }
}

/// Aggregated stats across multiple generations.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatureStats {
    /// Number of generations whose `.minisig` verified.
    pub signed_ok: u32,
    /// Number of generations without a `.minisig` file (waiting
    /// for the operator-supervised signer).
    pub unsigned: u32,
    /// Number of generations whose `.minisig` failed verification.
    /// HIGH-severity signal: tampering or key mismatch.
    pub signature_failed: u32,
    /// Path of the FIRST failed generation (if any) — operator's
    /// first investigation target.
    pub first_failure_at: Option<PathBuf>,
}

impl SignatureStats {
    /// `true` iff any generation is `SignatureFailed`.
    #[must_use]
    pub const fn has_failure(&self) -> bool {
        self.signature_failed > 0
    }

    /// Total generations seen.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.signed_ok + self.unsigned + self.signature_failed
    }
}

// ============================================================================
// verify_audit_generation
// ============================================================================

/// Verify a single rotated audit generation's `.minisig` against
/// the supplied `verifier`.
///
/// Returns [`SignatureOutcome::Unsigned`] when no `.minisig` exists
/// (this is NOT an error — it means the operator hasn't signed
/// this generation yet, or signing is disabled on this host).
///
/// Returns [`SignatureOutcome::SignatureFailed`] when the signature
/// exists but is invalid; the inner `reason` is the message from
/// `selfdef-signing`.
///
/// Returns [`SignatureOutcome::SignedOk`] on a clean verify.
///
/// # Errors
///
/// Returns [`PolicySignerError::Io`] if the target audit file
/// itself doesn't exist (the caller's catalog of generations is
/// stale). Other failures are reported via [`SignatureOutcome`].
pub fn verify_audit_generation(
    audit_path: &Path,
    verifier: &Verifier,
) -> Result<SignatureOutcome, PolicySignerError> {
    if !audit_path.exists() {
        return Err(PolicySignerError::Io {
            path: audit_path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "audit file missing"),
        });
    }
    let sig_path = selfdef_signing::signature_path_for(audit_path);
    if !sig_path.exists() {
        return Ok(SignatureOutcome::Unsigned);
    }
    match verifier.verify_detached_file(audit_path) {
        Ok(()) => Ok(SignatureOutcome::SignedOk),
        Err(e) => Ok(SignatureOutcome::SignatureFailed {
            reason: e.to_string(),
        }),
    }
}

// ============================================================================
// verify_all_signed_generations
// ============================================================================

/// Walk `base_path.1` ... `base_path.<max_generations>` and verify
/// each that exists. Returns aggregate `SignatureStats`.
///
/// The current (un-rotated) `base_path` is INTENTIONALLY SKIPPED —
/// it's growing and shouldn't be signed yet.
///
/// # Errors
///
/// Returns [`PolicySignerError::Io`] only on catalog enumeration
/// failure (highly unlikely — we just probe `path.exists()`).
pub fn verify_all_signed_generations(
    base_path: &Path,
    verifier: &Verifier,
    max_generations: u32,
) -> Result<SignatureStats, PolicySignerError> {
    let mut stats = SignatureStats::default();
    for n in 1..=max_generations {
        let gen_path = generation_path(base_path, n);
        if !gen_path.exists() {
            continue;
        }
        let outcome = verify_audit_generation(&gen_path, verifier)?;
        match outcome {
            SignatureOutcome::SignedOk => stats.signed_ok += 1,
            SignatureOutcome::Unsigned => stats.unsigned += 1,
            SignatureOutcome::SignatureFailed { .. } => {
                stats.signature_failed += 1;
                if stats.first_failure_at.is_none() {
                    stats.first_failure_at = Some(gen_path);
                }
            }
        }
    }
    Ok(stats)
}

fn generation_path(base: &Path, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_signing::SIGNATURE_SUFFIX;
    use std::fs;
    use tempfile::tempdir;

    /// Test keypair + signing helper. Generates a fresh keypair per
    /// test so tests are isolated and don't share signature material.
    /// Mirrors the pattern used in selfdef-cli's
    /// cli_keys_verify_dir.rs and cli_modules_apply.rs.
    struct TestSigner {
        keypair: minisign::KeyPair,
    }

    impl TestSigner {
        fn new() -> Self {
            Self {
                keypair: minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
            }
        }

        /// Write the public key as a minisign `.pub` file to `dir`.
        fn write_public_key(&self, dir: &Path) -> PathBuf {
            let p = dir.join("policy.pub");
            fs::write(&p, self.keypair.pk.to_box().unwrap().into_string()).unwrap();
            p
        }

        /// Load a [`Verifier`] from this signer's public key.
        fn verifier(&self, dir: &Path) -> Verifier {
            let pub_path = self.write_public_key(dir);
            Verifier::load(&pub_path).expect("test public key must load")
        }

        /// Sign `target_path` and write the detached `.minisig` next
        /// to it. Mirrors what `minisign -S -m <target>` does.
        fn sign_file(&self, target_path: &Path) {
            let sk = self.keypair.sk.clone();
            let mut target =
                std::fs::File::open(target_path).expect("test target file must open");
            let sig = minisign::sign(None, &sk, &mut target, None, None)
                .expect("minisign sign must succeed");
            let sig_path = selfdef_signing::signature_path_for(target_path);
            fs::write(&sig_path, sig.into_string()).unwrap();
        }
    }

    // ---------------- SignatureStats predicates ------------------------

    #[test]
    fn signature_stats_predicates() {
        let s = SignatureStats {
            signed_ok: 3,
            unsigned: 1,
            signature_failed: 0,
            first_failure_at: None,
        };
        assert!(!s.has_failure());
        assert_eq!(s.total(), 4);

        let s2 = SignatureStats {
            signed_ok: 1,
            unsigned: 0,
            signature_failed: 2,
            first_failure_at: Some(PathBuf::from("/x.1")),
        };
        assert!(s2.has_failure());
        assert_eq!(s2.total(), 3);
    }

    // ---------------- SignatureOutcome predicates ----------------------

    #[test]
    fn signature_outcome_predicates() {
        assert!(SignatureOutcome::SignedOk.is_signed_ok());
        assert!(!SignatureOutcome::SignedOk.is_failure());
        assert!(!SignatureOutcome::Unsigned.is_signed_ok());
        assert!(!SignatureOutcome::Unsigned.is_failure());
        let f = SignatureOutcome::SignatureFailed {
            reason: "x".into(),
        };
        assert!(!f.is_signed_ok());
        assert!(f.is_failure());
    }

    // ---------------- verify_audit_generation --------------------------

    #[test]
    fn missing_audit_file_returns_io_error() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let missing = tmp.path().join("never-created.jsonl.1");
        let err = verify_audit_generation(&missing, &verifier).unwrap_err();
        assert!(matches!(err, PolicySignerError::Io { .. }));
    }

    #[test]
    fn audit_file_present_but_no_signature_returns_unsigned() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let audit = tmp.path().join("scheduler.driver.audit.jsonl.1");
        fs::write(&audit, b"any contents").unwrap();
        let outcome = verify_audit_generation(&audit, &verifier).unwrap();
        assert_eq!(outcome, SignatureOutcome::Unsigned);
    }

    #[test]
    fn malformed_signature_returns_signature_failed() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let audit = tmp.path().join("scheduler.driver.audit.jsonl.1");
        fs::write(&audit, b"any contents").unwrap();
        let sig_path = tmp
            .path()
            .join(format!("scheduler.driver.audit.jsonl.1{SIGNATURE_SUFFIX}"));
        fs::write(&sig_path, b"not a real minisign signature").unwrap();
        let outcome = verify_audit_generation(&audit, &verifier).unwrap();
        assert!(matches!(outcome, SignatureOutcome::SignatureFailed { .. }));
    }

    #[test]
    fn tampered_file_returns_signature_failed() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        // Sign the file with valid contents...
        let audit = tmp.path().join("audit.bin");
        fs::write(&audit, b"original-payload").unwrap();
        signer.sign_file(&audit);
        // ...then TAMPER the file — verification must fail.
        fs::write(&audit, b"tampered-payload").unwrap();
        let outcome = verify_audit_generation(&audit, &verifier).unwrap();
        assert!(matches!(outcome, SignatureOutcome::SignatureFailed { .. }));
    }

    #[test]
    fn correct_signature_returns_signed_ok() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let audit = tmp.path().join("audit.bin");
        fs::write(&audit, b"the canonical payload").unwrap();
        signer.sign_file(&audit);
        let outcome = verify_audit_generation(&audit, &verifier).unwrap();
        assert_eq!(
            outcome,
            SignatureOutcome::SignedOk,
            "valid signature must verify"
        );
    }

    #[test]
    fn signature_under_wrong_public_key_returns_signature_failed() {
        // Two signers; sign with A, verify with B.
        let tmp = tempdir().unwrap();
        let signer_a = TestSigner::new();
        let signer_b = TestSigner::new();
        let verifier_b = signer_b.verifier(tmp.path());
        let audit = tmp.path().join("audit.bin");
        fs::write(&audit, b"payload").unwrap();
        signer_a.sign_file(&audit);
        let outcome = verify_audit_generation(&audit, &verifier_b).unwrap();
        assert!(matches!(outcome, SignatureOutcome::SignatureFailed { .. }));
    }

    // ---------------- verify_all_signed_generations --------------------

    #[test]
    fn bulk_no_generations_returns_empty_stats() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let base = tmp.path().join("scheduler.driver.audit.jsonl");
        let stats = verify_all_signed_generations(&base, &verifier, 5).unwrap();
        assert_eq!(stats, SignatureStats::default());
    }

    #[test]
    fn bulk_mixed_signed_unsigned_failed() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let base = tmp.path().join("scheduler.driver.audit.jsonl");

        // .1 — signed OK
        let g1 = generation_path(&base, 1);
        fs::write(&g1, b"generation one").unwrap();
        signer.sign_file(&g1);

        // .2 — unsigned (no .minisig)
        let g2 = generation_path(&base, 2);
        fs::write(&g2, b"unsigned generation").unwrap();

        // .3 — signature_failed (signed then tampered)
        let g3 = generation_path(&base, 3);
        fs::write(&g3, b"original").unwrap();
        signer.sign_file(&g3);
        fs::write(&g3, b"tampered").unwrap();

        let stats = verify_all_signed_generations(&base, &verifier, 5).unwrap();
        assert_eq!(stats.signed_ok, 1);
        assert_eq!(stats.unsigned, 1);
        assert_eq!(stats.signature_failed, 1);
        assert_eq!(stats.first_failure_at, Some(g3));
        assert_eq!(stats.total(), 3);
        assert!(stats.has_failure());
    }

    #[test]
    fn bulk_walks_in_order_and_records_first_failure() {
        let tmp = tempdir().unwrap();
        let signer = TestSigner::new();
        let verifier = signer.verifier(tmp.path());
        let base = tmp.path().join("scheduler.driver.audit.jsonl");
        // .1 — sign-then-tamper (fails first)
        let g1 = generation_path(&base, 1);
        fs::write(&g1, b"x").unwrap();
        signer.sign_file(&g1);
        fs::write(&g1, b"x-tampered").unwrap();
        // .2 — ALSO fails (sign-then-tamper)
        let g2 = generation_path(&base, 2);
        fs::write(&g2, b"y").unwrap();
        signer.sign_file(&g2);
        fs::write(&g2, b"y-tampered").unwrap();
        let stats = verify_all_signed_generations(&base, &verifier, 5).unwrap();
        assert_eq!(stats.signature_failed, 2);
        assert_eq!(stats.first_failure_at, Some(g1));
    }

    // ---------------- Constants ----------------------------------------

    #[test]
    fn default_public_key_path_matches_convention() {
        assert_eq!(DEFAULT_PUBLIC_KEY_PATH, "/etc/selfdef/keys/policy.pub");
    }
}
