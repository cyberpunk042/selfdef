//! Minisign-compatible detached signature verification.
//!
//! Closes the original SECURITY.md "rule signing" Known gap and
//! sets up the verifier infrastructure for the SDD-004 F-2026-024
//! follow-up (TracingPolicy signing). This crate is **verify-only**:
//! operators sign with the standalone `minisign` CLI
//! (Jedisct1/minisign) which is already widely used and audited.
//!
//! ## Usage shape
//!
//! Operators generate a key pair once:
//!
//! ```sh
//! minisign -G -p /etc/selfdef/keys/policy.pub -s ~/.selfdef-policy.key
//! # ship the .pub to every host running the daemon; keep the
//! # .key on the offline signing machine
//! ```
//!
//! Operators sign a rule:
//!
//! ```sh
//! minisign -S -m /etc/selfdef/rules/my-rule.yml -s ~/.selfdef-policy.key
//! # produces my-rule.yml.minisig in the same directory
//! ```
//!
//! The daemon loads the public key once at startup, then for each
//! rule file calls [`verify_detached_file`] which reads the
//! sibling `<rule>.minisig` and verifies.
//!
//! Disabled by default; turn on via the daemon's
//! `[security].require_signed_rules = true` (see
//! `selfdef-config::SecurityConfig`).

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::debug;

/// Suffix for the detached signature file. Operators run
/// `minisign -S -m <file>`; the tool emits `<file>.minisig`
/// by default.
pub const SIGNATURE_SUFFIX: &str = ".minisig";

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("public key file {path} unreadable or malformed: {reason}")]
    BadPublicKey { path: PathBuf, reason: String },
    #[error("signature file {path} is missing — operator must sign with `minisign -S -m {target}`")]
    MissingSignature { path: PathBuf, target: PathBuf },
    #[error("signature file {path} malformed: {reason}")]
    BadSignature { path: PathBuf, reason: String },
    #[error("signature on {target} does not verify under the configured public key")]
    VerificationFailed { target: PathBuf },
}

/// A verifier holding a parsed minisign public key. Construct once
/// at daemon startup, then reuse across many verifications. Cheap
/// to clone (the inner key is small).
#[derive(Clone)]
pub struct Verifier {
    public_key: minisign_verify::PublicKey,
    /// Original path the public key was loaded from. Carried so
    /// error messages and tracing logs can identify it.
    source: PathBuf,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// Load the public key from disk. Accepts either the raw
    /// minisign `.pub` file (two lines: header comment + base64
    /// body) or a single base64 body line on its own. Caller
    /// errors are returned as [`SigningError::BadPublicKey`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let path = path.as_ref();
        let body = std::fs::read_to_string(path).map_err(SigningError::Io)?;
        // minisign's .pub file has a comment header on line 1 and
        // the base64 key on line 2. Pick whichever non-empty line
        // looks like base64.
        let key_line = body
            .lines()
            .find(|l| !l.is_empty() && !l.starts_with("untrusted"))
            .unwrap_or("")
            .trim()
            .to_string();
        let public_key = minisign_verify::PublicKey::from_base64(&key_line).map_err(|e| {
            SigningError::BadPublicKey {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })?;
        Ok(Self {
            public_key,
            source: path.to_path_buf(),
        })
    }

    /// Where this verifier's key was loaded from. Used by tracing.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Verify the detached signature for `target_path`. Looks for
    /// `<target_path>.minisig` and verifies it against the
    /// target's bytes under this verifier's public key.
    ///
    /// Returns `Ok(())` on a valid signature.
    pub fn verify_detached_file(&self, target_path: &Path) -> Result<(), SigningError> {
        let sig_path = signature_path_for(target_path);
        if !sig_path.exists() {
            return Err(SigningError::MissingSignature {
                path: sig_path,
                target: target_path.to_path_buf(),
            });
        }
        let target_bytes = std::fs::read(target_path).map_err(SigningError::Io)?;
        let sig_str = std::fs::read_to_string(&sig_path).map_err(SigningError::Io)?;
        let signature = minisign_verify::Signature::decode(&sig_str).map_err(|e| {
            SigningError::BadSignature {
                path: sig_path.clone(),
                reason: e.to_string(),
            }
        })?;
        self.public_key
            .verify(&target_bytes, &signature, false)
            .map_err(|_| SigningError::VerificationFailed {
                target: target_path.to_path_buf(),
            })?;
        debug!(
            target = %target_path.display(),
            "signature verified",
        );
        Ok(())
    }
}

/// The expected detached-signature path for a target file:
/// `<target>.minisig`. Used by [`Verifier::verify_detached_file`]
/// and by tooling that needs to enumerate the expected sig files.
#[must_use]
pub fn signature_path_for(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(SIGNATURE_SUFFIX);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    //! Tests generate a real ed25519 keypair via the `minisign`
    //! dev-dep and write the public key + signed targets to a
    //! tempdir. No external `minisign` CLI required at test time.
    use super::*;

    /// Build a (verifier-friendly public key file path, secret
    /// key handle) pair in the given dir. The public key file
    /// uses minisign's standard `.pub` format (header + base64).
    fn fresh_keypair(dir: &Path) -> (PathBuf, minisign::SecretKey) {
        // No password protection — the operator's real key is
        // password-protected by `minisign -G`. Tests don't need
        // that; the key never leaves the tempdir.
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pub_path = dir.join("policy.pub");
        std::fs::write(&pub_path, kp.pk.to_box().unwrap().to_string()).unwrap();
        (pub_path, kp.sk)
    }

    /// Sign `target` and write `<target>.minisig`.
    fn sign_file(sk: &minisign::SecretKey, target: &Path) {
        let body = std::fs::read(target).unwrap();
        let sig = minisign::sign(None, sk, &body[..], None, None).unwrap();
        let sig_path = signature_path_for(target);
        std::fs::write(&sig_path, sig.to_string()).unwrap();
    }

    #[test]
    fn verifier_loads_from_minisign_dot_pub_format() {
        let dir = tempfile::tempdir().unwrap();
        let (pub_path, _sk) = fresh_keypair(dir.path());
        let v = Verifier::load(&pub_path).unwrap();
        assert_eq!(v.source(), pub_path.as_path());
    }

    #[test]
    fn verifier_loads_from_raw_base64_line() {
        // Strip the comment header — the loader must still
        // accept a bare base64 body.
        let dir = tempfile::tempdir().unwrap();
        let (full, _sk) = fresh_keypair(dir.path());
        let body = std::fs::read_to_string(&full).unwrap();
        let bare = body
            .lines()
            .find(|l| !l.is_empty() && !l.starts_with("untrusted"))
            .unwrap()
            .to_string();
        let bare_path = dir.path().join("policy-bare.pub");
        std::fs::write(&bare_path, bare).unwrap();
        Verifier::load(&bare_path).unwrap();
    }

    #[test]
    fn verifier_rejects_malformed_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pk.pub");
        std::fs::write(&p, "not a key").unwrap();
        let err = Verifier::load(&p).unwrap_err();
        assert!(matches!(err, SigningError::BadPublicKey { .. }), "{err:?}");
    }

    #[test]
    fn verify_detached_file_accepts_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (pub_path, sk) = fresh_keypair(dir.path());
        let target = dir.path().join("rule.yml");
        std::fs::write(&target, b"title: example\nlevel: high\n").unwrap();
        sign_file(&sk, &target);

        let v = Verifier::load(&pub_path).unwrap();
        v.verify_detached_file(&target)
            .expect("matching signature must verify");
    }

    #[test]
    fn verify_detached_file_missing_signature_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (pub_path, _sk) = fresh_keypair(dir.path());
        let target = dir.path().join("rule.yml");
        std::fs::write(&target, b"title: x\n").unwrap();
        // No .minisig file.
        let v = Verifier::load(&pub_path).unwrap();
        let err = v.verify_detached_file(&target).unwrap_err();
        match err {
            SigningError::MissingSignature { path, target: t } => {
                assert!(path.ends_with("rule.yml.minisig"));
                assert_eq!(t, target);
            }
            other => panic!("expected MissingSignature, got: {other:?}"),
        }
    }

    #[test]
    fn verify_detached_file_rejects_tampered_target() {
        let dir = tempfile::tempdir().unwrap();
        let (pub_path, sk) = fresh_keypair(dir.path());
        let target = dir.path().join("rule.yml");
        std::fs::write(&target, b"title: original\n").unwrap();
        sign_file(&sk, &target);

        // Tamper: rewrite the target after signing.
        std::fs::write(&target, b"title: tampered\n").unwrap();

        let v = Verifier::load(&pub_path).unwrap();
        let err = v.verify_detached_file(&target).unwrap_err();
        assert!(
            matches!(err, SigningError::VerificationFailed { .. }),
            "expected VerificationFailed, got: {err:?}",
        );
    }

    #[test]
    fn verify_detached_file_rejects_signature_from_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let (pub_path_a, _sk_a) = fresh_keypair(dir.path());
        let dir_b = tempfile::tempdir().unwrap();
        let (_pub_path_b, sk_b) = fresh_keypair(dir_b.path());

        let target = dir.path().join("rule.yml");
        std::fs::write(&target, b"title: x\n").unwrap();
        // Sign with key B, verify with key A → must fail.
        sign_file(&sk_b, &target);

        let v = Verifier::load(&pub_path_a).unwrap();
        let err = v.verify_detached_file(&target).unwrap_err();
        assert!(
            matches!(err, SigningError::VerificationFailed { .. }),
            "expected VerificationFailed, got: {err:?}",
        );
    }

    #[test]
    fn verify_detached_file_rejects_malformed_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (pub_path, _sk) = fresh_keypair(dir.path());
        let target = dir.path().join("rule.yml");
        std::fs::write(&target, b"title: x\n").unwrap();
        // Garbage signature file.
        std::fs::write(signature_path_for(&target), b"not a minisig file").unwrap();

        let v = Verifier::load(&pub_path).unwrap();
        let err = v.verify_detached_file(&target).unwrap_err();
        assert!(
            matches!(err, SigningError::BadSignature { .. }),
            "expected BadSignature, got: {err:?}",
        );
    }

    #[test]
    fn signature_path_for_appends_minisig() {
        assert_eq!(
            signature_path_for(Path::new("/etc/selfdef/rules/foo.yml")),
            PathBuf::from("/etc/selfdef/rules/foo.yml.minisig"),
        );
    }
}
