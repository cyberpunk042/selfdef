//! MS003 verifier — verify sovereign-os's ed25519 mutation-record signatures.
//!
//! Closes the **selfdef half** of sovereign-os finding F-2026-034: sovereign-os
//! (the producer) mints an ed25519 signature over every durable mutation /
//! decision record; **selfdef verifies** it against the operator's public trust
//! anchor. Per SDD-083 the operator chose **Option 1** — shell to the system
//! `openssl` (already present; SecureBoot uses it), so this adds **no new crypto
//! dependency** and is byte-identical to the producer's own verify path.
//!
//! Verify-only: no key material is minted or handled here beyond *public* trust
//! anchors. selfdef trusts anchors from its **own** directory, never a path
//! sovereign-os can write, and it only reads sovereign-os records (R10212).
//!
//! # Wire contract (from `sovereign-os/scripts/lib/ms003.py`, pinned by SDD-083)
//! - `signature` field value: `ms003:ed25519:<keyid>:<sig>`
//!   - `keyid` = first 16 chars of unpadded base64url of the raw 32-byte pubkey.
//!   - `sig`   = unpadded base64url of the 64-byte ed25519 signature.
//! - signed bytes = [`canonical_bytes`] — the record minus its `signature`
//!   field, serialized as compact, **sorted-key** JSON (matching the producer's
//!   `json.dumps(..., sort_keys=True, separators=(",",":"), ensure_ascii=False)`).
//! - trust anchor = the operator's raw 32-byte ed25519 public key, stored as
//!   unpadded base64url in `<keyid>.pub`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The `signature` value a keyless sovereign-os producer node writes.
pub const UNSIGNED_PLACEHOLDER: &str = "unsigned-pending-MS003";
const PREFIX: &str = "ms003:ed25519:";
/// RFC 8410 ed25519 `SubjectPublicKeyInfo` DER prefix; append the 32 raw key
/// bytes for a 44-byte DER SPKI that `openssl pkeyutl -keyform DER` accepts.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The classification of one record against the trust-anchor store. The five
/// variants are the stable contract adopted verbatim from the sovereign-os
/// producer's `VERIFY_STATUSES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    /// Real signature, anchor found for its `keyid`, ed25519 verify OK.
    Verified,
    /// `signature == "unsigned-pending-MS003"` — a keyless producer node.
    UnsignedPlaceholder,
    /// The record carries no `signature` field (or it is JSON `null`).
    NoSignatureField,
    /// Signed, but selfdef holds no trust anchor for that `keyid`.
    UnknownKeyid,
    /// Signed, anchor found, but the signature does not verify — or the
    /// envelope is malformed. On a record that claims a committed mutation,
    /// this is a security event.
    InvalidSignature,
}

impl VerifyStatus {
    /// The stable lower-kebab status string (matches sovereign-os `VERIFY_STATUSES`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::UnsignedPlaceholder => "unsigned-placeholder",
            Self::NoSignatureField => "no-signature-field",
            Self::UnknownKeyid => "unknown-keyid",
            Self::InvalidSignature => "invalid-signature",
        }
    }

    #[must_use]
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// A record that *claims* a signature but fails to verify, or names a signer
    /// selfdef does not trust — the operationally-meaningful cases the IPS
    /// should surface as a security event.
    #[must_use]
    pub fn is_security_event(self) -> bool {
        matches!(self, Self::InvalidSignature | Self::UnknownKeyid)
    }
}

// --- base64url (unpadded), inline — honors SDD-083 Option 1's zero-new-dep ----

const B64U: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64u_encode(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    for chunk in raw.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64U[((n >> 18) & 63) as usize] as char);
        out.push(B64U[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64U[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64U[(n & 63) as usize] as char);
        }
    }
    out
}

fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim().as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        if chunk.len() < 2 {
            return None; // a lone trailing char cannot encode any byte
        }
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * (4 - chunk.len() as u32); // left-align to a full 24-bit group
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// The `keyid` for a raw 32-byte ed25519 public key: the first 16 chars of its
/// unpadded base64url (matches the producer's `keyid`).
#[must_use]
pub fn keyid(pub_raw: &[u8; 32]) -> String {
    let mut e = b64u_encode(pub_raw);
    e.truncate(16);
    e
}

// --- canonical bytes ---------------------------------------------------------

fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(map) => {
            out.push(b'{');
            // Sort keys explicitly: robust even if serde_json's `preserve_order`
            // feature is ever enabled workspace-wide (it would otherwise iterate
            // in insertion order and break the canonical form).
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let _ = serde_json::to_writer(&mut *out, k); // key as a JSON string
                out.push(b':');
                if let Some(val) = map.get(*k) {
                    write_canonical(val, out);
                }
            }
            out.push(b'}');
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(e, out);
            }
            out.push(b']');
        }
        // scalars (string / number / bool / null): delegate to serde_json so
        // escaping + number formatting match the compact producer output.
        other => {
            let _ = serde_json::to_writer(&mut *out, other);
        }
    }
}

/// The exact bytes signed and verified: the record **minus its top-level
/// `signature` field**, serialized as compact, sorted-key JSON. Producer and
/// verifier MUST agree byte-for-byte.
#[must_use]
pub fn canonical_bytes(record: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    match record {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&str> = map
                .keys()
                .map(String::as_str)
                .filter(|k| *k != "signature")
                .collect();
            keys.sort_unstable();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let _ = serde_json::to_writer(&mut out, k);
                out.push(b':');
                if let Some(val) = map.get(*k) {
                    write_canonical(val, &mut out);
                }
            }
            out.push(b'}');
        }
        other => write_canonical(other, &mut out),
    }
    out
}

// --- trust-anchor store ------------------------------------------------------

/// A selfdef-owned store of operator ed25519 public trust anchors, one
/// `<keyid>.pub` file per key (unpadded base64url of the raw 32 bytes).
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    dir: PathBuf,
}

impl TrustAnchors {
    /// A store rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The default selfdef-owned anchor directory:
    /// `$SELFDEF_MS003_TRUST_ANCHORS`, else `/etc/selfdef/ms003-trust-anchors`.
    /// selfdef trusts its **own** path — never one sovereign-os can write.
    #[must_use]
    pub fn from_env() -> Self {
        let dir = std::env::var_os("SELFDEF_MS003_TRUST_ANCHORS")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/selfdef/ms003-trust-anchors"));
        Self::new(dir)
    }

    /// The store's root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The raw 32-byte ed25519 public key for `key_id`, iff the anchor file
    /// exists, decodes to 32 bytes, and its recomputed keyid matches the
    /// filename (defense against a misnamed anchor). `None` otherwise.
    #[must_use]
    pub fn load(&self, key_id: &str) -> Option<[u8; 32]> {
        let body = std::fs::read_to_string(self.dir.join(format!("{key_id}.pub"))).ok()?;
        let raw: [u8; 32] = b64u_decode(&body)?.try_into().ok()?;
        (keyid(&raw) == key_id).then_some(raw)
    }

    /// Install a base64url raw 32-byte public key as a trust anchor; returns its
    /// keyid. Errors if the input is not a valid 32-byte key or the write fails.
    pub fn add(&self, pub_b64u: &str) -> std::io::Result<String> {
        let raw: [u8; 32] = b64u_decode(pub_b64u)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a base64url raw 32-byte ed25519 public key",
                )
            })?;
        let kid = keyid(&raw);
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(
            self.dir.join(format!("{kid}.pub")),
            format!("{}\n", b64u_encode(&raw)),
        )?;
        Ok(kid)
    }

    /// The keyids of every valid anchor in the store, sorted.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("pub") {
                    continue;
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if self.load(stem).is_some() {
                        ids.push(stem.to_string());
                    }
                }
            }
        }
        ids.sort();
        ids
    }
}

// --- verification ------------------------------------------------------------

/// ed25519-verify `sig` over `msg` under `pub_raw`, via the system `openssl`
/// (SDD-083 Option 1). Writes the reconstructed DER public key + message + raw
/// signature to a private tempdir and runs `openssl pkeyutl -verify`. Any I/O
/// or spawn failure is a non-verification (`false`), never a panic.
fn openssl_verify(pub_raw: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(dir) = tempfile::tempdir() else {
        return false;
    };
    let der_path = dir.path().join("k.der");
    let msg_path = dir.path().join("m.bin");
    let sig_path = dir.path().join("s.bin");

    let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(pub_raw);

    if std::fs::write(&der_path, &der).is_err()
        || std::fs::write(&msg_path, msg).is_err()
        || std::fs::write(&sig_path, sig).is_err()
    {
        return false;
    }

    Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(&der_path)
        .args(["-keyform", "DER", "-rawin", "-in"])
        .arg(&msg_path)
        .arg("-sigfile")
        .arg(&sig_path)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Classify one sovereign-os record against the trust-anchor store → one of the
/// five [`VerifyStatus`] variants. Never panics. Mirrors the producer's
/// `ms003.verify_record` branching exactly.
#[must_use]
pub fn verify_record(record: &Value, anchors: &TrustAnchors) -> VerifyStatus {
    let sig = match record.get("signature") {
        None | Some(Value::Null) => return VerifyStatus::NoSignatureField,
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return VerifyStatus::InvalidSignature,
    };
    if sig == UNSIGNED_PLACEHOLDER {
        return VerifyStatus::UnsignedPlaceholder;
    }
    let Some(rest) = sig.strip_prefix(PREFIX) else {
        return VerifyStatus::InvalidSignature;
    };
    // rest == "<keyid>:<sig_b64>"
    let mut parts = rest.splitn(2, ':');
    let (Some(kid), Some(sig_b64)) = (parts.next(), parts.next()) else {
        return VerifyStatus::InvalidSignature;
    };
    let Some(pub_raw) = anchors.load(kid) else {
        return VerifyStatus::UnknownKeyid;
    };
    let sig_bytes = match b64u_decode(sig_b64) {
        Some(b) if b.len() == 64 => b,
        _ => return VerifyStatus::InvalidSignature,
    };
    if openssl_verify(&pub_raw, &canonical_bytes(record), &sig_bytes) {
        VerifyStatus::Verified
    } else {
        VerifyStatus::InvalidSignature
    }
}

#[cfg(test)]
mod tests {
    //! Real-crypto tests. The golden fixture (`GOLDEN_*`) was produced by the
    //! actual sovereign-os producer `scripts/lib/ms003.py` — so a green
    //! `golden_verifies` proves this Rust verifier agrees with the Python
    //! producer byte-for-byte (canonical form + envelope + openssl path). The
    //! verifying tests shell to the system `openssl` (as the producer does).
    use super::*;
    use serde_json::json;

    // Raw 32-byte operator public key (unpadded base64url) + the signature the
    // producer emitted over `golden_record()`.
    const GOLDEN_PUB: &str = "MSC1I_5sR6G2V_NNv0kL4ZBmyfiHsxR31_2Iey1EKh0";
    const GOLDEN_KEYID: &str = "MSC1I_5sR6G2V_NN";
    const GOLDEN_SIG: &str = "ms003:ed25519:MSC1I_5sR6G2V_NN:mfuFPMK6yNI6WCzm_m_H4VsqFnSuHbrm89lS3r6jxaIZMdQdMv9MvjwImyf-_JDtgfmZBdpiA21UL-ZoKaTKDQ";

    fn golden_record() -> Value {
        json!({
            "id": "T-42",
            "kind": "memory-decide",
            "verdict": "allow",
            "note": "unicode ✓ café",
            "n": 7,
            "nested": {"z": 1, "a": [3, 2, 1]},
            "signature": GOLDEN_SIG,
        })
    }

    #[test]
    fn base64url_roundtrips_and_keyid() {
        let raw = b64u_decode(GOLDEN_PUB).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(b64u_encode(&raw), GOLDEN_PUB);
        let arr: [u8; 32] = raw.try_into().unwrap();
        assert_eq!(keyid(&arr), GOLDEN_KEYID);
    }

    #[test]
    fn canonical_matches_python_producer() {
        // The exact bytes `ms003.py::canonical_bytes` produced for this record:
        // sorted keys (incl. the nested object: a before z), compact, literal
        // UTF-8 (not \u-escaped).
        let expected = r#"{"id":"T-42","kind":"memory-decide","n":7,"nested":{"a":[3,2,1],"z":1},"note":"unicode ✓ café","verdict":"allow"}"#;
        assert_eq!(canonical_bytes(&golden_record()), expected.as_bytes());
    }

    #[test]
    fn golden_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        assert_eq!(anchors.add(GOLDEN_PUB).unwrap(), GOLDEN_KEYID);
        assert_eq!(
            verify_record(&golden_record(), &anchors),
            VerifyStatus::Verified
        );
    }

    #[test]
    fn tampered_body_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        anchors.add(GOLDEN_PUB).unwrap();
        let mut rec = golden_record();
        rec["verdict"] = json!("deny"); // flip a signed field
        let status = verify_record(&rec, &anchors);
        assert_eq!(status, VerifyStatus::InvalidSignature);
        assert!(status.is_security_event());
    }

    #[test]
    fn unknown_keyid_when_anchor_absent() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path()); // empty store
        assert_eq!(
            verify_record(&golden_record(), &anchors),
            VerifyStatus::UnknownKeyid
        );
    }

    #[test]
    fn placeholder_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        assert_eq!(
            verify_record(
                &json!({"id": "x", "signature": UNSIGNED_PLACEHOLDER}),
                &anchors
            ),
            VerifyStatus::UnsignedPlaceholder
        );
        assert_eq!(
            verify_record(&json!({"id": "x"}), &anchors),
            VerifyStatus::NoSignatureField
        );
        assert_eq!(
            verify_record(&json!({"id": "x", "signature": Value::Null}), &anchors),
            VerifyStatus::NoSignatureField
        );
        assert_eq!(
            verify_record(&json!({"id": "x", "signature": 123}), &anchors),
            VerifyStatus::InvalidSignature
        );
        assert_eq!(
            verify_record(
                &json!({"id": "x", "signature": "not-an-ms003-envelope"}),
                &anchors
            ),
            VerifyStatus::InvalidSignature
        );
    }

    #[test]
    fn anchor_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        let kid = anchors.add(GOLDEN_PUB).unwrap();
        assert_eq!(kid, GOLDEN_KEYID);
        assert_eq!(anchors.list(), vec![GOLDEN_KEYID.to_string()]);
        assert_eq!(b64u_encode(&anchors.load(&kid).unwrap()), GOLDEN_PUB);
        assert!(anchors.load("nope").is_none());
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(VerifyStatus::Verified.as_str(), "verified");
        assert_eq!(
            VerifyStatus::UnsignedPlaceholder.as_str(),
            "unsigned-placeholder"
        );
        assert_eq!(
            VerifyStatus::NoSignatureField.as_str(),
            "no-signature-field"
        );
        assert_eq!(VerifyStatus::UnknownKeyid.as_str(), "unknown-keyid");
        assert_eq!(VerifyStatus::InvalidSignature.as_str(), "invalid-signature");
    }
}
