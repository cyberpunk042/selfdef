//! `selfdefctl ms003` — verify sovereign-os's ed25519 mutation-record signatures.
//!
//! The operator surface over [`selfdef_signing::ms003`] (SDD-083) — the selfdef
//! consumer half of sovereign-os finding F-2026-034. Verify-only; selfdef trusts
//! anchors from its **own** directory and only reads sovereign-os records
//! (R10212).
//!
//! Four subverbs:
//!   - `anchor-add <pub_b64u>` — install the operator's exported sovereign-os
//!     ed25519 public key (unpadded base64url of the raw 32 bytes) as a trust
//!     anchor; prints its keyid.
//!   - `anchor-list` — the keyids of every valid anchor in the store.
//!   - `verify <file>` — classify one JSON record. Exit 0 iff `verified`; 2 on a
//!     security event (`invalid-signature` / `unknown-keyid`); 1 otherwise
//!     (`unsigned-placeholder` / `no-signature-field`) — so operators can
//!     shell-gate on a real signature.
//!   - `sweep <file> [--metrics <path>]` — classify a whole sovereign-os ledger
//!     (a JSON array or JSONL), print per-status counts, optionally emit Layer-B
//!     Prometheus gauges the selfdef alert engine consumes, and exit 2 if any
//!     record is a security event.
//!
//! Source: SDD-083 + the `selfdef-signing::ms003` verifier.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use selfdef_signing::ms003::{self, TrustAnchors, VerifyStatus};

/// The stable status keys, always emitted (even at count 0) so the metric series
/// and the printed summary never silently drop a category.
const STATUSES: [&str; 5] = [
    "verified",
    "unsigned-placeholder",
    "no-signature-field",
    "unknown-keyid",
    "invalid-signature",
];

fn store() -> TrustAnchors {
    TrustAnchors::from_env()
}

// --- anchor-add --------------------------------------------------------------

fn add(anchors: &TrustAnchors, pub_b64u: &str) -> i32 {
    match anchors.add(pub_b64u.trim()) {
        Ok(kid) => {
            println!("anchor added: keyid={kid}  dir={}", anchors.dir().display());
            0
        }
        Err(e) => {
            eprintln!("anchor-add failed: {e}");
            1
        }
    }
}

pub(crate) fn run_anchor_add(pub_b64u: &str) -> Result<i32> {
    Ok(add(&store(), pub_b64u))
}

// --- anchor-list -------------------------------------------------------------

fn list(anchors: &TrustAnchors) -> i32 {
    let ids = anchors.list();
    if ids.is_empty() {
        println!("no trust anchors in {}", anchors.dir().display());
    } else {
        println!(
            "{} trust anchor(s) in {}:",
            ids.len(),
            anchors.dir().display()
        );
        for id in &ids {
            println!("  {id}");
        }
    }
    0
}

pub(crate) fn run_anchor_list() -> Result<i32> {
    Ok(list(&store()))
}

// --- verify (one record) -----------------------------------------------------

fn exit_for(status: VerifyStatus) -> i32 {
    match status {
        VerifyStatus::Verified => 0,
        // security events — an unverifiable / untrusted claimed signature
        VerifyStatus::InvalidSignature | VerifyStatus::UnknownKeyid => 2,
        // benign non-signed shapes
        VerifyStatus::UnsignedPlaceholder | VerifyStatus::NoSignatureField => 1,
    }
}

fn verify_one(anchors: &TrustAnchors, file: &Path) -> Result<i32> {
    let body =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let record: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("parsing {} as JSON", file.display()))?;
    let status = ms003::verify_record(&record, anchors);
    println!("{}", status.as_str());
    Ok(exit_for(status))
}

pub(crate) fn run_verify(file: &Path) -> Result<i32> {
    verify_one(&store(), file)
}

// --- sweep (a whole ledger) --------------------------------------------------

/// Parse a sovereign-os ledger: a JSON array of records, a single JSON object,
/// or JSONL (one JSON object per non-empty line). Non-JSON lines are an error.
fn parse_ledger(body: &str) -> Result<Vec<serde_json::Value>> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        // Try a single JSON document first (array or object).
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            return Ok(match v {
                serde_json::Value::Array(a) => a,
                other => vec![other],
            });
        }
    }
    // Fall back to JSONL.
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("ledger line {} is not valid JSON", i + 1))?;
        out.push(v);
    }
    Ok(out)
}

/// Prometheus Layer-B textfile body for a sweep result. `selfdef_ms003_records`
/// is a labelled gauge per status; `selfdef_ms003_security_events` is the
/// alertable rollup (invalid-signature + unknown-keyid).
fn prom_body(counts: &BTreeMap<&str, u64>, security_events: u64) -> String {
    let mut s = String::new();
    s.push_str("# HELP selfdef_ms003_records sovereign-os mutation records classified by the selfdef MS003 verifier, by status.\n");
    s.push_str("# TYPE selfdef_ms003_records gauge\n");
    for status in STATUSES {
        let n = counts.get(status).copied().unwrap_or(0);
        s.push_str(&format!(
            "selfdef_ms003_records{{status=\"{status}\"}} {n}\n"
        ));
    }
    s.push_str("# HELP selfdef_ms003_security_events records claiming a signature that failed to verify or named an untrusted signer.\n");
    s.push_str("# TYPE selfdef_ms003_security_events gauge\n");
    s.push_str(&format!(
        "selfdef_ms003_security_events {security_events}\n"
    ));
    s
}

fn sweep(anchors: &TrustAnchors, file: &Path, metrics: Option<&Path>) -> Result<i32> {
    let body =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let records = parse_ledger(&body)?;

    let mut counts: BTreeMap<&str, u64> = STATUSES.iter().map(|s| (*s, 0)).collect();
    let mut events: Vec<(usize, VerifyStatus, String)> = Vec::new();
    for (i, rec) in records.iter().enumerate() {
        let status = ms003::verify_record(rec, anchors);
        *counts.entry(status.as_str()).or_default() += 1;
        if status.is_security_event() {
            let id = rec
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<no-id>")
                .to_string();
            events.push((i, status, id));
        }
    }

    println!(
        "ms003 sweep: {} record(s) in {}",
        records.len(),
        file.display()
    );
    for status in STATUSES {
        println!("  {status}: {}", counts[status]);
    }
    for (i, status, id) in &events {
        // Security events go to stderr so they stand out in operator + log tails.
        eprintln!("  SECURITY: record[{i}] id={id} -> {}", status.as_str());
    }

    if let Some(path) = metrics {
        std::fs::write(path, prom_body(&counts, events.len() as u64))
            .with_context(|| format!("writing metrics to {}", path.display()))?;
        println!("metrics -> {}", path.display());
    }

    // Exit 2 when any record is a security event, so the sweep can shell-gate.
    Ok(i32::from(!events.is_empty()) * 2)
}

pub(crate) fn run_sweep(file: &Path, metrics: Option<&Path>) -> Result<i32> {
    sweep(&store(), file, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Golden fixture produced by the real sovereign-os producer
    // `scripts/lib/ms003.py` — the same one the `selfdef-signing::ms003` crate
    // tests use. A green sweep/verify here proves the CLI surface drives the
    // verified cross-implementation path.
    const GOLDEN_PUB: &str = "MSC1I_5sR6G2V_NNv0kL4ZBmyfiHsxR31_2Iey1EKh0";
    const GOLDEN_KEYID: &str = "MSC1I_5sR6G2V_NN";
    const GOLDEN_REC: &str = r#"{"id":"T-42","kind":"memory-decide","verdict":"allow","note":"unicode ✓ café","n":7,"nested":{"z":1,"a":[3,2,1]},"signature":"ms003:ed25519:MSC1I_5sR6G2V_NN:mfuFPMK6yNI6WCzm_m_H4VsqFnSuHbrm89lS3r6jxaIZMdQdMv9MvjwImyf-_JDtgfmZBdpiA21UL-ZoKaTKDQ"}"#;

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn anchor_add_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        assert_eq!(add(&anchors, GOLDEN_PUB), 0);
        assert_eq!(add(&anchors, "not-a-key"), 1);
        assert_eq!(list(&anchors), 0);
        assert_eq!(anchors.list(), vec![GOLDEN_KEYID.to_string()]);
    }

    #[test]
    fn verify_exit_codes() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        anchors.add(GOLDEN_PUB).unwrap();

        let ok = write(dir.path(), "ok.json", GOLDEN_REC);
        assert_eq!(verify_one(&anchors, &ok).unwrap(), 0); // verified

        let tampered = GOLDEN_REC.replace("allow", "deny");
        let bad = write(dir.path(), "bad.json", &tampered);
        assert_eq!(verify_one(&anchors, &bad).unwrap(), 2); // security event

        let ph = write(
            dir.path(),
            "ph.json",
            r#"{"id":"x","signature":"unsigned-pending-MS003"}"#,
        );
        assert_eq!(verify_one(&anchors, &ph).unwrap(), 1); // benign
    }

    #[test]
    fn verify_unknown_keyid_without_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path()); // empty store
        let f = write(dir.path(), "r.json", GOLDEN_REC);
        assert_eq!(verify_one(&anchors, &f).unwrap(), 2); // unknown-keyid → security
    }

    #[test]
    fn sweep_jsonl_counts_metrics_and_exit() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        anchors.add(GOLDEN_PUB).unwrap();

        let tampered = GOLDEN_REC.replace("allow", "deny");
        let ledger = format!(
            "{GOLDEN_REC}\n{tampered}\n{{\"id\":\"p\",\"signature\":\"unsigned-pending-MS003\"}}\n{{\"id\":\"n\"}}\n"
        );
        let lpath = write(dir.path(), "ledger.jsonl", &ledger);
        let mpath = dir.path().join("ms003.prom");

        let code = sweep(&anchors, &lpath, Some(&mpath)).unwrap();
        assert_eq!(code, 2); // one tampered record → security exit

        let prom = std::fs::read_to_string(&mpath).unwrap();
        assert!(
            prom.contains("selfdef_ms003_records{status=\"verified\"} 1"),
            "{prom}"
        );
        assert!(
            prom.contains("selfdef_ms003_records{status=\"invalid-signature\"} 1"),
            "{prom}"
        );
        assert!(
            prom.contains("selfdef_ms003_records{status=\"unsigned-placeholder\"} 1"),
            "{prom}"
        );
        assert!(
            prom.contains("selfdef_ms003_records{status=\"no-signature-field\"} 1"),
            "{prom}"
        );
        assert!(prom.contains("selfdef_ms003_security_events 1"), "{prom}");
    }

    #[test]
    fn sweep_accepts_json_array() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = TrustAnchors::new(dir.path());
        anchors.add(GOLDEN_PUB).unwrap();
        let arr = format!("[{GOLDEN_REC}]");
        let lpath = write(dir.path(), "ledger.json", &arr);
        assert_eq!(sweep(&anchors, &lpath, None).unwrap(), 0); // all verified
    }
}
