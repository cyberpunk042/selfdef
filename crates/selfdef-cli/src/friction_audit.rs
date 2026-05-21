//! `selfdefctl friction-audit` — operator surface for the boot-time
//! hardware-integrity gate.
//!
//! Reads the verdict ring buffer at `/var/cache/selfdef/friction-audit/
//! ring/` that `/usr/local/bin/friction-audit` writes on every
//! `sovereign-guard.service` boot. The mirror crate
//! `selfdef-friction-audit-mirror` provides the on-disk shape.
//!
//! This is the read-only minimum-viable CLI; mutating actions
//! (override-create, override-revoke, bundle, verify-bundle) require
//! Ring 0 authority + MS003 multi-sig and land in the next round.
//!
//! Cross-references:
//! - SDD-027 Deliverable 5
//! - MS046 R10913-R10920 (CLI subcommands), R10941-R10942 (perf budget),
//!   R10920 (--json convention)
//! - Pattern parallel: `selfdef-cli/src/hardware.rs`.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use selfdef_friction_audit_mirror::{Gate, Status, Verdict};

/// Ring buffer path (matches the env-default in
/// packaging/scripts/friction-audit.sh). Operator-overridable via
/// `SELFDEF_FRICTION_AUDIT_RING_DIR` env var — same shape as the
/// bash script's env contract, so test rigs + non-default deploys
/// see the same path on both sides.
const DEFAULT_RING_DIR: &str = "/var/cache/selfdef/friction-audit/ring";

fn ring_dir() -> std::path::PathBuf {
    std::env::var_os("SELFDEF_FRICTION_AUDIT_RING_DIR")
        .map_or_else(|| Path::new(DEFAULT_RING_DIR).to_path_buf(), Into::into)
}

/// `selfdefctl friction-audit` default (no subverb) = `show`.
///
/// Renders the latest verdict per Gate. Exit 0 if all gates are
/// `Pass` / `Skipped` / `OverrideActive`; exit 1 if any gate is in
/// `Fail` status.
///
/// # Errors
/// Returns an error if the ring buffer directory exists but cannot
/// be read. Missing-dir is NOT an error — surfaces as "no verdicts
/// recorded yet" output, exit 0.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let dir = ring_dir();
    let verdicts = load_latest_per_gate(&dir)?;
    let failing = verdicts.iter().any(Verdict::is_failing);
    if json {
        let body = serde_json::to_string_pretty(&verdicts)
            .context("serializing verdicts as JSON")?;
        println!("{body}");
    } else {
        if verdicts.is_empty() {
            println!("friction-audit: no verdicts recorded.");
            println!("(Ring buffer empty at {}.)", dir.display());
            println!("Run `sudo /usr/local/bin/friction-audit` to populate, or check sovereign-guard.service.");
            return Ok(0);
        }
        render_human(&verdicts);
    }
    Ok(if failing { 1 } else { 0 })
}

/// `selfdefctl friction-audit history --limit N` — list last N verdicts
/// (newest-first).
///
/// # Errors
/// Returns an error on ring-dir read failure.
pub(crate) fn run_history(limit: u32, json: bool) -> Result<i32> {
    let all = load_all(&ring_dir())?;
    let slice: Vec<&Verdict> = all.iter().take(limit as usize).collect();
    if json {
        let body = serde_json::to_string_pretty(&slice)
            .context("serializing verdicts as JSON")?;
        println!("{body}");
    } else if slice.is_empty() {
        println!("friction-audit: no verdicts recorded.");
    } else {
        for v in &slice {
            print_row(v);
        }
    }
    Ok(0)
}

/// `selfdefctl friction-audit replay` — re-run the gate manually.
///
/// Per MS046 R10927, replay is operator-triggered only (never
/// automatic). Wraps `/usr/local/bin/friction-audit` with the
/// expected env defaults; reports the script exit code unchanged.
///
/// # Errors
/// Returns an error if the script binary is missing or fails to
/// execute. A non-zero script exit code is NOT an error — it's
/// surfaced as our exit code (PCIe=1, ZFS=2, memory=3, timeout=4).
pub(crate) fn run_replay(json: bool) -> Result<i32> {
    use std::process::Command;
    let script = Path::new("/usr/local/bin/friction-audit");
    if !script.exists() {
        if json {
            println!("{}", serde_json::json!({
                "error": "script_missing",
                "expected_path": "/usr/local/bin/friction-audit",
                "hint": "package may not be installed; run apt-get install selfdef-daemon"
            }));
        } else {
            eprintln!("friction-audit: script not installed at {}", script.display());
            eprintln!("hint: package may not be installed; run `apt-get install selfdef-daemon`");
        }
        return Ok(127);
    }
    let status = Command::new(script)
        .status()
        .context("invoking friction-audit script")?;
    let code = status.code().unwrap_or(-1);
    if json {
        println!("{}", serde_json::json!({
            "exit_code": code,
            "passed": code == 0
        }));
    }
    Ok(code)
}

// ---------------------------------------------------------------
// internals
// ---------------------------------------------------------------

fn load_all(ring: &Path) -> Result<Vec<Verdict>> {
    if !ring.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Verdict> = Vec::new();
    for entry in fs::read_dir(ring).with_context(|| format!("reading {}", ring.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        // The script-written entries use a shorter shape than the
        // mirror Verdict (script writes {gate, status, ts_ms, hostname});
        // we map them to the mirror shape with a defaulted signer kid
        // so the operator-facing CLI works even pre-signing-rollout.
        match serde_json::from_slice::<RingEntry>(&bytes) {
            Ok(re) => out.push(re.into_verdict()),
            Err(e) => {
                tracing::warn!(error=%e, path=%path.display(), "skipping malformed ring entry");
            }
        }
    }
    // Newest first by ts_ms.
    out.sort_by_key(|v| std::cmp::Reverse(v.ts_ms));
    Ok(out)
}

fn load_latest_per_gate(ring: &Path) -> Result<Vec<Verdict>> {
    let all = load_all(ring)?;
    let mut seen: std::collections::BTreeMap<String, Verdict> =
        std::collections::BTreeMap::new();
    for v in all {
        let key = format!("{:?}", v.gate);
        seen.entry(key).or_insert(v);
    }
    // Render in fixed Gate order for stable output.
    let mut out = Vec::new();
    for g in [
        Gate::Pcie,
        Gate::Zfs,
        Gate::Memory,
        Gate::Immutability,
        Gate::Signature,
        Gate::Timeout,
    ] {
        if let Some(v) = seen.remove(&format!("{g:?}")) {
            out.push(v);
        }
    }
    Ok(out)
}

fn render_human(verdicts: &[Verdict]) {
    println!("FRICTION-AUDIT verdict summary ({} gates recorded)", verdicts.len());
    println!("─────────────────────────────────────────────────────");
    for v in verdicts {
        print_row(v);
    }
}

fn print_row(v: &Verdict) {
    let (status_tag, status_detail) = match &v.status {
        Status::Pass => ("PASS", String::new()),
        Status::Fail(code) => ("FAIL", format!(" (exit {code})")),
        Status::Skipped(reason) => ("SKIP", format!(" ({reason})")),
        Status::OverrideActive {
            manifest_sha256,
            expires_at_ms,
        } => (
            "OVRD",
            format!(" (manifest {}…, expires {})",
                &manifest_sha256.chars().take(8).collect::<String>(),
                expires_at_ms),
        ),
    };
    println!(
        "  {gate:13} {status:5}{detail}  ts_ms={ts}  host={host}",
        gate = format!("{:?}", v.gate),
        status = status_tag,
        detail = status_detail,
        ts = v.ts_ms,
        host = v.hostname
    );
}

/// On-disk shape written by the friction-audit bash script. Narrower
/// than the canonical mirror `Verdict` (no schema_version, no
/// signer_kid_*); we map up.
#[derive(serde::Deserialize)]
struct RingEntry {
    gate: String,
    status: String,
    ts_ms: u64,
    hostname: String,
}

impl RingEntry {
    fn into_verdict(self) -> Verdict {
        let gate = match self.gate.as_str() {
            "pcie" => Gate::Pcie,
            "zfs" => Gate::Zfs,
            "memory" => Gate::Memory,
            "immutability" => Gate::Immutability,
            "signature" => Gate::Signature,
            "timeout" => Gate::Timeout,
            "overall" => Gate::Pcie, // "overall" entries collapse to pcie display row
            _ => Gate::Pcie,
        };
        let status = match self.status.as_str() {
            "pass" => Status::Pass,
            "skip" => Status::Skipped("operator-extended SKIP (tool absent)".into()),
            "fail" => match gate {
                Gate::Pcie => Status::Fail(1),
                Gate::Zfs => Status::Fail(2),
                Gate::Memory => Status::Fail(3),
                Gate::Timeout => Status::Fail(4),
                _ => Status::Fail(255),
            },
            _ => Status::Fail(255),
        };
        Verdict {
            schema_version: "1.0.0".into(),
            gate,
            status,
            ts_ms: self.ts_ms,
            hostname: self.hostname,
            // Pre-signing rollout: signer kid is the canonical
            // unconfigured marker. selfdef-friction-audit runtime crate
            // (Deliverable 4) will overwrite this with the real
            // MS003-signed kid once shipped.
            signer_kid_policy: "<unsigned>".into(),
            signer_kid_extension: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_entry(dir: &Path, ts: u64, gate: &str, status: &str) {
        let path = dir.join(format!("{ts}-{gate}.json"));
        let body = serde_json::json!({
            "gate": gate,
            "status": status,
            "ts_ms": ts,
            "hostname": "test-host"
        });
        fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();
    }

    #[test]
    fn load_all_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let v = load_all(tmp.path()).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn load_all_missing_dir() {
        let v = load_all(Path::new("/nonexistent/path/should/be/fine")).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn load_all_sorts_newest_first() {
        let tmp = TempDir::new().unwrap();
        write_entry(tmp.path(), 100, "pcie", "pass");
        write_entry(tmp.path(), 300, "pcie", "fail");
        write_entry(tmp.path(), 200, "pcie", "pass");
        let v = load_all(tmp.path()).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].ts_ms, 300);
        assert_eq!(v[1].ts_ms, 200);
        assert_eq!(v[2].ts_ms, 100);
    }

    #[test]
    fn load_latest_per_gate_dedupes() {
        let tmp = TempDir::new().unwrap();
        write_entry(tmp.path(), 100, "pcie", "pass");
        write_entry(tmp.path(), 300, "pcie", "fail");
        write_entry(tmp.path(), 200, "zfs", "pass");
        let v = load_latest_per_gate(tmp.path()).unwrap();
        assert_eq!(v.len(), 2);
        // PCIe first (Gate ordering), and shows the newest (ts=300, fail)
        assert!(matches!(v[0].status, Status::Fail(_)));
        assert_eq!(v[0].ts_ms, 300);
        // ZFS second
        assert!(matches!(v[1].status, Status::Pass));
    }

    #[test]
    fn ring_entry_fail_maps_to_correct_exit_code() {
        let tmp = TempDir::new().unwrap();
        write_entry(tmp.path(), 100, "pcie", "fail");
        write_entry(tmp.path(), 200, "zfs", "fail");
        write_entry(tmp.path(), 300, "memory", "fail");
        let v = load_latest_per_gate(tmp.path()).unwrap();
        assert!(matches!(v[0].status, Status::Fail(1)));
        assert!(matches!(v[1].status, Status::Fail(2)));
        assert!(matches!(v[2].status, Status::Fail(3)));
    }

    #[test]
    fn ring_entry_skip_maps_to_skipped() {
        let tmp = TempDir::new().unwrap();
        write_entry(tmp.path(), 100, "zfs", "skip");
        let v = load_latest_per_gate(tmp.path()).unwrap();
        assert!(matches!(v[0].status, Status::Skipped(_)));
    }

    #[test]
    fn malformed_entry_skipped() {
        let tmp = TempDir::new().unwrap();
        write_entry(tmp.path(), 100, "pcie", "pass");
        fs::write(tmp.path().join("bad.json"), "{not json").unwrap();
        let v = load_all(tmp.path()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ts_ms, 100);
    }
}
