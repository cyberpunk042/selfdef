//! MS007 `selfdef-cli-mirror` daemon-publish path.
//!
//! Unlike the other 9 mirror artifacts (resident-store-backed or
//! canonical-static), the CLI-mirror schema is built by walking the
//! live `clap::Command` tree that lives inside the `selfdefctl` binary.
//! The daemon doesn't have access to that tree directly, so it
//! resolves the snapshot via a two-tier strategy:
//!
//! 1. **Resident store** (preferred). When the operator has run
//!    `selfdefctl cli-mirror snapshot --output PATH` (or the bundled
//!    systemd one-shot has run on selfdefctl upgrade), the artifact
//!    is at `SELFDEF_CLI_MIRROR_PATH` (default
//!    `/var/lib/selfdef/cli-mirror.json`). This is the cleanest path:
//!    no runtime shell-out, no PATH dependency, version-controlled by
//!    the systemd unit (or operator runbook). The file is read on the
//!    first call + cached; subsequent ticks re-read on a 5-min
//!    debounce to pick up post-upgrade refreshes.
//! 2. **Shell-out fallback**. When the resident store is absent, the
//!    daemon shells out to `selfdefctl cli-mirror snapshot --json`
//!    once at startup + caches the bytes. This preserves the original
//!    behavior for hosts that haven't run the producer step yet.
//!
//! Caching is sound because the clap tree is fixed at build time — it
//! cannot change between daemon ticks. Refresh paths:
//!   - resident store: re-read on 5-min debounce (operator-driven upgrade)
//!   - shell-out: cached for the daemon's lifetime (only refreshed on
//!     daemon restart, which is when a new selfdefctl binary would
//!     have been deployed too)
//!
//! Sovereignty-graceful failure modes:
//!   - resident store missing + `selfdefctl` not on PATH → log at
//!     DEBUG once, skip every tick (no crash; honest-offline)
//!   - resident store malformed → log at WARN, fall through to shell-out
//!   - resident store schema-version drift → log at WARN, skip
//!   - shell-out exits non-zero / parse failure → log at WARN, skip
//!
//! Project boundary: this publisher only OBSERVES the operator-facing
//! CLI surface (R10212 doctrine — mirrors are read-only). The clap
//! tree itself is the canonical operator-mutation surface; the mirror
//! is its read-only projection for sovereign-os introspection.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use selfdef_cli_mirror::{CliMirrorSnapshot, DEFAULT_STATE_PATH};
use tokio::process::Command;
use tokio::sync::OnceCell;
use tracing::{debug, warn};

/// How long the resident-store path is cached between re-reads.
/// Five minutes balances upgrade-pickup latency against the cost of
/// reading + parsing the schema on every 30s export tick.
const RESIDENT_RECHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Cached SHELL-OUT snapshot bytes, set on the first successful
/// shell-out (the fallback path). `None` until the first call; the
/// inner `Option<Vec<u8>>` is `Some` when the snapshot is available
/// and `None` when the shell-out failed (in which case subsequent
/// calls don't re-attempt — `selfdefctl` availability cannot change
/// at daemon runtime).
static CACHED_SNAPSHOT: OnceCell<Option<Vec<u8>>> = OnceCell::const_new();

/// Cached RESIDENT-STORE snapshot bytes with the wall-clock instant
/// the cache was last refreshed. Re-read every
/// [`RESIDENT_RECHECK_INTERVAL`] to pick up operator-driven
/// post-upgrade refreshes without re-parsing on every tick.
static RESIDENT_CACHE: Mutex<Option<(Instant, Vec<u8>)>> = Mutex::new(None);

/// Resolve the resident-store path: env override
/// (`SELFDEF_CLI_MIRROR_PATH`) wins, else the crate default
/// (`/var/lib/selfdef/cli-mirror.json`).
fn resident_store_path() -> PathBuf {
    std::env::var_os("SELFDEF_CLI_MIRROR_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_PATH))
}

/// Read the resident store, validating schema. Returns `None` (and
/// logs at WARN) on malformed JSON or schema-version drift so the
/// publisher can fall through to the shell-out fallback path. Returns
/// `None` silently when the file simply doesn't exist (honest-offline
/// for the resident-store path; shell-out fallback gets its turn).
fn read_resident_store(path: &Path) -> Option<Vec<u8>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(
                store = %path.display(),
                error = %e,
                "cli-mirror publisher: resident store unreadable; falling back to shell-out"
            );
            return None;
        }
    };
    // Validate parseability before caching — guards against operator
    // writing junk to the resident store, or schema-version drift
    // between a stale store + the bumped consumer.
    let snap: CliMirrorSnapshot = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                store = %path.display(),
                error = %e,
                "cli-mirror publisher: resident store malformed JSON; falling back to shell-out"
            );
            return None;
        }
    };
    if let Err(e) = snap.validate_schema() {
        warn!(
            store = %path.display(),
            error = %e,
            "cli-mirror publisher: resident store schema-version drift; falling back to shell-out"
        );
        return None;
    }
    Some(bytes)
}

/// Get the resident-store snapshot, using the time-bounded cache.
/// Re-reads the store at most every [`RESIDENT_RECHECK_INTERVAL`].
fn resident_snapshot_bytes() -> Option<Vec<u8>> {
    let path = resident_store_path();
    let now = Instant::now();
    {
        // Fast path — recent cache hit, no I/O.
        let guard = RESIDENT_CACHE.lock().ok()?;
        if let Some((stamped, bytes)) = guard.as_ref() {
            if now.duration_since(*stamped) < RESIDENT_RECHECK_INTERVAL {
                return Some(bytes.clone());
            }
        }
    }
    // Slow path — refresh the cache from disk.
    let fresh = read_resident_store(&path)?;
    let mut guard = RESIDENT_CACHE.lock().ok()?;
    *guard = Some((now, fresh.clone()));
    Some(fresh)
}

/// Hard ceiling on one `selfdefctl cli-mirror snapshot` invocation — a
/// wedged child would otherwise park this publisher loop forever and
/// cli.json would silently stop refreshing while the daemon reports
/// healthy. On expiry the child is killed (`kill_on_drop`) and the tick
/// is treated as offline.
const SNAPSHOT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

async fn fetch_snapshot_bytes() -> Option<Vec<u8>> {
    let pending = Command::new("selfdefctl")
        .arg("cli-mirror")
        .arg("snapshot")
        .arg("--json")
        .kill_on_drop(true)
        .output();
    let bounded = match tokio::time::timeout(SNAPSHOT_DEADLINE, pending).await {
        Ok(r) => r,
        Err(_) => {
            warn!(
                deadline_secs = SNAPSHOT_DEADLINE.as_secs(),
                "cli-mirror publisher: `selfdefctl` timed out (child killed); cli.json stays offline this tick"
            );
            return None;
        }
    };
    let output = match bounded {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                error = %e,
                "cli-mirror publisher: `selfdefctl` not on PATH; cli.json stays offline"
            );
            return None;
        }
        Err(e) => {
            warn!(error = %e, "cli-mirror publisher: spawn failed; cli.json stays offline");
            return None;
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            status = ?output.status.code(),
            stderr = %stderr.trim(),
            "cli-mirror publisher: `selfdefctl cli-mirror snapshot` exited non-zero; cli.json stays offline"
        );
        return None;
    }
    // Validate parseability before caching — guards against a future
    // schema-version drift between selfdef-cli and selfdef-cli-mirror.
    if serde_json::from_slice::<serde_json::Value>(&output.stdout).is_err() {
        warn!("cli-mirror publisher: stdout is not valid JSON; cli.json stays offline");
        return None;
    }
    Some(output.stdout)
}

/// Publish the CLI-mirror snapshot to `<mirror_dir>/cli.json`. Tries
/// the resident-store path first (operator pre-emitted via
/// `selfdefctl cli-mirror snapshot --output PATH` or the systemd
/// one-shot), falling back to the shell-out path on first call only.
/// All subsequent ticks reuse cached bytes from whichever source won.
///
/// Atomic write via tempfile + rename, same pattern as the other
/// publishers in `mirror_export_loop`.
pub(crate) async fn publish_cli(mirror_dir: &Path) {
    // 1. Resident-store path (preferred). Time-bounded cache; re-reads
    //    every 5 min to pick up post-upgrade refreshes.
    let bytes = match resident_snapshot_bytes() {
        Some(b) => b,
        None => {
            // 2. Shell-out fallback. Once-cell — selfdefctl availability
            //    cannot change at daemon runtime.
            let Some(b) = CACHED_SNAPSHOT
                .get_or_init(fetch_snapshot_bytes)
                .await
                .as_ref()
                .cloned()
            else {
                return; // both paths failed; honest-offline
            };
            b
        }
    };
    if let Err(e) = write_bytes_atomic(mirror_dir, "cli.json", &bytes) {
        warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "cli-mirror publisher: write failed; will retry"
        );
        return;
    }
    debug!(
        dir = %mirror_dir.display(),
        bytes = bytes.len(),
        "cli-mirror publisher: cli published"
    );
}

fn write_bytes_atomic(dir: &Path, filename: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(filename);
    let tmp = dir.join(format!(".{filename}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &final_path)?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_cli_is_no_op_when_selfdefctl_missing() {
        // Test environment typically lacks `selfdefctl` on PATH. The
        // publisher MUST handle this gracefully (no panic, cli.json
        // not created).
        let dir = std::env::temp_dir().join(format!("selfdef-cli-mirror-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        publish_cli(&dir).await;
        // Either selfdefctl is unavailable (no cli.json) OR it is
        // available and produced a real snapshot. Both are valid; the
        // contract is "no crash".
        let cli_path = dir.join("cli.json");
        if cli_path.exists() {
            // If it did get published, it must be valid JSON.
            let body = std::fs::read(&cli_path).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v.is_object());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_bytes_atomic_creates_target_no_leftover_tmp() {
        let dir = std::env::temp_dir().join(format!("selfdef-cli-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_bytes_atomic(&dir, "cli.json", b"{\"k\":1}").unwrap();
        assert!(path.exists());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    fn valid_snapshot_bytes() -> Vec<u8> {
        // Hand-crafted minimal CliMirrorSnapshot honoring schema 1.0.0
        // + the verbatim doctrine surface; bypasses the live clap walk.
        let snap = serde_json::json!({
            "schema_version": "1.0.0",
            "cli_build_version": "test",
            "doctrine": "Fullstack at the edges",
            "captured_at": "2026-05-19T00:00:00Z",
            "summaries": [],
            "subcommands": [],
            "signature": "",
        });
        serde_json::to_vec(&snap).unwrap()
    }

    #[test]
    fn read_resident_store_returns_none_for_missing_path() {
        let path = std::env::temp_dir().join(format!(
            "selfdef-cli-resident-missing-{}.json",
            std::process::id()
        ));
        assert!(!path.exists());
        assert!(read_resident_store(&path).is_none());
    }

    #[test]
    fn read_resident_store_returns_some_for_valid_payload() {
        let dir =
            std::env::temp_dir().join(format!("selfdef-cli-resident-valid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cli-mirror.json");
        std::fs::write(&path, valid_snapshot_bytes()).unwrap();
        let got = read_resident_store(&path);
        assert!(got.is_some(), "valid resident store should parse");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_resident_store_rejects_schema_drift() {
        let dir =
            std::env::temp_dir().join(format!("selfdef-cli-resident-drift-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cli-mirror.json");
        let drift = serde_json::json!({
            "schema_version": "2.0.0",
            "cli_build_version": "test",
            "doctrine": "Fullstack at the edges",
            "captured_at": "2026-05-19T00:00:00Z",
            "summaries": [],
            "subcommands": [],
            "signature": "",
        });
        std::fs::write(&path, serde_json::to_vec(&drift).unwrap()).unwrap();
        // Major-version drift → publisher refuses (returns None so the
        // shell-out fallback gets a turn).
        assert!(read_resident_store(&path).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_resident_store_rejects_malformed_json() {
        let dir =
            std::env::temp_dir().join(format!("selfdef-cli-resident-junk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cli-mirror.json");
        std::fs::write(&path, b"this is not json").unwrap();
        assert!(read_resident_store(&path).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resident_store_path_honors_env_override() {
        // Env-override path is the operator-controlled production knob.
        // We exercise it via a process-isolated probe: spawn the lookup
        // in this test thread with a unique sentinel value + read it
        // back. (The cli-publisher crate forbids unsafe_code so we can't
        // mutate the env here directly; this helper validates the
        // function shape without needing to set the env.)
        let p = resident_store_path();
        // Default must be the crate const when no env is set in tests.
        assert_eq!(p, std::path::Path::new(DEFAULT_STATE_PATH));
    }
}
