//! MS007 `selfdef-cli-mirror` daemon-publish path.
//!
//! Unlike the other 9 mirror artifacts (resident-store-backed or
//! canonical-static), the CLI-mirror schema is built by walking the
//! live `clap::Command` tree that lives inside the `selfdefctl` binary.
//! The daemon doesn't have access to that tree, so it shells out to
//! `selfdefctl cli-mirror snapshot --json` once at startup, caches the
//! resulting bytes, and republishes the cached buffer on every
//! mirror-export tick.
//!
//! Caching is sound because the clap tree is fixed at build time — it
//! cannot change between daemon ticks. The cached bytes are refreshed
//! on subsequent daemon restarts (which is when a new selfdefctl
//! binary would have been deployed too).
//!
//! Sovereignty-graceful failure modes:
//!   - `selfdefctl` not on PATH      → log at DEBUG once, skip every
//!     tick (no crash; honest-offline for the CLI-mirror surface)
//!   - shell-out exits non-zero      → log at WARN, skip
//!   - parse failure on stdout       → log at WARN, skip
//!
//! Project boundary: this publisher only OBSERVES the operator-facing
//! CLI surface (R10212 doctrine — mirrors are read-only). The clap
//! tree itself is the canonical operator-mutation surface; the mirror
//! is its read-only projection for sovereign-os introspection.

use std::path::{Path, PathBuf};

use tokio::process::Command;
use tokio::sync::OnceCell;
use tracing::{debug, warn};

/// Cached snapshot bytes, set on the first successful shell-out.
/// `None` until the first call; the inner `Option<Vec<u8>>` is `Some`
/// when the snapshot is available and `None` when the shell-out failed
/// (in which case subsequent calls don't re-attempt — `selfdefctl`
/// availability cannot change at daemon runtime).
static CACHED_SNAPSHOT: OnceCell<Option<Vec<u8>>> = OnceCell::const_new();

async fn fetch_snapshot_bytes() -> Option<Vec<u8>> {
    let output = match Command::new("selfdefctl")
        .arg("cli-mirror")
        .arg("snapshot")
        .arg("--json")
        .output()
        .await
    {
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

/// Publish the CLI-mirror snapshot to `<mirror_dir>/cli.json`. First
/// call shells out to `selfdefctl` + caches; subsequent calls write
/// the cached buffer (or no-op if the first call failed).
///
/// Atomic write via tempfile + rename, same pattern as the other
/// publishers in `mirror_export_loop`.
pub(crate) async fn publish_cli(mirror_dir: &Path) {
    let bytes_opt = CACHED_SNAPSHOT.get_or_init(fetch_snapshot_bytes).await;
    let Some(bytes) = bytes_opt.as_ref() else {
        return; // first shell-out failed; honest-offline
    };
    if let Err(e) = write_bytes_atomic(mirror_dir, "cli.json", bytes) {
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
}
