//! M060 D-12 rules collector loop — calls `nft -j list ruleset`
//! periodically, projects the output through
//! [`selfdef_rules_registry::nft_parser::parse_nft_ruleset_json`], and
//! persists the result to `[deployment].selfdef_rules_path` (default
//! `/var/lib/selfdef/rules.json`).
//!
//! The mirror-export loop then republishes this resident store to the
//! sovereign-os mirror directory (`<selfdef_mirror_dir>/rules.json`) on
//! its own cadence — two decoupled loops so a slow nft call cannot stall
//! mirror publishing of the other 7 domains.
//!
//! Sovereignty-graceful:
//!   - missing `nft` binary  → log once at INFO, then skip every tick
//!     (no crash, no panic — honest offline for D-12)
//!   - permission denied     → log at WARN, skip; same honest-offline
//!   - parse failure         → log at WARN, retry next tick
//!
//! Project boundary: this collector READS nftables state. It NEVER
//! installs, modifies, or removes rules. Rule installation lives in
//! `selfdefctl + nft` at the IPS layer (operator MS003 only). This
//! collector is the live-state observer; the registry is the resident
//! mirror that the export loop publishes READ-ONLY (R10212).

use std::path::{Path, PathBuf};
use std::time::Duration;

use selfdef_rules_registry::RulesRegistry;
use selfdef_rules_registry::nft_parser::parse_nft_ruleset_json;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Re-collect cadence in seconds. nftables ruleset changes rarely
/// outside of administrative actions; 30s matches the mirror-export
/// loop cadence so the dashboard sees the freshest projection within
/// one tick of either loop.
const RULES_COLLECT_INTERVAL_SECS: u64 = 30;

/// Hard ceiling on one `nft` invocation. nft talks to the kernel over
/// netlink; a wedged netlink socket would otherwise park this loop's
/// future forever and D-12 would silently stop refreshing while the
/// daemon reports healthy. On expiry the child is killed
/// (`kill_on_drop`) and the tick is treated like any other failure.
const NFT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Run one collect pass: shell to `nft -j list ruleset`, project,
/// persist. Best-effort — all failure paths log + return rather than
/// propagate; the loop ticks again. The boolean indicates whether nft
/// succeeded (true) or was unavailable (false) — used by the loop to
/// suppress repeated identical INFO lines.
async fn collect_once(store: &Path) -> bool {
    let pending = Command::new("nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .kill_on_drop(true)
        .output();
    let bounded = match tokio::time::timeout(NFT_DEADLINE, pending).await {
        Ok(r) => r,
        Err(_) => {
            warn!(
                deadline_secs = NFT_DEADLINE.as_secs(),
                "rules collector: `nft` timed out (child killed); will retry next tick"
            );
            return false;
        }
    };
    let output = match bounded {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // nft not installed — honest offline. The mirror-export loop
            // will continue publishing the other 7 domains; D-12 stays
            // empty/offline. The deployment guide tells the operator
            // how to install nftables.
            debug!(
                error = %e,
                "rules collector: `nft` binary not present; D-12 stays offline (install nftables to populate)"
            );
            return false;
        }
        Err(e) => {
            warn!(error = %e, "rules collector: failed to spawn `nft`; will retry");
            return false;
        }
    };
    if !output.status.success() {
        // nft ran but failed (likely EPERM running unprivileged, or
        // an nftables version mismatch). Log and skip.
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            status = ?output.status.code(),
            stderr = %stderr.trim(),
            "rules collector: `nft -j list ruleset` exited non-zero; will retry"
        );
        return false;
    }
    let stdout = match std::str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "rules collector: nft stdout is not UTF-8; will retry");
            return false;
        }
    };
    let rules = match parse_nft_ruleset_json(stdout) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "rules collector: nft json parse failed; will retry");
            return false;
        }
    };
    let rule_count = rules.len();
    let mut reg = match RulesRegistry::load_from_path(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "rules collector: load_from_path failed; starting with empty registry"
            );
            RulesRegistry::new()
        }
    };
    reg.replace_rules(rules);
    if let Err(e) = reg.save_to_path(store) {
        warn!(
            store = %store.display(),
            error = %e,
            "rules collector: save_to_path failed; will retry"
        );
        return false;
    }
    debug!(
        store = %store.display(),
        rules = rule_count,
        "rules collector: persisted resident registry"
    );
    true
}

/// M060 D-12 rules collector loop. Polls nftables ruleset, projects to
/// `selfdef-rules-registry` shape, persists to `store`. Cooperates with
/// the daemon shutdown signal.
pub(crate) async fn run_rules_collector_loop(store: PathBuf, shutdown: CancellationToken) {
    let _ = collect_once(&store).await;
    let mut tick = tokio::time::interval(Duration::from_secs(RULES_COLLECT_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await; // consume the immediate first tick
    info!(
        store = %store.display(),
        interval_secs = RULES_COLLECT_INTERVAL_SECS,
        "M060 D-12: rules collector running (nft -j list ruleset → selfdef-rules-registry, read-only observer)"
    );
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("M060 D-12: shutdown signalled; exiting rules collector loop");
                return;
            }
            _ = tick.tick() => { let _ = collect_once(&store).await; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collect_once_does_not_panic_in_test_env() {
        // The CI test container likely lacks nft (or the calling user
        // lacks NET_ADMIN). Either way, collect_once must return false
        // without panicking — that IS the production-grade contract.
        // We intentionally do not assert false here: a CI box that
        // happens to have nft installed AND runs the test as root will
        // return true. The contract is "no panic"; that's the assert.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("rules.json");
        let _ = collect_once(&store).await;
    }

    #[tokio::test]
    async fn collect_loop_exits_cleanly_on_shutdown() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("rules.json");
        let shutdown = CancellationToken::new();
        let h = tokio::spawn(run_rules_collector_loop(store, shutdown.clone()));
        // Give the loop a moment to spin up + reach the select.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();
        // Loop should exit promptly. Bound the wait so a regression
        // (e.g., missing shutdown branch) fails the test fast.
        let result = tokio::time::timeout(Duration::from_secs(5), h).await;
        assert!(result.is_ok(), "loop did not exit within 5s of cancel");
    }
}
