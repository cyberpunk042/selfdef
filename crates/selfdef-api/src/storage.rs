//! `GET /v1/storage` — MS011 Z-10 filesystem-usage + log surface.
//!
//! Per-mount disk usage and per-selfdef-managed-path log volume,
//! as called out in SDD-026 Z-10:
//!
//! - **Filesystem mounts** — `df --output=source,fstype,size,used,
//!   avail,pcent,target` filtered to the operator-relevant subset
//!   (excludes tmpfs/devtmpfs/squashfs; operator override via
//!   `SELFDEF_STORAGE_INCLUDE_PSEUDO=1`).
//! - **Log directories** — `/var/log/selfdef`, `/var/cache/selfdef`,
//!   `/var/lib/selfdef`. Each one's recursive byte count + file
//!   count. Missing path → 0 bytes / 0 files (best-effort; doesn't
//!   error the whole response).
//!
//! Probe runs synchronously per request. `df` is fast (kernel
//! syscall, not a filesystem walk); the log dir walks are bounded
//! by the natural file count under each path (typically dozens, not
//! millions).
//!
//! Source: MS011 catalog row M00277 / Z-10 + SDD-026 § Z-10.

use std::path::Path;
use std::process::Command;

use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MountUsage {
    pub source: String,
    pub fstype: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub avail_bytes: u64,
    pub used_pct: u32,
    pub mountpoint: String,
    /// `"green"` (< 70 %), `"yellow"` (70-89 %), `"red"` (≥ 90 %).
    pub state: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LogDirUsage {
    pub path: String,
    pub bytes: u64,
    pub files: u64,
    /// True iff the path exists; false → bytes/files are 0 by
    /// convention so JSON consumers don't need special-casing.
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StorageResponse {
    /// Worst-state across the mounts (`red > yellow > green`); log
    /// dirs don't contribute to the aggregate (they're informational).
    pub worst: &'static str,
    pub mounts: Vec<MountUsage>,
    pub log_dirs: Vec<LogDirUsage>,
}

fn classify_used_pct(pct: u32) -> &'static str {
    if pct >= 90 {
        "red"
    } else if pct >= 70 {
        "yellow"
    } else {
        "green"
    }
}

fn worst_mount(mounts: &[MountUsage]) -> &'static str {
    let mut worst = "green";
    for m in mounts {
        match (worst, m.state) {
            (_, "red") => return "red",
            ("green", "yellow") => worst = "yellow",
            _ => {}
        }
    }
    worst
}

fn parse_size_kib(s: &str) -> u64 {
    // df --output=...,size,used,avail with default block-size=1K
    s.trim().parse::<u64>().unwrap_or(0) * 1024
}

fn parse_pct(s: &str) -> u32 {
    s.trim().trim_end_matches('%').parse::<u32>().unwrap_or(0)
}

/// Parse the body of `df -P --output=source,fstype,size,used,avail,pcent,target`.
/// Splits each line into 7 whitespace-delimited columns (with the
/// last column allowed to contain spaces — mountpoints rarely do but
/// the parser tolerates them).
fn parse_df_output(body: &str, include_pseudo: bool) -> Vec<MountUsage> {
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // split_whitespace collapses runs of whitespace. The last
        // column (mountpoint) is rarely spaced; if it is, we rejoin.
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 7 {
            continue;
        }
        let source = parts[0].to_string();
        let fstype = parts[1].to_string();
        let size_bytes = parse_size_kib(parts[2]);
        let used_bytes = parse_size_kib(parts[3]);
        let avail_bytes = parse_size_kib(parts[4]);
        let used_pct = parse_pct(parts[5]);
        let mountpoint = parts[6..].join(" ");
        // Exclude pseudo-filesystems unless operator opted in.
        if !include_pseudo
            && matches!(
                fstype.as_str(),
                "tmpfs" | "devtmpfs" | "squashfs" | "proc" | "sysfs" | "cgroup2" | "overlay"
            )
        {
            continue;
        }
        let state = classify_used_pct(used_pct);
        out.push(MountUsage {
            source,
            fstype,
            size_bytes,
            used_bytes,
            avail_bytes,
            used_pct,
            mountpoint,
            state,
        });
    }
    out
}

fn run_df() -> Vec<MountUsage> {
    let include_pseudo = std::env::var("SELFDEF_STORAGE_INCLUDE_PSEUDO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let out = Command::new("df")
        .args(["-P", "--output=source,fstype,size,used,avail,pcent,target"])
        .output();
    let body = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return Vec::new(),
    };
    parse_df_output(&body, include_pseudo)
}

/// Walk a directory recursively, summing file sizes + file count.
/// Returns (bytes, files). Silently skips entries it can't stat (the
/// daemon runs as a specific user; some files may be owned by other
/// users and unreadable — that's fine).
fn dir_usage(path: &Path) -> (u64, u64) {
    let mut bytes: u64 = 0;
    let mut files: u64 = 0;
    let mut stack: Vec<std::path::PathBuf> = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                bytes += meta.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

fn probe_log_dirs() -> Vec<LogDirUsage> {
    let paths = ["/var/log/selfdef", "/var/cache/selfdef", "/var/lib/selfdef"];
    paths
        .iter()
        .map(|p| {
            let path_obj = Path::new(p);
            if path_obj.exists() {
                let (bytes, files) = dir_usage(path_obj);
                LogDirUsage {
                    path: (*p).to_string(),
                    bytes,
                    files,
                    exists: true,
                }
            } else {
                LogDirUsage {
                    path: (*p).to_string(),
                    bytes: 0,
                    files: 0,
                    exists: false,
                }
            }
        })
        .collect()
}

/// `GET /v1/storage` handler.
/// Sync probe — extracted from `show` so the Prometheus
/// `watchdog_metrics::render` path (sync) can reuse the same
/// classified result without spinning up an executor.
pub(crate) fn probe() -> StorageResponse {
    let mounts = run_df();
    let worst = worst_mount(&mounts);
    let log_dirs = probe_log_dirs();
    StorageResponse {
        worst,
        mounts,
        log_dirs,
    }
}

/// Hard ceiling on what one `/v1/storage` request waits for the SYNC
/// probe — `df` can block INDEFINITELY on a hung network mount (NFS hard
/// mount with a dead server is the classic). The probe runs on the
/// blocking pool so it can't starve async workers; on expiry the request
/// gets an honest `unknown` (reason logged) instead of hanging.
const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

async fn show_bounded(
    deadline: std::time::Duration,
    probe_fn: fn() -> StorageResponse,
) -> Json<StorageResponse> {
    let degraded = || StorageResponse {
        worst: "unknown",
        mounts: Vec::new(),
        log_dirs: Vec::new(),
    };
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(probe_fn)).await {
        Ok(Ok(resp)) => Json(resp),
        Ok(Err(join_err)) => {
            tracing::warn!(error = %join_err, "storage probe task failed; reporting unknown");
            Json(degraded())
        }
        Err(_) => {
            tracing::warn!(
                deadline_secs = deadline.as_secs(),
                "storage probe timed out (hung mount?); reporting unknown"
            );
            Json(degraded())
        }
    }
}

pub(crate) async fn show() -> Json<StorageResponse> {
    show_bounded(PROBE_DEADLINE, probe).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_used_pct_thresholds() {
        assert_eq!(classify_used_pct(0), "green");
        assert_eq!(classify_used_pct(69), "green");
        assert_eq!(classify_used_pct(70), "yellow");
        assert_eq!(classify_used_pct(89), "yellow");
        assert_eq!(classify_used_pct(90), "red");
        assert_eq!(classify_used_pct(100), "red");
    }

    #[test]
    fn parse_df_skips_pseudo_filesystems_by_default() {
        let body = "Filesystem     Type      1024-blocks      Used Available Capacity Mounted on\n\
                    /dev/vda1      ext4         10485760    5242880   5242880  50% /\n\
                    tmpfs          tmpfs         2097152          0   2097152   0% /run\n\
                    udev           devtmpfs      1048576          0   1048576   0% /dev\n";
        let mounts = parse_df_output(body, false);
        assert_eq!(mounts.len(), 1, "tmpfs + devtmpfs should be filtered");
        assert_eq!(mounts[0].source, "/dev/vda1");
        assert_eq!(mounts[0].fstype, "ext4");
        assert_eq!(mounts[0].used_pct, 50);
        assert_eq!(mounts[0].state, "green");
        // size column is in 1K blocks per -P; we convert to bytes.
        assert_eq!(mounts[0].size_bytes, 10_485_760u64 * 1024);
        assert_eq!(mounts[0].mountpoint, "/");
    }

    #[test]
    fn parse_df_includes_pseudo_when_opted_in() {
        let body = "Filesystem     Type      1024-blocks      Used Available Capacity Mounted on\n\
                    tmpfs          tmpfs         2097152          0   2097152   0% /run\n";
        let mounts = parse_df_output(body, true);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].fstype, "tmpfs");
    }

    #[test]
    fn parse_df_state_thresholds() {
        let body = "Filesystem     Type      1024-blocks      Used Available Capacity Mounted on\n\
                    /dev/vda1      ext4         10485760    9437184   1048576  91% /\n";
        let mounts = parse_df_output(body, false);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].used_pct, 91);
        assert_eq!(mounts[0].state, "red");
    }

    #[test]
    fn worst_mount_red_dominates() {
        let mounts = vec![
            MountUsage {
                source: "/dev/a".into(),
                fstype: "ext4".into(),
                size_bytes: 0,
                used_bytes: 0,
                avail_bytes: 0,
                used_pct: 10,
                mountpoint: "/".into(),
                state: "green",
            },
            MountUsage {
                source: "/dev/b".into(),
                fstype: "ext4".into(),
                size_bytes: 0,
                used_bytes: 0,
                avail_bytes: 0,
                used_pct: 95,
                mountpoint: "/data".into(),
                state: "red",
            },
        ];
        assert_eq!(worst_mount(&mounts), "red");
    }

    #[test]
    fn dir_usage_counts_known_path() {
        // Use a tempdir we create ourselves so the test is portable.
        let tmp = std::env::temp_dir().join(format!("selfdef-storage-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.txt"), b"hello").unwrap();
        std::fs::write(tmp.join("b.txt"), b"world!!!").unwrap();
        let nested = tmp.join("sub");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("c.txt"), b"nested").unwrap();
        let (bytes, files) = dir_usage(&tmp);
        assert_eq!(bytes, 5 + 8 + 6);
        assert_eq!(files, 3);
        let _ = std::fs::remove_dir_all(&tmp);
    }
    /// A zero deadline deterministically takes the timeout branch: the
    /// request must get an honest degraded `unknown`, never hang on the probe.
    #[tokio::test]
    async fn show_bounded_returns_degraded_unknown_on_deadline() {
        // Injected probe that wedges far past the deadline — deterministic
        // stand-in for `df` hung on a dead NFS hard mount.
        fn stalled() -> StorageResponse {
            std::thread::sleep(std::time::Duration::from_secs(5));
            probe()
        }
        let start = std::time::Instant::now();
        let axum::Json(resp) = show_bounded(std::time::Duration::from_millis(50), stalled).await;
        assert!(
            start.elapsed() < std::time::Duration::from_secs(4),
            "must not wait the probe out"
        );
        assert_eq!(resp.worst, "unknown");
        assert!(resp.mounts.is_empty());
        assert!(resp.log_dirs.is_empty());
    }
}
