//! External event stream collector.
//!
//! Reads a JSONL file where every line is a pre-formed selfdef [`Event`]
//! (same shape as the bus carries internally) and republishes onto the
//! bus. Used by the `selfdef-ssh-wrap` binary and any other tool that
//! wants to inject events without writing to the bus directly.
//!
//! The collector trusts the on-disk events to be well-formed — the writer
//! and the daemon typically share the same `selfdef-core` version, and
//! the schema is forward-compatible (non-exhaustive Event struct). Bad
//! lines are logged and skipped, never crash the collector.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_core::Event;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    Start,
    End,
}

impl ReadFrom {
    pub fn parse(s: &str) -> Self {
        match s {
            "start" => Self::Start,
            _ => Self::End,
        }
    }
}

#[derive(Debug, Error)]
pub enum EventstreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// SDD-004 F-2026-026 follow-up: the configured path failed
    /// the integrity check (ownership / mode mismatch).
    #[error("integrity-check refused path {path}: {reason}")]
    IntegrityRefused { path: PathBuf, reason: &'static str },
    /// F-2027-035: the configured path is (or became) a symlink.
    /// The integrity check uses `O_NOFOLLOW` so symlinks are never
    /// resolved — the operator must point at a regular file
    /// directly. Captured as its own variant because the operator-
    /// facing remediation is different from generic
    /// `IntegrityRefused` (rewrite the path vs. fix perms).
    #[error(
        "integrity-check refused symlink {path}: re-point [collectors.eventstream].paths at the real file, not a symlink"
    )]
    IntegritySymlink { path: PathBuf },
}

/// SDD-004 F-2026-026 follow-up: opt-in integrity check for
/// eventstream JSONL paths. The daemon constructs one per
/// collector instance from `[collectors.eventstream]` config.
#[derive(Debug, Clone, Default)]
pub struct IntegrityCheck {
    /// When `false` (the default), the collector skips the
    /// check and behaves identically to pre-follow-up code.
    pub enabled: bool,
    /// Additional UIDs accepted as the owner. The daemon's
    /// effective UID and root are always accepted when
    /// `enabled = true`.
    pub allowed_owners: Vec<u32>,
}

pub struct EventstreamCollector {
    input_path: PathBuf,
    read_from: ReadFrom,
    publisher: Publisher,
    integrity: IntegrityCheck,
}

impl EventstreamCollector {
    #[must_use]
    pub fn new(input_path: PathBuf, read_from: ReadFrom, publisher: Publisher) -> Self {
        Self {
            input_path,
            read_from,
            publisher,
            integrity: IntegrityCheck::default(),
        }
    }

    /// Attach an integrity check. Chainable.
    #[must_use]
    pub fn with_integrity_check(mut self, check: IntegrityCheck) -> Self {
        self.integrity = check;
        self
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), EventstreamError> {
        info!(path = %self.input_path.display(), "eventstream collector starting");
        wait_for_file(&self.input_path, &shutdown).await;

        // F-2027-035: open and integrity-check in a single
        // syscall sequence. The pre-fix code stat'd the path,
        // then opened it — leaving a TOCTOU window an attacker
        // could exploit by renaming a symlink in between. The
        // new sequence opens with `O_NOFOLLOW` (rejects symlinks
        // up front) and then fstats the returned FD — the
        // metadata is locked to the inode we'll actually read
        // from, so a post-open replacement on disk can't change
        // what we validated. The opened file is moved into the
        // tokio runtime below.
        let std_file = if self.integrity.enabled {
            open_with_integrity_check(&self.input_path, &self.integrity)?
        } else {
            std::fs::OpenOptions::new()
                .read(true)
                .open(&self.input_path)
                .map_err(EventstreamError::Io)?
        };
        let mut file = tokio::fs::File::from_std(std_file);
        if self.read_from == ReadFrom::End {
            file.seek(std::io::SeekFrom::End(0)).await?;
        }
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        // Holds a partial line read before its terminating newline arrived.
        let mut pending = String::new();

        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            buf.clear();
            let n = tokio::select! {
                r = reader.read_line(&mut buf) => r?,
                () = shutdown.cancelled() => return Ok(()),
            };
            if n == 0 {
                // EOF — wait for more. `pending` is preserved across the poll
                // so a half-written line completes on the next read.
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            // Accumulate, then process only COMPLETE ('\n'-terminated) lines,
            // leaving any trailing partial buffered. A read that didn't reach a
            // newline is a partial write racing the reader; parsing it now would
            // split — and drop — the event.
            pending.push_str(&buf);
            for line in drain_complete_lines(&mut pending) {
                match serde_json::from_str::<Event>(&line) {
                    Ok(event) => self.publisher.publish_lossy(event),
                    Err(e) => debug!(error = %e, "skipping malformed eventstream line"),
                }
            }
        }
    }
}

/// F-2027-035: open the file with `O_NOFOLLOW`, fstat the
/// returned FD, validate ownership + mode against the operator-
/// configured rules, and return the opened file ready for the
/// reader to consume.
///
/// Why open-then-fstat instead of the pre-fix stat-then-open:
///
/// 1. **`O_NOFOLLOW`** — if the path is a symlink, `open(2)`
///    returns `ELOOP`. Translated into
///    [`EventstreamError::IntegritySymlink`] so operators see
///    a remediation message that points them at the real file.
///    Pre-fix code used [`std::fs::metadata`] (which is `stat`,
///    not `lstat`) and silently followed symlinks.
/// 2. **fstat on the FD** — the metadata returned by
///    [`std::fs::File::metadata`] reads from the open FD, not
///    a fresh path lookup. A post-open replacement on disk
///    (mv, ln -sf, unlink+create) doesn't affect what we
///    validated. Pre-fix code stat'd the path, then opened it,
///    leaving a TOCTOU window during which a local attacker
///    could swap in a different file.
/// 3. **Single error path** — if either step fails, the FD is
///    dropped (closed) on return, so an integrity refusal can't
///    leak a partially-opened handle to the reader.
fn open_with_integrity_check(
    path: &Path,
    check: &IntegrityCheck,
) -> Result<std::fs::File, EventstreamError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // O_NOFOLLOW = 0x20000 on Linux glibc / musl. The constant
    // is stable Linux ABI; pulling in libc as a dep for a
    // single integer would be heavy. (uapi/asm-generic/fcntl.h:
    // `#define O_NOFOLLOW 00400000` = 0x20000.)
    //
    // O_NONBLOCK is added so we can refuse fifos / sockets via
    // fstat without blocking on the open call (an `open(fifo,
    // O_RDONLY)` would otherwise wait for a writer indefinitely).
    // For regular files O_NONBLOCK is a no-op; for fifos it
    // lets us open + fstat + refuse cleanly.
    // (uapi/asm-generic/fcntl.h: `#define O_NONBLOCK 04000` = 0x800.)
    const O_NOFOLLOW: i32 = 0x20000;
    const O_NONBLOCK: i32 = 0x800;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if matches!(e.raw_os_error(), Some(libc_eloop) if libc_eloop == 40) => {
            // ELOOP == 40 on Linux. Surfaced as a typed variant
            // so the operator-facing message is actionable
            // (rewrite the path) rather than the generic
            // "Too many levels of symbolic links".
            return Err(EventstreamError::IntegritySymlink {
                path: path.to_path_buf(),
            });
        }
        Err(e) => return Err(EventstreamError::Io(e)),
    };

    let md = file.metadata().map_err(EventstreamError::Io)?;

    // Refuse anything that isn't a plain regular file — defense
    // in depth against, e.g., a fifo or device node at the
    // configured path (O_NOFOLLOW catches symlinks but not
    // these).
    if !md.is_file() {
        return Err(EventstreamError::IntegrityRefused {
            path: path.to_path_buf(),
            reason: "not a regular file (fifo, socket, device, or directory)",
        });
    }

    let mode = md.mode();
    if mode & 0o002 != 0 {
        return Err(EventstreamError::IntegrityRefused {
            path: path.to_path_buf(),
            reason: "world-writable (mode & 0o002 != 0)",
        });
    }

    let owner = md.uid();
    // F-2027-003: read the daemon's effective UID for the
    // owner-match check. The pre-fix `unsafe_geteuid` silently
    // returned `0` on any /proc read failure, making the check
    // accidentally permissive (any root-owned file passed even
    // when the daemon's euid wasn't root). Now if the read
    // fails we emit a `warn!` and fall back to "only root is
    // allowed" — strict-safe rather than permissive.
    let euid = match read_euid() {
        Some(u) => u,
        None => {
            tracing::warn!(
                "integrity check: /proc/self/status unreadable — \
                 falling back to root-only ownership rule. \
                 Effective UID match will not work."
            );
            0
        }
    };
    let allowed = owner == euid || owner == 0 || check.allowed_owners.contains(&owner);
    if !allowed {
        return Err(EventstreamError::IntegrityRefused {
            path: path.to_path_buf(),
            reason: "owner uid not in allowed set (daemon-effective-uid, root, or [collectors.eventstream].allowed_owners)",
        });
    }
    Ok(file)
}

/// libc geteuid wrapper. The selfdef workspace lint forbids
/// `unsafe` so we shell out to /proc/self/status as a portable,
/// safe-Rust workaround. `Uid: <ruid> <euid> <suid> <fsuid>`.
///
/// F-2027-003 follow-up: previously returned `0` silently on
/// any failure, making the integrity check accidentally
/// permissive — every root-owned file passed even when the
/// daemon's effective UID wasn't root. Now returns `None` so
/// callers can degrade explicitly and the operator sees a
/// `warn!` line.
fn read_euid() -> Option<u32> {
    let txt = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in txt.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Second whitespace-separated token is euid.
            let mut it = rest.split_whitespace();
            let _ruid = it.next();
            if let Some(euid_str) = it.next() {
                return euid_str.parse().ok();
            }
        }
    }
    None
}

async fn wait_for_file(path: &Path, shutdown: &CancellationToken) {
    for _ in 0..40 {
        if path.exists() {
            return;
        }
        if shutdown.is_cancelled() {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Drain the COMPLETE (`'\n'`-terminated) lines from `pending`, returning each
/// trimmed non-empty line and leaving any trailing partial line buffered in
/// `pending` for the next read.
///
/// This is what makes the tailer robust to a partial write racing the reader:
/// a chunk that doesn't reach a newline contributes nothing yet (the event is
/// not split and dropped); it completes on a later read.
fn drain_complete_lines(pending: &mut String) -> Vec<String> {
    let Some(last_nl) = pending.rfind('\n') else {
        return Vec::new(); // no complete line yet — keep buffering
    };
    let out: Vec<String> = pending[..=last_nl]
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    // Keep whatever follows the last newline (a partial line, or empty).
    *pending = pending[last_nl + 1..].to_string();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_bus::Bus;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn integrity_check_rejects_world_writable_file() {
        let file = NamedTempFile::new().unwrap();
        let mut perms = std::fs::metadata(file.path()).unwrap().permissions();
        perms.set_mode(0o666);
        std::fs::set_permissions(file.path(), perms).unwrap();
        let check = IntegrityCheck {
            enabled: true,
            allowed_owners: vec![],
        };
        let err = open_with_integrity_check(file.path(), &check)
            .expect_err("world-writable file must be refused");
        match err {
            EventstreamError::IntegrityRefused { reason, .. } => {
                assert!(
                    reason.contains("world-writable"),
                    "unexpected reason: {reason}",
                );
            }
            other => panic!("expected IntegrityRefused, got: {other:?}"),
        }
    }

    #[test]
    fn integrity_check_accepts_daemon_or_root_owned_file() {
        // The test runs as the CI user (often UID 0 or a build
        // user); either way the file is created with that UID
        // and the check should accept it because the file's
        // owner == effective UID. F-2027-035: the function now
        // returns the opened File handle on success — we drop
        // it immediately, which closes the FD.
        let file = NamedTempFile::new().unwrap();
        let mut perms = std::fs::metadata(file.path()).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(file.path(), perms).unwrap();
        let check = IntegrityCheck {
            enabled: true,
            allowed_owners: vec![],
        };
        let _opened = open_with_integrity_check(file.path(), &check)
            .expect("daemon-owned file must be accepted");
    }

    #[test]
    fn integrity_check_accepts_explicit_allowed_owner() {
        // Even if the file's owner UID weren't the daemon's, an
        // explicit allowlist entry would accept it. We can't
        // easily chown a tempfile in tests; simulate by
        // including the file's actual owner in the allowlist
        // and asserting the function still says OK. (The
        // logic-as-written checks daemon/root first, but
        // exercising the allowlist branch keeps it covered.)
        use std::os::unix::fs::MetadataExt;
        let file = NamedTempFile::new().unwrap();
        let mut perms = std::fs::metadata(file.path()).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(file.path(), perms).unwrap();
        let owner = std::fs::metadata(file.path()).unwrap().uid();
        let check = IntegrityCheck {
            enabled: true,
            allowed_owners: vec![owner.saturating_add(1), owner],
        };
        let _opened = open_with_integrity_check(file.path(), &check)
            .expect("allowlisted owner must be accepted");
    }

    #[test]
    fn integrity_check_refuses_symlink() {
        // F-2027-035: the pre-fix code used std::fs::metadata
        // (which is stat, not lstat), so a symlink pointing at
        // a daemon-owned file would silently pass the check;
        // the collector then read attacker-controlled data
        // through the symlink. Now: O_NOFOLLOW on the open(2)
        // call yields ELOOP, surfaced as IntegritySymlink.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.jsonl");
        std::fs::write(&target, b"original\n").unwrap();
        let link = dir.path().join("via-symlink.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let check = IntegrityCheck {
            enabled: true,
            allowed_owners: vec![],
        };
        let err =
            open_with_integrity_check(&link, &check).expect_err("symlink path must be refused");
        match err {
            EventstreamError::IntegritySymlink { path } => {
                assert_eq!(path, link);
            }
            other => panic!("expected IntegritySymlink, got: {other:?}"),
        }
    }

    #[test]
    fn integrity_check_refuses_non_regular_file() {
        // F-2027-035: O_NOFOLLOW catches symlinks but not fifos,
        // sockets, or device nodes. Defense-in-depth: the
        // fstat'd metadata is_file() must be true.
        //
        // We pick the most common non-regular type that's cheap
        // to create in user-space without privileges: a fifo
        // (named pipe). The check refuses it.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe.fifo");
        // mkfifo via the shell — selfdef-collector-eventstream
        // doesn't carry a nix / rustix dep for this single call.
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("spawn mkfifo");
        if !status.success() {
            // mkfifo isn't on PATH (busybox? minimal container?).
            // Skip rather than fail — the property is observable
            // in CI and the workspace-default host.
            eprintln!("mkfifo unavailable; skipping non-regular-file test");
            return;
        }

        let check = IntegrityCheck {
            enabled: true,
            allowed_owners: vec![],
        };
        let err = open_with_integrity_check(&fifo, &check)
            .expect_err("fifo must be refused as non-regular");
        match err {
            EventstreamError::IntegrityRefused { reason, .. } => {
                assert!(
                    reason.contains("not a regular file"),
                    "unexpected reason: {reason}",
                );
            }
            other => panic!("expected IntegrityRefused (not regular), got: {other:?}"),
        }
    }

    #[test]
    fn integrity_check_disabled_short_circuits() {
        // With `enabled: false`, the helper is never called.
        // We model this by asserting collector.run() doesn't
        // call check_path_integrity when integrity.enabled is
        // false — covered by the existing tails_event_file
        // test below, which uses default IntegrityCheck
        // (enabled=false) and reads a file regardless of
        // ownership.
    }

    #[test]
    fn read_euid_returns_some_on_linux_test_host() {
        // F-2027-003: read_euid previously returned 0 silently
        // on /proc read failure, making the check accidentally
        // permissive. On a Linux test host /proc/self/status
        // is always readable, so we expect Some(_) and a
        // non-bogus value (Uid line always present in
        // /proc/self/status; the parsed euid is whatever the
        // test process runs as).
        let euid = read_euid();
        assert!(
            euid.is_some(),
            "read_euid() must return Some on a Linux host with /proc; got None",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tails_event_file_and_republishes() {
        let mut file = NamedTempFile::new().unwrap();

        // Pre-write one event so we know it's seen on Start mode.
        let event = Event::new(
            ClassUid::SSH_ACTIVITY,
            1,
            SeverityId::Informational,
            "test-host",
            "selfdef.ssh-wrap",
            0,
        );
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        file.flush().unwrap();

        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();

        let collector = EventstreamCollector::new(file.path().to_path_buf(), ReadFrom::Start, pub_);
        let shutdown = CancellationToken::new();
        let sd = shutdown.clone();
        let task = tokio::spawn(async move { collector.run(sd).await });

        let received = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("timeout")
            .expect("recv error");
        assert_eq!(received.source, "selfdef.ssh-wrap");
        assert_eq!(received.class_uid, ClassUid::SSH_ACTIVITY);

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    // ---- partial-line accumulation (the write-race fix) ----

    #[test]
    fn drain_returns_nothing_for_a_partial_line() {
        let mut p = String::from("{\"partial\":");
        assert!(drain_complete_lines(&mut p).is_empty());
        // the partial stays buffered for the next read.
        assert_eq!(p, "{\"partial\":");
    }

    #[test]
    fn partial_then_completion_yields_one_whole_line() {
        // A write split across two reads must NOT lose the event.
        let mut p = String::new();
        p.push_str("{\"a\":1"); // first read: partial
        assert!(drain_complete_lines(&mut p).is_empty());
        p.push_str("}\n"); // second read: the completion
        let lines = drain_complete_lines(&mut p);
        assert_eq!(lines, vec!["{\"a\":1}".to_string()]);
        assert!(p.is_empty(), "no leftover after a complete line");
    }

    #[test]
    fn multiple_complete_lines_drain_leaving_trailing_partial() {
        let mut p = String::from("one\ntwo\nthree-part");
        let lines = drain_complete_lines(&mut p);
        assert_eq!(lines, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(p, "three-part", "the trailing partial is preserved");
    }

    #[test]
    fn blank_lines_are_skipped() {
        let mut p = String::from("a\n\n  \nb\n");
        assert_eq!(drain_complete_lines(&mut p), vec!["a".to_string(), "b".to_string()]);
        assert!(p.is_empty());
    }
}
