//! Userspace loader for selfdef's BPF programs.
//!
//! Loads a precompiled `.bpf.o` object via [aya], attaches its programs to
//! the kernel, drains the `EVENTS` ring buffer, decodes records into OCSF
//! [`Event`]s, and publishes onto the bus.
//!
//! **Graceful degradation.** If the BPF object isn't installed at the
//! configured path, the collector logs a warning and runs idle. The daemon
//! still functions with its other collectors. To install eBPF support, see
//! `docs/ebpf-build.md`.
//!
//! **Required capabilities.** `CAP_BPF` + `CAP_PERFMON` (modern kernels;
//! Linux >= 5.8 without root). The systemd unit grants these explicitly.
//!
//! **Tested kernels.** Designed for Linux >= 5.15 with BTF support
//! (`/sys/kernel/btf/vmlinux` present). Debian 13 / Ubuntu 24 ship this.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aya::maps::RingBuf;
use aya::programs::{KProbe, Lsm, TracePoint};
use aya::{Btf, EbpfError as AyaEbpfError};
use selfdef_bus::Publisher;
use selfdef_core::Event;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_ebpf_common::{EventKind, FileOpenEvent, ProcessExecEvent, UnlinkEvent};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("aya: {0}")]
    Aya(#[from] AyaEbpfError),
    #[error("aya-program: {0}")]
    Program(#[from] aya::programs::ProgramError),
    #[error("aya-map: {0}")]
    Map(#[from] aya::maps::MapError),
    #[error("bpf object not found at {0}")]
    NotFound(PathBuf),
}

/// Which optional probes the loader should try to attach. Each flag
/// degrades gracefully — if the corresponding program is missing from
/// the BPF object, or the kernel doesn't support the hook, we log a
/// warning and keep going.
#[derive(Debug, Clone, Copy)]
pub struct EbpfProbes {
    pub execve: bool,
    pub lsm_file_open: bool,
    pub kprobe_unlinkat: bool,
}

impl Default for EbpfProbes {
    fn default() -> Self {
        // Mirrors the conservative defaults in `[collectors.ebpf]`: execve
        // is the only probe enabled out of the box.
        Self {
            execve: true,
            lsm_file_open: false,
            kprobe_unlinkat: false,
        }
    }
}

pub struct EbpfCollector {
    bpf_object_path: PathBuf,
    publisher: Publisher,
    host_tag: String,
    sequence: AtomicU64,
    probes: EbpfProbes,
}

impl EbpfCollector {
    #[must_use]
    pub fn new(bpf_object_path: PathBuf, publisher: Publisher, host_tag: String) -> Self {
        Self::with_probes(bpf_object_path, publisher, host_tag, EbpfProbes::default())
    }

    #[must_use]
    pub fn with_probes(
        bpf_object_path: PathBuf,
        publisher: Publisher,
        host_tag: String,
        probes: EbpfProbes,
    ) -> Self {
        Self {
            bpf_object_path,
            publisher,
            host_tag,
            sequence: AtomicU64::new(0),
            probes,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), EbpfError> {
        if !self.bpf_object_path.exists() {
            warn!(
                path = %self.bpf_object_path.display(),
                "no BPF object installed; ebpf collector idle. \
                See docs/ebpf-build.md to enable kernel collection."
            );
            shutdown.cancelled().await;
            return Ok(());
        }

        info!(path = %self.bpf_object_path.display(), "loading BPF object");
        let mut bpf = aya::Ebpf::load_file(&self.bpf_object_path)?;

        // Route BPF-side `aya_log` messages into our tracing pipeline. Best-
        // effort; programs that don't use aya-log will return an error and
        // we ignore it.
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            debug!(error = %e, "aya log not initialized (BPF programs may not use aya-log)");
        }

        // Attach probes. Each one is opt-in via config and degrades
        // gracefully if absent from the BPF object or unsupported by the
        // kernel — a slimmer `.bpf.o` or a non-BTF-LSM kernel shouldn't
        // break the loader, just narrow what the collector sees.
        if self.probes.execve {
            attach_execve(&mut bpf);
        }
        if self.probes.lsm_file_open {
            attach_lsm_file_open(&mut bpf);
        }
        if self.probes.kprobe_unlinkat {
            attach_kprobe_unlinkat(&mut bpf);
        }

        // Take ownership of the ring buffer for async polling.
        let Some(events_map) = bpf.take_map("EVENTS") else {
            warn!("BPF object missing `EVENTS` ring buffer; nothing to drain");
            shutdown.cancelled().await;
            return Ok(());
        };
        let ring = RingBuf::try_from(events_map)?;
        let mut async_fd = AsyncFd::new(ring)?;

        info!("draining BPF ring buffer");
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("ebpf collector shutting down");
                    return Ok(());
                }
                readable = async_fd.readable_mut() => {
                    let mut guard = match readable {
                        Ok(g) => g,
                        Err(e) => {
                            warn!(error = %e, "async_fd readable_mut error");
                            return Ok(());
                        }
                    };
                    let ring = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        self.handle_record(&item);
                    }
                    guard.clear_ready();
                }
            }
        }
    }

    fn handle_record(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match bytes[0] {
            x if x == EventKind::ProcessExec as u8 => {
                if let Ok(ev) = bytemuck::try_from_bytes::<ProcessExecEvent>(bytes) {
                    self.publisher.publish_lossy(self.process_exec_to_event(ev));
                } else {
                    debug!(len = bytes.len(), "ignored short ProcessExecEvent");
                }
            }
            x if x == EventKind::FileOpen as u8 => {
                if let Ok(ev) = bytemuck::try_from_bytes::<FileOpenEvent>(bytes) {
                    self.publisher.publish_lossy(self.file_open_to_event(ev));
                }
            }
            x if x == EventKind::Unlink as u8 => {
                if let Ok(ev) = bytemuck::try_from_bytes::<UnlinkEvent>(bytes) {
                    self.publisher.publish_lossy(self.unlink_to_event(ev));
                }
            }
            other => debug!(kind = other, "unknown ebpf event kind"),
        }
    }

    fn next_seq(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub fn process_exec_to_event(&self, raw: &ProcessExecEvent) -> Event {
        let comm = raw.comm_str();
        let argv = raw.argv_strings();
        let cmdline = if argv.is_empty() {
            comm.clone()
        } else {
            argv.join(" ")
        };
        let process = Process {
            pid: raw.pid as i32,
            parent_pid: if raw.ppid > 0 {
                Some(raw.ppid as i32)
            } else {
                None
            },
            name: Some(comm.clone()),
            cmdline: Some(cmdline.clone()),
            user: Some(User {
                uid: Some(raw.uid),
                ..User::default()
            }),
            ..Process::default()
        };
        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            1, // Launch
            SeverityId::Informational,
            &self.host_tag,
            "selfdef.ebpf",
            self.next_seq(),
        )
        .with_process(process)
        .with_message(format!("exec: {cmdline}"))
        .with_raw(serde_json::json!({
            "comm": comm,
            "pid": raw.pid,
            "ppid": raw.ppid,
            "uid": raw.uid,
            "gid": raw.gid,
            "argc": raw.argc,
            "argv_truncated": raw.argv_truncated != 0,
            "argv": argv,
        }))
    }

    pub fn file_open_to_event(&self, raw: &FileOpenEvent) -> Event {
        let path = raw.path_str();
        let comm = raw.comm_str();
        let mut event = Event::new(
            ClassUid::FILE_SYSTEM_ACTIVITY,
            14, // Open
            SeverityId::Informational,
            &self.host_tag,
            "selfdef.ebpf",
            self.next_seq(),
        )
        .with_message(format!("file_open: {path}"))
        .with_file(File::at_path(path.clone()))
        .with_raw(serde_json::json!({
            "comm": comm,
            "pid": raw.pid,
            "uid": raw.uid,
            "flags": raw.flags,
        }));
        if raw.pid > 0 {
            event = event.with_process(Process {
                pid: raw.pid as i32,
                name: Some(comm),
                user: Some(User {
                    uid: Some(raw.uid),
                    ..User::default()
                }),
                ..Process::default()
            });
        }
        event
    }

    pub fn unlink_to_event(&self, raw: &UnlinkEvent) -> Event {
        let path = raw.path_str();
        let comm = raw.comm_str();
        let mut event = Event::new(
            ClassUid::FILE_SYSTEM_ACTIVITY,
            4, // Delete
            SeverityId::Low,
            &self.host_tag,
            "selfdef.ebpf",
            self.next_seq(),
        )
        .with_message(format!("unlink: {path}"))
        .with_file(File::at_path(path.clone()))
        .with_raw(serde_json::json!({
            "comm": comm,
            "pid": raw.pid,
            "uid": raw.uid,
        }));
        if raw.pid > 0 {
            event = event.with_process(Process {
                pid: raw.pid as i32,
                name: Some(comm),
                user: Some(User {
                    uid: Some(raw.uid),
                    ..User::default()
                }),
                ..Process::default()
            });
        }
        event
    }
}

/// Sentinel used when the daemon needs the well-known install path. Override
/// at deploy time via the `[collectors.ebpf]` config section.
#[must_use]
pub fn default_object_path() -> &'static Path {
    Path::new("/usr/lib/selfdef/selfdef.bpf.o")
}

// --------- attach helpers ----------------------------------------------------
//
// Each helper logs a warning on any failure and never propagates — a kernel
// without BPF LSM support, or a BPF object that was built without one of the
// optional programs, shouldn't abort the daemon.

fn attach_execve(bpf: &mut aya::Ebpf) {
    let Some(prog) = bpf.program_mut("execve_enter") else {
        warn!("BPF object missing `execve_enter` program");
        return;
    };
    let prog: &mut TracePoint = match prog.try_into() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "execve_enter is not a TracePoint program");
            return;
        }
    };
    if let Err(e) = prog.load() {
        warn!(error = %e, "execve_enter load failed");
        return;
    }
    match prog.attach("syscalls", "sys_enter_execve") {
        Ok(_) => info!("attached tracepoint: syscalls/sys_enter_execve"),
        Err(e) => warn!(error = %e, "execve_enter attach failed"),
    }
}

fn attach_lsm_file_open(bpf: &mut aya::Ebpf) {
    let Some(prog) = bpf.program_mut("file_open") else {
        warn!(
            "BPF object missing `file_open` LSM program; \
             rebuild the BPF object to enable lsm_file_open"
        );
        return;
    };
    let prog: &mut Lsm = match prog.try_into() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "file_open is not an LSM program");
            return;
        }
    };

    // LSM programs need a BTF reference to find the hook by name. On
    // kernels without `CONFIG_BPF_LSM=y` or without `bpf` in
    // `CONFIG_LSM=...`, loading will fail loudly — log it and move on.
    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            warn!(
                error = %e,
                "kernel BTF not available; cannot attach LSM probe. \
                 Check /sys/kernel/btf/vmlinux exists."
            );
            return;
        }
    };
    if let Err(e) = prog.load("file_open", &btf) {
        warn!(
            error = %e,
            "file_open LSM load failed. Kernel may lack CONFIG_BPF_LSM=y \
             or `bpf` is not in CONFIG_LSM."
        );
        return;
    }
    match prog.attach() {
        Ok(_) => info!("attached LSM probe: file_open"),
        Err(e) => warn!(error = %e, "file_open LSM attach failed"),
    }
}

fn attach_kprobe_unlinkat(bpf: &mut aya::Ebpf) {
    let Some(prog) = bpf.program_mut("do_unlinkat") else {
        warn!(
            "BPF object missing `do_unlinkat` kprobe program; \
             rebuild the BPF object to enable kprobe_unlinkat"
        );
        return;
    };
    let prog: &mut KProbe = match prog.try_into() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "do_unlinkat is not a KProbe program");
            return;
        }
    };
    if let Err(e) = prog.load() {
        warn!(error = %e, "do_unlinkat load failed");
        return;
    }
    match prog.attach("do_unlinkat", 0) {
        Ok(_) => info!("attached kprobe: do_unlinkat"),
        Err(e) => warn!(
            error = %e,
            "do_unlinkat attach failed (kernel may have inlined the symbol)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_bus::Bus;
    use selfdef_ebpf_common::{ARGV_BUF_LEN, COMM_LEN};

    fn make_exec_event() -> ProcessExecEvent {
        let mut ev = ProcessExecEvent {
            kind: EventKind::ProcessExec as u8,
            _pad0: [0; 3],
            pid: 1234,
            tgid: 1234,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: [0; COMM_LEN],
            argv: [0; ARGV_BUF_LEN],
            argv_len: 0,
            argc: 0,
            argv_truncated: 0,
        };
        ev.comm[..2].copy_from_slice(b"ls");
        let argv = b"ls\0-la\0/etc\0";
        ev.argv[..argv.len()].copy_from_slice(argv);
        ev.argv_len = argv.len() as u16;
        ev.argc = 3;
        ev
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_object_runs_idle_without_error() {
        let bus = Bus::new(8);
        let pub_ = bus.publisher();
        let coll = EbpfCollector::new(
            PathBuf::from("/nonexistent/selfdef.bpf.o"),
            pub_,
            "test-host".into(),
        );
        let shutdown = CancellationToken::new();
        let sd = shutdown.clone();
        let task = tokio::spawn(async move { coll.run(sd).await });
        // The collector should be idle waiting on shutdown.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown.cancel();
        let res = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("task hung")
            .expect("task panicked");
        assert!(res.is_ok(), "expected graceful Ok: {res:?}");
    }

    #[test]
    fn exec_event_converts_to_ocsf_with_full_argv() {
        let bus = Bus::new(4);
        let coll = EbpfCollector::new(PathBuf::from("/unused"), bus.publisher(), "h".into());
        let ev = make_exec_event();
        let event = coll.process_exec_to_event(&ev);
        assert_eq!(event.class_uid, ClassUid::PROCESS_ACTIVITY);
        assert_eq!(event.activity_id, 1);
        assert_eq!(event.source, "selfdef.ebpf");
        let p = event.process.unwrap();
        assert_eq!(p.pid, 1234);
        assert_eq!(p.parent_pid, Some(1));
        assert_eq!(p.cmdline.as_deref(), Some("ls -la /etc"));
    }

    #[test]
    fn exec_event_marks_argv_truncated() {
        let bus = Bus::new(4);
        let coll = EbpfCollector::new(PathBuf::from("/unused"), bus.publisher(), "h".into());
        let mut ev = make_exec_event();
        ev.argv_truncated = 1;
        let event = coll.process_exec_to_event(&ev);
        let raw = event.raw.expect("raw payload");
        assert_eq!(raw["argv_truncated"], serde_json::Value::Bool(true));
    }

    #[test]
    fn file_open_event_converts_to_ocsf() {
        let bus = Bus::new(4);
        let coll = EbpfCollector::new(PathBuf::from("/unused"), bus.publisher(), "h".into());
        let mut ev = FileOpenEvent {
            kind: EventKind::FileOpen as u8,
            _pad0: [0; 3],
            pid: 4242,
            uid: 0,
            comm: [0; COMM_LEN],
            path: [0; selfdef_ebpf_common::PATH_BUF_LEN],
            path_len: 0,
            flags: 0,
        };
        ev.comm[..4].copy_from_slice(b"cat\0");
        let event = coll.file_open_to_event(&ev);
        assert_eq!(event.class_uid, ClassUid::FILE_SYSTEM_ACTIVITY);
        assert_eq!(event.activity_id, 14);
        assert_eq!(event.source, "selfdef.ebpf");
        // Path is currently always empty from the LSM hook — the conversion
        // path should still produce a valid OCSF event rather than fail.
        let f = event.file.expect("file observable");
        assert_eq!(f.path.as_deref(), Some(""));
        let p = event.process.expect("process observable");
        assert_eq!(p.pid, 4242);
        assert_eq!(p.name.as_deref(), Some("cat"));
    }

    #[test]
    fn unlink_event_converts_to_ocsf() {
        let bus = Bus::new(4);
        let coll = EbpfCollector::new(PathBuf::from("/unused"), bus.publisher(), "h".into());
        let mut ev = UnlinkEvent {
            kind: EventKind::Unlink as u8,
            _pad0: [0; 3],
            pid: 9999,
            uid: 1000,
            comm: [0; COMM_LEN],
            path: [0; selfdef_ebpf_common::PATH_BUF_LEN],
            path_len: 0,
        };
        ev.comm[..2].copy_from_slice(b"rm");
        let event = coll.unlink_to_event(&ev);
        assert_eq!(event.class_uid, ClassUid::FILE_SYSTEM_ACTIVITY);
        assert_eq!(event.activity_id, 4); // Delete
        assert_eq!(event.severity_id, SeverityId::Low);
        let p = event.process.expect("process observable");
        assert_eq!(p.pid, 9999);
    }

    #[test]
    fn default_probes_match_conservative_config() {
        let probes = EbpfProbes::default();
        assert!(probes.execve);
        assert!(!probes.lsm_file_open);
        assert!(!probes.kprobe_unlinkat);
    }
}
