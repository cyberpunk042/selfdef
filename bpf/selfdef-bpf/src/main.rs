//! selfdef-bpf — kernel-space BPF programs.
//!
//! Programs shipped:
//!
//! - `execve_enter` — `tracepoint:syscalls:sys_enter_execve`. Captures
//!   pid/tgid/uid/gid, comm, and a bounded slice of argv (up to
//!   [`MAX_ARGV_ENTRIES`] entries, total size capped at
//!   [`selfdef_ebpf_common::ARGV_BUF_LEN`] bytes).
//!
//! - `file_open` — `lsm/file_open`. Observe-only: always returns 0.
//!   Reports pid/uid/comm/flags. Path extraction via `bpf_d_path`
//!   requires CO-RE access to `struct file.f_path` and is left to a
//!   later polish; the userspace decoder treats `path_len == 0` as
//!   "path not captured".
//!
//! - `do_unlinkat` — kprobe on the `do_unlinkat` syscall helper. Reports
//!   pid/uid/comm. Same path-deferral rationale as the LSM hook.
//!
//! All programs share one ring buffer (`EVENTS`). The first byte of each
//! record is an [`EventKind`] discriminator so the userspace loader can
//! dispatch on it.
//!
//! ## Why the path stays empty for `file_open` and `do_unlinkat`
//!
//! Rendering a kernel `dentry` into a string requires `bpf_d_path`, which
//! itself wants a `struct path *`. Pulling the `f_path` field out of
//! `struct file` from BPF needs either generated `vmlinux.rs` bindings
//! (`aya-tool generate`) or hardcoded field offsets. Neither is in the
//! current build, so the programs ship without path capture. The probe
//! and its OCSF mapping are still useful on their own — pid/uid/comm
//! tell you *who*, and a follow-up patch can add *what*.

#![no_std]
#![no_main]
#![allow(clippy::cast_possible_truncation, clippy::missing_safety_doc)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, lsm, map, tracepoint},
    maps::RingBuf,
    programs::{LsmContext, ProbeContext, TracePointContext},
};
use selfdef_ebpf_common::{
    ARGV_BUF_LEN, COMM_LEN, EventKind, FileOpenEvent, ProcessExecEvent, UnlinkEvent,
};

/// Ring buffer: 256 KB. Tune with care — the kernel reserves this memory.
#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ---------------- argv capture knobs ----------------------------------------
//
// The BPF verifier insists every loop have a small, statically-known bound.
// 16 entries covers the vast majority of real-world execs (median is 4-6).
// Past this, `argv_truncated` is set and the userspace decoder can flag it
// to detection rules.
const MAX_ARGV_ENTRIES: usize = 16;

// ====================== tracepoint: execve_enter ============================

/// Tracepoint context layout for `sys_enter_execve` (consistent across
/// modern kernels):
///
/// ```text
/// offset:8   field:int __syscall_nr;
/// offset:16  field:const char *filename;
/// offset:24  field:const char *const *argv;
/// offset:32  field:const char *const *envp;
/// ```
const ARGV_PTR_OFFSET: usize = 24;

#[tracepoint]
pub fn execve_enter(ctx: TracePointContext) -> u32 {
    match try_execve_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_execve_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<ProcessExecEvent>(0) else {
        return Err(0);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    // SAFETY: aya guarantees the reserved slot is at least
    // size_of::<ProcessExecEvent>() bytes and properly aligned.
    let ev = unsafe { &mut *entry.as_mut_ptr() };

    ev.kind = EventKind::ProcessExec as u8;
    ev._pad0 = [0; 3];
    ev.pid = (pid_tgid >> 32) as u32;
    ev.tgid = pid_tgid as u32;
    ev.ppid = 0; // not available from this tracepoint without task_struct walking
    ev.uid = uid_gid as u32;
    ev.gid = (uid_gid >> 32) as u32;

    ev.comm = [0u8; COMM_LEN];
    if let Ok(comm) = bpf_get_current_comm() {
        ev.comm = comm;
    }

    // Capture argv. We start by reading the userspace argv pointer out of
    // the tracepoint context, then walk up to MAX_ARGV_ENTRIES pointers,
    // probing each into our fixed-size buffer.
    ev.argv = [0u8; ARGV_BUF_LEN];
    ev.argv_len = 0;
    ev.argc = 0;
    ev.argv_truncated = 0;

    if let Ok(argv_ptr) = unsafe { ctx.read_at::<*const *const u8>(ARGV_PTR_OFFSET) } {
        if !argv_ptr.is_null() {
            capture_argv(ev, argv_ptr);
        }
    }

    entry.submit(0);
    Ok(())
}

/// Walk the userspace argv array and copy each entry into `ev.argv` as a
/// null-separated stream. Sets `ev.argv_len`, `ev.argc`, and
/// `ev.argv_truncated`. Best-effort — any probe-read error stops capture
/// but doesn't fail the program.
fn capture_argv(ev: &mut ProcessExecEvent, argv_ptr: *const *const u8) {
    let mut used: usize = 0;
    let mut argc: u8 = 0;

    // Verifier-friendly fixed bound.
    for i in 0..MAX_ARGV_ENTRIES {
        // Read element i of the userspace argv array. NULL terminates the array.
        let arg_ptr = match unsafe { bpf_probe_read_user::<*const u8>(argv_ptr.add(i)) } {
            Ok(p) => p,
            Err(_) => break,
        };
        if arg_ptr.is_null() {
            break;
        }

        // Leave at least one byte for the null separator we write after the
        // string. If the buffer is full, mark truncated and stop.
        if used + 1 >= ARGV_BUF_LEN {
            ev.argv_truncated = 1;
            break;
        }

        // Reslice the destination so the verifier can see the bounded write.
        // `used` is in `0..ARGV_BUF_LEN - 1`, so the slice is non-empty.
        let dst = &mut ev.argv[used..ARGV_BUF_LEN - 1];

        match unsafe { bpf_probe_read_user_str_bytes(arg_ptr, dst) } {
            Ok(bytes) => {
                let n = bytes.len();
                used += n;
                // Null separator between argv entries (and after the last one).
                ev.argv[used] = 0;
                used += 1;
                argc = argc.saturating_add(1);
            }
            Err(_) => {
                // Couldn't read this entry — stop here rather than producing
                // a malformed stream.
                break;
            }
        }
    }

    // If we filled all slots without seeing a NULL terminator, conservatively
    // mark as truncated. False positives are fine (just a noisier flag).
    if argc as usize >= MAX_ARGV_ENTRIES {
        ev.argv_truncated = 1;
    }

    ev.argv_len = used as u16;
    ev.argc = argc;
}

// ====================== lsm: file_open ======================================

/// LSM hook for `file_open`. Observe-only: always returns 0 so we never
/// veto an open. Captures pid/uid/comm; path capture is deferred (see the
/// crate-level doc for why).
#[lsm(hook = "file_open")]
pub fn file_open(_ctx: LsmContext) -> i32 {
    // Errors here don't affect the LSM verdict; we just want the side
    // effect of pushing a record. Drop the result silently.
    let _ = try_file_open();
    0
}

fn try_file_open() -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<FileOpenEvent>(0) else {
        return Err(0);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let ev = unsafe { &mut *entry.as_mut_ptr() };
    ev.kind = EventKind::FileOpen as u8;
    ev._pad0 = [0; 3];
    ev.pid = (pid_tgid >> 32) as u32;
    ev.uid = uid_gid as u32;
    ev.flags = 0; // arg-extraction deferred along with path capture.

    ev.comm = [0u8; COMM_LEN];
    if let Ok(comm) = bpf_get_current_comm() {
        ev.comm = comm;
    }

    // Path capture is deferred — see crate-level doc. Zero out the buffer
    // explicitly so the userspace decoder reports an empty path rather
    // than reading uninit memory.
    ev.path = [0u8; selfdef_ebpf_common::PATH_BUF_LEN];
    ev.path_len = 0;

    entry.submit(0);
    Ok(())
}

// ====================== kprobe: do_unlinkat =================================

#[kprobe]
pub fn do_unlinkat(_ctx: ProbeContext) -> u32 {
    let _ = try_do_unlinkat();
    0
}

fn try_do_unlinkat() -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<UnlinkEvent>(0) else {
        return Err(0);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let ev = unsafe { &mut *entry.as_mut_ptr() };
    ev.kind = EventKind::Unlink as u8;
    ev._pad0 = [0; 3];
    ev.pid = (pid_tgid >> 32) as u32;
    ev.uid = uid_gid as u32;

    ev.comm = [0u8; COMM_LEN];
    if let Ok(comm) = bpf_get_current_comm() {
        ev.comm = comm;
    }

    ev.path = [0u8; selfdef_ebpf_common::PATH_BUF_LEN];
    ev.path_len = 0;

    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The BPF verifier rejects programs that could actually reach a panic,
    // so this is dead code in practice.
    loop {}
}
