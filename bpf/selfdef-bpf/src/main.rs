//! selfdef-bpf — kernel-space BPF programs.
//!
//! Currently ships one tracepoint program: `execve_enter`, hooked to
//! `tracepoint:syscalls:sys_enter_execve`. On every execve call it
//! captures the calling task's PID/TGID/UID/GID plus the comm and writes
//! a fixed-size record into the `EVENTS` ring buffer for userspace
//! drainage.
//!
//! Future programs (LSM `file_open`, kprobe `do_unlinkat`) live under
//! their own `#[lsm]` / `#[kprobe]` handlers and share the same
//! `EVENTS` map.

#![no_std]
#![no_main]
#![allow(clippy::cast_possible_truncation, clippy::missing_safety_doc)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use selfdef_ebpf_common::{
    EventKind, ProcessExecEvent, ARGV_BUF_LEN, COMM_LEN,
};

/// Ring buffer: 256 KB. Picked to comfortably absorb bursty exec storms
/// (kernel build, package install). Tune with care — the kernel reserves
/// this memory.
#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn execve_enter(ctx: TracePointContext) -> u32 {
    match try_execve_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_execve_enter(_ctx: &TracePointContext) -> Result<(), i64> {
    // Reserve a slot in the ring buffer for our event. If reservation
    // fails (ring full, OOM, etc.) we drop the event silently — better
    // than blocking the syscall.
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

    // argv capture from the tracepoint requires bpf_probe_read_user on the
    // userspace pointer array referenced by ctx; that's a bigger program
    // (loops, bounds, probe-read fallibility). For M10 we ship without
    // argv; subsequent milestones can add it once the loader and rules
    // are settled.
    ev.argv = [0u8; ARGV_BUF_LEN];
    ev.argv_len = 0;
    ev.argc = 0;
    ev.argv_truncated = 0;

    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The BPF target has no stack-trace machinery; abort by jumping into
    // hint::unreachable_unchecked. The verifier rejects programs that
    // could actually reach a panic, so this is dead code in practice.
    loop {}
}
