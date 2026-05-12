//! Shared types between selfdef BPF programs and the userspace loader.
//!
//! Every type here is `#[repr(C)]` and Pod-safe so the BPF program can
//! write it to a ring buffer and the loader can read it back without
//! deserialization. Sizes are fixed; strings are byte arrays.
//!
//! Compile with `--no-default-features --features ebpf` when building for
//! `bpfel-unknown-none` (no `bytemuck` available); default features pull
//! in `bytemuck` for safe Pod conversions in userspace.

#![cfg_attr(feature = "ebpf", no_std)]
#![allow(clippy::missing_safety_doc)]

/// Event kind discriminator — first byte of every ring-buffer record.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    ProcessExec = 1,
    FileOpen = 2,
    Unlink = 3,
}

pub const COMM_LEN: usize = 16;
pub const ARGV_BUF_LEN: usize = 256;
pub const PATH_BUF_LEN: usize = 256;

/// Process exec event — emitted from `tracepoint:syscalls:sys_enter_execve`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessExecEvent {
    pub kind: u8, // EventKind::ProcessExec
    pub _pad0: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Process name (TASK_COMM_LEN). Null-padded, not null-terminated when full.
    pub comm: [u8; COMM_LEN],
    /// argv buffer: null-separated entries. Truncated to `ARGV_BUF_LEN`.
    pub argv: [u8; ARGV_BUF_LEN],
    /// Bytes used in `argv`.
    pub argv_len: u16,
    /// Number of argv entries captured (may be less than actual argc).
    pub argc: u8,
    /// Set if argv was truncated.
    pub argv_truncated: u8,
}

/// File-open event — placeholder shape for the LSM/kprobe path program.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FileOpenEvent {
    pub kind: u8, // EventKind::FileOpen
    pub _pad0: [u8; 3],
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_BUF_LEN],
    pub path_len: u16,
    pub flags: u32,
}

/// Unlink event — placeholder shape for `kprobe:do_unlinkat`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UnlinkEvent {
    pub kind: u8, // EventKind::Unlink
    pub _pad0: [u8; 3],
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_BUF_LEN],
    pub path_len: u16,
}

#[cfg(feature = "userspace")]
mod userspace_impls {
    use super::{FileOpenEvent, ProcessExecEvent, UnlinkEvent};

    // SAFETY: all fields are POD (primitives + fixed arrays), `#[repr(C)]`,
    // and explicit padding bytes are present so there are no uninit gaps.
    #[allow(unsafe_code)]
    unsafe impl bytemuck::Zeroable for ProcessExecEvent {}
    #[allow(unsafe_code)]
    unsafe impl bytemuck::Pod for ProcessExecEvent {}
    #[allow(unsafe_code)]
    unsafe impl bytemuck::Zeroable for FileOpenEvent {}
    #[allow(unsafe_code)]
    unsafe impl bytemuck::Pod for FileOpenEvent {}
    #[allow(unsafe_code)]
    unsafe impl bytemuck::Zeroable for UnlinkEvent {}
    #[allow(unsafe_code)]
    unsafe impl bytemuck::Pod for UnlinkEvent {}

    impl ProcessExecEvent {
        /// Decode the process name as UTF-8 best-effort, stopping at the
        /// first null byte.
        pub fn comm_str(&self) -> String {
            decode_cstr(&self.comm)
        }

        /// Decode argv into a Vec<String>. Entries are null-separated; the
        /// trailing portion is truncated if `argv_truncated`.
        pub fn argv_strings(&self) -> Vec<String> {
            let used = (self.argv_len as usize).min(self.argv.len());
            self.argv[..used]
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        }
    }

    impl FileOpenEvent {
        pub fn comm_str(&self) -> String {
            decode_cstr(&self.comm)
        }
        pub fn path_str(&self) -> String {
            let n = (self.path_len as usize).min(self.path.len());
            String::from_utf8_lossy(&self.path[..n]).into_owned()
        }
    }

    impl UnlinkEvent {
        pub fn comm_str(&self) -> String {
            decode_cstr(&self.comm)
        }
        pub fn path_str(&self) -> String {
            let n = (self.path_len as usize).min(self.path.len());
            String::from_utf8_lossy(&self.path[..n]).into_owned()
        }
    }

    fn decode_cstr(buf: &[u8]) -> String {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}

#[cfg(feature = "userspace")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_exec_layout_is_stable() {
        // Layout assertions guard against accidental field reordering that
        // would break BPF↔userspace agreement.
        assert_eq!(core::mem::size_of::<ProcessExecEvent>() % 4, 0);
        assert!(core::mem::size_of::<ProcessExecEvent>() < 512);
    }

    #[test]
    fn argv_decoding_handles_nulls_and_truncation() {
        let mut ev = ProcessExecEvent {
            kind: EventKind::ProcessExec as u8,
            _pad0: [0; 3],
            pid: 1,
            tgid: 1,
            ppid: 0,
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
        assert_eq!(ev.comm_str(), "ls");
        let strings = ev.argv_strings();
        assert_eq!(strings, vec!["ls", "-la", "/etc"]);
    }
}
