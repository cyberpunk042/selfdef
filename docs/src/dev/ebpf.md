# Custom eBPF programs

selfdef ships its own in-kernel BPF program. It gives the daemon a
native view of process exec events without depending on Tetragon. When
Tetragon *is* installed and configured, both sources publish to the same
bus; rules can match either (Sigma's `logsource: tetragon` vs
`logsource: selfdef.ebpf` discriminates).

## What ships

| Probe | Hook | Status |
|---|---|---|
| `execve_enter` | `tracepoint:syscalls:sys_enter_execve` | **shipping** — pid/tgid/ppid/uid/gid/comm + argv (up to 16 entries / 256 bytes) |
| LSM `file_open` | `lsm/file_open` | **shipping** — pid/uid/comm/flags. Path capture deferred (needs CO-RE `bpf_d_path` over `file->f_path`). |
| `do_unlinkat` kprobe | `kprobe:do_unlinkat` | **shipping** — pid/uid/comm. Path capture deferred (same rationale). |

argv capture in the execve program walks the userspace argv array with
`bpf_probe_read_user` plus `bpf_probe_read_user_str_bytes`, bounded at
16 entries and 256 total bytes. The `argv_truncated` flag is set when
the buffer fills or when 16 entries are captured without seeing the
NULL terminator — detection rules can match on it to catch obfuscated
long-argv attacks.

The LSM hook and unlinkat kprobe ship without path capture because
rendering a kernel `dentry` into a string from BPF needs either
generated `vmlinux.rs` bindings or hardcoded field offsets. The records
are still useful — pid/uid/comm tell you *who* — and a follow-up patch
can layer `bpf_d_path` on top without changing the ring-buffer schema
(the `path` and `path_len` fields are already in place; the userspace
decoder treats `path_len == 0` as "path not captured").

The LSM probe needs `CONFIG_BPF_LSM=y` *and* `bpf` listed in the
kernel's `CONFIG_LSM=...` set. Debian and Ubuntu have shipped this
since kernel 5.7+. The loader checks `/sys/kernel/btf/vmlinux` is
present before attempting to attach the LSM program; if not available,
or if the attach fails for any other reason, it logs a warning and
keeps the other probes running.

## Prerequisites (one-time)

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly install bpf-linker
```

The BPF crate at `bpf/selfdef-bpf/` is **outside** the main workspace.
`cargo build --workspace` from the repo root never touches it. All BPF
work goes through the xtask:

```bash
cargo xtask build-bpf              # debug build
cargo xtask build-bpf --release    # optimized (use this for installs)
cargo xtask install-bpf            # builds release + copies to /usr/lib/selfdef/
```

`install-bpf` defaults to `/usr/lib/selfdef/selfdef.bpf.o`. Pass a path
as the first argument to install elsewhere (e.g. under `~/.local` for
non-root operation):

```bash
cargo xtask install-bpf ~/.local/share/selfdef/selfdef.bpf.o
```

## Kernel requirements

- `tracepoint:syscalls:sys_enter_execve` — Linux 4.7+ (universal).
- Ring buffer maps — Linux 5.8+. Debian 13 / Ubuntu 24 ship newer kernels.
- BTF — `/sys/kernel/btf/vmlinux` must exist for CO-RE-style loading;
  again, modern Debian/Ubuntu have this on by default.

## Capabilities

`CAP_BPF` + `CAP_PERFMON` — no full root. Apply the drop-in:

```bash
sudo mkdir -p /etc/systemd/system/selfdefd.service.d
sudo install -m 0644 packaging/systemd/selfdefd.service.d/ebpf.conf \
    /etc/systemd/system/selfdefd.service.d/ebpf.conf
sudo systemctl daemon-reload
sudo systemctl restart selfdefd
```

The drop-in raises `LimitMEMLOCK=infinity` because older kernels still
charge BPF map pages against the legacy memlock limit.

## Enabling

In `/etc/selfdef/selfdef.toml`:

```toml
[collectors.ebpf]
enabled = true
program_path = "/usr/lib/selfdef/selfdef.bpf.o"
enable_execve = true
enable_lsm_open = false        # opt-in: needs CONFIG_BPF_LSM=y kernel
enable_kprobe_unlink = false   # opt-in: noisy by default
```

Then `systemctl restart selfdefd`. Verify with:

```bash
journalctl -u selfdefd -f | grep -i ebpf
# loading BPF object path=/usr/lib/selfdef/selfdef.bpf.o
# attached tracepoint: syscalls/sys_enter_execve
# draining BPF ring buffer
```

## What you get

Each execve on the host produces a `PROCESS_ACTIVITY` event with
`source = "selfdef.ebpf"`, capturing pid, tgid, ppid (when discoverable),
uid, gid, and comm. The OCSF `process` field is populated; the `raw`
field carries the same fields plus `argv_truncated` so downstream rules
can detect cases where argv exceeds the buffer.

## Graceful degradation

If the BPF object isn't installed at `program_path`, the collector logs
a warning at startup and runs idle. The daemon stays up; other
collectors keep working. This lets you ship the same daemon binary to
hosts with and without eBPF support and let config drive the difference.

## Honest deferrals (not yet in M10)

- **argv capture from execve.** The tracepoint context exposes
  `argv` as a user-pointer array. Reading it requires looped
  `bpf_probe_read_user` calls with verifier-friendly bounds. Real work,
  but contained; will land in an M10 follow-up. Until then, `argv` in
  the event is empty and `argv_truncated = false`.
- **LSM `file_open` program.** The type is reserved in
  `selfdef-ebpf-common` and the userspace decode path is in the
  collector, but no kernel-side program ships yet. Requires
  `CONFIG_BPF_LSM=y` AND `bpf` in `CONFIG_LSM` (typically a kernel
  cmdline `lsm=...,bpf`).
- **`do_unlinkat` kprobe.** Same shape: type reserved, kernel-side
  program pending.

The pattern: M10 nailed loader infrastructure + one probe end-to-end.
Subsequent milestones add probes by writing one more
`#[tracepoint]`/`#[lsm]`/`#[kprobe]` handler in `bpf/selfdef-bpf/src/`,
rebuilding via xtask, and listing the new event kind in `EventKind`.

## Troubleshooting

- `no BPF object installed; ebpf collector idle` — install via
  `cargo xtask install-bpf` (or build then copy manually).
- `aya: program load failed` — the verifier rejected the program. Run
  `dmesg | tail` for the verifier log; aya surfaces it. Most often
  caused by unbounded loops or unverified pointer reads — both common
  when extending argv capture or path extraction.
- `Permission denied` from `aya::Ebpf::load_file` — drop-in not applied.
  Check with `systemctl show selfdefd | grep AmbientCap`. Should
  include `CAP_BPF CAP_PERFMON`.
- BPF build fails with `error: linker bpf-linker not found` —
  `cargo +nightly install bpf-linker`.
