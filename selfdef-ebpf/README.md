# selfdef-ebpf

eBPF programs for custom in-kernel detections that Tetragon's policy language
can't express cleanly (M10).

Built with [aya](https://aya-rs.dev/) — a pure-Rust eBPF toolchain. Unlike the
rest of the workspace, this crate targets `bpfel-unknown-none` and is *not*
part of the default `cargo build`. Scaffolding lands in M10 using:

```bash
cargo install bpf-linker
cargo generate --git https://github.com/aya-rs/aya-template
```

Planned programs:

- `proc-ancestry`     — full process tree tracking with parent inheritance
                        and detection of orphaned shells.
- `hidden-process`    — ground-truth process list from `task_struct` walk,
                        cross-checked against `/proc`.
- `ld-preload-watch`  — detect `LD_PRELOAD` and `/etc/ld.so.preload` use.
                        **Companion shipped 2026-05-21** via `modules/
                        host-sentinel/policies/ld-preload-watch.yaml`
                        (Tetragon kprobe on `security_file_open` against
                        `/etc/ld.so.preload`, host-PID-ns scope, audit
                        default + enforce-Sigkill profile). The aya-rs
                        eBPF program remains deferred for the broader
                        `LD_PRELOAD` env-var-watch surface.
- `kmod-watch`        — kernel module load/unload, signed/unsigned tracking.
                        **Companion shipped 2026-05-21** via `modules/
                        host-sentinel/policies/kmod-watch.yaml`
                        (Tetragon kprobe on `do_init_module`, host-PID-ns
                        scope, Post action in both profiles). The aya-rs
                        eBPF program remains deferred for module signing
                        + unload tracking.
- `tcp-fingerprint`   — passive TCP fingerprinting on inbound SYN, fed into
                        the correlator alongside Suricata.
