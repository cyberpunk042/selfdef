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
- `kmod-watch`        — kernel module load/unload, signed/unsigned tracking.
- `tcp-fingerprint`   — passive TCP fingerprinting on inbound SYN, fed into
                        the correlator alongside Suricata.
