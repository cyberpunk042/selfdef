# MS016 — eBPF programs + Tetragon TracingPolicies

> Parent: `backlog/milestones/INDEX.md` row MS016.
> Source: `bpf/selfdef-bpf/` (Cargo.toml + src/main.rs + .cargo/config.toml; out-of-workspace BPF crate) + `selfdef-ebpf/README.md` (planned-programs catalog: proc-ancestry / hidden-process / ld-preload-watch / kmod-watch / tcp-fingerprint) + `crates/selfdef-ebpf-common/` (179-line lib.rs; shared types between kernel-space and userspace) + `crates/selfdef-collector-ebpf/` (555-line lib.rs; userspace ringbuf decoder + event publisher) + `crates/selfdef-collector-tetragon/` (415-line lib.rs + tests/; Tetragon event ingester) + `docs/src/dev/ebpf.md` (M10 spec: 3 probes shipping + 3 deferred; prerequisites; xtask build/install; kernel requirements; capabilities; enable config; graceful degradation; honest deferrals; troubleshooting) + `rules/tetragon/observe-sensitive-files.yaml` (concrete TracingPolicy). All entries below extract verbatim. No invention.

## Epics (E0161–E0170)

| Epic ID | Phrase | Source |
|---|---|---|
| E0161 | Mission — selfdef ships its own in-kernel BPF program for native exec/file view without depending on Tetragon; when Tetragon IS installed and configured, both sources publish to same bus; rules can match either (Sigma `logsource: tetragon` vs `logsource: selfdef.ebpf` discriminates) | `docs/src/dev/ebpf.md` § header |
| E0162 | What ships (M10 baseline) — 3 probes: `execve_enter` (tracepoint:syscalls:sys_enter_execve; pid/tgid/ppid/uid/gid/comm + argv up to 16 entries / 256 bytes + argv_truncated flag); LSM `file_open` (lsm/file_open; pid/uid/comm/flags; path capture deferred); `do_unlinkat` kprobe (kprobe:do_unlinkat; pid/uid/comm; path capture deferred); LSM probe needs CONFIG_BPF_LSM=y + bpf in CONFIG_LSM; loader checks `/sys/kernel/btf/vmlinux` present before attempting LSM attach; logs warning + continues on failure | `docs/src/dev/ebpf.md` § "What ships" |
| E0163 | Prerequisites + build — one-time: `rustup toolchain install nightly` + `rustup component add rust-src --toolchain nightly` + `cargo +nightly install bpf-linker`; BPF crate at `bpf/selfdef-bpf/` is OUTSIDE main workspace; xtask verbs: `cargo xtask build-bpf` (debug) / `--release` / `install-bpf` (release + copy to /usr/lib/selfdef/); install-bpf default path `/usr/lib/selfdef/selfdef.bpf.o`; pass first arg to install elsewhere | `docs/src/dev/ebpf.md` § Prerequisites |
| E0164 | Kernel requirements — `tracepoint:syscalls:sys_enter_execve` Linux 4.7+ (universal); Ring buffer maps Linux 5.8+ (Debian 13 / Ubuntu 24 ship newer); BTF `/sys/kernel/btf/vmlinux` must exist for CO-RE-style loading (modern Debian/Ubuntu have on by default) | `docs/src/dev/ebpf.md` § "Kernel requirements" |
| E0165 | Capabilities — `CAP_BPF` + `CAP_PERFMON` (no full root); drop-in `packaging/systemd/selfdefd.service.d/ebpf.conf` → `/etc/systemd/system/selfdefd.service.d/ebpf.conf` after `daemon-reload` + `systemctl restart selfdefd`; raises `LimitMEMLOCK=infinity` (older kernels charge BPF map pages against legacy memlock limit) | `docs/src/dev/ebpf.md` § Capabilities |
| E0166 | Enable config — `[collectors.ebpf]` block (enabled / program_path / enable_execve / enable_lsm_open opt-in needs CONFIG_BPF_LSM=y / enable_kprobe_unlink opt-in noisy by default); verify with `journalctl -u selfdefd -f | grep -i ebpf` (3 startup log markers: "loading BPF object path=..." / "attached tracepoint: syscalls/sys_enter_execve" / "draining BPF ring buffer") | `docs/src/dev/ebpf.md` § Enabling |
| E0167 | What you get + Graceful degradation — each execve produces PROCESS_ACTIVITY event with `source="selfdef.ebpf"` (pid/tgid/ppid/uid/gid/comm; OCSF process field populated; raw field carries argv_truncated); if BPF object isn't installed at program_path, collector logs warning at startup + runs idle (daemon stays up; other collectors keep working) — ship same daemon binary to hosts with and without eBPF support, config drives difference | `docs/src/dev/ebpf.md` § "What you get" + § "Graceful degradation" |
| E0168 | Honest deferrals + extension pattern — 3 deferred (argv capture from execve: needs looped bpf_probe_read_user with verifier-friendly bounds, M10 follow-up; LSM file_open program: type reserved + userspace decode path in collector but no kernel-side ships yet; do_unlinkat kprobe: same shape — type reserved, kernel-side pending); pattern = M10 nailed loader infrastructure + one probe end-to-end; subsequent milestones add probes by writing one more `#[tracepoint]`/`#[lsm]`/`#[kprobe]` handler in `bpf/selfdef-bpf/src/` + rebuilding via xtask + listing new event kind in `EventKind` | `docs/src/dev/ebpf.md` § "Honest deferrals" |
| E0169 | Troubleshooting — 4 common failure modes (no BPF object installed → install via `cargo xtask install-bpf`; aya program load failed → verifier rejection, run `dmesg | tail`; Permission denied from `aya::Ebpf::load_file` → drop-in not applied, check `systemctl show selfdefd | grep AmbientCap`; BPF build fails `error: linker bpf-linker not found` → `cargo +nightly install bpf-linker`) | `docs/src/dev/ebpf.md` § Troubleshooting |
| E0170 | Planned programs roadmap (`selfdef-ebpf/README.md`) — 5 future programs (proc-ancestry: full process tree tracking with parent inheritance + detection of orphaned shells; hidden-process: ground-truth process list from task_struct walk cross-checked against /proc; ld-preload-watch: detect LD_PRELOAD and /etc/ld.so.preload use; kmod-watch: kernel module load/unload signed/unsigned tracking; tcp-fingerprint: passive TCP fingerprinting on inbound SYN fed into correlator alongside Suricata) + Tetragon TracingPolicy ledger (`rules/tetragon/observe-sensitive-files.yaml`) + collector pair (selfdef-collector-ebpf + selfdef-collector-tetragon) | `selfdef-ebpf/README.md` + `rules/tetragon/` |

## Modules (M00395–M00420)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00395 | BPF crate root — `bpf/selfdef-bpf/` (out-of-workspace; own [workspace] block) | `bpf/selfdef-bpf/Cargo.toml` | E0163 |
| M00396 | BPF crate binary — `[[bin]] name = "selfdef-bpf" path = "src/main.rs"` | `bpf/selfdef-bpf/Cargo.toml` | E0163 |
| M00397 | BPF crate target — `bpfel-unknown-none` (build via `cargo +nightly build --target bpfel-unknown-none --release -Z build-std=core`) | `bpf/selfdef-bpf/Cargo.toml` § comment | E0163 |
| M00398 | BPF crate dependencies — aya-ebpf 0.1 + aya-log-ebpf 0.1 + selfdef-ebpf-common (path=`../../crates/selfdef-ebpf-common`, default-features=false, features=["ebpf"]) | `bpf/selfdef-bpf/Cargo.toml` | E0163 |
| M00399 | BPF crate profile — opt-level=3 / debug=false / debug-assertions=false / overflow-checks=false / lto=true / panic="abort" / incremental=false / codegen-units=1 / rpath=false (dev profile matches release profile due to BPF verifier requirements) | `bpf/selfdef-bpf/Cargo.toml` `[profile.dev]` + `[profile.release]` | E0163 |
| M00400 | Probe 1 — `execve_enter` tracepoint:syscalls:sys_enter_execve (shipping; pid/tgid/ppid/uid/gid/comm + argv up to 16 entries / 256 bytes total + argv_truncated flag) | `docs/src/dev/ebpf.md` § "What ships" | E0162 |
| M00401 | Probe 2 — LSM `file_open` lsm/file_open (shipping; pid/uid/comm/flags; path capture deferred — needs CO-RE bpf_d_path over file->f_path) | `docs/src/dev/ebpf.md` § "What ships" | E0162 |
| M00402 | Probe 3 — `do_unlinkat` kprobe (shipping; pid/uid/comm; path capture deferred — same rationale as LSM file_open) | `docs/src/dev/ebpf.md` § "What ships" | E0162 |
| M00403 | argv capture mechanism — `bpf_probe_read_user` for argv array + `bpf_probe_read_user_str_bytes` for each entry; bounded at 16 entries + 256 total bytes; `argv_truncated` flag set when buffer fills OR 16 entries captured without seeing NULL terminator | `docs/src/dev/ebpf.md` § "What ships" + argv detail | E0162 |
| M00404 | argv_truncated rule-matching value — detection rules can match on it to catch obfuscated long-argv attacks | `docs/src/dev/ebpf.md` § "What ships" + argv detail | E0162 |
| M00405 | LSM CO-RE requirement — `CONFIG_BPF_LSM=y` in kernel config | `docs/src/dev/ebpf.md` § "What ships" + § Enabling | E0166 |
| M00406 | LSM CO-RE requirement — `bpf` listed in kernel's `CONFIG_LSM=...` set (typically kernel cmdline `lsm=...,bpf`) | `docs/src/dev/ebpf.md` § "What ships" + § Honest deferrals | E0166 |
| M00407 | LSM debian/ubuntu — both ship CONFIG_BPF_LSM since 5.7+ | `docs/src/dev/ebpf.md` § "What ships" | E0164 |
| M00408 | Loader pre-flight — checks `/sys/kernel/btf/vmlinux` present before attempting LSM attach | `docs/src/dev/ebpf.md` § "What ships" | E0162 |
| M00409 | Loader fallback — on LSM attach failure (or BTF missing), logs warning + keeps other probes running | `docs/src/dev/ebpf.md` § "What ships" + § "Graceful degradation" | E0167 |
| M00410 | xtask `build-bpf` — debug build of BPF crate | `docs/src/dev/ebpf.md` § Prerequisites | E0163 |
| M00411 | xtask `build-bpf --release` — optimized build (use for installs) | `docs/src/dev/ebpf.md` § Prerequisites | E0163 |
| M00412 | xtask `install-bpf` — builds release + copies to `/usr/lib/selfdef/selfdef.bpf.o` (default); first-arg overrides destination | `docs/src/dev/ebpf.md` § Prerequisites | E0163 |
| M00413 | Capability drop-in — `packaging/systemd/selfdefd.service.d/ebpf.conf` → `/etc/systemd/system/selfdefd.service.d/ebpf.conf`; raises CAP_BPF + CAP_PERFMON + LimitMEMLOCK=infinity | `docs/src/dev/ebpf.md` § Capabilities | E0165 |
| M00414 | Enable config `[collectors.ebpf]` block — knobs: enabled / program_path / enable_execve / enable_lsm_open (opt-in needs CONFIG_BPF_LSM=y) / enable_kprobe_unlink (opt-in noisy by default) | `docs/src/dev/ebpf.md` § Enabling | E0166 |
| M00415 | OCSF event — `PROCESS_ACTIVITY` with `source="selfdef.ebpf"`; pid/tgid/ppid/uid/gid/comm; OCSF process field populated; raw field carries argv_truncated | `docs/src/dev/ebpf.md` § "What you get" | E0167 |
| M00416 | Crate `selfdef-ebpf-common` — 179-line lib.rs; shared types between kernel-space (`features=["ebpf"]`) and userspace (default features); reserved type slots for deferred probes | `crates/selfdef-ebpf-common/` + `docs/src/dev/ebpf.md` § "Honest deferrals" | E0162 |
| M00417 | Crate `selfdef-collector-ebpf` — 555-line lib.rs; userspace ringbuf decoder + event publisher; uses aya runtime + selfdef-ebpf-common types | `crates/selfdef-collector-ebpf/` | E0167 |
| M00418 | Crate `selfdef-collector-tetragon` — 415-line lib.rs + tests/; Tetragon event ingester (consumes `tetra` events, republishes to selfdef bus with `source="selfdef.tetragon"` or `policy_name=...`) | `crates/selfdef-collector-tetragon/` | E0161 |
| M00419 | Planned eBPF program catalog (`selfdef-ebpf/README.md`) — 5 future programs (proc-ancestry / hidden-process / ld-preload-watch / kmod-watch / tcp-fingerprint) | `selfdef-ebpf/README.md` § "Planned programs" | E0170 |
| M00420 | Tetragon TracingPolicy ledger — `rules/tetragon/` (README.md + observe-sensitive-files.yaml + sister policies; observed-by selfdef-collector-tetragon + cross-references to agent-guard scope MS012) | `rules/tetragon/` + cross-ref MS012 | E0170 |

## Features (F01801–F01920)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01801 | selfdef ships its own in-kernel BPF program | `docs/src/dev/ebpf.md` § header | E0161 | composite | false |
| F01802 | BPF program gives the daemon a native view of process exec events | `docs/src/dev/ebpf.md` § header | E0161 | composite | false |
| F01803 | BPF program works WITHOUT depending on Tetragon | `docs/src/dev/ebpf.md` § header | E0161 | composite | false |
| F01804 | When Tetragon IS installed and configured, both sources publish to same bus | `docs/src/dev/ebpf.md` § header | E0161 | composite | true |
| F01805 | Discriminator — Sigma `logsource: tetragon` vs `logsource: selfdef.ebpf` | `docs/src/dev/ebpf.md` § header | E0161 | composite | false |
| F01806 | Probe execve_enter — hook `tracepoint:syscalls:sys_enter_execve` | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01807 | Probe execve_enter — shipping status (M10 baseline) | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | false |
| F01808 | Probe execve_enter — captures pid | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01809 | Probe execve_enter — captures tgid | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01810 | Probe execve_enter — captures ppid | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01811 | Probe execve_enter — captures uid | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01812 | Probe execve_enter — captures gid | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01813 | Probe execve_enter — captures comm | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01814 | Probe execve_enter — captures argv up to 16 entries | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01815 | Probe execve_enter — captures argv up to 256 total bytes | `docs/src/dev/ebpf.md` § "What ships" | M00400 | composite | true |
| F01816 | Probe LSM file_open — hook `lsm/file_open` | `docs/src/dev/ebpf.md` § "What ships" | M00401 | composite | true |
| F01817 | Probe LSM file_open — shipping status | `docs/src/dev/ebpf.md` § "What ships" | M00401 | composite | false |
| F01818 | Probe LSM file_open — captures pid/uid/comm/flags | `docs/src/dev/ebpf.md` § "What ships" | M00401 | composite | true |
| F01819 | Probe LSM file_open — path capture DEFERRED (needs CO-RE bpf_d_path over file->f_path) | `docs/src/dev/ebpf.md` § "What ships" | M00401 | composite | false |
| F01820 | Probe do_unlinkat kprobe — hook `kprobe:do_unlinkat` | `docs/src/dev/ebpf.md` § "What ships" | M00402 | composite | true |
| F01821 | Probe do_unlinkat kprobe — shipping status | `docs/src/dev/ebpf.md` § "What ships" | M00402 | composite | false |
| F01822 | Probe do_unlinkat kprobe — captures pid/uid/comm | `docs/src/dev/ebpf.md` § "What ships" | M00402 | composite | true |
| F01823 | Probe do_unlinkat kprobe — path capture DEFERRED (same rationale) | `docs/src/dev/ebpf.md` § "What ships" | M00402 | composite | false |
| F01824 | argv capture — walks userspace argv array with `bpf_probe_read_user` | `docs/src/dev/ebpf.md` § argv detail | M00403 | composite | false |
| F01825 | argv capture — uses `bpf_probe_read_user_str_bytes` for each entry | `docs/src/dev/ebpf.md` § argv detail | M00403 | composite | false |
| F01826 | argv capture — bounded at 16 entries | `docs/src/dev/ebpf.md` § argv detail | M00403 | composite | false |
| F01827 | argv capture — bounded at 256 total bytes | `docs/src/dev/ebpf.md` § argv detail | M00403 | composite | false |
| F01828 | argv_truncated flag — set when buffer fills | `docs/src/dev/ebpf.md` § argv detail | M00404 | composite | false |
| F01829 | argv_truncated flag — set when 16 entries captured without seeing NULL terminator | `docs/src/dev/ebpf.md` § argv detail | M00404 | composite | false |
| F01830 | argv_truncated — detection rules can match on it to catch obfuscated long-argv attacks | `docs/src/dev/ebpf.md` § argv detail | M00404 | composite | false |
| F01831 | LSM and unlinkat ship WITHOUT path capture | `docs/src/dev/ebpf.md` § "What ships" | M00401 + M00402 | composite | false |
| F01832 | Rendering kernel dentry into string from BPF needs vmlinux.rs bindings OR hardcoded field offsets | `docs/src/dev/ebpf.md` § "What ships" | M00401 + M00402 | composite | false |
| F01833 | Records still useful — pid/uid/comm tell you WHO | `docs/src/dev/ebpf.md` § "What ships" | M00401 + M00402 | composite | false |
| F01834 | Follow-up patch can layer `bpf_d_path` without changing ring-buffer schema | `docs/src/dev/ebpf.md` § "What ships" | M00401 + M00402 | composite | false |
| F01835 | path + path_len fields already in place; userspace decoder treats `path_len == 0` as "path not captured" | `docs/src/dev/ebpf.md` § "What ships" | M00401 + M00402 | composite | false |
| F01836 | LSM kernel config requirement — `CONFIG_BPF_LSM=y` | `docs/src/dev/ebpf.md` § "What ships" | M00405 | composite | true |
| F01837 | LSM kernel config requirement — `bpf` listed in `CONFIG_LSM=...` set | `docs/src/dev/ebpf.md` § "What ships" | M00406 | composite | true |
| F01838 | LSM kernel availability — Debian and Ubuntu ship since kernel 5.7+ | `docs/src/dev/ebpf.md` § "What ships" | M00407 | composite | true |
| F01839 | Loader checks `/sys/kernel/btf/vmlinux` present before LSM attach | `docs/src/dev/ebpf.md` § "What ships" | M00408 | composite | false |
| F01840 | Loader logs warning + keeps other probes running on LSM attach failure | `docs/src/dev/ebpf.md` § "What ships" | M00409 | composite | false |
| F01841 | Prereq — `rustup toolchain install nightly` | `docs/src/dev/ebpf.md` § Prerequisites | E0163 | composite | true |
| F01842 | Prereq — `rustup component add rust-src --toolchain nightly` | `docs/src/dev/ebpf.md` § Prerequisites | E0163 | composite | true |
| F01843 | Prereq — `cargo +nightly install bpf-linker` | `docs/src/dev/ebpf.md` § Prerequisites | E0163 | composite | true |
| F01844 | BPF crate `bpf/selfdef-bpf/` is OUTSIDE the main workspace | `docs/src/dev/ebpf.md` § Prerequisites + `bpf/selfdef-bpf/Cargo.toml` `[workspace]` | E0163 | composite | false |
| F01845 | `cargo build --workspace` from repo root never touches BPF crate | `docs/src/dev/ebpf.md` § Prerequisites | E0163 | composite | false |
| F01846 | All BPF work goes through the xtask | `docs/src/dev/ebpf.md` § Prerequisites | E0163 | composite | false |
| F01847 | xtask verb — `cargo xtask build-bpf` (debug build) | `docs/src/dev/ebpf.md` § Prerequisites | M00410 | composite | true |
| F01848 | xtask verb — `cargo xtask build-bpf --release` (optimized) | `docs/src/dev/ebpf.md` § Prerequisites | M00411 | composite | true |
| F01849 | xtask verb — `cargo xtask install-bpf` (release + copy) | `docs/src/dev/ebpf.md` § Prerequisites | M00412 | composite | true |
| F01850 | install-bpf default path — `/usr/lib/selfdef/selfdef.bpf.o` | `docs/src/dev/ebpf.md` § Prerequisites | M00412 | composite | false |
| F01851 | install-bpf first-arg override — `cargo xtask install-bpf ~/.local/share/selfdef/selfdef.bpf.o` | `docs/src/dev/ebpf.md` § Prerequisites | M00412 | composite | true |
| F01852 | install-bpf non-root operation supported via custom path | `docs/src/dev/ebpf.md` § Prerequisites | M00412 | composite | true |
| F01853 | Kernel req — tracepoint:syscalls:sys_enter_execve needs Linux 4.7+ (universal) | `docs/src/dev/ebpf.md` § "Kernel requirements" | E0164 | composite | false |
| F01854 | Kernel req — Ring buffer maps need Linux 5.8+ | `docs/src/dev/ebpf.md` § "Kernel requirements" | E0164 | composite | false |
| F01855 | Kernel req — Debian 13 / Ubuntu 24 ship newer kernels (sufficient) | `docs/src/dev/ebpf.md` § "Kernel requirements" | E0164 | composite | true |
| F01856 | Kernel req — BTF `/sys/kernel/btf/vmlinux` must exist for CO-RE-style loading | `docs/src/dev/ebpf.md` § "Kernel requirements" | E0164 | composite | false |
| F01857 | Kernel req — modern Debian/Ubuntu have BTF on by default | `docs/src/dev/ebpf.md` § "Kernel requirements" | E0164 | composite | true |
| F01858 | Capability — CAP_BPF (no full root) | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01859 | Capability — CAP_PERFMON (no full root) | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01860 | Capability drop-in path source — `packaging/systemd/selfdefd.service.d/ebpf.conf` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01861 | Capability drop-in path target — `/etc/systemd/system/selfdefd.service.d/ebpf.conf` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01862 | Capability drop-in apply — `sudo mkdir -p /etc/systemd/system/selfdefd.service.d` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01863 | Capability drop-in apply — `sudo install -m 0644 ...` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01864 | Capability drop-in apply — `sudo systemctl daemon-reload` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01865 | Capability drop-in apply — `sudo systemctl restart selfdefd` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | true |
| F01866 | Capability drop-in — raises `LimitMEMLOCK=infinity` | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | false |
| F01867 | LimitMEMLOCK rationale — older kernels charge BPF map pages against legacy memlock limit | `docs/src/dev/ebpf.md` § Capabilities | M00413 | composite | false |
| F01868 | Config — `[collectors.ebpf]` block | `docs/src/dev/ebpf.md` § Enabling | M00414 | composite | true |
| F01869 | Config knob — `enabled` (bool) | `docs/src/dev/ebpf.md` § Enabling | M00414 | composite | true |
| F01870 | Config knob — `program_path = "/usr/lib/selfdef/selfdef.bpf.o"` (default) | `docs/src/dev/ebpf.md` § Enabling | M00414 | composite | true |
| F01871 | Config knob — `enable_execve` (bool; default true) | `docs/src/dev/ebpf.md` § Enabling | M00414 | composite | true |
| F01872 | Config knob — `enable_lsm_open` (bool; opt-in; needs CONFIG_BPF_LSM=y kernel) | `docs/src/dev/ebpf.md` § Enabling | M00414 | composite | true |
| F01873 | Config knob — `enable_kprobe_unlink` (bool; opt-in; noisy by default) | `docs/src/dev/ebpf.md` § Enabling | M00414 | composite | true |
| F01874 | Verify — `systemctl restart selfdefd` | `docs/src/dev/ebpf.md` § Enabling | E0166 | composite | true |
| F01875 | Verify — `journalctl -u selfdefd -f \| grep -i ebpf` | `docs/src/dev/ebpf.md` § Enabling | E0166 | composite | true |
| F01876 | Verify — startup log "loading BPF object path=/usr/lib/selfdef/selfdef.bpf.o" | `docs/src/dev/ebpf.md` § Enabling | E0166 | composite | false |
| F01877 | Verify — startup log "attached tracepoint: syscalls/sys_enter_execve" | `docs/src/dev/ebpf.md` § Enabling | E0166 | composite | false |
| F01878 | Verify — startup log "draining BPF ring buffer" | `docs/src/dev/ebpf.md` § Enabling | E0166 | composite | false |
| F01879 | OCSF event — `PROCESS_ACTIVITY` per execve | `docs/src/dev/ebpf.md` § "What you get" | M00415 | composite | false |
| F01880 | OCSF event — `source = "selfdef.ebpf"` | `docs/src/dev/ebpf.md` § "What you get" | M00415 | composite | false |
| F01881 | OCSF event — process field populated (pid/tgid/ppid/uid/gid/comm) | `docs/src/dev/ebpf.md` § "What you get" | M00415 | composite | false |
| F01882 | OCSF event — raw field carries argv_truncated for downstream rule matching | `docs/src/dev/ebpf.md` § "What you get" | M00415 | composite | false |
| F01883 | Graceful degradation — if BPF object isn't installed, collector logs warning + runs idle | `docs/src/dev/ebpf.md` § "Graceful degradation" | E0167 | composite | false |
| F01884 | Graceful degradation — daemon stays up; other collectors keep working | `docs/src/dev/ebpf.md` § "Graceful degradation" | E0167 | composite | false |
| F01885 | Graceful degradation — ship same daemon binary to hosts with and without eBPF support | `docs/src/dev/ebpf.md` § "Graceful degradation" | E0167 | composite | false |
| F01886 | Graceful degradation — config drives the difference | `docs/src/dev/ebpf.md` § "Graceful degradation" | E0167 | composite | false |
| F01887 | Honest deferral 1 — argv capture from execve (M10 follow-up) | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01888 | argv capture deferral — needs looped bpf_probe_read_user with verifier-friendly bounds | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01889 | argv capture deferral — real work, but contained | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01890 | argv capture deferral — until then, argv is empty + argv_truncated=false | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01891 | Honest deferral 2 — LSM file_open kernel-side program pending | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01892 | LSM file_open deferral — type reserved in selfdef-ebpf-common | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01893 | LSM file_open deferral — userspace decode path is in the collector | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01894 | LSM file_open deferral — no kernel-side program ships yet | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01895 | Honest deferral 3 — do_unlinkat kprobe kernel-side program pending | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01896 | do_unlinkat deferral — same shape (type reserved, kernel-side pending) | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01897 | Extension pattern — M10 nailed loader infrastructure + one probe end-to-end | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01898 | Extension pattern — subsequent milestones add probes by writing one more #[tracepoint] / #[lsm] / #[kprobe] handler | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01899 | Extension pattern — handlers live in `bpf/selfdef-bpf/src/` | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01900 | Extension pattern — rebuild via xtask | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01901 | Extension pattern — list new event kind in `EventKind` | `docs/src/dev/ebpf.md` § "Honest deferrals" | E0168 | composite | false |
| F01902 | Troubleshooting — "no BPF object installed; ebpf collector idle" → install via `cargo xtask install-bpf` | `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | composite | false |
| F01903 | Troubleshooting — "aya: program load failed" → verifier rejected; run `dmesg \| tail` | `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | composite | false |
| F01904 | Troubleshooting — verifier rejection often caused by unbounded loops OR unverified pointer reads (common when extending argv/path capture) | `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | composite | false |
| F01905 | Troubleshooting — "Permission denied from `aya::Ebpf::load_file`" → drop-in not applied; check `systemctl show selfdefd \| grep AmbientCap` should include CAP_BPF CAP_PERFMON | `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | composite | false |
| F01906 | Troubleshooting — "error: linker bpf-linker not found" → `cargo +nightly install bpf-linker` | `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | composite | false |
| F01907 | Planned program — `proc-ancestry` (full process tree tracking with parent inheritance + detection of orphaned shells) | `selfdef-ebpf/README.md` § Planned programs | M00419 | composite | true |
| F01908 | Planned program — `hidden-process` (ground-truth process list from task_struct walk, cross-checked against /proc) | `selfdef-ebpf/README.md` § Planned programs | M00419 | composite | true |
| F01909 | Planned program — `ld-preload-watch` (detect LD_PRELOAD and /etc/ld.so.preload use) | `selfdef-ebpf/README.md` § Planned programs | M00419 | composite | true |
| F01910 | Planned program — `kmod-watch` (kernel module load/unload, signed/unsigned tracking) | `selfdef-ebpf/README.md` § Planned programs | M00419 | composite | true |
| F01911 | Planned program — `tcp-fingerprint` (passive TCP fingerprinting on inbound SYN, fed into correlator alongside Suricata) | `selfdef-ebpf/README.md` § Planned programs | M00419 | composite | true |
| F01912 | Crate `selfdef-ebpf-common` — 179-line lib.rs | `crates/selfdef-ebpf-common/src/lib.rs` | M00416 | composite | false |
| F01913 | Crate `selfdef-ebpf-common` — feature `ebpf` enables kernel-space types | `bpf/selfdef-bpf/Cargo.toml` dependency line + `crates/selfdef-ebpf-common/` | M00416 | composite | false |
| F01914 | Crate `selfdef-collector-ebpf` — 555-line lib.rs | `crates/selfdef-collector-ebpf/src/lib.rs` | M00417 | composite | false |
| F01915 | Crate `selfdef-collector-tetragon` — 415-line lib.rs + tests/ | `crates/selfdef-collector-tetragon/src/lib.rs` | M00418 | composite | false |
| F01916 | Crate `selfdef-collector-tetragon` — Tetragon event ingester | `crates/selfdef-collector-tetragon/` + `docs/src/dev/ebpf.md` § header | M00418 | composite | false |
| F01917 | Tetragon TracingPolicy ledger — `rules/tetragon/` | `rules/tetragon/` | M00420 | composite | false |
| F01918 | Tetragon TracingPolicy — observe-sensitive-files.yaml | `rules/tetragon/observe-sensitive-files.yaml` | M00420 | composite | true |
| F01919 | Tetragon TracingPolicy README — `rules/tetragon/README.md` | `rules/tetragon/README.md` | M00420 | composite | false |
| F01920 | Composite — eBPF programs + Tetragon TracingPolicies form the kernel-event-observation layer of selfdef; 3 shipping probes + 5 planned programs + 1 shipping TracingPolicy; out-of-workspace BPF crate built via xtask; aya runtime in userspace collectors; OCSF events with discriminator source field; graceful degradation; honest deferrals; troubleshooting playbook | `bpf/` + `selfdef-ebpf/` + `crates/selfdef-ebpf-common/` + `crates/selfdef-collector-ebpf/` + `crates/selfdef-collector-tetragon/` + `docs/src/dev/ebpf.md` + `rules/tetragon/` | E0161 + E0162 + E0163 + E0164 + E0165 + E0166 + E0167 + E0168 + E0169 + E0170 | composite | false |

## Requirements (R03601–R03840)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R03601 | selfdef ships its own in-kernel BPF program | `docs/src/dev/ebpf.md` § header | F01801 | non-negotiable | false | 10 |
| R03602 | BPF program gives daemon native view of process exec events | `docs/src/dev/ebpf.md` § header | F01802 | non-negotiable | false | 10 |
| R03603 | BPF program works without depending on Tetragon | `docs/src/dev/ebpf.md` § header | F01803 | non-negotiable | false | 10 |
| R03604 | When Tetragon IS installed, both sources publish to same bus | `docs/src/dev/ebpf.md` § header | F01804 | non-negotiable | true | 10 |
| R03605 | Discriminator — Sigma `logsource: tetragon` vs `logsource: selfdef.ebpf` | `docs/src/dev/ebpf.md` § header | F01805 | non-negotiable | false | 10 |
| R03606 | Probe — `execve_enter` tracepoint:syscalls:sys_enter_execve (shipping) | `docs/src/dev/ebpf.md` § "What ships" | F01806 + F01807 | non-negotiable | true | 10 |
| R03607 | Probe execve_enter captures pid | `docs/src/dev/ebpf.md` § "What ships" | F01808 | non-negotiable | true | 10 |
| R03608 | Probe execve_enter captures tgid | `docs/src/dev/ebpf.md` § "What ships" | F01809 | non-negotiable | true | 10 |
| R03609 | Probe execve_enter captures ppid | `docs/src/dev/ebpf.md` § "What ships" | F01810 | non-negotiable | true | 10 |
| R03610 | Probe execve_enter captures uid | `docs/src/dev/ebpf.md` § "What ships" | F01811 | non-negotiable | true | 10 |
| R03611 | Probe execve_enter captures gid | `docs/src/dev/ebpf.md` § "What ships" | F01812 | non-negotiable | true | 10 |
| R03612 | Probe execve_enter captures comm | `docs/src/dev/ebpf.md` § "What ships" | F01813 | non-negotiable | true | 10 |
| R03613 | Probe execve_enter captures argv up to 16 entries | `docs/src/dev/ebpf.md` § "What ships" | F01814 | non-negotiable | true | 10 |
| R03614 | Probe execve_enter captures argv up to 256 total bytes | `docs/src/dev/ebpf.md` § "What ships" | F01815 | non-negotiable | true | 10 |
| R03615 | Probe — LSM `file_open` lsm/file_open (shipping; pid/uid/comm/flags) | `docs/src/dev/ebpf.md` § "What ships" | F01816 + F01817 + F01818 | non-negotiable | true | 10 |
| R03616 | Probe LSM file_open — path capture DEFERRED (needs CO-RE bpf_d_path over file->f_path) | `docs/src/dev/ebpf.md` § "What ships" | F01819 | non-negotiable | false | 10 |
| R03617 | Probe — `do_unlinkat` kprobe (shipping; pid/uid/comm) | `docs/src/dev/ebpf.md` § "What ships" | F01820 + F01821 + F01822 | non-negotiable | true | 10 |
| R03618 | Probe do_unlinkat — path capture DEFERRED (same rationale) | `docs/src/dev/ebpf.md` § "What ships" | F01823 | non-negotiable | false | 10 |
| R03619 | argv capture uses `bpf_probe_read_user` to walk userspace argv array | `docs/src/dev/ebpf.md` § argv detail | F01824 | non-negotiable | false | 10 |
| R03620 | argv capture uses `bpf_probe_read_user_str_bytes` for each entry | `docs/src/dev/ebpf.md` § argv detail | F01825 | non-negotiable | false | 10 |
| R03621 | argv capture bounded at 16 entries | `docs/src/dev/ebpf.md` § argv detail | F01826 | non-negotiable | false | 10 |
| R03622 | argv capture bounded at 256 total bytes | `docs/src/dev/ebpf.md` § argv detail | F01827 | non-negotiable | false | 10 |
| R03623 | `argv_truncated` flag set when buffer fills | `docs/src/dev/ebpf.md` § argv detail | F01828 | non-negotiable | false | 10 |
| R03624 | `argv_truncated` flag set when 16 entries captured without seeing NULL terminator | `docs/src/dev/ebpf.md` § argv detail | F01829 | non-negotiable | false | 10 |
| R03625 | Detection rules can match on `argv_truncated` to catch obfuscated long-argv attacks | `docs/src/dev/ebpf.md` § argv detail | F01830 | non-negotiable | false | 10 |
| R03626 | LSM and unlinkat probes ship WITHOUT path capture | `docs/src/dev/ebpf.md` § "What ships" | F01831 | non-negotiable | false | 10 |
| R03627 | Rendering kernel dentry into string from BPF needs vmlinux.rs bindings OR hardcoded field offsets | `docs/src/dev/ebpf.md` § "What ships" | F01832 | non-negotiable | false | 10 |
| R03628 | Records still useful — pid/uid/comm answer "who" | `docs/src/dev/ebpf.md` § "What ships" | F01833 | non-negotiable | false | 10 |
| R03629 | Follow-up patch can layer `bpf_d_path` without changing ring-buffer schema | `docs/src/dev/ebpf.md` § "What ships" | F01834 | non-negotiable | false | 10 |
| R03630 | path + path_len fields already in ring-buffer schema | `docs/src/dev/ebpf.md` § "What ships" | F01835 | non-negotiable | false | 10 |
| R03631 | Userspace decoder treats `path_len == 0` as "path not captured" | `docs/src/dev/ebpf.md` § "What ships" | F01835 | non-negotiable | false | 10 |
| R03632 | LSM kernel config requirement — `CONFIG_BPF_LSM=y` | `docs/src/dev/ebpf.md` § "What ships" | F01836 | non-negotiable | true | 10 |
| R03633 | LSM kernel config requirement — `bpf` listed in `CONFIG_LSM=...` set | `docs/src/dev/ebpf.md` § "What ships" | F01837 | non-negotiable | true | 10 |
| R03634 | LSM Debian/Ubuntu — both ship CONFIG_BPF_LSM since kernel 5.7+ | `docs/src/dev/ebpf.md` § "What ships" | F01838 | non-negotiable | true | 10 |
| R03635 | Loader checks `/sys/kernel/btf/vmlinux` is present before attempting to attach LSM program | `docs/src/dev/ebpf.md` § "What ships" | F01839 | non-negotiable | false | 10 |
| R03636 | Loader logs warning + keeps other probes running on LSM attach failure | `docs/src/dev/ebpf.md` § "What ships" | F01840 | non-negotiable | false | 10 |
| R03637 | Prereq — `rustup toolchain install nightly` | `docs/src/dev/ebpf.md` § Prerequisites | F01841 | non-negotiable | true | 10 |
| R03638 | Prereq — `rustup component add rust-src --toolchain nightly` | `docs/src/dev/ebpf.md` § Prerequisites | F01842 | non-negotiable | true | 10 |
| R03639 | Prereq — `cargo +nightly install bpf-linker` | `docs/src/dev/ebpf.md` § Prerequisites | F01843 | non-negotiable | true | 10 |
| R03640 | BPF crate at `bpf/selfdef-bpf/` is OUTSIDE the main workspace | `docs/src/dev/ebpf.md` § Prerequisites + `bpf/selfdef-bpf/Cargo.toml` `[workspace]` | F01844 | non-negotiable | false | 10 |
| R03641 | `cargo build --workspace` from repo root never touches BPF crate | `docs/src/dev/ebpf.md` § Prerequisites | F01845 | non-negotiable | false | 10 |
| R03642 | All BPF work goes through the xtask | `docs/src/dev/ebpf.md` § Prerequisites | F01846 | non-negotiable | false | 10 |
| R03643 | xtask verb — `cargo xtask build-bpf` (debug build) | `docs/src/dev/ebpf.md` § Prerequisites | F01847 | non-negotiable | true | 10 |
| R03644 | xtask verb — `cargo xtask build-bpf --release` (optimized) | `docs/src/dev/ebpf.md` § Prerequisites | F01848 | non-negotiable | true | 10 |
| R03645 | xtask verb — `cargo xtask install-bpf` (release + copy) | `docs/src/dev/ebpf.md` § Prerequisites | F01849 | non-negotiable | true | 10 |
| R03646 | install-bpf default path — `/usr/lib/selfdef/selfdef.bpf.o` | `docs/src/dev/ebpf.md` § Prerequisites | F01850 | non-negotiable | false | 10 |
| R03647 | install-bpf first-arg overrides default path | `docs/src/dev/ebpf.md` § Prerequisites | F01851 | non-negotiable | true | 10 |
| R03648 | install-bpf supports non-root operation via custom path (e.g. `~/.local/share/selfdef/selfdef.bpf.o`) | `docs/src/dev/ebpf.md` § Prerequisites | F01852 | non-negotiable | true | 10 |
| R03649 | Kernel req — tracepoint:syscalls:sys_enter_execve needs Linux 4.7+ (universal) | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01853 | non-negotiable | false | 10 |
| R03650 | Kernel req — Ring buffer maps need Linux 5.8+ | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01854 | non-negotiable | false | 10 |
| R03651 | Kernel req — Debian 13 / Ubuntu 24 ship newer kernels (sufficient) | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01855 | non-negotiable | true | 10 |
| R03652 | Kernel req — BTF `/sys/kernel/btf/vmlinux` must exist for CO-RE-style loading | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01856 | non-negotiable | false | 10 |
| R03653 | Kernel req — modern Debian/Ubuntu have BTF on by default | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01857 | non-negotiable | true | 10 |
| R03654 | Capability — CAP_BPF (no full root) | `docs/src/dev/ebpf.md` § Capabilities | F01858 | non-negotiable | true | 10 |
| R03655 | Capability — CAP_PERFMON (no full root) | `docs/src/dev/ebpf.md` § Capabilities | F01859 | non-negotiable | true | 10 |
| R03656 | Drop-in source — `packaging/systemd/selfdefd.service.d/ebpf.conf` | `docs/src/dev/ebpf.md` § Capabilities | F01860 | non-negotiable | true | 10 |
| R03657 | Drop-in target — `/etc/systemd/system/selfdefd.service.d/ebpf.conf` | `docs/src/dev/ebpf.md` § Capabilities | F01861 | non-negotiable | true | 10 |
| R03658 | Drop-in apply step 1 — `sudo mkdir -p /etc/systemd/system/selfdefd.service.d` | `docs/src/dev/ebpf.md` § Capabilities | F01862 | non-negotiable | true | 10 |
| R03659 | Drop-in apply step 2 — `sudo install -m 0644 ...` | `docs/src/dev/ebpf.md` § Capabilities | F01863 | non-negotiable | true | 10 |
| R03660 | Drop-in apply step 3 — `sudo systemctl daemon-reload` | `docs/src/dev/ebpf.md` § Capabilities | F01864 | non-negotiable | true | 10 |
| R03661 | Drop-in apply step 4 — `sudo systemctl restart selfdefd` | `docs/src/dev/ebpf.md` § Capabilities | F01865 | non-negotiable | true | 10 |
| R03662 | Drop-in raises `LimitMEMLOCK=infinity` | `docs/src/dev/ebpf.md` § Capabilities | F01866 | non-negotiable | false | 10 |
| R03663 | LimitMEMLOCK rationale — older kernels charge BPF map pages against legacy memlock limit | `docs/src/dev/ebpf.md` § Capabilities | F01867 | non-negotiable | false | 10 |
| R03664 | Config block — `[collectors.ebpf]` | `docs/src/dev/ebpf.md` § Enabling | F01868 | non-negotiable | true | 10 |
| R03665 | Config knob — `enabled` (bool) | `docs/src/dev/ebpf.md` § Enabling | F01869 | non-negotiable | true | 10 |
| R03666 | Config knob — `program_path = "/usr/lib/selfdef/selfdef.bpf.o"` (default) | `docs/src/dev/ebpf.md` § Enabling | F01870 | non-negotiable | true | 10 |
| R03667 | Config knob — `enable_execve` (bool; default true) | `docs/src/dev/ebpf.md` § Enabling | F01871 | non-negotiable | true | 10 |
| R03668 | Config knob — `enable_lsm_open` (bool; opt-in; needs CONFIG_BPF_LSM=y kernel) | `docs/src/dev/ebpf.md` § Enabling | F01872 | non-negotiable | true | 10 |
| R03669 | Config knob — `enable_kprobe_unlink` (bool; opt-in; noisy by default) | `docs/src/dev/ebpf.md` § Enabling | F01873 | non-negotiable | true | 10 |
| R03670 | Verify — `systemctl restart selfdefd` | `docs/src/dev/ebpf.md` § Enabling | F01874 | non-negotiable | true | 10 |
| R03671 | Verify — `journalctl -u selfdefd -f \| grep -i ebpf` | `docs/src/dev/ebpf.md` § Enabling | F01875 | non-negotiable | true | 10 |
| R03672 | Verify — startup log line "loading BPF object path=/usr/lib/selfdef/selfdef.bpf.o" | `docs/src/dev/ebpf.md` § Enabling | F01876 | non-negotiable | false | 10 |
| R03673 | Verify — startup log line "attached tracepoint: syscalls/sys_enter_execve" | `docs/src/dev/ebpf.md` § Enabling | F01877 | non-negotiable | false | 10 |
| R03674 | Verify — startup log line "draining BPF ring buffer" | `docs/src/dev/ebpf.md` § Enabling | F01878 | non-negotiable | false | 10 |
| R03675 | OCSF event — each execve produces `PROCESS_ACTIVITY` event | `docs/src/dev/ebpf.md` § "What you get" | F01879 | non-negotiable | false | 10 |
| R03676 | OCSF event — `source = "selfdef.ebpf"` | `docs/src/dev/ebpf.md` § "What you get" | F01880 | non-negotiable | false | 10 |
| R03677 | OCSF event — process field populated (pid, tgid, ppid (when discoverable), uid, gid, comm) | `docs/src/dev/ebpf.md` § "What you get" | F01881 | non-negotiable | false | 10 |
| R03678 | OCSF event — raw field carries argv_truncated for downstream rule matching | `docs/src/dev/ebpf.md` § "What you get" | F01882 | non-negotiable | false | 10 |
| R03679 | Graceful degradation — collector logs warning at startup + runs idle if BPF object isn't installed | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01883 | non-negotiable | false | 10 |
| R03680 | Graceful degradation — daemon stays up; other collectors keep working | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01884 | non-negotiable | false | 10 |
| R03681 | Graceful degradation — same daemon binary ships to hosts with and without eBPF support | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01885 | non-negotiable | false | 10 |
| R03682 | Graceful degradation — config drives the difference | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01886 | non-negotiable | false | 10 |
| R03683 | Honest deferral — argv capture from execve (M10 follow-up) | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01887 | non-negotiable | false | 10 |
| R03684 | argv capture deferral — needs looped bpf_probe_read_user with verifier-friendly bounds | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01888 | non-negotiable | false | 10 |
| R03685 | argv capture deferral — until lands, argv in event is empty + argv_truncated=false | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01890 | non-negotiable | false | 10 |
| R03686 | Honest deferral — LSM file_open kernel-side program pending (type reserved + userspace decode path present) | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01891 + F01892 + F01893 + F01894 | non-negotiable | false | 10 |
| R03687 | LSM file_open deferral — requires CONFIG_BPF_LSM=y AND `bpf` in CONFIG_LSM (kernel cmdline `lsm=...,bpf`) | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01837 | non-negotiable | true | 10 |
| R03688 | Honest deferral — do_unlinkat kprobe kernel-side program pending (same shape: type reserved + kernel-side pending) | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01895 + F01896 | non-negotiable | false | 10 |
| R03689 | Extension pattern — M10 nailed loader infrastructure + one probe end-to-end | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01897 | non-negotiable | false | 10 |
| R03690 | Extension pattern — add probe by writing #[tracepoint] / #[lsm] / #[kprobe] handler in `bpf/selfdef-bpf/src/` | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01898 + F01899 | non-negotiable | false | 10 |
| R03691 | Extension pattern — rebuild via xtask | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01900 | non-negotiable | false | 10 |
| R03692 | Extension pattern — list new event kind in `EventKind` (selfdef-ebpf-common) | `docs/src/dev/ebpf.md` § "Honest deferrals" + `crates/selfdef-ebpf-common/` | F01901 | non-negotiable | false | 10 |
| R03693 | Troubleshooting case 1 — "no BPF object installed; ebpf collector idle" → run `cargo xtask install-bpf` (or build then copy manually) | `docs/src/dev/ebpf.md` § Troubleshooting | F01902 | non-negotiable | false | 10 |
| R03694 | Troubleshooting case 2 — "aya: program load failed" → verifier rejected; run `dmesg \| tail` for verifier log | `docs/src/dev/ebpf.md` § Troubleshooting | F01903 | non-negotiable | false | 10 |
| R03695 | Troubleshooting case 2 — most often caused by unbounded loops OR unverified pointer reads | `docs/src/dev/ebpf.md` § Troubleshooting | F01904 | non-negotiable | false | 10 |
| R03696 | Troubleshooting case 2 — both common when extending argv capture or path extraction | `docs/src/dev/ebpf.md` § Troubleshooting | F01904 | non-negotiable | false | 10 |
| R03697 | Troubleshooting case 3 — "Permission denied from `aya::Ebpf::load_file`" → drop-in not applied | `docs/src/dev/ebpf.md` § Troubleshooting | F01905 | non-negotiable | false | 10 |
| R03698 | Troubleshooting case 3 — check via `systemctl show selfdefd \| grep AmbientCap` → should include CAP_BPF CAP_PERFMON | `docs/src/dev/ebpf.md` § Troubleshooting | F01905 | non-negotiable | true | 10 |
| R03699 | Troubleshooting case 4 — "error: linker bpf-linker not found" → `cargo +nightly install bpf-linker` | `docs/src/dev/ebpf.md` § Troubleshooting | F01906 | non-negotiable | true | 10 |
| R03700 | Planned program — `proc-ancestry` (full process tree tracking with parent inheritance + detection of orphaned shells) | `selfdef-ebpf/README.md` § Planned programs | F01907 | non-negotiable | true | 10 |
| R03701 | Planned program — `hidden-process` (ground-truth process list from task_struct walk cross-checked against /proc) | `selfdef-ebpf/README.md` § Planned programs | F01908 | non-negotiable | true | 10 |
| R03702 | Planned program — `ld-preload-watch` (detect LD_PRELOAD and /etc/ld.so.preload use) | `selfdef-ebpf/README.md` § Planned programs | F01909 | non-negotiable | true | 10 |
| R03703 | Planned program — `kmod-watch` (kernel module load/unload, signed/unsigned tracking) | `selfdef-ebpf/README.md` § Planned programs | F01910 | non-negotiable | true | 10 |
| R03704 | Planned program — `tcp-fingerprint` (passive TCP fingerprinting on inbound SYN, fed into correlator alongside Suricata) | `selfdef-ebpf/README.md` § Planned programs | F01911 | non-negotiable | true | 10 |
| R03705 | Crate `selfdef-ebpf-common` exists at `crates/selfdef-ebpf-common/` | `crates/selfdef-ebpf-common/` | M00416 | non-negotiable | false | 10 |
| R03706 | Crate `selfdef-ebpf-common/src/lib.rs` is 179 lines (audit-cycle snapshot) | `crates/selfdef-ebpf-common/src/lib.rs` | F01912 | non-negotiable | false | 10 |
| R03707 | Crate `selfdef-ebpf-common` feature `ebpf` toggles kernel-space types vs userspace types | `bpf/selfdef-bpf/Cargo.toml` dependency line | F01913 | non-negotiable | false | 10 |
| R03708 | Crate `selfdef-collector-ebpf` exists at `crates/selfdef-collector-ebpf/` | `crates/selfdef-collector-ebpf/` | M00417 | non-negotiable | false | 10 |
| R03709 | Crate `selfdef-collector-ebpf/src/lib.rs` is 555 lines (audit-cycle snapshot) | `crates/selfdef-collector-ebpf/src/lib.rs` | F01914 | non-negotiable | false | 10 |
| R03710 | Crate `selfdef-collector-tetragon` exists at `crates/selfdef-collector-tetragon/` | `crates/selfdef-collector-tetragon/` | M00418 | non-negotiable | false | 10 |
| R03711 | Crate `selfdef-collector-tetragon/src/lib.rs` is 415 lines (audit-cycle snapshot) | `crates/selfdef-collector-tetragon/src/lib.rs` | F01915 | non-negotiable | false | 10 |
| R03712 | Crate `selfdef-collector-tetragon` ingests Tetragon events | `crates/selfdef-collector-tetragon/` + `docs/src/dev/ebpf.md` § header | F01916 | non-negotiable | false | 10 |
| R03713 | BPF crate `bpf/selfdef-bpf/Cargo.toml` has its own `[workspace]` block | `bpf/selfdef-bpf/Cargo.toml` | F01844 | non-negotiable | false | 10 |
| R03714 | BPF crate `bpf/selfdef-bpf/Cargo.toml` dependency note — "this crate has its own [workspace] block so it does NOT inherit the main workspace's dependency table" | `bpf/selfdef-bpf/Cargo.toml` § comment | F01844 | non-negotiable | false | 10 |
| R03715 | BPF crate build command — `cargo +nightly build --manifest-path bpf/selfdef-bpf/Cargo.toml --target bpfel-unknown-none --release -Z build-std=core` | `bpf/selfdef-bpf/Cargo.toml` § comment | M00397 | non-negotiable | true | 10 |
| R03716 | BPF crate target — `bpfel-unknown-none` | `bpf/selfdef-bpf/Cargo.toml` § comment | M00397 | non-negotiable | false | 10 |
| R03717 | BPF crate edition — 2021 | `bpf/selfdef-bpf/Cargo.toml` | M00395 | non-negotiable | false | 10 |
| R03718 | BPF crate rust-version — 1.81 | `bpf/selfdef-bpf/Cargo.toml` | M00395 | non-negotiable | false | 10 |
| R03719 | BPF crate license — Apache-2.0 OR MIT | `bpf/selfdef-bpf/Cargo.toml` | M00395 | non-negotiable | false | 10 |
| R03720 | BPF crate publish — false (never published to crates.io) | `bpf/selfdef-bpf/Cargo.toml` | M00395 | non-negotiable | false | 10 |
| R03721 | BPF crate description — "selfdef BPF kernel-space programs." | `bpf/selfdef-bpf/Cargo.toml` | M00395 | non-negotiable | false | 10 |
| R03722 | BPF crate binary name — `selfdef-bpf` | `bpf/selfdef-bpf/Cargo.toml` `[[bin]]` | M00396 | non-negotiable | false | 10 |
| R03723 | BPF crate binary path — `src/main.rs` | `bpf/selfdef-bpf/Cargo.toml` `[[bin]]` | M00396 | non-negotiable | false | 10 |
| R03724 | BPF crate dependency — aya-ebpf = "0.1" | `bpf/selfdef-bpf/Cargo.toml` | M00398 | non-negotiable | true | 10 |
| R03725 | BPF crate dependency — aya-log-ebpf = "0.1" | `bpf/selfdef-bpf/Cargo.toml` | M00398 | non-negotiable | true | 10 |
| R03726 | BPF crate dependency — selfdef-ebpf-common (path `../../crates/selfdef-ebpf-common`, default-features=false, features=["ebpf"]) | `bpf/selfdef-bpf/Cargo.toml` | M00398 | non-negotiable | true | 10 |
| R03727 | BPF crate profile.dev — opt-level=3 / debug=false / debug-assertions=false / overflow-checks=false / lto=true / panic="abort" / incremental=false / codegen-units=1 / rpath=false | `bpf/selfdef-bpf/Cargo.toml` `[profile.dev]` | M00399 | non-negotiable | false | 10 |
| R03728 | BPF crate profile.release — lto=true / panic="abort" / codegen-units=1 | `bpf/selfdef-bpf/Cargo.toml` `[profile.release]` | M00399 | non-negotiable | false | 10 |
| R03729 | BPF crate profile rationale — dev profile matches release because BPF verifier requirements | `bpf/selfdef-bpf/Cargo.toml` `[profile.dev]` (matches release) | M00399 | non-negotiable | false | 10 |
| R03730 | Aya toolchain — pure-Rust eBPF toolchain (aya-rs.dev) | `selfdef-ebpf/README.md` § header | M00417 | non-negotiable | false | 10 |
| R03731 | Aya scaffolding workflow — `cargo install bpf-linker` + `cargo generate --git https://github.com/aya-rs/aya-template` | `selfdef-ebpf/README.md` § header | E0163 | non-negotiable | true | 10 |
| R03732 | Tetragon TracingPolicy directory — `rules/tetragon/` | `rules/tetragon/` | M00420 | non-negotiable | false | 10 |
| R03733 | Tetragon TracingPolicy — `observe-sensitive-files.yaml` (concrete policy) | `rules/tetragon/observe-sensitive-files.yaml` | F01918 | non-negotiable | true | 10 |
| R03734 | Tetragon TracingPolicy README — `rules/tetragon/README.md` | `rules/tetragon/README.md` | F01919 | non-negotiable | false | 10 |
| R03735 | Tetragon TracingPolicies coexist with sovereign-kernel-fence per MS012 perimeter coexistence | MS012 + `rules/tetragon/` | M00420 | non-negotiable | false | 10 |
| R03736 | Project boundary — selfdef-collector-tetragon consumes Tetragon events but does NOT modify Tetragon TracingPolicies authored by sovereign-os | architecture + MS012 | M00420 | non-negotiable | false | 10 |
| R03737 | Project boundary — selfdef-ebpf is selfdef-scope; sovereign-os does NOT import the BPF crate directly | architecture + MS007 + SDD-038 | E0162 | non-negotiable | false | 10 |
| R03738 | Project boundary — eBPF events emitted into local bus (per MS002 collector fabric); bridge (MS015) may republish to NATS | MS002 + MS015 + `docs/src/dev/ebpf.md` § header | F01880 | non-negotiable | false | 10 |
| R03739 | Project boundary — sovereign-os MAY subscribe to selfdef-ebpf events via NATS for fleet-wide eBPF visibility (NOT direct collector import) | MS015 + MS007 + SDD-038 | E0162 | non-negotiable | false | 10 |
| R03740 | Integration with MS001 daemon core — eBPF collector is one of the daemon's spawned tasks during startup | MS001 + `docs/src/dev/ebpf.md` § Enabling | E0166 | non-negotiable | false | 10 |
| R03741 | Integration with MS002 collector fabric — selfdef-collector-ebpf is one of the collector implementations | MS002 + `crates/selfdef-collector-ebpf/` | M00417 | non-negotiable | false | 10 |
| R03742 | Integration with MS002 collector fabric — selfdef-collector-tetragon is one of the collector implementations | MS002 + `crates/selfdef-collector-tetragon/` | M00418 | non-negotiable | false | 10 |
| R03743 | Integration with MS003 correlator — Sigma rules can match `logsource: selfdef.ebpf` OR `logsource: tetragon` to discriminate | MS003 + `docs/src/dev/ebpf.md` § header | F01805 | non-negotiable | false | 10 |
| R03744 | Integration with MS003 store sink — UUIDv7 dedupe handles redeliveries if BPF events somehow re-emit | MS003 + `docs/src/ops/nats.md` § Loop avoidance | F01884 | non-negotiable | false | 10 |
| R03745 | Integration with MS006 agent-guard module — Tetragon TracingPolicies are agent-guard's authoring surface; eBPF is agent-guard's kernel-event source | MS006 agent-guard + MS012 + `rules/tetragon/` | M00420 | non-negotiable | false | 10 |
| R03746 | Integration with MS008 SAIN-01 — eBPF + Tetragon are part of SAIN-01 selfdef deployment | MS008 + `docs/src/dev/ebpf.md` § Enabling | E0166 | non-negotiable | false | 10 |
| R03747 | Integration with MS009 audit cycles — phase-6/30-crate-audit covers selfdef-ebpf-common + selfdef-collector-ebpf + selfdef-collector-tetragon | MS009 phase-6 30-crate-audit | M00416 + M00417 + M00418 | non-negotiable | false | 10 |
| R03748 | Integration with MS009 audit cycles — phase-6/80-security-audit covers eBPF capabilities (CAP_BPF + CAP_PERFMON; LSM kernel requirements; verifier rejection diagnostics) | MS009 phase-6 80-security-audit | E0165 + E0169 | non-negotiable | false | 10 |
| R03749 | Integration with MS010 hardware-aware modules — eBPF [requires_hardware] may include `kernel_version_min` (5.8+ for ring buffer maps) in future expansion | MS010 + `docs/src/dev/ebpf.md` § "Kernel requirements" | F01854 | non-negotiable | false | 10 |
| R03750 | Integration with MS011 operator dashboard — dashboard MCP tab + Hardware tab may show eBPF status (loaded probes, ring-buffer drain rate, BTF availability) | MS011 + `docs/src/dev/ebpf.md` § Enabling | E0166 | non-negotiable | false | 10 |
| R03751 | Integration with MS012 perimeter coexistence — eBPF + Tetragon both publish to local bus; perimeter coexistence ensures no policy overlap (sovereign-kernel-fence host-scope vs agent-guard container-scope) | MS012 + `docs/src/dev/ebpf.md` § header | M00420 | non-negotiable | false | 10 |
| R03752 | Integration with MS013 27-SDD charter — eBPF currently has no dedicated SDD (codified in `docs/src/dev/ebpf.md` + crates); future SDD slot available if scope grows | MS013 + `docs/sdd/` ledger | E0161 | non-negotiable | false | 10 |
| R03753 | Integration with MS014 SSH-wrap — ssh-wrap events flow via eventstream collector; eBPF events flow via selfdef-collector-ebpf; both land on local bus | MS014 + MS002 + `crates/selfdef-collector-ebpf/` | F01880 | non-negotiable | false | 10 |
| R03754 | Integration with MS015 NATS messaging — eBPF events propagate across hosts via NATS bridge (Core or JetStream mode) | MS015 + `docs/src/ops/nats.md` § header | F01880 | non-negotiable | false | 10 |
| R03755 | Operator scenario — fleet-wide LD_PRELOAD detection via planned `ld-preload-watch` program + NATS bridge | `selfdef-ebpf/README.md` § Planned programs + MS015 | F01909 | non-negotiable | true | 10 |
| R03756 | Operator scenario — fleet-wide hidden-process detection via planned `hidden-process` program + correlator cross-check against /proc | `selfdef-ebpf/README.md` § Planned programs + MS003 | F01908 | non-negotiable | true | 10 |
| R03757 | Operator scenario — fleet-wide kernel-module-load tracking via planned `kmod-watch` program | `selfdef-ebpf/README.md` § Planned programs | F01910 | non-negotiable | true | 10 |
| R03758 | Operator scenario — fleet-wide TCP fingerprinting via planned `tcp-fingerprint` program + Suricata sister channel | `selfdef-ebpf/README.md` § Planned programs + MS006 suricata module | F01911 | non-negotiable | true | 10 |
| R03759 | Operator scenario — fleet-wide proc-ancestry tracking via planned `proc-ancestry` program + agent-guard policy gates | `selfdef-ebpf/README.md` § Planned programs + MS006 agent-guard | F01907 | non-negotiable | true | 10 |
| R03760 | Doctrine — selfdef-ebpf is a kernel-space companion to selfdef-collector-tetragon (one in-kernel, one event-ingester) | `crates/selfdef-collector-ebpf/` + `crates/selfdef-collector-tetragon/` + `docs/src/dev/ebpf.md` § header | M00417 + M00418 | non-negotiable | false | 10 |
| R03761 | Doctrine — eBPF and Tetragon both publish PROCESS_ACTIVITY events with source-field discriminator (no double-handling at correlator) | `docs/src/dev/ebpf.md` § header + § "What you get" | F01805 + F01880 | non-negotiable | false | 10 |
| R03762 | Doctrine — selfdef-ebpf-common is the shared type contract between kernel-space (BPF crate) and userspace (collector crate) | `crates/selfdef-ebpf-common/` + `bpf/selfdef-bpf/Cargo.toml` dependency | M00416 | non-negotiable | false | 10 |
| R03763 | Doctrine — argv_truncated flag is a first-class detection signal (NOT a noise filter) | `docs/src/dev/ebpf.md` § argv detail | F01830 | non-negotiable | false | 10 |
| R03764 | Doctrine — path capture is deferred but ring-buffer schema is FORWARD-COMPATIBLE (no schema break when path lands) | `docs/src/dev/ebpf.md` § "What ships" | F01834 + F01835 | non-negotiable | false | 10 |
| R03765 | Doctrine — eBPF probes ship one at a time (M10 baseline = 3 probes; future milestones add probes incrementally) | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01897 + F01898 | non-negotiable | false | 10 |
| R03766 | Doctrine — eBPF crate is out-of-workspace (different target, different toolchain, different optimizer-required-profile) | `bpf/selfdef-bpf/Cargo.toml` `[workspace]` | F01844 | non-negotiable | false | 10 |
| R03767 | Doctrine — eBPF capabilities are CAP_BPF + CAP_PERFMON (no full root) — supports unprivileged operator deployment | `docs/src/dev/ebpf.md` § Capabilities | F01858 + F01859 | non-negotiable | false | 10 |
| R03768 | Doctrine — eBPF graceful degradation is mandatory (daemon must work without BPF object installed) | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01884 | non-negotiable | false | 10 |
| R03769 | Doctrine — eBPF troubleshooting is operator-facing (4 documented failure modes with remediations) | `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | non-negotiable | false | 10 |
| R03770 | Doctrine — Tetragon TracingPolicy authoring stays at `rules/tetragon/` (selfdef-scoped agent-guard policies; sovereign-kernel-fence is sovereign-os-scoped per MS012) | `rules/tetragon/` + MS012 | M00420 | non-negotiable | false | 10 |
| R03771 | Doctrine — Sigma rules discriminate logsource (`selfdef.ebpf` vs `tetragon`) when both sources active | `docs/src/dev/ebpf.md` § header + `rules/sigma/` (sister directory) | F01805 | non-negotiable | false | 10 |
| R03772 | Sigma rules directory — `rules/sigma/` (sister to `rules/tetragon/` + `rules/yara/`) | `rules/` tree | M00420 | non-negotiable | false | 10 |
| R03773 | YARA rules directory — `rules/yara/` (sister; file-content matching) | `rules/` tree | M00420 | non-negotiable | false | 10 |
| R03774 | Three rule families — Sigma (event matching) + Tetragon (in-kernel TracingPolicy) + YARA (file/memory pattern matching) | `rules/` tree | M00420 | non-negotiable | false | 10 |
| R03775 | Composite — eBPF kernel-event observation layer is selfdef's primary in-kernel telemetry channel (Tetragon is the alternative when installed) | `docs/src/dev/ebpf.md` § header + `crates/selfdef-collector-tetragon/` | E0161 | non-negotiable | false | 10 |
| R03776 | Composite — selfdef provides BOTH eBPF (selfdef-authored kernel programs) AND Tetragon collector (third-party kernel telemetry consumer); operators can use either or both | `crates/selfdef-collector-ebpf/` + `crates/selfdef-collector-tetragon/` + `docs/src/dev/ebpf.md` § header | E0161 | non-negotiable | false | 10 |
| R03777 | Composite — kernel-event observation is OPTIONAL (graceful degradation; daemon works with or without it) | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01884 | non-negotiable | false | 10 |
| R03778 | Composite — kernel-event observation is CONFIG-DRIVEN (`[collectors.ebpf]` block toggles probes independently) | `docs/src/dev/ebpf.md` § Enabling | F01868 | non-negotiable | false | 10 |
| R03779 | Composite — kernel-event observation is FORWARD-COMPATIBLE (ring-buffer schema stable; new probes add EventKind variants) | `docs/src/dev/ebpf.md` § "What ships" + § "Honest deferrals" | F01834 + F01901 | non-negotiable | false | 10 |
| R03780 | Composite — kernel-event observation is OPERATOR-DEPLOYABLE (CAP_BPF+CAP_PERFMON; not full-root; non-root install path supported) | `docs/src/dev/ebpf.md` § Capabilities + § Prerequisites | F01858 + F01852 | non-negotiable | false | 10 |
| R03781 | Audit verb (implied per architecture) — `selfdefctl ebpf status` shows loaded probes + drain rate | architecture + MS011 dashboard Hardware tab | E0166 | non-negotiable | true | 10 |
| R03782 | Audit verb (implied per architecture) — `selfdefctl ebpf events tail` shows raw eBPF events | architecture | E0167 | non-negotiable | true | 10 |
| R03783 | Audit verb (implied per architecture) — `selfdefctl ebpf install` runs `cargo xtask install-bpf` from package | architecture | E0163 | non-negotiable | true | 10 |
| R03784 | Build artifact — `target/release/selfdef.bpf.o` (BPF object) | `docs/src/dev/ebpf.md` § Prerequisites | M00411 | non-negotiable | false | 10 |
| R03785 | Install artifact — `/usr/lib/selfdef/selfdef.bpf.o` (default install path) | `docs/src/dev/ebpf.md` § Prerequisites | F01850 | non-negotiable | false | 10 |
| R03786 | Install artifact — `~/.local/share/selfdef/selfdef.bpf.o` (non-root install path) | `docs/src/dev/ebpf.md` § Prerequisites | F01852 | non-negotiable | true | 10 |
| R03787 | Failure mode — BPF object missing → graceful degradation (log warning, idle, daemon continues) | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01883 | non-negotiable | false | 10 |
| R03788 | Failure mode — verifier rejection → log error with verifier diagnostic; daemon continues without affected probe | `docs/src/dev/ebpf.md` § Troubleshooting | F01903 | non-negotiable | false | 10 |
| R03789 | Failure mode — missing CAP_BPF/CAP_PERFMON → Permission denied; daemon logs error + idle | `docs/src/dev/ebpf.md` § Troubleshooting | F01905 | non-negotiable | false | 10 |
| R03790 | Failure mode — BTF missing → LSM probe skipped with warning; tracepoint and kprobe continue | `docs/src/dev/ebpf.md` § "What ships" | F01840 | non-negotiable | false | 10 |
| R03791 | Failure mode — kernel < 5.8 (no ring-buffer maps) → BPF object load fails; graceful degradation kicks in | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01854 + F01883 | non-negotiable | false | 10 |
| R03792 | Failure mode — kernel < 4.7 (no tracepoint:syscalls:sys_enter_execve) → entire eBPF collector idle | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01853 + F01883 | non-negotiable | false | 10 |
| R03793 | Failure mode — config `enabled = false` → BPF object never loaded; no kernel impact | `docs/src/dev/ebpf.md` § Enabling | F01869 | non-negotiable | false | 10 |
| R03794 | Failure mode — config `enabled = true` + `enable_execve = false` → BPF object loaded but execve probe not attached | `docs/src/dev/ebpf.md` § Enabling | F01871 | non-negotiable | false | 10 |
| R03795 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_ebpf_events_emitted_total{kind}` | architecture + MS009 phase-6 80-security | E0167 | non-negotiable | true | 10 |
| R03796 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_ebpf_ringbuf_drops_total` | architecture | E0167 | non-negotiable | true | 10 |
| R03797 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_ebpf_argv_truncated_total` | architecture + `docs/src/dev/ebpf.md` § argv detail | F01830 | non-negotiable | true | 10 |
| R03798 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_ebpf_attached_probes` (gauge of active probe count) | architecture | E0166 | non-negotiable | true | 10 |
| R03799 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_ebpf_load_failures_total{probe,reason}` | architecture + `docs/src/dev/ebpf.md` § Troubleshooting | E0169 | non-negotiable | true | 10 |
| R03800 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_tetragon_events_emitted_total{policy_name}` | architecture + MS009 phase-6 80-security | M00418 | non-negotiable | true | 10 |
| R03801 | Tests — selfdef-collector-tetragon/tests/ covers Tetragon event parsing | `crates/selfdef-collector-tetragon/tests/` | M00418 | non-negotiable | false | 10 |
| R03802 | Tests — selfdef-collector-tetragon/tests/ covers policy_name prefix discrimination (per MS012 audit-trail discriminator) | `crates/selfdef-collector-tetragon/tests/` + MS012 § Coverage 5 | M00418 | non-negotiable | false | 10 |
| R03803 | Tests — selfdef-collector-tetragon/tests/ covers OCSF envelope publication to local bus | `crates/selfdef-collector-tetragon/tests/` | M00418 | non-negotiable | false | 10 |
| R03804 | Tests — xtask integration tests cover build-bpf + install-bpf workflows | architecture + `docs/src/dev/ebpf.md` § Prerequisites | M00410 + M00411 + M00412 | non-negotiable | false | 10 |
| R03805 | Tests — manual smoke test workflow documented + repeatable | `docs/src/dev/ebpf.md` § Enabling | F01874 + F01875 | non-negotiable | false | 10 |
| R03806 | Capability invariant — daemon MUST run with CAP_BPF + CAP_PERFMON (NOT full root) | `docs/src/dev/ebpf.md` § Capabilities | F01858 + F01859 | non-negotiable | false | 10 |
| R03807 | Capability invariant — daemon MUST verify ambient caps via `systemctl show selfdefd \| grep AmbientCap` | `docs/src/dev/ebpf.md` § Troubleshooting | F01905 | non-negotiable | true | 10 |
| R03808 | Schema invariant — ring-buffer schema is forward-compatible (path/path_len fields reserved for future use) | `docs/src/dev/ebpf.md` § "What ships" | F01834 + F01835 | non-negotiable | false | 10 |
| R03809 | Schema invariant — selfdef-ebpf-common is the type contract; both kernel-space and userspace must depend on it | `crates/selfdef-ebpf-common/` + `bpf/selfdef-bpf/Cargo.toml` dependency | M00416 | non-negotiable | false | 10 |
| R03810 | Schema invariant — new EventKind variant added to selfdef-ebpf-common per new probe | `docs/src/dev/ebpf.md` § "Honest deferrals" | F01901 | non-negotiable | false | 10 |
| R03811 | Deployment invariant — single daemon binary ships to hosts with and without eBPF support | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01885 | non-negotiable | false | 10 |
| R03812 | Deployment invariant — config drives the eBPF behavior difference (NOT separate binaries) | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01886 | non-negotiable | false | 10 |
| R03813 | Build invariant — BPF crate NEVER builds from `cargo build --workspace` (must use xtask) | `docs/src/dev/ebpf.md` § Prerequisites | F01845 + F01846 | non-negotiable | false | 10 |
| R03814 | Build invariant — BPF crate uses nightly toolchain (NOT stable) | `docs/src/dev/ebpf.md` § Prerequisites | F01841 + F01843 | non-negotiable | false | 10 |
| R03815 | Build invariant — BPF crate target is `bpfel-unknown-none` (NOT x86_64-unknown-linux-gnu) | `bpf/selfdef-bpf/Cargo.toml` § comment | M00397 | non-negotiable | false | 10 |
| R03816 | Build invariant — BPF crate uses `-Z build-std=core` (no std) | `bpf/selfdef-bpf/Cargo.toml` § comment | M00397 | non-negotiable | false | 10 |
| R03817 | Build invariant — BPF crate dev profile matches release profile (verifier-required optimization) | `bpf/selfdef-bpf/Cargo.toml` `[profile.dev]` | M00399 | non-negotiable | false | 10 |
| R03818 | Privacy invariant — eBPF probes capture process identity (pid/uid/comm) NOT file content | `docs/src/dev/ebpf.md` § "What ships" | F01818 | non-negotiable | false | 10 |
| R03819 | Privacy invariant — argv captured up to 256 bytes (NOT full command line; intentional limit) | `docs/src/dev/ebpf.md` § "What ships" | F01815 | non-negotiable | false | 10 |
| R03820 | Privacy invariant — path capture deferred (will NOT include file content even when added) | `docs/src/dev/ebpf.md` § "What ships" | F01819 + F01823 | non-negotiable | false | 10 |
| R03821 | Performance invariant — eBPF probes run in kernel context (no userspace round-trip per event) | `docs/src/dev/ebpf.md` § header | E0161 | non-negotiable | false | 10 |
| R03822 | Performance invariant — events delivered via ring buffer (no per-event syscall; batched read) | `docs/src/dev/ebpf.md` § "Kernel requirements" | F01854 | non-negotiable | false | 10 |
| R03823 | Performance invariant — argv capture bounded (16 entries / 256 bytes) prevents unbounded kernel-side work | `docs/src/dev/ebpf.md` § "What ships" | F01826 + F01827 | non-negotiable | false | 10 |
| R03824 | Doctrine — graceful degradation is doctrine, not optional (daemon MUST run with eBPF idle) | `docs/src/dev/ebpf.md` § "Graceful degradation" | F01884 | non-negotiable | false | 10 |
| R03825 | Doctrine — operator opt-in for noisy probes (enable_kprobe_unlink default false) | `docs/src/dev/ebpf.md` § Enabling | F01873 | non-negotiable | false | 10 |
| R03826 | Doctrine — operator opt-in for kernel-LSM-required probes (enable_lsm_open default false) | `docs/src/dev/ebpf.md` § Enabling | F01872 | non-negotiable | false | 10 |
| R03827 | Doctrine — execve probe is the baseline (enable_execve default true) | `docs/src/dev/ebpf.md` § Enabling | F01871 | non-negotiable | false | 10 |
| R03828 | Documentation — `docs/src/dev/ebpf.md` is the operator-facing dev doc | `docs/src/dev/ebpf.md` | E0161 | non-negotiable | false | 10 |
| R03829 | Documentation — `selfdef-ebpf/README.md` is the planned-programs roadmap | `selfdef-ebpf/README.md` | E0170 | non-negotiable | false | 10 |
| R03830 | Documentation — `bpf/selfdef-bpf/Cargo.toml` § comment is the build-command reference | `bpf/selfdef-bpf/Cargo.toml` § comment | M00397 | non-negotiable | false | 10 |
| R03831 | Audit-cycle integration — MS009 phase-6 audit covers eBPF crates + docs + capabilities + verifier diagnostics | MS009 phase-6 30-crate-audit + 60-docs-audit + 80-security-audit | E0161 | non-negotiable | false | 10 |
| R03832 | Audit-cycle integration — MS009 phase-7 audit covers eBPF + Tetragon cross-collector behavior | MS009 phase-7 50-integration-audit | E0161 | non-negotiable | false | 10 |
| R03833 | Audit-cycle integration — findings ledger F-2026-NNN may record eBPF-related deployment issues (e.g. missing CAP_BPF) | MS009 99-findings-ledger | E0169 | non-negotiable | false | 10 |
| R03834 | Cross-repo binding — selfdef-ebpf events flow into NATS bridge per MS015; sovereign-os may subscribe externally with mTLS | MS015 + MS007 + SDD-038 | F01880 | non-negotiable | false | 10 |
| R03835 | Cross-repo binding — sovereign-kernel-fence (sovereign-os authority) and agent-guard-*.yaml (selfdef authority) both consumed by Tetragon; selfdef-collector-tetragon emits OCSF events for both into local bus | MS012 + `rules/tetragon/` + `crates/selfdef-collector-tetragon/` | M00418 | non-negotiable | false | 10 |
| R03836 | Cross-repo binding — selfdef discriminates Tetragon events via policy_name prefix (`agent-guard-*` = selfdef-authored; otherwise = sovereign-os-authored) per MS012 audit-discriminator | MS012 § Coverage 5 + `crates/selfdef-collector-tetragon/` | M00418 | non-negotiable | false | 10 |
| R03837 | Composite scenario — single-host workstation: eBPF execve probe enabled by default (baseline detection); LSM + kprobe opt-in | `docs/src/dev/ebpf.md` § Enabling | F01871 + F01872 + F01873 | non-negotiable | true | 10 |
| R03838 | Composite scenario — multi-host fleet: eBPF probes on each host + NATS bridge propagates events to hub correlator | MS015 + MS003 + `docs/src/dev/ebpf.md` § Enabling | F01880 | non-negotiable | true | 10 |
| R03839 | Composite scenario — non-root deployment: `~/.local/share/selfdef/selfdef.bpf.o` + CAP_BPF/CAP_PERFMON drop-in + non-root selfdef user | `docs/src/dev/ebpf.md` § Prerequisites + § Capabilities | F01852 + F01858 + F01859 | non-negotiable | true | 10 |
| R03840 | Composite — eBPF + Tetragon TracingPolicies form selfdef's in-kernel telemetry layer; 3 shipping probes (execve_enter + LSM file_open + do_unlinkat kprobe) + 5 planned programs (proc-ancestry / hidden-process / ld-preload-watch / kmod-watch / tcp-fingerprint) + Tetragon TracingPolicy ledger (`rules/tetragon/` with observe-sensitive-files.yaml shipping); out-of-workspace BPF crate built via xtask; aya runtime; OCSF events with source-field discriminator; CAP_BPF+CAP_PERFMON (no full root); graceful degradation; honest deferrals; troubleshooting playbook; integrates with MS001-MS015 | `bpf/` + `selfdef-ebpf/` + `crates/selfdef-ebpf-common/` + `crates/selfdef-collector-ebpf/` + `crates/selfdef-collector-tetragon/` + `docs/src/dev/ebpf.md` + `rules/tetragon/` | E0161 + E0162 + E0163 + E0164 + E0165 + E0166 + E0167 + E0168 + E0169 + E0170 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS015: 18720 + 2400 = 21120 sub-requirements when MS016 lands

## Cross-references

- Crate roots: `bpf/selfdef-bpf/` (out-of-workspace) + `crates/selfdef-ebpf-common/` + `crates/selfdef-collector-ebpf/` + `crates/selfdef-collector-tetragon/`
- Documentation: `docs/src/dev/ebpf.md` (operator-facing dev doc) + `selfdef-ebpf/README.md` (planned-programs roadmap) + `bpf/selfdef-bpf/Cargo.toml` § comment (build command)
- Rule directories: `rules/tetragon/` (TracingPolicies; sister to MS012 perimeter coexistence) + `rules/sigma/` (event-matching rules with logsource discriminator) + `rules/yara/` (file/memory patterns)
- Sister milestones: MS002 collector fabric (selfdef-collector-ebpf + selfdef-collector-tetragon) / MS003 correlator+responder+store-sink / MS006 agent-guard (Tetragon TracingPolicies + eBPF kernel-event source) / MS012 perimeter coexistence (sovereign-kernel-fence vs agent-guard scope split) / MS015 NATS messaging (fleet-wide eBPF event propagation)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (sovereign-os reads selfdef-ebpf events via NATS subscription with mTLS; NOT crate import)
