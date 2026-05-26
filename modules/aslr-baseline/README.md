# aslr-baseline

Guarantees `kernel.randomize_va_space=2` (full Address
Space Layout Randomization). ASLR is the foundational
exploit mitigation that makes memory-corruption attacks
probabilistic instead of deterministic — this module
ensures it stays at the secure value across drift.

## Why this matters

ASLR randomizes the base addresses of the stack, heap,
mmap region, VDSO, and brk on every exec. Without it, an
attacker exploiting a buffer overflow / use-after-free
knows exactly where their shellcode + gadgets live —
exploitation is reliable. With full ASLR, they must
first defeat the randomization (an info-leak), raising
the bar substantially.

`kernel.randomize_va_space` values:

| Value | Randomized | Security |
|---|---|---|
| `0` | nothing | INSECURE — deterministic exploitation |
| `1` | stack, VDSO, shared libs (NOT heap/brk) | partial |
| `2` (this module) | stack, heap, mmap, VDSO, brk | full — the secure target |

Modern distros default to 2. The risk is DRIFT: a
developer debugging a crash runs
`echo 0 > /proc/sys/kernel/randomize_va_space` to get
reproducible addresses and forgets to restore it; a
misguided "performance tuning" guide recommends disabling
it. This module guarantees + drift-detects the secure
value.

## Profile

Single profile `full` (=2). There is no meaningful
"stricter than full" for this knob, so no profile matrix.

## File

`/etc/sysctl.d/50-selfdef-aslr.conf` rendered with selfdef
header marker. Loaded at boot via `sysctl --system`;
apply.sh also writes live.

## MITRE coverage

- **T1203** Exploitation for Client Execution — ASLR is
  the mitigation that breaks reliable memory-corruption
  exploitation.
- **T1068** Exploitation for Privilege Escalation — local
  exploits depend on known addresses; ASLR forces an
  info-leak first.
- **T1211** Exploitation for Defense Evasion — ASLR raises
  the cost of the exploit chain.
- **T1055** Process Injection — some injection techniques
  rely on predictable address layout.

## Operator workflow

```bash
# Verify
sysctl kernel.randomize_va_space        # expect 2
cat /proc/sys/kernel/randomize_va_space

# Confirm randomization is live (addresses differ per run)
for i in 1 2; do cat /proc/self/maps | grep '\[stack\]'; done
# The two stack base addresses should differ.

# If a developer disabled it for debugging, re-apply:
sudo selfdefctl modules apply aslr-baseline
```

## Caveats

- **Debugging reproducibility**: developers sometimes need
  ASLR off for deterministic crash reproduction. They
  should use `setarch $(uname -m) -R <prog>` (per-process
  ASLR disable) instead of the global sysctl — that
  doesn't trip this module's drift detection.
- **Some HPC / numerical workloads** historically disabled
  ASLR for micro-performance. The cost on modern CPUs is
  negligible; keep ASLR on.
- **32-bit hosts** have a smaller randomization entropy
  space (ASLR is weaker but still on); 64-bit is the norm
  + has strong entropy.

## Coexistence

- **kernel-lockdown**: complementary — kernel-lockdown
  covers kexec/bpf/userfaultfd/dmesg/module-load; this
  covers ASLR. Separate sysctl drop-ins, no conflict.
- **kernel-yama-baseline + file-protections-baseline +
  sysctl-network-baseline + kernel-sysrq-restrict +
  unprivileged-userns-baseline**: the kernel-sysctl
  hardening family — each owns a distinct knob in its own
  drop-in file.
- **coredump-suid-restrict**: complementary — ASLR makes
  exploitation hard; coredump-suid-restrict prevents the
  info-leak (memory dump) that would defeat ASLR.
