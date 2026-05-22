# entropy-baseline

Detection module verifying that the host has a healthy
kernel CSPRNG seed + sufficient runtime entropy. Catches
the entropy-starved-VM class where early-boot
cryptographic key generation produces predictable
output that an attacker can replicate.

## Why this matters

Linux's `/dev/urandom` and `getrandom()` produce
cryptographic-quality output ONLY AFTER the kernel
CSPRNG has been seeded with sufficient entropy at boot.
On modern (5.18+) kernels, `getrandom()` blocks until
seed; older or misconfigured kernels can let unseeded
output reach userspace.

Real attack chain:

| Step | What happens |
|---|---|
| 1 | Cloud VM boots with no hwrng + no IRQ entropy (headless, no keyboard, no NIC traffic) |
| 2 | `/dev/urandom` is pre-seed; ssh-keygen / openssl / gpg seed from it |
| 3 | Generated SSH host key / TLS cert / GPG key has only ~10-50 bits of effective entropy |
| 4 | Attacker brute-forces the predictable key in minutes |

This was the canonical attack against early AWS VMs
(2010s) and remains relevant for under-provisioned
cloud micro-instances and embedded Linux without hwrng.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 if entropy < threshold OR no daemon → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| entropy ≥ threshold AND (daemon OR hwrng OR CPU RNG) | `ok` | `entropy_ok` |
| entropy < threshold OR no entropy source available | `warn` | `entropy_low` |
| entropy < 64 AND no daemon AND no hwrng AND no CPU RNG | `alert` | `entropy_starved` (crypto is risky) |

Default threshold: 256 (bits). Override via
`SELFDEF_ENTROPY_THRESHOLD` env in systemctl-edit.

## Detection

Per-scan the wrapper checks:

1. **`/proc/sys/kernel/random/entropy_avail`** — current
   estimated entropy pool depth (256+ healthy).
2. **Entropy daemon active?** Probes for:
   - `jitterentropy.service` (kernel jitterentropy RNG)
   - `haveged.service` (userspace IRQ-based RNG)
   - `rngd.service` / `rng-tools.service` (rngd
     forwarding from hwrng / TPM)
3. **Hardware RNG node?** `/sys/class/misc/hw_random/
   rng_available` — typically TPM-RNG, Intel DRNG,
   AMD-RNG, or board hwrng.
4. **CPU-side RNG?** `cpuinfo` flag for
   `rdrand` / `rdseed` (Intel) / VIA padlock.
5. **CRNG init done?** `dmesg | grep "random: crng init
   done"` — confirms the kernel CSPRNG was seeded
   post-boot. Falls back to a /proc/sys/kernel/random/
   uuid read (succeeds only if CRNG up).

## Cadence

| Trigger | Why |
|---|---|
| `OnBootSec=5min` | Catches the canonical case — entropy-starved early-boot keys |
| `OnUnitActiveSec=6h` | Refresh for gradual depletion (rare on modern kernels) |
| `RandomizedDelaySec=5min` | Avoid herd-collision |

## MITRE coverage

- **T1552.004** Unsecured Credentials: Private Keys —
  PRIMARY; predictable-CSPRNG-generated private keys
  are the canonical credential leak via weak crypto.
- **T1600.001** Weaken Encryption: Reduce Key Space —
  conceptually identical at the kernel-RNG layer.
- **T1190** Exploit Public-Facing Application —
  predictable session keys / TLS keys exposed to the
  network are exploitable.
- **T1565.003** Stored Data Manipulation: Runtime
  Data Manipulation — defender visibility.

## Operator workflow

```bash
# Check current state
cat /proc/sys/kernel/random/entropy_avail
systemctl status jitterentropy haveged rngd 2>/dev/null
ls /sys/class/misc/hw_random/
grep -E 'rdrand|rdseed' /proc/cpuinfo | head -1

# Inspect last scan
journalctl -t selfdef-entropy -n 1 --no-pager

# On-demand check (after enabling a daemon)
sudo systemctl start selfdef-entropy.service

# Common remediation — enable jitterentropy (Linux 5.4+)
# It's a kernel module, no install needed; just ensure
# /etc/modules-load.d/ includes it OR /lib/modules has it.
sudo modprobe jitterentropy_rng

# Or install haveged (operator-side fallback)
sudo apt install haveged && sudo systemctl enable --now haveged

# Or install rng-tools for hwrng forwarding
sudo apt install rng-tools && sudo systemctl enable --now rngd
```

## Caveats

- **Linux 5.18+ kernels don't really "have low
  entropy"** in the cryptographic sense post-init —
  the pool model was simplified. entropy_avail is
  informational. But the SEED itself may still be
  weak if no hwrng + no RDRAND + no jitterentropy
  was available at first-boot.
- **dmesg may be restricted** by kernel-lockdown +
  dmesg_restrict; falls back to /proc-uuid-read
  probe.
- **rdrand-only on AMD Ryzen** had a notorious bug in
  some early-Ryzen BIOSes where rdrand returned a
  constant — relying on it alone is insufficient.
  This module just confirms presence; it does not
  test entropy quality of the source.
- **Hibernate resume** can leave the CSPRNG in a
  weird state until re-seeded; module catches this
  at next 6h-cycle.

## Coexistence

- **chrony-baseline + time-skew-watchdog**:
  complementary — time-sync is independent of
  entropy but both are boot-init hygiene.
- **kernel-yama-baseline + kernel-lockdown**:
  orthogonal kernel hardening.
- **secure-boot-status + bootloader-password-detect**:
  complementary trust-chain visibility.
- **swap-encryption-detect**: complementary data-at-
  rest hygiene.
- **integrity-sentinel + aide-bridge**: complementary
  detection.
