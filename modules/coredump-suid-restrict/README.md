# coredump-suid-restrict

Sets `fs.suid_dumpable=0` (setuid binaries never dump
their memory on crash) and, in the strict profile, a
hard `core` ulimit of 0 for all users. Prevents the
credential-leak-via-core-dump class.

## Why this matters

When a process crashes, the kernel can write a core
dump — a snapshot of the process's entire memory — to
disk. For a **setuid binary** (passwd, sudo, su, mount,
ping, polkit helpers), that memory routinely contains:

- The shadow-file hash being verified (passwd).
- The password the operator just typed (sudo / su).
- Decrypted key material (mount.cifs credentials,
  gpg-agent helpers).

If `fs.suid_dumpable` is set to 1, those dumps are
written world-readable — any local user can read the
crashed setuid binary's secrets. Setting it to 0 means
setuid processes never dump at all.

This is CIS Benchmark 1.5.x and DISA-STIG mandated.

## fs.suid_dumpable values

| Value | Behavior |
|---|---|
| `0` (this module) | setuid/setgid processes never dump (SECURE) |
| `1` | setuid processes dump WORLD-READABLE (INSECURE — credential leak) |
| `2` | setuid processes dump root-readable-only (partial; still risky if root is compromised) |

## Profiles

| Profile | Effect |
|---|---|
| `suid-only` (default) | `fs.suid_dumpable=0` only. Normal-process core dumps still allowed (operator can debug their own non-setuid crashes). |
| `all-off` | suid_dumpable=0 + limits.d hard core 0 for ALL users — no process produces any core dump. Strongest; breaks crash-debug workflows. |

## Files installed

| Path | Profile | Purpose |
|---|---|---|
| `/etc/sysctl.d/50-selfdef-suid-dumpable.conf` | both | `fs.suid_dumpable=0` |
| `/etc/security/limits.d/50-selfdef-coredump.conf` | all-off | `* hard core 0` + `root hard core 0` |

Header marker on both for uninstall ownership check.

## MITRE coverage

- **T1003** OS Credential Dumping — PRIMARY; a setuid
  binary's core dump is a direct in-memory credential
  dump.
- **T1552.001** Unsecured Credentials: Credentials In
  Files — the world-readable core file IS the
  credentials-in-a-file.
- **T1005** Data from Local System — core dumps expose
  arbitrary in-memory data.
- **T1212** Exploitation for Credential Access —
  triggering a setuid crash to harvest its memory is a
  known technique.

## Operator workflow

```bash
# Verify
sysctl fs.suid_dumpable             # expect 0
cat /etc/security/limits.d/50-selfdef-coredump.conf  # all-off only
ulimit -Hc                          # all-off: expect 0 (new login)

# Test: a setuid crash should NOT leave a core file
# (can't easily test without crashing sudo; trust the sysctl)

# Switch to all-off (no core dumps anywhere)
sudo sed -i 's/^profile.*/profile = "all-off"/' \
    /etc/selfdef/modules/coredump-suid-restrict.toml
sudo selfdefctl modules apply coredump-suid-restrict
# Log out + back in for the limits.d hard-core-0 to take effect.
```

## Caveats

- **Crash debugging** of setuid binaries is impossible
  with suid_dumpable=0 — that's the point. Developers
  debugging a setuid binary set it to 2 temporarily in
  a controlled environment.
- **all-off limits.d takes effect on NEXT login** —
  PAM evaluates limits.conf at session start. Existing
  sessions keep their old core limit until re-login.
- **systemd services** get their core limit from the
  unit's `LimitCORE=`, NOT from limits.conf. all-off's
  limits.d doesn't govern daemons — operator sets
  `DefaultLimitCORE=0` in `/etc/systemd/system.conf`
  for that (separate from this module).
- **Container hosts**: fs.suid_dumpable is namespaced
  per-container in recent kernels; the host setting is
  the default containers inherit.

## Coexistence

- **coredumpd-redirect**: complementary — coredumpd-
  redirect controls WHERE systemd-coredump writes
  (locked-down dir); this controls WHETHER setuid
  binaries dump at all. suid_dumpable=0 wins for
  setuid processes regardless of coredumpd config.
- **apport-disable**: complementary on Ubuntu —
  apport-disable removes the apport crash handler;
  this prevents the setuid memory from being dumped
  in the first place.
- **swap-encryption-detect + kdump-disable**:
  complementary data-at-rest leak defense (swap +
  kernel-crash-dump + core-dump are the three
  in-memory-to-disk leak channels).
- **kernel-yama-baseline**: complementary — yama
  blocks live ptrace memory-scrape; this blocks
  post-crash memory-dump. Both protect setuid binary
  secrets.
