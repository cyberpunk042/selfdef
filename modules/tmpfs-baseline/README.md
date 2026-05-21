# tmpfs-baseline

`/tmp` + `/var/tmp` hardening via systemd-mount drop-ins. Adds
`noexec,nosuid,nodev` to both world-writable temp dirs.

## Why this matters

`/tmp` is the most-common attacker-writable directory on a Linux
host. Default mount options allow:
- `exec` → attacker drops a shell script + runs it directly
- `suid` → attacker stages a SUID binary for privesc
- `dev` → attacker creates `/tmp/mydev` device node to bypass
  filesystem permissions

The selfdef baseline closes all three:

| Mount option | Blocks |
|---|---|
| `noexec` | `exec()` on any `/tmp` file → `EACCES` |
| `nosuid` | SUID bit ignored on `/tmp` files |
| `nodev` | device nodes on `/tmp` ignored |

## Profiles

| Profile | Backing | Size cap | Notes |
|---|---|---|---|
| `noexec` (default) | OS default (usually disk) | unbounded | Safe for hosts with large /tmp use (builds, video) |
| `tmpfs` | RAM | 25% of RAM | Ephemeral across reboot. Requires `acknowledge_tmpfs=true` refuse-to-brick gate |

## MITRE coverage

- **T1059** Command and Scripting Interpreter — noexec blocks
  direct script execution from `/tmp`. Attacker must explicitly
  pipe through `bash -c "$(cat /tmp/payload.sh)"` — caught by
  audit-rules paranoid profile's universal exec audit + the
  selfdef-collector-auditd SYSCALL+EXECVE pair (SDD-059 C-5)
  surfaces the args.
- **T1564.001** Hide Artifacts: Hidden Files and Directories —
  the audit-rules base profile watches /tmp's write surface.
- **T1546** Event Triggered Execution — SUID binaries in /tmp
  no longer elevate (nosuid).
- **T1027.002** Software Packing — packed payloads dropped in
  /tmp can't directly execute.

## Caveats

- **Live mount options take effect after reboot OR manual
  remount.** apply.sh CAN run `systemctl restart tmp.mount` but
  that breaks any process holding an fd open in /tmp.
  Conservative default: log a NOTICE recommending reboot.
- **Some installers use /tmp for exec'd build steps.** Affected:
  some shell-based installers (older Oracle DB installers,
  hand-rolled vendor scripts). Operator runs the installer with
  `TMPDIR=/var/lib/operator-tmp` workaround.
- **systemd-tmpfiles + tmpfs profile**: re-mounting /tmp as tmpfs
  loses any operator-installed long-lived state in /tmp. By
  default /tmp is ephemeral so this is usually fine, but the
  acknowledge_tmpfs flag forces explicit operator confirmation.

## Coexistence

- **audit-rules**: paranoid profile's universal exec watch fires
  on `bash -c <payload>` workaround attempts.
- **kernel-lockdown**: `fs.suid_dumpable=0` already prevents SUID
  coredumps; nosuid on /tmp prevents SUID binaries from running
  there in the first place.

## Operator workflow

```bash
# Verify live mount options
findmnt /tmp /var/tmp -o TARGET,OPTIONS

# Apply now without reboot (CAREFUL: kills processes with open
# fds in /tmp)
sudo systemctl restart tmp.mount var-tmp.mount

# Verify post-remount
findmnt /tmp /var/tmp -o TARGET,OPTIONS

# Operator extension: increase tmpfs size cap from 25% RAM to 50%
sudo mkdir -p /etc/systemd/system/tmp.mount.d
cat | sudo tee /etc/systemd/system/tmp.mount.d/60-operator-size.conf <<EOF
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%
EOF
sudo systemctl daemon-reload + reboot
```

## When to use tmpfs profile

Indicators for the tmpfs profile (over noexec default):
- High-volume /tmp churn (CI builds, video transcoding) where
  disk I/O is a bottleneck → tmpfs avoids the disk roundtrip
- Forensic isolation requirement: /tmp content must NOT survive
  reboot
- The host has ample RAM (24GB+) so 25% (6GB) is comfortable

Indicators AGAINST tmpfs:
- /tmp used for large build artifacts (Chromium build = ~30GB
  in /tmp = will OOM on a 16GB-RAM host with the 25% cap)
- Long-running database temp files
- Operator workflows that touch a /tmp file expecting it to
  survive a graceful reboot
