# acct-baseline

Enables GNU process accounting (psacct/acct package) — every
process exit records PID + UID + comm + CPU + wall-clock + exit-
code in `/var/account/pacct`. Complementary to auditd's syscall-
level events: acct is **post-mortem ground-truth** for "which
processes ran on this host" without depending on log-tampering-
prone application logs.

## Why this matters

auditd events are syscall-level + can be VERY high-volume.
Process accounting is per-exit (much lower volume, ~thousands of
records/day on a workstation vs millions of auditd events) +
records ARE STILL THERE EVEN IF auditd was disabled by the
attacker. The two layers together give:

| Layer | Volume | Granularity | Tamper-resistance |
|---|---|---|---|
| `audit-rules` (paranoid) | millions/day | every execve syscall + args | auditd disable = blind |
| `acct-baseline` | thousands/day | per-process exit summary | accton off = blind, BUT acct.service status visible |
| Both together | — | best-of-both | mutual cross-corroboration |

`lastcomm -f /var/account/pacct` shows every process that exited
in the file's window, regardless of whether the application
logged anything. Forensic-grade.

## Profiles

| Profile | accton state | Use |
|---|---|---|
| `enabled` (default) | on, /var/account/pacct active | Always-on detection baseline |
| `disabled` | off | Operator-pull suspend (preserves existing pacct files for forensics; just stops appending) |

## Files installed

| Path | Purpose |
|---|---|
| `/var/account/pacct` | The accounting file (binary format; read with lastcomm or sa) |
| `/etc/logrotate.d/selfdef-acct` | Daily rotation + 30-day retention; postrotate cycles accton |

## MITRE coverage

- **T1059** Command and Scripting Interpreter — every exec'd
  process (shell, interpreter, binary) leaves a pacct record.
- **T1070** Indicator Removal — pacct file is binary +
  append-only (no in-place edit); attacker who shells in CAN
  delete the file but cannot subtly modify entries.
- **T1078** Valid Accounts — the UID field surfaces which user
  ran what.
- **T1057** Process Discovery — `sa` (summary) + `lastcomm` give
  the operator the same ground-truth view the attacker uses
  via ps/top, but historical.

## Operator workflow

```bash
# Per-process list (newest first)
sudo lastcomm | head -20

# Filter by user
sudo lastcomm --user operator | head -20

# Filter by command
sudo lastcomm --command bash | head -20

# Summary: aggregated CPU + per-command counts
sudo sa | head -20

# Per-user summary
sudo sa -u | head -20

# Inspect a specific rotated file (logrotate keeps 30 days
# compressed at pacct.1.gz, pacct.2.gz, ...)
sudo zcat /var/account/pacct.5.gz | lastcomm -f - | head -20
```

## Disk cost

A typical workstation: ~50 MB/day → 1.5 GB at 30 days. Server:
proportional to fork rate. Operator who needs longer retention
edits the logrotate drop-in (rotate 90 for 3 months).

## Caveats

- **Forks without exec are NOT recorded** until the child exits
  → bash subshell that just runs builtins won't show up as a
  child command (only the parent shell's eventual exit will).
- **Daemon long-runners** don't appear until exit. acct is
  POST-MORTEM; for current-state ps/top is operator's tool.
- **Doesn't capture command arguments** — only the comm field
  (executable basename). For full argv, pair with audit-rules
  paranoid's universal exec watch (SDD-059 C-5 SYSCALL+EXECVE
  pair).
- **Different distros use different package names** — Debian
  ships `acct`, RHEL ships `psacct`. The systemctl service-name
  also varies (acct.service vs psacct.service). apply.sh tries
  both.

## Coexistence with the detection stack

- **audit-rules + auditd-tune + journal-tune**: syscall + auditd
  + journald layers.
- **acct-baseline**: per-exit forensic layer (low-volume +
  high-resilience to event-log tampering).
- **selfdef-collector-auditd**: the SYSCALL+EXECVE pair (SDD-
  059 C-5) captures argv at exec time → richer than acct's
  exec-name-only but higher volume.

Operator picks based on disk budget + threat model. Both can
coexist; ALL of acct + auditd + Tetragon emit independent
event streams the correlator can cross-reference.
