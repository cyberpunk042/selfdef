# securetty-watchdog

Boot + daily delta of `/etc/securetty` (the TTYs on which
`pam_securetty` permits direct root login) against a learned
baseline, plus an ownership scan. Catches a widen of the root
direct-login surface. MITRE **T1556** (Modify Authentication
Process) / **T1078** (Valid Accounts).

## Why this matters

`pam_securetty.so` permits **direct root login** only on the TTYs
listed in `/etc/securetty`, which traditionally enumerates
physical consoles (`tty1`..`tty63`, `ttyS0`, `hvc0`, …). Two
attacker moves widen root login:

```
echo 'pts/0' >> /etc/securetty     # direct root login on a network pty
rm /etc/securetty                  # fail-open: historic pam_securetty
                                   #   permits root on ALL ttys when the
                                   #   file is absent
```

This is the console/PAM root-login gate — complementary to
`sshd-config`'s `PermitRootLogin` (the ssh gate).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any securetty change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No securetty (first scan, none) | `ok` | `no_securetty` |
| No delta | `ok` | `securetty_intact` |
| A TTY added / removed, or file changed | `warn` | `securetty_changed` |
| A NEWLY-ADDED pts/network TTY, or a world-writable/non-root file | `alert` | `securetty_widened` |
| The file was REMOVED since baseline (fail-open) | `alert` | `securetty_removed` |

`ttyS*` serial consoles are treated as benign (legit on many
hosts); `pts/*` and other pseudo-terminal/network ttys are the
high-signal widen.

## What's recorded

- `tty:<name>` — each permitted TTY.
- `file:<path>:<sha12>` — hash of /etc/securetty.
- `own:<path>:<owner:mode>` — owner + mode.

## Cadence

`OnBootSec=33min` + `OnCalendar=*-*-* 08:50:00` — extends the
staggered ladder after rhosts (08:45). A widen is live for the
next root login attempt, so the boot catch confirms the allowlist
after a restart.

## MITRE coverage

- **T1556** Modify Authentication Process — widening where root
  may authenticate directly.
- **T1078.003** Valid Accounts: Local Accounts — enabling direct
  root login on additional terminals.
- **T1562.001** Impair Defenses (adjacent) — removing securetty
  to fail-open root login.

## Operator workflow

```bash
journalctl -t selfdef-securetty -n 1 --no-pager
journalctl -t selfdef-securetty-detail --since "1 day ago"

# Current allowlist
grep -vE '^\s*#|^\s*$' /etc/securetty
# Is pam_securetty even active for login?
grep -rn pam_securetty /etc/pam.d/

# Investigate a widened/removed alert, then re-baseline:
sudo $EDITOR /etc/securetty       # remove the pts entry / restore the file
sudo rm /var/lib/selfdef/securetty-baseline.tsv
sudo systemctl start selfdef-securetty.service
```

## Caveats

- **Many modern distros ship a large default securetty** (tty1..63
  + serial); legit edits fire `warn` (re-baseline). The `pts`-add,
  ownership, and removal tiers are the high-confidence ones.
- **pam_securetty must be in the login PAM stack** for the file to
  matter; pam-config-watchdog covers whether it's wired.
- **Daily+boot cadence** misses a widen-login-revert within the
  window; an audit-rules watch on `/etc/securetty` writes is the
  real-time complement.

## Coexistence

- **sshd-config-watchdog**: `PermitRootLogin` (the ssh root gate);
  this is the console/PAM root gate. Both root-login surfaces.
- **access-conf-watchdog / login-defs-baseline**: the other
  PAM/login policy files; this adds the root-TTY allowlist.
- **pam-config-watchdog**: whether `pam_securetty` is wired; this
  watches the allowlist it enforces.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the file; this adds the per-TTY + widen semantic view.
