# sudoers-defaults-watchdog

Boot + daily delta of the sudoers `Defaults` directives
(`/etc/sudoers` + `/etc/sudoers.d/*`) against a learned baseline.
Catches a Defaults tunable an attacker abuses for privilege
escalation. MITRE **T1548.003** (Sudo and Sudo Caching) /
**T1574** (Hijack Execution Flow).

## Why this matters

`sudoers-integrity-watchdog` tracks the GRANT set and
deliberately excludes `Defaults`. But the Defaults tunables are a
privesc surface in their own right:

```
Defaults secure_path="/usr/bin:/tmp"    # sudo finds a trojan in /tmp
Defaults env_keep += "LD_PRELOAD"       # LD_PRELOAD into the root command
Defaults !env_reset                     # ALL caller env survives into sudo
```

Each lets an unprivileged but sudo-capable user escalate:
`secure_path` controls where sudo looks for the command binary
(a writable element = trojan), and `env_keep`/`!env_reset` leak
attacker-controlled environment (`LD_PRELOAD`, `BASH_ENV`, …)
into the root command. `sudo-tune` SETS hardened Defaults; this
DETECTS tampering.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any Defaults change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No sudoers | `ok` | `no_sudoers` |
| No delta | `ok` | `sudoers_defaults_intact` |
| Any Defaults parameter added / removed / changed | `warn` | `sudoers_defaults_changed` |
| A NEWLY-ADDED dangerous Default | `alert` | `sudoers_defaults_dangerous` |

Dangerous = `secure_path` with a writable/tmp/home/relative
element · `env_keep`/`env_check`/`env_delete` `+=` of a dangerous
var (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PYTHONPATH`,
`PERL5LIB`, `RUBYLIB`, `BASH_ENV`, `ENV`, `IFS`, `PS4`) ·
`!env_reset`. The alert is delta-based — a pre-existing dangerous
Default is flagged once at baseline for vetting, then not
re-alerted.

## What's recorded

- `default:<params>` — each normalized `Defaults` directive's
  parameters (the `Defaults[:user@host>runas!cmnd]` keyword
  stripped).
- `file:<path>:<sha12>` — hash of each sudoers file.

## Cadence

`OnBootSec=27min` + `OnCalendar=*-*-* 08:20:00` — extends the
staggered ladder after modules-load (08:15). A Defaults change
takes effect on the next sudo invocation, so the boot catch
confirms the set after a restart.

## MITRE coverage

- **T1548.003** Abuse Elevation Control Mechanism: Sudo and Sudo
  Caching — manipulating sudo's behaviour to escalate.
- **T1574.006/.007** Hijack Execution Flow — `secure_path` PATH
  hijack + `env_keep` `LD_PRELOAD` injection into the root
  command.

## Operator workflow

```bash
journalctl -t selfdef-sudoers-defaults -n 1 --no-pager
journalctl -t selfdef-sudoers-defaults-detail --since "1 day ago"

# Current Defaults
sudo grep -rhE '^\s*Defaults' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
# Effective env policy
sudo sudo -V | grep -iE 'env_reset|env_keep|secure_path' 2>/dev/null

# Investigate a dangerous alert, then re-baseline:
sudo visudo               # remove the writable secure_path / env_keep leak
sudo rm /var/lib/selfdef/sudoers-defaults-baseline.tsv
sudo systemctl start selfdef-sudoers-defaults.service
```

## Caveats

- **Legit env_keep entries exist** (e.g. `DISPLAY`, `EDITOR`); the
  alert tier targets only the curated dangerous-var set
  (LD_*/interpreter-path/IFS/etc.). Other Defaults changes are
  `warn` (surfaced for review).
- **secure_path mode check** dereferences symlinks (`stat -L`)
  and flags a writable directory element; a relative element on
  the PATH is always flagged.
- **Daily+boot cadence** misses a change-sudo-revert within the
  window; an audit-rules watch on `/etc/sudoers*` writes is the
  real-time complement.

## Coexistence

- **sudoers-integrity-watchdog**: tracks the GRANT set
  (user/group → ALL/NOPASSWD); this tracks the `Defaults`
  tunables it excludes. Together they cover the whole sudoers
  policy.
- **sudo-tune**: SETS hardened Defaults (I/O logging,
  timestamp_timeout); this DETECTS tampering with Defaults.
  Prevention + detection pair.
- **ld-preload-watchdog**: watches `LD_PRELOAD`/`LD_AUDIT` in
  env files; this watches the sudo `env_keep` that would let
  those survive into a root command. Complementary env-injection
  views.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the sudoers files; this adds the Defaults-semantic + dangerous-
  tunable view.
