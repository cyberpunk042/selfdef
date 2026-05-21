# at-disable

Disables the `at(1)` scheduler entirely. Pairs with `cron-baseline`
(which restricts cron to root + named operators) for a complete
user-scheduling persistence lockdown.

## Why this matters

`at(1)` is the second-most-common Linux user-persistence primitive
after `crontab -e`. An attacker who lands an unprivileged shell can:

```bash
echo 'bash /tmp/payload.sh' | at now + 1 minute
```

This is:
- One-shot (single execution, no recurring schedule)
- Doesn't appear in `crontab -l`
- Often missed by operator audit scripts that only check cron
- Survives logout (no PTY needed)

Unlike `crontab`, `at(1)` doesn't honor `/etc/at.allow` by default
on every distro — older Debian + RHEL had bugs where empty at.allow
fell through to "everyone permitted". Disabling `atd.service`
entirely closes the vector at the system level.

## Profiles

| Profile | atd.service state | Operator-restart difficulty |
|---|---|---|
| `mask` (default) | stopped + disabled + **masked** | Requires explicit `systemctl unmask atd` first |
| `stop` | stopped + disabled (not masked) | `systemctl start atd` (one command) |

Masking is the strongest disable — systemd refuses to start the
unit until manually unmasked. Defends against:
- Package install pulling in atd dependency + auto-starting it
- Operator accidentally `systemctl enable atd` thinking it was
  the cron service

## What this does NOT block

- **System-level at(1) configured by root + queued** — these run
  via the kernel timer regardless of `atd` running. But: in
  practice atd is what processes the queue. With atd stopped,
  pending jobs sit in `/var/spool/at/` indefinitely.
- **systemd-timer** — orthogonal scheduling. selfdef's own
  detection modules (aide-bridge, rkhunter-cron, lynis-cron,
  clamav-cron, time-skew-watchdog) all use systemd-timer.
- **anacron** — runs cron-style. anacron has its own /etc/
  anacrontab; pair with `cron-baseline`-style restriction OR
  remove the `anacron` package.

## MITRE coverage

- **T1053.001** Scheduled Task/Job: at — direct prevention.
- **T1053.005** Scheduled Task/Job: Scheduled Task (Windows) —
  not applicable but parallel concept.

## Cross-distro support

- **Debian/Ubuntu**: `at` package installed in standard server
  + workstation profile.
- **RHEL/Fedora**: `at` package optional; many minimal installs
  skip it.
- **Arch / Alpine**: `at` package not in base.

The apply.sh runs `systemctl list-unit-files atd.service` to
detect whether the unit exists. If not, no-op + log line.

## Operator workflow

```bash
# Verify atd is disabled + masked
systemctl status atd
# Expected: "Loaded: masked (Reason: Unit atd.service is masked.)"

# Test that at(1) fails
echo 'whoami' | at now + 1 minute
# Expected: "Can't open /var/run/atd.pid to signal atd. No atd running?"

# To re-enable for an operator-pull legitimate use
sudo systemctl unmask atd
sudo systemctl enable --now atd
# (Then selfdefctl modules apply at-disable later to re-disable)
```

## Defense-in-depth combination

| Mechanism | Module | Coverage |
|---|---|---|
| Cron access restriction | `cron-baseline` | `crontab -e` blocked for non-listed users |
| at(1) disabled | `at-disable` | at(1) jobs cannot be queued |
| systemd-timer for operator | (selfdef default) | Scheduled selfdef detection modules use systemd-timer |
| User-persistence audit | `audit-rules` paranoid | execve watch catches workarounds |

Together: no user-scheduling persistence vector remains
operator-accessible at the OS layer. Operators wanting scheduled
jobs install a per-job systemd-timer + service unit pair (root-
owned + auditable).
