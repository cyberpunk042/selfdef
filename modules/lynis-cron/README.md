# lynis-cron

systemd-timer-driven weekly [Lynis](https://cisofy.com/lynis/)
security audit. Emits a structured JSON event tagged
`selfdef-lynis` per run with the hardening index + warning /
suggestion counts.

## How it differs from aide-bridge + rkhunter-cron

| Module | What it checks | Cadence | Output |
|---|---|---|---|
| `aide-bridge` | File diff vs operator-built baseline | Daily 03:30 | per-file change list |
| `rkhunter-cron` | Known-rootkit signature DB match | Daily 04:30 | per-warning lines |
| `lynis-cron` | CIS-style **compliance + hardening** posture | Weekly Sun 05:30 | hardening-index score (0-100) + categorized warnings + suggestions |

Lynis surfaces the broader **compliance & posture** questions:
- Is SSH PermitRootLogin disabled?
- Is the firewall actually running?
- Are world-writable files limited?
- Is the kernel hardened (matches ~50 sysctl checks similar to
  `kernel-lockdown`)?
- Are unattended-upgrades enabled?
- Is the audit framework running?

Many of selfdef's hardening modules (kernel-lockdown,
audit-rules, ssh-wrap, agent-guard) align with specific Lynis
checks — the audit confirms they're actually applied + flags
the gaps.

## Profiles

| Profile | Args | Runtime |
|---|---|---|
| `quick` (default) | `audit system --quick --cronjob` | ~3-5 min |
| `full` | `audit system --cronjob` | ~10-30 min (plugins enabled) |

The `--cronjob` flag suppresses interactive prompts + colourized
output for clean log capture.

## Event severity ladder

| Severity | Hardening index | Operator action |
|---|---|---|
| `ok` | ≥ 80 | Tune individual suggestions at leisure |
| `warn` | 60-79 | Worth reviewing this week's findings |
| `alert` | < 60 | Significant gaps — investigate immediately |
| `high` | report file missing | Lynis itself failed |

## Event schema

```json
{
  "tag": "selfdef-lynis",
  "severity": "warn",
  "event": "hardening_moderate",
  "profile": "quick",
  "lynis_rc": 0,
  "hardening_index": 72,
  "warnings": 4,
  "suggestions": 28,
  "sample": "AUTH-9229|FILE-7524|HRDN-7222|KRNL-5820|..."
}
```

`/var/log/lynis-report.dat` carries the full structured report
(operator parses with `awk -F= '/^suggestion\[\]/ {print $2}'`
or similar). selfdef-collector-journald ingests the
`selfdef-lynis` summary tag; full report stays on disk for
operator inspection.

## Why weekly cadence?

Daily would generate notifier-fatigue: hardening index +
suggestions don't change meaningfully day-to-day on a stable
host. Lynis's value is the cumulative score + the categorized
suggestion list, both of which need a longer review interval.

The Sunday-morning schedule gives operators a fresh report by
Monday — actionable in the work week.

## Operator workflow

```bash
# Inspect last audit's findings
sudo cat /var/log/lynis-report.dat | grep '^suggestion'

# Apply Lynis-recommended changes one at a time
sudo lynis show details <TEST-ID>  # e.g. lynis show details AUTH-9229

# Re-audit after fix to confirm closure
sudo systemctl start selfdef-lynis-audit.service
sudo journalctl -t selfdef-lynis -n 1
```

## Always-exit-0 policy

Unlike aide-bridge / rkhunter-cron's `enforce` profile, Lynis
findings are ALWAYS advisory. There is no `enforce` profile
because:
- a hardening index of 78 is fine for many operator workflows;
  failing the unit on every score < 80 is operator-fatigue
- suggestions are tunable per-host (e.g. "disable IPv6" is
  wrong for IPv6-mandatory operator environments)

Operators who want hard-fail behavior set their notifier-engine
rules on the `selfdef-lynis` events with `severity in (alert,
high)` and route to PagerDuty / ntfy / etc.
