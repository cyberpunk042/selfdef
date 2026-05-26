# audit-config-watchdog

Daily + boot delta of the Linux audit subsystem state —
loaded rule count (`auditctl -l`), the `enabled` flag
(`auditctl -s`), auditd service active-state, and the
`/etc/audit/` config + rules.d hashes. An attacker
disabling auditd or flushing its rules to blind the host
is MITRE **T1562.001 Impair Defenses**; this surfaces it.

## Why this matters

auditd is selfdef's own kernel-event source (the
collector-fabric consumes its events) AND a primary
forensic record. A capable attacker's early move is to
blind it:
- `auditctl -D` — flush ALL rules (kernel stops emitting).
- `auditctl -e 0` — disable auditing.
- `systemctl stop auditd` — kill the daemon.
- delete `/etc/audit/rules.d/*` so rules don't reload at
  next boot.

Each leaves the host's audit trail dark. This module
baselines the audit STATE + alerts when it degrades:
rule count collapses, the enabled flag flips off, auditd
goes inactive, or the config files change.

Note: `auditd-immutable` (a sibling module) sets the
audit config to mode 2 (locked until reboot) to PREVENT
runtime flushing. This module DETECTS the degradation
(including the reboot-then-no-rules path that immutable
mode can't stop). Prevention + detection pair.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on rule-count drop / auditd disabled / enabled-flag off → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| No delta | `ok` | `audit_intact` |
| Conf-file change OR rule count reduced (still >0) | `warn` | `audit_conf_changed` / `audit_rules_reduced` |
| Rules flushed to 0 (was >0) | `alert` | `audit_rules_flushed` |
| `enabled` flag turned off | `alert` | `audit_disabled_flag` |
| auditd service stopped (was active) | `alert` | `auditd_disabled` |

## What's recorded

`rules:<count>`, `enabled:<0|1|2>`, `auditd:<active|...>`,
`conf:<file>:<sha256-12>` for auditd.conf + audit.rules +
every rules.d file.

## Cadence

`OnBootSec=9min` + `OnUnitActiveSec=2h` + jitter —
disabling auditd is a fast pre-attack blinding move; boot
catch confirms the subsystem came up WITH its rules (an
attacker who deleted the persistent rules.d files shows at
next boot as rules=0).

## MITRE coverage

- **T1562.001** Impair Defenses: Disable or Modify Tools
  — PRIMARY; flushing/disabling auditd is the exact
  technique.
- **T1562** Impair Defenses — the class.
- **T1070** Indicator Removal — blinding the audit trail
  to prevent evidence collection.
- **T1489** Service Stop — stopping auditd.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-audit-config -n 1 --no-pager

# Manual state
sudo auditctl -s         # enabled flag + backlog
sudo auditctl -l | wc -l # loaded rule count
systemctl is-active auditd

# Investigate an alert
# - Did rules drop to 0? Reload them:
sudo augenrules --load     # or: auditctl -R /etc/audit/audit.rules
# - Did auditd stop? Restart + investigate WHO stopped it:
sudo systemctl start auditd
sudo journalctl -u auditd --since "2 hours ago"

# Re-baseline after a legitimate rule change
sudo rm /var/lib/selfdef/audit-config-baseline.tsv
sudo systemctl start selfdef-audit-config.service
```

## Caveats

- **auditctl needs root** — the systemd unit runs as root;
  on hosts without auditd installed, rule_count=0 +
  auditd=inactive is the steady state (no false alert
  after the first baseline captures it).
- **Legitimate rule changes** (operator runs augenrules
  after editing rules.d) reduce/increase the count →
  re-baseline. The module updates its state each run so a
  one-time legit change doesn't re-alert forever (it
  alerts once, then the new state is the baseline).
- **2h cadence** misses a flush-then-reload within the
  window; auditd's OWN logs + the kernel audit=1 boot
  param are complementary. For real-time, audit-rules can
  include a watch on /sbin/auditctl execution.
- **immutable mode (auditd-immutable)** prevents the
  runtime flush entirely (mode 2) — pair the two: prevent
  + detect.

## Coexistence

- **audit-rules + auditd-tune + auditd-immutable**: this
  module WATCHES the subsystem those CONFIGURE. auditd-
  immutable prevents runtime tampering; this detects
  degradation (incl. the post-reboot no-rules path).
- **logfile-integrity-watchdog**: complementary — that
  watches the audit LOG for truncation; this watches the
  audit CONFIG/STATE for disablement. Together: the trail
  can't be silenced OR erased without an alert.
- **pam-config / sudoers / ssh-authkeys / systemd-unit
  watchdogs**: sibling defense-tampering + persistence
  detectors. An attacker who disables auditd usually does
  it BEFORE the persistence step those modules catch — so
  audit-config firing is an early-warning.
