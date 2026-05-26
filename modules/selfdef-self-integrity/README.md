# selfdef-self-integrity

The meta-watchdog — **who watches the watchers**. Hashes
selfdef's own trust root (the delta-watchdog baselines +
the wrapper scripts that produce them + the per-module
configs) and alerts on tampering. The 100th module, and
the one that closes the recursion: every other detection
module trusts its baseline; this one makes that trust
verifiable.

## Why this matters

selfdef ships a family of baseline+delta watchdogs —
`account-watchdog`, `cron-job-watchdog`,
`suid-sgid-watchdog`, `file-capabilities-watchdog`,
`listening-ports-watchdog`, `kernel-module-watchdog`,
`dns-resolver-watchdog`, `ssh-authkeys-watchdog`,
`sudoers-integrity-watchdog`, `systemd-unit-watchdog`,
`pam-config-watchdog`, `logfile-integrity-watchdog`,
`audit-config-watchdog`. Each stores a known-good baseline
in `/var/lib/selfdef/*-baseline.tsv` and alerts on
deviation.

That creates a single point an advanced attacker can
attack: **the baselines themselves**. If they:
- append their backdoor's signature to
  `ssh-authkeys-baseline.tsv` → ssh-authkeys-watchdog
  sees "no delta" and stays silent;
- edit `suid-sgid-baseline.tsv` to include their setuid
  binary → suid-sgid-watchdog goes quiet;
- patch a wrapper `*.sh` to skip their indicator → the
  detector lies;
- flip a module config from `enforce` to `report` → alerts
  stop failing the unit.

This module hashes all three artifact classes and surfaces
any change — so tampering with the detection stack is
itself detected. Defense-in-depth's final layer.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 on any trust-root change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `manifest_initial` |
| No change | `ok` | `trust_root_intact` |
| A module config `.toml` changed (maybe a legit profile switch) | `warn` | `config_changed` |
| A baseline `.tsv` or wrapper `.sh` changed/added/removed | `alert` | `trust_root_tampered` |

## Tracked trust-root artifacts

| Class | Path glob | Why it matters |
|---|---|---|
| `baseline` | `/var/lib/selfdef/*.tsv` | the known-good state every delta-watchdog compares against |
| `wrapper` | `/usr/local/libexec/selfdef/*.sh` | the detector scripts (a patched detector lies) |
| `config` | `/etc/selfdef/modules/*.toml` | per-module profile (enforce→report silences alerts) |

(The module excludes its OWN manifest + its OWN wrapper
script from the set to avoid self-reference churn.)

## Cadence

`OnBootSec=11min` + `OnUnitActiveSec=90min` + jitter — the
meta-watchdog runs MORE often (90 min) than most of the
delta-watchdogs it guards, so a tamper-then-act sequence is
caught in the window between the baseline edit and the next
watchdog run.

## MITRE coverage

- **T1562.001** Impair Defenses: Disable or Modify Tools —
  PRIMARY; editing the detection baselines/scripts IS
  modifying the security tooling.
- **T1565.001** Stored Data Manipulation — tampering with
  the stored baselines.
- **T1070** Indicator Removal — making the watchdogs blind
  is a form of indicator removal.
- **T1554** Compromise Host Software Binary — patching a
  wrapper script.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-self-integrity -n 1 --no-pager

# What changed
journalctl -t selfdef-self-integrity-detail --since "1 day ago"

# An ALERT (trust_root_tampered) is serious — investigate:
# - Did a baseline change WITHOUT an operator re-baseline?
ls -la /var/lib/selfdef/*.tsv
sudo stat /var/lib/selfdef/ssh-authkeys-baseline.tsv   # mtime?
# - Was a wrapper patched?
sudo sha256sum /usr/local/libexec/selfdef/*.sh
# Compare against a known-good copy from the repo / package.

# Legit changes (operator re-baselined a watchdog, switched
# a profile) fire once then become the new trusted manifest.
```

## Caveats

- **Legit re-baselines fire once**: when the operator
  intentionally re-baselines a watchdog (e.g. after
  installing a package that adds a setuid binary), the
  baseline `.tsv` changes → this fires `trust_root_tampered`
  ONE time, then absorbs the new state as trusted. The
  operator correlates: "I just re-baselined suid-sgid, so
  this alert is expected." An UNEXPLAINED alert is the real
  signal.
- **The manifest itself is a target** — stored 0600. For
  true tamper-evidence, the durable answer is OFF-HOST: the
  notifier engine ships these events to Loki/OpenSearch, so
  even an attacker who edits the local manifest can't unsend
  the alert that already fired. Pair with `auditd` watching
  `/var/lib/selfdef`.
- **Not a substitute for the watchdogs** — it guards their
  integrity; the watchdogs do the actual detection. Run the
  whole family.
- **90-min cadence** — a very fast attacker who tampers +
  acts + restores within 90 min could slip; tetragon
  watching `/var/lib/selfdef` writes is the real-time
  complement.

## Coexistence

- **All delta-watchdogs** (account/cron/suid/file-caps/
  listeners/kernel-modules/dns/ssh-authkeys/sudoers/
  systemd-units/pam/logfile/audit-config): this module is
  their guardian — it protects the baselines they depend on.
- **audit-config-watchdog**: complementary — that guards
  the KERNEL audit subsystem; this guards SELFDEF's own
  detection state. Together they cover "don't let the
  attacker blind either the OS audit OR selfdef."
- **integrity-sentinel + aide-bridge**: general file
  integrity; this is the selfdef-trust-root-specific,
  semantically-aware version (knows which files are
  baselines vs wrappers vs configs + severity-classes
  accordingly).
- **notifier engine (Loki/OpenSearch/etc.)**: the durable
  off-host shipping that makes a fired alert un-erasable —
  the true backstop for the "manifest is also a target"
  caveat.
