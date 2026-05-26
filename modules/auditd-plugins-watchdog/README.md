# auditd-plugins-watchdog

Boot + daily delta of the auditd dispatcher-plugin configs against a
learned baseline, plus an ownership + plugin-path scan. Catches a
plugin auditd runs as root over the live audit event stream. MITRE
**T1546** / **T1562.001**.

## Why this matters

`auditd` launches each **active** plugin's `path =` program **as
root** and feeds it the live audit event stream:

- `/etc/audit/plugins.d/*.conf` — current
- `/etc/audisp/plugins.d/*.conf` — legacy `audisp`

```
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
```

A planted plugin (`active = yes`, `path = /tmp/evil`) is **root-exec
persistence driven by audit activity** — and, uniquely, it sits
**inside the audit pipeline**, where a malicious dispatcher can also
suppress or tamper with the very events that would reveal it (impair
defenses). That dual role makes it a high-value foothold.

This is distinct from **audit-config-watchdog** (which watches
`auditd.conf` + `audit.rules` content); this is the audit
**dispatcher-plugin exec** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any auditd plugin change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No auditd plugins present | `ok` | `no_audit_plugins` |
| No delta | `ok` | `audit_plugins_intact` |
| A plugin / key added / changed / removed | `warn` | `audit_plugins_changed` |
| A `.conf` world-writable/non-root, OR a plugin `path` under `/tmp` `/var/tmp` `/dev/shm` `/home` or relative-with-slash | `alert` | `audit_plugins_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `path:<path>:<prog>` — the plugin `path =` program.
- `active:<path>:<value>` — the plugin `active =` flag.

## Cadence

`OnBootSec=83min` + `OnCalendar=*-*-* 13:30:00` — extends the
staggered ladder after incron (13:20). A planted active plugin runs
as root as soon as auditd is (re)started, so the daily catch bounds
dwell time; the boot catch confirms the plugin set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — audit events drive the
  plugin program.
- **T1562.001** Impair Defenses: Disable or Modify Tools — a
  malicious dispatcher can drop/alter audit events in-pipeline.

## Operator workflow

```bash
journalctl -t selfdef-audit-plugins -n 1 --no-pager
journalctl -t selfdef-audit-plugins-detail --since "1 day ago"

# Inventory
grep -inE '^\s*(active|path)\s*=' \
     /etc/audit/plugins.d/*.conf /etc/audisp/plugins.d/*.conf 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/audit/plugins.d/<file>.conf
sudo rm /var/lib/selfdef/auditd-plugins-baseline.tsv
sudo systemctl start selfdef-audit-plugins.service
```

## Caveats

- **Distro plugins ship legitimate configs** (`af_unix`, `syslog`,
  `au-remote`/`audisp-remote`) with standard absolute `path`s under
  `/sbin` or `/usr/sbin`; these are not flagged. A new plugin still
  fires `warn` (re-baseline). The writable/relative-path / writable /
  non-root tiers are the high-confidence alert.
- **An inactive (`active = no`) plugin with a writable path is still
  flagged** — it is one config edit away from running.
- **Daily+boot cadence** misses a drop-restart-revert inside the
  window; an audit-rules watch on the plugins.d dirs' writes is the
  real-time complement (note the recursion: protect the auditd
  config that protects everything else).

## Coexistence

- **audit-config-watchdog**: auditd.conf + audit.rules; this is the
  dispatcher-plugin exec surface — together they cover the audit
  subsystem's integrity.
- **rsyslog-exec / syslog-ng-exec watchdogs**: log-pipeline exec via
  the syslog daemons; this is the audit-pipeline equivalent.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  plugin `.conf` files; this adds the path/active semantic view.
