# dnf-plugins-watchdog

Boot + daily delta of the dnf plugin config +
post-transaction-actions (`/etc/dnf/plugins/*.conf` +
`/etc/dnf/plugins/post-transaction-actions.d/*.action`) against a
learned baseline, plus an ownership + command scan. Catches an
action dnf runs as root on a package transaction. MITRE **T1546**
(Event Triggered Execution).

## Why this matters

The dnf `post-transaction-actions` plugin runs a command **as
root** after a matching package transaction — the RPM-side
equivalent of apt's `DPkg::Post-Invoke`. Action files use:

```
<package-glob>:<transaction-state>:<command>
*:in:/tmp/.payload                  # root, on the next dnf install
```

A rogue `.action` is root-exec persistence triggered by any
package change. It hides in package-manager plugin config.
Distinct from `dnf-automatic-config` (auto-update policy).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any dnf-plugins change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No dnf plugins/actions | `ok` | `no_dnf_plugins` |
| No delta | `ok` | `dnf_plugins_intact` |
| A file / action added, removed, or changed | `warn` | `dnf_plugins_changed` |
| An action command under /tmp /home /dev/shm, world-writable, or bare/relative; an injection pattern; or a world-writable/non-root file | `alert` | `dnf_plugins_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each plugin `.conf` + `.action`
  file.
- `own:<path>:<owner:mode>` — owner + mode.
- `action:<file>:<cmd0>` — each post-transaction-action command
  (first token of the 3rd colon field).

## Cadence

`OnBootSec=42min` + `OnCalendar=*-*-* 09:35:00` — extends the
staggered ladder after rsyslog-exec (09:30). A rogue action runs
on the next dnf transaction, so the boot catch confirms the set
after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a package transaction is
  the trigger that runs the action as root.
- **T1059.004** — the action command is shell execution.
- **T1195.002** (adjacent) — package-manager subversion.

## Operator workflow

```bash
journalctl -t selfdef-dnf-plugins -n 1 --no-pager
journalctl -t selfdef-dnf-plugins-detail --since "1 day ago"

# Inventory
ls -la /etc/dnf/plugins/ /etc/dnf/plugins/post-transaction-actions.d/ 2>/dev/null
grep -rvE '^\s*#|^\s*$' /etc/dnf/plugins/post-transaction-actions.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo rm /etc/dnf/plugins/post-transaction-actions.d/<file>.action
sudo rm /var/lib/selfdef/dnf-plugins-baseline.tsv
sudo systemctl start selfdef-dnf-plugins.service
```

## Caveats

- **Legit actions exist** (e.g. `dnf-plugin-post-transaction-actions`
  shipping a `systemd-tmpfiles` or `ldconfig` action); a new one
  fires `warn`, and the tmp/relative-command + injection +
  ownership tiers are the high-confidence alert. Re-baseline a
  vetted action.
- **apt-based distros** → `no_dnf_plugins` no-op; apt-hooks-watchdog
  covers the apt side.
- **Daily+boot cadence** misses an inject-dnf-revert within the
  window; an audit-rules watch on `/etc/dnf/plugins` writes is the
  real-time complement.

## Coexistence

- **apt-hooks-watchdog**: the apt-side equivalent (DPkg/APT::Update
  invoke hooks); this is the dnf/RPM-side post-transaction-actions
  surface. Both package-manager exec surfaces.
- **dnf-automatic-config**: dnf auto-update policy; this watches the
  dnf plugin exec actions. Complementary dnf-subsystem views.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  dnf plugin files; this adds the action-command semantic view.
