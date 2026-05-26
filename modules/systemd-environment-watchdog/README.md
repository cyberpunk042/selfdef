# systemd-environment-watchdog

Boot + daily delta of the systemd manager environment config against
a learned baseline, plus an ownership + env-injection scan. Catches
a `DefaultEnvironment` that injects `LD_PRELOAD` (or other library
hijack) into every service. MITRE **T1574.006**.

## Why this matters

In `/etc/systemd/system.conf` (+ `system.conf.d/*.conf`) and the
user-manager `/etc/systemd/user.conf[.d]`:

- `DefaultEnvironment=KEY=VAL …` sets environment variables for
  **every service the systemd manager spawns**.
- `ManagerEnvironment=KEY=VAL …` sets them for the manager (PID 1)
  itself.

A planted:

```
DefaultEnvironment=LD_PRELOAD=/tmp/evil.so
```

(or `LD_AUDIT` / `LD_LIBRARY_PATH` pointing at a writable dir)
injects attacker code into the address space of **every service on
the host** — a near-total, persistent code-execution foothold. There
is essentially no legitimate reason for a global `LD_PRELOAD` in the
manager environment, so its presence is high-signal.

This is distinct from **ld-preload-watchdog** (`/etc/ld.so.preload` +
shell/PAM env files); this is the **systemd-manager env** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any systemd env-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No override present | `ok` | `no_systemd_env` |
| No delta | `ok` | `systemd_env_intact` |
| A config / env pair added / changed / removed | `warn` | `systemd_env_changed` |
| A config world-writable/non-root, OR a `DefaultEnvironment`/`ManagerEnvironment` setting `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`, OR an env value path under `/tmp` `/var/tmp` `/dev/shm` `/home` | `alert` | `systemd_env_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `env:<path>:<directive>:<pair>` — each `KEY=VAL` env pair.

## Cadence

`OnBootSec=79min` + `OnCalendar=*-*-* 12:50:00` — extends the
staggered ladder after aliases (12:45). A planted
`DefaultEnvironment` `LD_PRELOAD` takes effect for every service
started after the next daemon-reload/reboot, so the daily catch
bounds dwell time; the boot catch confirms the manager-env config
after a restart.

## MITRE coverage

- **T1574.006** Hijack Execution Flow: Dynamic Linker Hijacking —
  `LD_PRELOAD`/`LD_AUDIT` in the manager env preloads attacker code
  into every service.
- **T1547** Boot or Logon Autostart Execution — the manager applies
  the env at boot.

## Operator workflow

```bash
journalctl -t selfdef-systemd-env -n 1 --no-pager
journalctl -t selfdef-systemd-env-detail --since "1 day ago"

# Inventory
grep -rinE '^\s*(Default|Manager)Environment\s*=' \
     /etc/systemd/system.conf /etc/systemd/system.conf.d/ \
     /etc/systemd/user.conf /etc/systemd/user.conf.d/ 2>/dev/null
systemctl show-environment 2>/dev/null   # live manager environment

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/systemd/system.conf.d/<file>.conf
sudo rm /var/lib/selfdef/systemd-environment-baseline.tsv
sudo systemctl start selfdef-systemd-env.service
```

## Caveats

- **`DefaultEnvironment` is rarely set at all** (the default is
  empty) → `no_systemd_env` no-op or a tiny baseline. Any
  appearance is worth a `warn` review; an `LD_*` injection or a
  writable-path value is the high-confidence alert.
- **Legit `DefaultEnvironment`** (e.g. setting a proxy or locale) is
  benign and fires only `warn`; the `LD_*`/writable tiers are the
  alert.
- **Per-unit `Environment=`/`EnvironmentFile=`** in individual
  service units is a separate surface (systemd-unit-watchdog
  territory); this watches the *manager-wide* default.
- **Daily+boot cadence** misses a set-reload-revert inside the
  window; an audit-rules watch on `/etc/systemd/*.conf*` writes is
  the real-time complement.

## Coexistence

- **ld-preload-watchdog / ld-so-conf-watchdog / musl-ld-path-watchdog**:
  the other dynamic-linker hijack surfaces (preload file, glibc/musl
  search paths); this is the systemd-manager env-injection path.
- **systemd-unit-watchdog / systemd-generator-watchdog**: unit files
  and generators; this is the manager-wide default environment.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  configs; this adds the env-pair / LD-injection semantic view.
