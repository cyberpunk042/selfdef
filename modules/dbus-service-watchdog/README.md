# dbus-service-watchdog

Boot + daily delta of the admin/local D-Bus system activation
services + policy files against a learned baseline, plus an
ownership + Exec/User + policy scan. Catches a service that runs
as root on a D-Bus call and a permissive bus-name policy. MITRE
**T1543** / **T1548**.

## Why this matters

A D-Bus-activated **system** service is described by a `.service`
file with an `Exec=` and a `User=`; when any client first calls
the service's bus name, `dbus-daemon` launches `Exec=` **as the
User=** (often root). A rogue activation file is root-exec-on-
demand persistence:

```ini
# /usr/local/share/dbus-1/system-services/org.evil.service
[D-BUS Service]
Name=org.evil
Exec=/usr/local/sbin/evil
User=root
```

A permissive **policy** (`/etc/dbus-1/system.d/*.conf`) that
allows a process to OWN a privileged bus name lets an attacker
impersonate a system service:

```xml
<policy context="default">
  <allow own="org.freedesktop.systemd1"/>   <!-- name hijack -->
</policy>
```

## Watched directories

| Directory | Watched | Why |
|---|---|---|
| `/usr/local/share/dbus-1/system-services/*.service` | **yes** | local activation |
| `/etc/dbus-1/system-services/*.service` | **yes** | admin activation |
| `/etc/dbus-1/system.d/*.conf` | **yes** | admin policy |
| `/usr/local/share/dbus-1/system.d/*.conf` | **yes** | local policy |
| `/usr/share/dbus-1/*` | **no** | package-managed; integrity-sentinel covers it |

No-ops cleanly if none exist (`event:no_dbus_dirs`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any dbus-service change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No D-Bus dirs present | `ok` | `no_dbus_dirs` |
| No delta | `ok` | `dbus_service_intact` |
| A file changed or removed | `warn` | `dbus_service_changed` |
| A NEW activation `.service` (new PATH) or a NEW `<allow own=>` policy | `alert` | `dbus_service_new` |
| A file world-writable / non-root, or an `Exec=` under /tmp /home /dev/shm / world-writable | `alert` | `dbus_service_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.service`/`.conf`.
- `own:<path>:<owner:mode>` — owner + mode.
- `exec:<svc>:<user>:<cmd0>` — the activation `Exec=` program +
  `User=` (defaults to root). An Exec under tmp/home/world-
  writable is the payload signature.
- `ownallow:<conf>:<name>` — each policy `<allow own="name">`
  bus name; a NEW one is alert-grade (potential name hijack).

## Cadence

`OnBootSec=25min` + `OnCalendar=*-*-* 08:10:00` — extends the
staggered ladder after motd-scripts (08:05). An activation
service launches on the next bus-name call, so the boot catch
confirms the set after a restart.

## MITRE coverage

- **T1543** Create or Modify System Process — a D-Bus
  activation service is a system process launched by
  dbus-daemon.
- **T1548** Abuse Elevation Control Mechanism — `User=root`
  activation + permissive own-policy are elevation paths.
- **T1059.004** — the `Exec=` is command execution.

## Operator workflow

```bash
journalctl -t selfdef-dbus-service -n 1 --no-pager
journalctl -t selfdef-dbus-service-detail --since "1 day ago"

# Inventory
ls -la /usr/local/share/dbus-1/system-services/ \
       /etc/dbus-1/system-services/ /etc/dbus-1/system.d/ 2>/dev/null
grep -rnE 'Exec=|User=' /usr/local/share/dbus-1/system-services/ 2>/dev/null
grep -rnE '<allow[^>]*own=' /etc/dbus-1/system.d/ 2>/dev/null

# Investigate a new/suspicious service
cat <svc>             # Exec under tmp/home? User=root + unknown name?
sudo rm <svc>
sudo rm /var/lib/selfdef/dbus-service-baseline.tsv
sudo systemctl start selfdef-dbus-service.service
```

## Caveats

- **Legit local D-Bus services** (custom integrations) fire
  `alert` (new) once; re-baseline after vetting. The Exec-path
  and ownership sub-signatures are the high-confidence ones.
- **Policy XML is grepped, not fully parsed** — the module
  records `<allow own=>` names + hashes the file; a permissive
  send/receive rule that does not grant `own` is surfaced via
  the file-hash `warn` (review) rather than a dedicated alert.
- **Daily+boot cadence** misses an inject-call-revert within the
  window; an audit-rules watch on the D-Bus dirs' writes is the
  real-time complement.

## Coexistence

- **systemd-unit-watchdog / systemd-generator-watchdog**: D-Bus
  activation is a third service-launch path alongside systemd
  units and generators; this covers the dbus-daemon-launched
  surface.
- **polkit-rules-watchdog**: polkit is the authorization layer
  many D-Bus methods consult; this is the activation + bus-name
  policy layer. Both D-Bus-adjacent privilege surfaces.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the files; this adds the Exec/User + own-policy + new-file
  semantic view.
