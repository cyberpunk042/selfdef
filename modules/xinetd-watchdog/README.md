# xinetd-watchdog

Boot + daily delta of the (x)inetd super-server service
definitions (`/etc/xinetd.d/*`, `/etc/xinetd.conf`,
`/etc/inetd.conf`) against a learned baseline, plus an ownership
+ server-path scan. Catches a service that runs a command as
root on a network connection. MITRE **T1543**.

## Why this matters

`xinetd`/`inetd` are super-servers that launch the configured
server program **as the configured user** (often root) on each
inbound connection to a service's port. A rogue or tampered
service definition is network-triggered root-exec persistence:

```
# /etc/xinetd.d/backdoor
service backdoor {
    type = UNLISTED  port = 4444  socket_type = stream
    protocol = tcp   wait = no    user = root
    server = /bin/bash           disable = no
}

# /etc/inetd.conf
4444 stream tcp nowait root /bin/bash bash -i
```

A connection to the port spawns the server as root — a bind-shell
backdoor that needs no running daemon of its own. Modern hosts
rarely run a super-server, so this no-ops cleanly there; it
matters on the legacy/embedded systems selfdef also targets.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any xinetd/inetd change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No super-server config present | `ok` | `no_super_server` |
| No delta | `ok` | `xinetd_intact` |
| A service / file added, removed, or changed | `warn` | `xinetd_changed` |
| A server path under /tmp /home /dev/shm or world-writable, OR a world-writable / non-root config | `alert` | `xinetd_suspicious_server` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config file.
- `own:<path>:<owner:mode>` — owner + mode (a world-writable /
  non-root super-server config lets an attacker define any
  service).
- `xinetd:<svc>:<server>` — each xinetd service's `server`
  program.
- `inetd:<svc>:<user>:<server>` — each inetd line's user +
  server program.

A server path under tmp/home/dev-shm or world-writable is the
backdoor signature.

## Cadence

`OnBootSec=28min` + `OnCalendar=*-*-* 08:25:00` — extends the
staggered ladder after sudoers-defaults (08:20). A service
launches on the next inbound connection, so the boot catch
confirms the definitions after a restart.

## MITRE coverage

- **T1543** Create or Modify System Process — a super-server
  service is a network-launched process (often root).
- **T1059.004** — the `server` is command execution.
- **T1571** Non-Standard Port (adjacent) — an UNLISTED xinetd
  service can bind any port for the backdoor.

## Operator workflow

```bash
journalctl -t selfdef-xinetd -n 1 --no-pager
journalctl -t selfdef-xinetd-detail --since "1 day ago"

# Inventory
ls -la /etc/xinetd.d/ 2>/dev/null
grep -rhE '^\s*(server|user|disable|port)' /etc/xinetd.d/ /etc/xinetd.conf 2>/dev/null
grep -vE '^\s*#|^\s*$' /etc/inetd.conf 2>/dev/null

# Investigate a suspicious_server alert
cat /etc/xinetd.d/<svc>     # server in /tmp? user=root? disable=no?
sudo rm /etc/xinetd.d/<svc> # or set disable=yes; then reload xinetd
sudo rm /var/lib/selfdef/xinetd-baseline.tsv
sudo systemctl start selfdef-xinetd.service

# Better yet, if no super-server is needed, remove xinetd/inetd
# entirely — this module then no-ops (no_super_server).
```

## Caveats

- **No super-server on most modern hosts** → `no_super_server`
  no-op. The module is cheap insurance for legacy/embedded
  targets and catches an attacker who INSTALLS xinetd to gain a
  super-server backdoor.
- **Daily+boot cadence** misses an inject-connect-revert within
  the window; an audit-rules watch on `/etc/xinetd.d` +
  `/etc/inetd.conf` writes is the real-time complement.

## Coexistence

- **systemd-unit / boot-script / cron / udev / network-dispatcher
  watchdogs**: the service-launch + persistence family — this
  adds the (x)inetd super-server network-triggered surface.
- **listening-ports-watchdog** (if present): a backdoor xinetd
  service opens a listening port; the two views (config + open
  port) corroborate.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the config files; this adds the server-path + ownership
  semantic view.
