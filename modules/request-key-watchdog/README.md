# request-key-watchdog

Boot + daily delta of the kernel key-upcall handlers
(`/etc/request-key.conf` + `/etc/request-key.d/*.conf`) against a
learned baseline, plus an ownership + callout-path scan. Catches
a rogue callout program that runs as root on a kernel key
request. MITRE **T1546** (Event Triggered Execution).

## Why this matters

When the kernel needs a key instantiated — `dns_resolver` (the
kernel DNS resolver), NFS `id_resolver`, `cifs.spnego`, etc. — it
upcalls `request-key(8)`, which consults these files and runs the
matching **callout program AS ROOT**. A rogue callout is
root-exec on key request, an obscure and easily-overlooked
persistence/privilege vector:

```
#op     type           desc  callout
create  dns_resolver   *  *  /tmp/.evil %k      # runs as root on upcall
```

The trigger (a key request) happens during ordinary operations
(DNS, NFS, CIFS), so the callout fires without operator action.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any request-key change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No request-key config | `ok` | `no_request_key` |
| No delta | `ok` | `request_key_intact` |
| A rule / file added, removed, or changed | `warn` | `request_key_changed` |
| A callout under /tmp /home /dev/shm, world-writable, or bare/relative; or a world-writable/non-root config | `alert` | `request_key_suspicious_callout` |

## What's recorded

- `file:<path>:<sha12>` — hash of each request-key config.
- `own:<path>:<owner:mode>` — owner + mode.
- `callout:<type>:<prog>` — the callout program (first token)
  per rule. `negate`/`pipe` and other request-key keywords + the
  standard `/usr/sbin/key.*` / `/sbin/request-key` handlers are
  benign; a tmp/writable/relative callout is the signature.

## Cadence

`OnBootSec=34min` + `OnCalendar=*-*-* 08:55:00` — extends the
staggered ladder after securetty (08:50). A rogue callout fires
on the next kernel key request, so the boot catch confirms the
handlers after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a kernel key request is
  the trigger that runs the callout as root.
- **T1059.004** — the callout is command execution.
- **T1547** Boot or Logon Autostart (adjacent) — key upcalls
  occur early + often during normal operation.

## Operator workflow

```bash
journalctl -t selfdef-request-key -n 1 --no-pager
journalctl -t selfdef-request-key-detail --since "1 day ago"

# Inventory
grep -rhvE '^\s*#|^\s*$' /etc/request-key.conf /etc/request-key.d/ 2>/dev/null

# Investigate a suspicious_callout alert
# - Is the callout under /tmp or writable? Normal handlers live in
#   /usr/sbin/key.* or /sbin/request-key.
sudo $EDITOR /etc/request-key.d/<file>.conf
sudo rm /var/lib/selfdef/request-key-baseline.tsv
sudo systemctl start selfdef-request-key.service
```

## Caveats

- **request-key is obscure** but present wherever the kernel DNS
  resolver / NFSv4 idmap / CIFS upcalls are used. Package-shipped
  handlers (`/usr/sbin/key.dns_resolver`, `cifs.upcall`) are
  benign; a new one fires `warn` (re-baseline). The tmp/writable
  callout tier is the high-confidence one.
- **Daily+boot cadence** misses an inject-upcall-revert within the
  window; an audit-rules watch on `/etc/request-key.*` writes is
  the real-time complement.

## Coexistence

- **modprobe-config / udev-rules / network-dispatcher watchdogs**:
  the other kernel/event-triggered root-exec surfaces; this adds
  the key-upcall one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the config + the callout binaries; this adds the callout-path
  semantic view.
