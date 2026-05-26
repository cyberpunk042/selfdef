# nfs-exports-watchdog

Boot + daily delta of the NFS **server** export table
(`/etc/exports` + `/etc/exports.d/*.exports`) against a learned
baseline. Catches a dangerous export grant. MITRE **T1199**
(Trusted Relationship) / **T1133** (External Remote Services).

## Why this matters

`nfs-mount-watchdog` covers the **client** (mounts); this watches
the **server** exports for dangerous grants:

```
/          *(rw,no_root_squash,insecure)   # whole FS, remote ROOT write
/srv/data  *(rw)                            # writable to ANY host
/etc       192.168.0.0/16(ro)               # leak system config
```

`no_root_squash` maps a remote root client to **local root** — an
attacker who mounts the export writes files as root (plant a
setuid binary, edit `/etc/passwd`, drop an authorized_keys) →
instant server compromise. A wildcard host `*` exports to anyone;
`insecure` allows mounts from unprivileged source ports (any
local user on a client host).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any exports change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No exports | `ok` | `no_exports` |
| No delta | `ok` | `nfs_exports_intact` |
| Any export added / removed / changed | `warn` | `nfs_exports_changed` |
| A NEWLY-ADDED dangerous export | `alert` | `nfs_exports_dangerous` |

Dangerous = `no_root_squash` · a `*` wildcard host with `rw` ·
`insecure` · exporting `/` or a sensitive path (`/etc`, `/home`,
`/root`, `/boot`, `/usr`, `/var`, `/bin`, `/sbin`, `/lib*`) · a
directory line with no host clause. The alert is delta-based — a
pre-existing dangerous export is flagged once at baseline for
vetting, then not re-alerted.

## What's recorded

- `file:<path>:<sha12>` — hash of each exports file.
- `export:<dir>:<host>(<opts>)` — each host clause per exported
  directory.

## Cadence

`OnBootSec=37min` + `OnCalendar=*-*-* 09:10:00` — extends the
staggered ladder after fstab (09:05). A dangerous export is live
once `exportfs`/`nfs-server` (re)reads it, so the boot catch
confirms the table after a restart.

## MITRE coverage

- **T1199** Trusted Relationship — an NFS export is a trust grant
  to client hosts.
- **T1133** External Remote Services — the export is the remote
  service surface.
- **T1068** / **T1078** (adjacent) — `no_root_squash` gives a
  remote attacker root-write to the server filesystem.

## Operator workflow

```bash
journalctl -t selfdef-nfs-exports -n 1 --no-pager
journalctl -t selfdef-nfs-exports-detail --since "1 day ago"

# Current export table (config + active)
grep -vE '^\s*#|^\s*$' /etc/exports /etc/exports.d/*.exports 2>/dev/null
sudo exportfs -v 2>/dev/null

# Investigate a dangerous alert
# - no_root_squash / wildcard rw / sensitive path? Tighten it:
sudo $EDITOR /etc/exports        # add root_squash, scope the host, drop insecure
sudo exportfs -ra                # re-export
sudo rm /var/lib/selfdef/nfs-exports-baseline.tsv
sudo systemctl start selfdef-nfs-exports.service
```

## Caveats

- **Some exports legitimately use `no_root_squash`** (e.g. a
  diskless-boot root export); the alert surfaces it for vetting
  (re-baseline to accept). The wildcard-rw + sensitive-path tiers
  are the high-confidence ones.
- **No NFS server installed** → `no_exports` no-op; the module is
  cheap insurance for hosts that do (or might) serve NFS.
- **Daily+boot cadence** misses an export-mount-revert within the
  window; an audit-rules watch on `/etc/exports*` writes is the
  real-time complement.

## Coexistence

- **nfs-mount-watchdog**: the CLIENT side (a mount WITHOUT nosuid
  honors a malicious server's setuid binaries); this is the SERVER
  side (a dangerous export). Both ends of the NFS trust.
- **ssh-authkeys / account watchdogs**: an attacker with
  no_root_squash write access plants authorized_keys / a UID-0
  account — those modules catch the landed artifact, this catches
  the export that enabled it.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  /etc/exports; this adds the per-export dangerous-grant view.
