# aide-bridge

[AIDE](https://aide.github.io/) (Advanced Intrusion Detection
Environment) file integrity monitoring. Snapshots the filesystem
baseline + diffs daily; emits structured JSON events tagged
`selfdef-aide` to the journal.

Complements `integrity-sentinel` (which SHA256-baselines selfdef's
own policy artifacts only). aide-bridge broadens to the host's
binary + config + boot + library surfaces.

## Profiles

| Profile | Diff handling | Exit code on diff |
|---|---|---|
| `baseline` (default) | Diffs logged to journal as `selfdef-aide` events; correlator + dashboard surfaces them; no systemd-unit failure state | 0 (always) |
| `enforce` | Same + any diff triggers exit 1 → `systemctl status` shows failed → operator-alertable via journald collector + correlator + notifier | 1 on diff; 0 on no-diff |

Switch to `enforce` AFTER baseline maturation (operator has
confirmed expected churn from package updates is accounted for
in regular `aide --update` runs).

## Watch set (drop-in adds to OS-default)

The shipped `/etc/aide/aide.conf.d/50-selfdef.conf` adds:

| Path | Rule | Why |
|---|---|---|
| `/etc` | NORMAL | Config drift (sysctl, systemd unit, ssh, sudoers) |
| `/boot` | NORMAL | Bootloader / kernel image tamper |
| `/bin /sbin /usr/{bin,sbin}` | NORMAL | Standard binaries |
| `/usr/local/{bin,sbin}` | NORMAL | Compiled-from-source binaries |
| `/usr/local/libexec/selfdef` | NORMAL | selfdef's own probe scripts |
| `/opt` | NORMAL | Operator-installed third-party |
| `/srv` | DIR | Served content (dir-perm only) |
| `/lib/modules` | NORMAL | Kernel modules (pairs with kernel-lockdown strict mode's modules_disabled — modifications mean attempted persistence) |
| `/etc/selfdef/modules` | NORMAL | selfdef module configs (operator-edited) |

Excludes (always-mutating paths):
- `/var/log` `/var/lib/selfdef` `/home` `/root` `/tmp` `/var/tmp`
  `/var/cache` `/run` `/proc` `/sys` `/dev`

## Event severity ladder

| Severity | Condition |
|---|---|
| `ok` | No diff (rc 0) |
| `warn` | Adds only (rc 1) — likely package install / log-rotate artifact |
| `alert` | Removals or changes (rc 2/4/3/5/6/7) — high-signal tamper indicator |
| `high` | AIDE internal error (rc ≥ 8) OR config missing |

Removals + changes are the high-signal cases — a rootkit replaces
a SUID binary (= change), or `sshd` is replaced with a hijacked
copy (= change). Adds alone are usually benign.

## Event schema

```json
{
  "tag": "selfdef-aide",
  "severity": "alert",
  "event": "diff_changed_or_removed",
  "profile": "baseline",
  "aide_rc": 4,
  "added": 0,
  "removed": 0,
  "changed": 3,
  "added_bit": 0,
  "removed_bit": 0,
  "changed_bit": 1
}
```

A companion `selfdef-aide-detail` tag carries up to 8 KiB of the
raw AIDE diff output line-by-line so operators can inspect via
`journalctl -t selfdef-aide-detail`.

## MITRE coverage

- **T1014** Rootkit — any rootkit modifying a binary in
  `/{bin,sbin,usr/bin,usr/sbin,usr/local/bin}` triggers a `changed`
  diff. Symbiote, Reptile, Diamorphine all visible.
- **T1547.001** Boot/Logon Autostart: Registry / Init Scripts —
  /etc/systemd/system + /etc/cron.d + /etc/init.d modifications
  visible via the /etc watch.
- **T1554** Compromise Client Software Binary — replacement of
  any binary (sshd, sudo, curl, etc.) triggers `changed`.
- **T1543.002** Create or Modify System Process: Systemd Service —
  /etc/systemd/system + /lib/systemd/system watched.

## Operator workflow

After legitimate package update (e.g. `apt upgrade`):
```bash
# Refresh the baseline.
sudo aide --update --config /etc/aide/aide.conf
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

Or, if the operator wants ALL changes to count as the new
baseline (no investigation):
```bash
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

## Cost

AIDE's daily check on a populated host (`/usr` ~5 GB) takes
2-10 minutes wall-clock + 1-2 minutes CPU + reads every file in
the watch set. The service unit runs with `Nice=10
IOSchedulingClass=idle` so it stays out of the operator's way.

## Interaction with kernel-lockdown

When `kernel-lockdown=strict` is active (`kernel.modules_disabled
=1`), any AIDE diff under `/lib/modules` is by definition
suspicious — late module loading is BLOCKED by the kernel but
a sufficiently-privileged attacker can still WRITE files there.
AIDE catches the write attempt even though the load will fail.
