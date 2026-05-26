# dhcpd-exec-watchdog

Boot + daily delta of the ISC DHCP **server** config against a
learned baseline, plus an ownership + `execute()`-statement scan.
Catches a program dhcpd runs as root on a DHCP lease event. MITRE
**T1546**.

## Why this matters

`dhcpd` (the ISC DHCP **server**) evaluates `execute("/path",
"arg", ...)` statements — typically inside `on commit { }`,
`on release { }`, or `on expiry { }` event blocks — and runs the
named program **as the dhcpd user (often root)** on the
corresponding DHCP lease event. Config:

- `/etc/dhcp/dhcpd.conf`, `/etc/dhcp/dhcpd6.conf`, `/etc/dhcpd.conf`
- `/etc/dhcp/dhcpd.conf.d/*`

A planted `execute()` pointing at a writable/attacker program is
**lease-event-triggered root command execution / persistence**,
fired by any client that obtains, renews, or releases a lease — i.e.
remotely inducible on a network the server serves.

This is distinct from **dhclient-hooks-watchdog** and
**dhcpcd-hooks-watchdog** (the DHCP **clients**); this is the DHCP
**server** `execute()` surface. Together the three cover both ends
of DHCP (client lease hooks + server lease-event exec).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any dhcpd execute() change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No dhcpd config present | `ok` | `no_dhcpd` |
| No delta | `ok` | `dhcpd_exec_intact` |
| A config / execute() added / changed / removed | `warn` | `dhcpd_exec_changed` |
| A config world-writable/non-root, OR an `execute()` program under `/tmp` `/var/tmp` `/dev/shm` `/home`, relative-with-slash, or with an injection pattern | `alert` | `dhcpd_exec_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `exec:<path>:<prog>` — each `execute()` program (first quoted arg).

## Cadence

`OnBootSec=86min` + `OnCalendar=*-*-* 13:50:00` — extends the
staggered ladder after autofs (13:45). A planted `execute()` fires
on the next matching lease event, so the daily catch bounds dwell
time; the boot catch confirms the config after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a DHCP lease event triggers
  the program.
- **T1059** — the `execute()` program is arbitrary code run by
  dhcpd.

## Operator workflow

```bash
journalctl -t selfdef-dhcpd-exec -n 1 --no-pager
journalctl -t selfdef-dhcpd-exec-detail --since "1 day ago"

# Inventory execute() statements
grep -inE 'execute[[:space:]]*\(' \
     /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd6.conf /etc/dhcpd.conf \
     /etc/dhcp/dhcpd.conf.d/* 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/dhcp/dhcpd.conf
sudo rm /var/lib/selfdef/dhcpd-exec-baseline.tsv
sudo systemctl start selfdef-dhcpd-exec.service
```

## Caveats

- **`execute()` requires dhcpd built with it** and is uncommon — its
  presence at all is worth a `warn` review. Legit uses (dynamic-DNS
  helpers, lease-event logging) with standard absolute paths are not
  flagged; the tmp-exec / injection / writable / non-root tiers are
  the high-confidence alert.
- **Most hosts are DHCP clients, not servers** → `no_dhcpd` no-op
  where dhcpd is not installed.
- **Multi-line `execute()`** spanning lines is matched on the line
  carrying the keyword; review the full statement on a `warn`.
- **Daily+boot cadence** misses a drop-lease-revert inside the
  window; an audit-rules watch on the dhcpd config's writes is the
  real-time complement.

## Coexistence

- **dhclient-hooks-watchdog / dhcpcd-hooks-watchdog**: the DHCP
  client lease-hook surfaces; this is the DHCP server `execute()`
  surface.
- **network-dispatcher-watchdog**: NM/ifupdown/ppp/networkd event
  scripts; another network-event exec class.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  dhcpd config; this adds the execute() semantic view.
