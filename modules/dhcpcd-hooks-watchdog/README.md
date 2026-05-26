# dhcpcd-hooks-watchdog

Boot + daily delta of the `dhcpcd` hook surface against a learned
baseline, plus an ownership + suspicious-pattern scan. Catches a
hook script that runs as root on every DHCP lease event under the
`dhcpcd` client. MITRE **T1546**.

## Why this matters

`dhcpcd` runs every hook **as root** on each lease event
(`PREINIT`, `CARRIER`, `BOUND`, `RENEW`, `REBIND`, `REBOOT`,
`EXPIRE`, `NOCARRIER`, …):

- `/lib/dhcpcd/dhcpcd-hooks/*` — distro-shipped
- `/usr/lib/dhcpcd/dhcpcd-hooks/*` — distro-shipped (newer layout)
- `/etc/dhcpcd/dhcpcd-hooks/*` — admin hooks
- `/etc/dhcpcd.enter-hook` — single-file enter hook
- `/etc/dhcpcd.exit-hook` — single-file exit hook

`RENEW` fires automatically on a timer (typically half the lease
time), so a dropped hook self-triggers with no operator action —
quiet, recurring root execution.

**`dhcpcd` is the default DHCP client on Alpine, Arch, Gentoo, and
Raspberry Pi OS** — exactly the hosts where the ISC
`dhclient-hooks-watchdog` no-ops because there are no
`/etc/dhcp/dhclient*` hooks. This watchdog fills that gap. It is
distinct from:

- **dhclient-hooks-watchdog** — ISC `isc-dhcp-client`, different
  files and code path.
- **network-dispatcher-watchdog** — NetworkManager / ifupdown / ppp
  / networkd-dispatcher.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any dhcpcd-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No dhcpcd hooks present | `ok` | `no_dhcpcd_hooks` |
| No delta | `ok` | `dhcpcd_hooks_intact` |
| A hook added / changed / removed | `warn` | `dhcpcd_hooks_changed` |
| A hook world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `dhcpcd_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each hook.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

Symlinked dirs (`/lib` → `/usr/lib`) are de-duplicated by resolved
real path.

## Cadence

`OnBootSec=53min` + `OnCalendar=*-*-* 10:30:00` — extends the
staggered ladder after the DM hooks (10:25). A dropped hook
self-triggers on the next lease renewal, so the daily catch bounds
dwell time; the boot catch confirms the hook set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the DHCP lease event is the
  trigger, and renewal is automatic/recurring.
- **T1059.004** — the hook is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-dhcpcd-hooks -n 1 --no-pager
journalctl -t selfdef-dhcpcd-hooks-detail --since "1 day ago"

# Inventory
ls -la /lib/dhcpcd/dhcpcd-hooks/ /usr/lib/dhcpcd/dhcpcd-hooks/ \
       /etc/dhcpcd/dhcpcd-hooks/ 2>/dev/null
for f in /etc/dhcpcd.enter-hook /etc/dhcpcd.exit-hook; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <hook>
sudo rm /var/lib/selfdef/dhcpcd-hooks-baseline.tsv
sudo systemctl start selfdef-dhcpcd-hooks.service
```

## Caveats

- **dhcpcd ships legitimate hooks** (`01-test`, `20-resolv.conf`,
  `30-hostname`, `10-wpa_supplicant`, …); a new root-owned hook with
  no suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **Hosts not using dhcpcd** (Debian/Ubuntu/RHEL default to ISC
  dhclient or NetworkManager-internal DHCP) have no hook dirs →
  `no_dhcpcd_hooks` no-op; those are covered by
  dhclient-hooks-watchdog / network-dispatcher-watchdog.
- **Daily+boot cadence** misses a drop-renew-revert inside the
  window; an audit-rules watch on the hook dirs' writes is the
  real-time complement.

## Coexistence

- **dhclient-hooks-watchdog**: ISC dhclient lease-event exec; this
  is the dhcpcd lease-event exec path. Together they cover both
  major DHCP clients' hook surfaces across distro families.
- **network-dispatcher-watchdog**: NM / ifupdown / ppp / networkd
  network-event exec — a third, distinct code path.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  hooks; this adds the ownership + injection-pattern view.
