# dhclient-hooks-watchdog

Boot + daily delta of the ISC `dhclient` hook surface against a
learned baseline, plus an ownership + suspicious-pattern scan.
Catches a hook script that runs as root on every DHCP lease event.
MITRE **T1546**.

## Why this matters

`dhclient-script` (from `isc-dhcp-client`) **sources** these files
**as root** on every DHCP lease state change
(MEDIUM/PREINIT/BOUND/RENEW/REBIND/REBOOT/EXPIRE/RELEASE/…):

- `/etc/dhcp/dhclient-enter-hooks.d/*` — Debian/Ubuntu enter hooks
- `/etc/dhcp/dhclient-exit-hooks.d/*` — Debian/Ubuntu exit hooks
- `/etc/dhcp/dhclient.d/*.sh` — RHEL/Fedora (sourced by name)
- `/etc/dhcp/dhclient-{enter,exit}-hooks` — single-file variants
- `/etc/dhclient-{enter,exit}-hooks` — legacy top-level

The key property: **lease RENEW fires automatically on a timer**
(typically half the lease time), so a dropped hook self-triggers
with no operator action — quiet, recurring root execution. A rogue
hook is root-exec-on-network-event persistence (T1546).

This is distinct from **network-dispatcher-watchdog**, which covers
the NetworkManager `dispatcher.d`, ifupdown `if-up.d`/`if-down.d`,
ppp `ip-up.d`/`ip-down.d`, and `networkd-dispatcher` surfaces — a
completely separate code path. The ISC dhclient hook chain runs
even on hosts that use none of those.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any dhclient-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No dhclient hooks present | `ok` | `no_dhclient_hooks` |
| No delta | `ok` | `dhclient_hooks_intact` |
| A hook added / changed / removed | `warn` | `dhclient_hooks_changed` |
| A hook world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `dhclient_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each hook file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=48min` + `OnCalendar=*-*-* 10:05:00` — extends the
staggered ladder after skel-watchdog (10:00). A dropped hook
self-triggers on the next DHCP lease renewal, so the daily catch
bounds dwell time; the boot catch confirms the hook set after a
restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the DHCP lease event is the
  trigger, and renewal is automatic/recurring.
- **T1059.004** — the hook is shell execution (sourced as root).

## Operator workflow

```bash
journalctl -t selfdef-dhclient-hooks -n 1 --no-pager
journalctl -t selfdef-dhclient-hooks-detail --since "1 day ago"

# Inventory
ls -la /etc/dhcp/dhclient-enter-hooks.d/ /etc/dhcp/dhclient-exit-hooks.d/ \
       /etc/dhcp/dhclient.d/ 2>/dev/null
for f in /etc/dhcp/dhclient-enter-hooks /etc/dhcp/dhclient-exit-hooks \
         /etc/dhclient-enter-hooks /etc/dhclient-exit-hooks; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <hook>
sudo rm /var/lib/selfdef/dhclient-hooks-baseline.tsv
sudo systemctl start selfdef-dhclient-hooks.service
```

## Caveats

- **Distro packages ship legitimate hooks** (e.g. Debian's
  `debug`, `samba`/`resolvconf`/`ntpdate` integration hooks); a new
  root-owned hook with no suspicious pattern fires `warn`
  (re-baseline). The writable/non-root/injection tiers are the
  high-confidence alert.
- **Hosts not using ISC dhclient** (NetworkManager-internal DHCP,
  `dhcpcd`, `systemd-networkd`) often have no hook files →
  `no_dhclient_hooks` no-op. Those paths are covered elsewhere
  (network-dispatcher-watchdog) or by their own client's hooks.
- **Daily+boot cadence** misses a drop-renew-revert inside the
  window; an audit-rules watch on the hook dirs' writes is the
  real-time complement.

## Coexistence

- **network-dispatcher-watchdog**: NM dispatcher.d / ifupdown /
  ppp / networkd-dispatcher network-event exec. This is the ISC
  dhclient lease-event exec path — a distinct mechanism. Together
  they cover the network-event root-exec surface.
- **cron-job-watchdog / anacrontab-watchdog**: time-triggered root
  exec; this is network-event-triggered root exec.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  hooks; this adds the ownership + injection-pattern view.
