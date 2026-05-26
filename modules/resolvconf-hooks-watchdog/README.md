# resolvconf-hooks-watchdog

Boot + daily delta of the resolvconf/openresolv update-hook dirs
against a learned baseline, plus an ownership + suspicious-pattern
scan. Catches a script that runs as root every time `/etc/resolv.conf`
is regenerated. MITRE **T1546**.

## Why this matters

`resolvconf` (and `openresolv`) run every script in these dirs **as
root** each time `/etc/resolv.conf` is regenerated:

- `/etc/resolvconf/update.d/*` — run on every resolvconf update
- `/etc/resolvconf/update-libc.d/*` — run after the libc resolver
  config is updated

Regeneration happens on **every DNS/network change** — interface
up/down, DHCP lease acquire/renew, VPN connect/disconnect — so a
dropped script self-triggers on routine network activity with no
operator action, giving quiet, recurring root execution.

This is distinct from **dns-resolver-watchdog**, which watches the
*content* of `resolv.conf` (the nameserver lines an attacker might
hijack). This watchdog watches the *scripts that regenerate it* —
the exec surface, not the data surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any resolvconf-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No resolvconf hooks present | `ok` | `no_resolvconf_hooks` |
| No delta | `ok` | `resolvconf_hooks_intact` |
| A script added / changed / removed | `warn` | `resolvconf_hooks_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `resolvconf_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=54min` + `OnCalendar=*-*-* 10:35:00` — extends the
staggered ladder after dhcpcd-hooks (10:30). A dropped update.d
script self-triggers on the next resolv.conf regeneration, so the
daily catch bounds dwell time; the boot catch confirms the script
set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the resolv.conf regeneration
  (driven by network/DNS changes) is the trigger.
- **T1059.004** — the script is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-resolvconf-hooks -n 1 --no-pager
journalctl -t selfdef-resolvconf-hooks-detail --since "1 day ago"

# Inventory
ls -la /etc/resolvconf/update.d/ /etc/resolvconf/update-libc.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <script>
sudo rm /var/lib/selfdef/resolvconf-hooks-baseline.tsv
sudo systemctl start selfdef-resolvconf-hooks.service
```

## Caveats

- **Packages ship legitimate hooks** (`libc`, `dnsmasq`, `bind9`,
  `unbound`, `pdnsd`); a new root-owned script with no suspicious
  pattern fires `warn` (re-baseline). The writable/non-root/injection
  tiers are the high-confidence alert.
- **Hosts without resolvconf/openresolv** (systemd-resolved-only,
  static resolv.conf) have no hook dirs → `no_resolvconf_hooks`
  no-op.
- **Daily+boot cadence** misses a drop-trigger-revert inside the
  window; an audit-rules watch on the update dirs' writes is the
  real-time complement.

## Coexistence

- **dns-resolver-watchdog**: resolv.conf content / nameserver
  hijack; this is the resolv.conf-regeneration exec surface — the
  scripts, not the data.
- **dhclient-hooks / dhcpcd-hooks / network-dispatcher**: the
  network events that *cause* resolv.conf to be regenerated; this
  watches the scripts those regenerations run.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  scripts; this adds the ownership + injection-pattern view.
