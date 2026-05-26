# network-dispatcher-watchdog

Boot + daily delta of the network-event dispatcher script
directories against a learned baseline, plus an ownership +
suspicious-pattern scan. Catches a script that runs as root on a
network event. MITRE **T1546** (Event Triggered Execution).

## Why this matters

NetworkManager, systemd-networkd-dispatcher, ifupdown, and ppp
all run scripts **as root** when a network event fires —
interface up/down, DHCP lease renew, VPN connect, connectivity
change. Those events happen at every boot and every network
transition, so a script dropped into one of these dirs is
reliable root-exec persistence:

```
cp /tmp/p /etc/NetworkManager/dispatcher.d/99-evil
chmod +x /etc/NetworkManager/dispatcher.d/99-evil
# → runs as root on the next interface-up (i.e. the next boot)
```

This is the **network-event** member of the persistence family,
alongside udev (device event), cron (time), systemd (service),
shell-init (login), and modprobe (module load).

## Watched directories

- `/etc/NetworkManager/dispatcher.d` + `pre-up.d` + `pre-down.d`
- `/etc/networkd-dispatcher/*.d` (routable.d, dormant.d, …)
- `/etc/network/if-up.d` · `if-pre-up.d` · `if-down.d` ·
  `if-post-down.d` (ifupdown)
- `/etc/ppp/ip-up.d` · `ip-down.d` · `ipv6-up.d` · `ipv6-down.d`

If none of these dirs exist (host has no such network stack), the
module no-ops cleanly (`event:no_dispatcher_dirs`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any dispatcher-dir change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No dispatcher dirs present | `ok` | `no_dispatcher_dirs` |
| No delta | `ok` | `network_dispatcher_intact` |
| A script added / changed / removed | `warn` | `network_dispatcher_changed` |
| A script world-writable or non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `network_dispatcher_suspicious` |

## What's recorded

- `file:<script>:<sha12>` — hash of each script.
- `own:<script>:<owner:mode>` — owner + mode. A dispatcher
  script that is **world-writable** or **not owned by root** is
  hijackable by a non-root user into root execution — flagged
  hard.
- `susp:<script>:<pattern>` — a high-risk exec pattern
  (`curl|sh`, `/dev/tcp`, `nc -e`, `bash -i`, `base64 -d`,
  `eval $()`, `python -c`, `mkfifo`, `setsid`); comment-only
  lines are stripped before the scan.

## Cadence

`OnBootSec=15min` + `OnCalendar=*-*-* 07:20:00` — extends the
staggered ladder after sshd-config (07:15). The boot catch
matters: these scripts fire on the interface-up that happens at
boot, so confirming the set right after a restart is valuable.

## MITRE coverage

- **T1546** Event Triggered Execution — PRIMARY; a network
  transition is the trigger that runs the dispatcher script as
  root.
- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  the injected script/pattern is shell execution.
- **T1037** Boot or Logon Initialization Scripts — interface-up
  at boot runs the script every reboot.
- **T1543** Create or Modify System Process (adjacent) — a
  world-writable/non-root dispatcher script is a privilege +
  persistence handle.

## Operator workflow

```bash
journalctl -t selfdef-network-dispatcher -n 1 --no-pager
journalctl -t selfdef-network-dispatcher-detail --since "1 day ago"

# Manual inventory
ls -la /etc/NetworkManager/dispatcher.d/ \
       /etc/networkd-dispatcher/*.d/ \
       /etc/network/if-*.d/ /etc/ppp/ip*-*.d/ 2>/dev/null

# Investigate a suspicious alert
# - world-writable / non-root script, or a curl|sh / reverse shell?
ls -l <script>; head -40 <script>
# Remove + re-baseline:
sudo rm <script>
sudo rm /var/lib/selfdef/network-dispatcher-baseline.tsv
sudo systemctl start selfdef-network-dispatcher.service

# Re-baseline after a legit dispatcher script (you added VPN
# automation, a package added one): re-run the service once.
sudo rm /var/lib/selfdef/network-dispatcher-baseline.tsv
sudo systemctl start selfdef-network-dispatcher.service
```

## Caveats

- **Packages legitimately add dispatcher scripts** (e.g.
  NetworkManager ships `01-ifupdown`; openvpn, chrony add some).
  A new root-owned script with no suspicious pattern fires
  `warn` (re-baseline). The `suspicious` tier (writable /
  non-root / injection pattern) is the high-confidence one.
- **Pattern set is a heuristic.** The content delta (`warn` on
  any change) is the backstop that surfaces every edit;
  aide-bridge / integrity-sentinel give byte-level integrity.
- **Daily+boot cadence** misses an inject-trigger-revert within
  the window; an audit-rules watch on the dispatcher dirs'
  writes is the real-time complement.

## Coexistence

- **udev-rules / cron-job / systemd-unit / shell-init / modprobe-
  config watchdogs**: the persistence-mechanism family — this
  adds the network-event trigger surface (the last common
  root-exec-on-event hook).
- **vpn-bridge**: if you run the selfdef VPN bridge, its legit
  dispatcher hooks are baselined here; this confirms they stay
  benign and flags any tamper.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the scripts; this adds the ownership + injection-pattern
  semantic view.
