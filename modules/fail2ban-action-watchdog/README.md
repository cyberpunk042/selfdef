# fail2ban-action-watchdog

Boot + daily delta of the fail2ban action definitions against a
learned baseline, plus an ownership + action-command scan. Catches
a root command fail2ban runs on a ban event. MITRE **T1546**.

## Why this matters

fail2ban runs these directives' command **as root** in each
`/etc/fail2ban/action.d/*.conf` (or `*.local`):

- `actionstart` / `actionstop` — on jail start/stop
- `actioncheck` — before each ban
- `actionban` / `actionunban` — on every ban / unban
- `actionflush` / `actionrepair`

The attacker advantage here is **self-triggering**: anyone who can
reach a fail2ban-protected service can deliberately fail auth from a
throwaway IP to **induce a ban**, which fires `actionban` — so a
planted `actionban = <payload>` is root code execution **on demand**,
no waiting for a scheduled event. `actionstart` additionally runs
when fail2ban starts (boot).

This is distinct from **fail2ban-bridge** (the hardening module that
*deploys* fail2ban jails); this is the detection watchdog over the
action command definitions.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any fail2ban action change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No fail2ban actions present | `ok` | `no_fail2ban_actions` |
| No delta | `ok` | `fail2ban_actions_intact` |
| A config / action added / changed / removed | `warn` | `fail2ban_actions_changed` |
| A `.conf` world-writable/non-root, OR an action command under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `fail2ban_actions_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `act:<path>:<directive>:<cmd>` — each `action*` command (parsed
  case-insensitively).

## Cadence

`OnBootSec=65min` + `OnCalendar=*-*-* 11:30:00` — extends the
staggered ladder after needrestart (11:25). A planted action fires
on the next ban/unban or fail2ban start, so the daily catch bounds
dwell time; the boot catch confirms the action set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a ban (attacker-inducible)
  triggers the action.
- **T1059** — the action command is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-fail2ban-action -n 1 --no-pager
journalctl -t selfdef-fail2ban-action-detail --since "1 day ago"

# Inventory the action commands
grep -rinE '^(actionban|actionstart|actionunban)\s*=' \
     /etc/fail2ban/action.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/fail2ban/action.d/<file>.conf
sudo rm /var/lib/selfdef/fail2ban-action-baseline.tsv
sudo systemctl start selfdef-fail2ban-action.service
```

## Caveats

- **Legit actions are full of firewall commands** (`iptables`,
  `nft`, `ipset`, `firewall-cmd`) with `<ip>`/`<name>` tag
  substitutions; these do not match the injection/tmp-exec patterns.
  A new action still fires `warn` (re-baseline). The tmp-exec /
  injection / writable / non-root tiers are the high-confidence
  alert.
- **Hosts without fail2ban** have no `/etc/fail2ban/action.d` →
  `no_fail2ban_actions` no-op.
- **Multi-line action values** with backslash continuation may carry
  a payload on a later line; the first line is scanned. Review the
  full action on a `warn`/`alert`.
- **Daily+boot cadence** misses a drop-ban-revert inside the window;
  an audit-rules watch on `/etc/fail2ban/action.d` writes is the
  real-time complement.

## Coexistence

- **fail2ban-bridge**: deploys the jails; this watches the action
  command definitions those jails invoke.
- **network-dispatcher / dhclient / dhcpcd / VPN hooks**: other
  event-triggered root-exec surfaces; this is the ban-event one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  action `.conf` files; this adds the action-command view.
