# snmpd-exec-watchdog

Boot + daily delta of the Net-SNMP daemon command directives against
a learned baseline, plus an ownership + command scan. Catches a
program snmpd runs (as root) and exposes over SNMP — remotely
triggerable. MITRE **T1546** / **T1059**.

## Why this matters

`snmpd` runs the program named in these directives **as its daemon
user (frequently root)** and exposes the output as an SNMP OID, in
`/etc/snmp/snmpd.conf` + `/etc/snmp/snmpd.conf.d/*.conf`:

- `exec [OID] NAME PROG ARGS`
- `extend [OID] NAME PROG ARGS` / `extend-sh …`
- `pass MIBOID PROG` / `pass_persist MIBOID PROG`
- `sh NAME SHELL-COMMAND`

The critical property: the command is **remotely triggerable**.
Anyone who can query the agent — with the default community
`public`, or any known community string — fires the program by
walking/getting its OID. So a planted `extend evil /tmp/x` (or an
`exec`/`pass` to a writable/attacker program) is **remote-triggered
command execution / persistence**, no local access required.

This is the **SNMP-query-triggered exec** surface — distinct from
cron (time), the login/network/boot watchdogs, and
postfix/aliases (mail).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any snmpd exec-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No snmpd config present | `ok` | `no_snmpd` |
| No delta | `ok` | `snmpd_exec_intact` |
| A config / directive added / changed / removed | `warn` | `snmpd_exec_changed` |
| A config world-writable/non-root, OR a command program under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `snmpd_exec_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `cmd:<path>:<directive>:<rest>` — each `exec`/`extend`/`pass`/`sh`
  command (parsed case-insensitively).

## Cadence

`OnBootSec=84min` + `OnCalendar=*-*-* 13:35:00` — extends the
staggered ladder after auditd-plugins (13:30). A planted
`exec`/`extend`/`pass` directive is reachable the instant the agent
is queried for its OID, so the daily catch bounds dwell time; the
boot catch confirms the config after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — an SNMP query for the OID
  triggers the program.
- **T1059** — the directive's program is arbitrary code run by
  snmpd.

## Operator workflow

```bash
journalctl -t selfdef-snmpd-exec -n 1 --no-pager
journalctl -t selfdef-snmpd-exec-detail --since "1 day ago"

# Inventory the exec points (and confirm the community is locked down!)
grep -inE '^\s*(exec|extend|extend-sh|pass|pass_persist|sh)\b' \
     /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.d/*.conf 2>/dev/null
grep -inE '^\s*(rocommunity|rwcommunity)\b' /etc/snmp/snmpd.conf 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/snmp/snmpd.conf
sudo rm /var/lib/selfdef/snmpd-exec-baseline.tsv
sudo systemctl start selfdef-snmpd-exec.service
```

## Caveats

- **Legit monitoring uses these directives** (`extend uptime
  /bin/uptime`, disk/script health checks under `/usr/local/bin`);
  those standard absolute paths are not flagged. A new directive
  still fires `warn` (re-baseline). The tmp-exec / injection /
  writable / non-root tiers are the high-confidence alert.
- **The community string is the real exposure multiplier** — a
  world-readable `rocommunity public` plus an `exec` makes the
  command anonymously triggerable. This module flags the exec
  directive; pair with a review of the community/ACL config.
- **AgentX subagents** (a separate extension mechanism) are out of
  scope here; this watches the built-in `exec`/`extend`/`pass`
  surface.
- **Daily+boot cadence** misses a drop-query-revert inside the
  window; an audit-rules watch on `/etc/snmp` writes is the
  real-time complement.

## Coexistence

- **cron / incron / at watchdogs**: time- and file-event-triggered
  exec; this is the SNMP-query-triggered one.
- **postfix-exec / aliases watchdogs**: mail-triggered exec; another
  remotely-reachable trigger class.
- **listening-ports-watchdog**: flags snmpd listening; this flags
  what a query to it can run.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  snmpd config; this adds the exec-directive semantic view.
