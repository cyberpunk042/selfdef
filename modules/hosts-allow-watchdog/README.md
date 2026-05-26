# hosts-allow-watchdog

Boot + daily delta of the tcpwrappers access files against a learned
baseline, plus an ownership + `spawn`/`twist`-command scan. Catches
a shell command tcpwrappers runs as root on a network connection.
MITRE **T1546**.

## Why this matters

A libwrap-linked daemon (vsftpd, some `sshd` builds, `rpcbind`,
legacy inetd services) evaluates these rules on **each connection**:

- `/etc/hosts.allow`
- `/etc/hosts.deny`

A rule's optional `spawn <cmd>` or `twist <cmd>` shell command runs
**as root** when the rule matches. So a planted rule like

```
ALL: ALL: spawn /tmp/.x/run %a >/dev/null 2>&1 &
```

is **root-exec-on-network-connection persistence** — triggered
*remotely* by simply connecting to any wrapped service, no local
access needed. This is a classic, low-profile tcpwrappers abuse.

It is distinct from **hosts-file-watchdog** (`/etc/hosts` name
resolution) and **access-conf-watchdog** (PAM
`/etc/security/access.conf`); those don't look at the tcpwrappers
exec directives.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any tcpwrappers change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No hosts.allow/deny present | `ok` | `no_hosts_allow` |
| No delta | `ok` | `hosts_allow_intact` |
| A rule / file added / changed / removed | `warn` | `hosts_allow_changed` |
| A file world-writable/non-root, OR a `spawn`/`twist` command under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `hosts_allow_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `exec:<path>:<spawn|twist>:<cmd>` — each spawn/twist command
  (parsed case-insensitively).

## Cadence

`OnBootSec=68min` + `OnCalendar=*-*-* 11:50:00` — extends the
staggered ladder after fish-config (11:45). A planted spawn/twist
directive fires on the next connection to a wrapped service, so the
daily catch bounds dwell time; the boot catch confirms the rule set
after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a connection to a wrapped
  service is the (remotely triggerable) trigger.
- **T1059** — the spawn/twist directive is shell execution run as
  root.

## Operator workflow

```bash
journalctl -t selfdef-hosts-allow -n 1 --no-pager
journalctl -t selfdef-hosts-allow-detail --since "1 day ago"

# Inspect + find spawn/twist directives
cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null
grep -inE '\b(spawn|twist)\b' /etc/hosts.allow /etc/hosts.deny 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/hosts.allow
sudo rm /var/lib/selfdef/hosts-allow-baseline.tsv
sudo systemctl start selfdef-hosts-allow.service
```

## Caveats

- **Legit `spawn` uses exist** (logging a connection via
  `spawn /usr/bin/logger ...`); these do not match the
  injection/tmp-exec patterns. A new spawn/twist still fires `warn`
  (re-baseline). The tmp-exec / injection / writable / non-root
  tiers are the high-confidence alert.
- **tcpwrappers is increasingly legacy** — modern `sshd` dropped
  libwrap support, and many services no longer link it; on such
  hosts these files may be inert. They are still consulted by the
  services that do link libwrap, and an attacker may plant a rule
  speculatively.
- **Line continuation** (`\`) can split a spawn command across
  lines; the keyword line is scanned. Review the full rule on a
  `warn`/`alert`.
- **Daily+boot cadence** misses a drop-connect-revert inside the
  window; an audit-rules watch on these files' writes is the
  real-time complement.

## Coexistence

- **hosts-file-watchdog**: `/etc/hosts` resolution; this is the
  tcpwrappers access + spawn/twist exec surface.
- **access-conf-watchdog / securetty / login-defs**: PAM/login
  access policy; this is the network-connection exec policy.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  files; this adds the spawn/twist-command view.
