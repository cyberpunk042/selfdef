# postfix-exec-watchdog

Boot + daily delta of the Postfix command-execution config against a
learned baseline, plus an ownership + command scan. Catches a
mail-triggered program that Postfix runs as root or a mail user.
MITRE **T1546**.

## Why this matters

Postfix runs external programs from two config surfaces:

- `/etc/postfix/master.cf` — `pipe`/`spawn` services name the
  external program via an `argv=<prog>` token; it runs (as the
  service's `user=`, often root or a mail user) whenever mail of that
  service class flows. This is the mechanism behind content filters,
  custom transports, and delivery agents.
- `/etc/postfix/main.cf` — `*_command` directives (e.g.
  `mailbox_command`) run a program on delivery.

A planted `pipe`/`spawn` `argv=`, or a `*_command`, pointing at a
**writable/attacker program** is **mail-triggered code execution** —
and the attacker can trigger it on demand simply by sending a
matching message.

This is distinct from **mta-loopback-detect** (which watches the
MTA's loopback-only listening posture); this is the Postfix
**command-exec** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any Postfix exec-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No Postfix config present | `ok` | `no_postfix` |
| No delta | `ok` | `postfix_exec_intact` |
| A config / command added / changed / removed | `warn` | `postfix_exec_changed` |
| A config world-writable/non-root, OR an `argv=`/`*_command` program under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `postfix_exec_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `argv:<path>:<prog>` — a `master.cf` pipe/spawn `argv=` program.
- `cmd:<path>:<directive>:<val>` — a `main.cf` `*_command` directive.

## Cadence

`OnBootSec=77min` + `OnCalendar=*-*-* 12:40:00` — extends the
staggered ladder after musl-ld-path (12:35). A planted pipe/spawn
service or `*_command` fires the next time matching mail flows, so
the daily catch bounds dwell time; the boot catch confirms the
config after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — mail delivery of a matching
  class triggers the program.
- **T1059** — the `argv=`/`*_command` program is arbitrary code run
  by Postfix.

## Operator workflow

```bash
journalctl -t selfdef-postfix-exec -n 1 --no-pager
journalctl -t selfdef-postfix-exec-detail --since "1 day ago"

# Inventory the exec points
grep -inE 'argv=' /etc/postfix/master.cf 2>/dev/null
grep -inE '^\s*[a-z0-9_]*command\s*=' /etc/postfix/main.cf 2>/dev/null
postconf -M 2>/dev/null    # canonical master.cf view

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/postfix/master.cf
sudo rm /var/lib/selfdef/postfix-exec-baseline.tsv
sudo systemctl start selfdef-postfix-exec.service
```

## Caveats

- **Legit `argv=` programs are common** (`/usr/lib/dovecot/deliver`,
  SpamAssassin/amavis content filters, `procmail`); a new `argv=`
  with a standard absolute path fires `warn` (re-baseline). The
  tmp-exec / injection / writable / non-root tiers are the
  high-confidence alert.
- **master.cf continuation lines** (leading whitespace) are scanned
  individually; an `argv=` split across a continuation is captured on
  the line that carries it.
- **`content_filter`/`transport_maps`** name a *transport* (resolved
  via master.cf), not a path directly — follow the transport to its
  master.cf `argv=` to see the program.
- **Daily+boot cadence** misses a drop-mail-revert inside the window;
  an audit-rules watch on `/etc/postfix` writes is the real-time
  complement.

## Coexistence

- **mta-loopback-detect**: the MTA listening posture (loopback-only);
  this is the Postfix command-exec surface.
- **rsyslog-exec / syslog-ng-exec / cron watchdogs**: other
  data/time-triggered root-exec surfaces; this is the mail-triggered
  one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  Postfix configs; this adds the argv/command semantic view.
