# rhosts-watchdog

Boot + daily delta of the rsh/rlogin trust files
(`/etc/hosts.equiv` + root's `~/.rhosts` `~/.shosts` +
`/etc/ssh/shosts.equiv`) against a learned baseline, plus an
ownership scan. Catches a wildcard trust that grants passwordless
access. MITRE **T1199** (Trusted Relationship).

## Why this matters

`hosts.equiv` and per-user `~/.rhosts` declare hosts (and users)
trusted for **passwordless** rlogin/rsh/rcp. A wildcard entry is
a classic trusted-relationship backdoor:

```
+              # any host may rlogin as the matching user
+ +            # any host AND any user — total passwordless access
+@netgroup     # any host in the netgroup
```

On a modern host these files are normally **absent**; root's
`~/.rhosts` existing at all is almost always a backdoor. `~/.shosts`
is the SSH equivalent honored when `HostbasedAuthentication` /
`IgnoreRhosts no` is set.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any trust-file change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No trust files present | `ok` | `no_rhosts_files` |
| No delta | `ok` | `rhosts_intact` |
| A trust entry / file added, removed, or changed | `warn` | `rhosts_changed` |
| A `+` wildcard entry; a world-writable/non-root trust file; or the presence of root's `~/.rhosts`/`~/.shosts` | `alert` | `rhosts_trust_backdoor` |

## What's recorded

- `file:<path>:<sha12>` — hash of each trust file.
- `own:<path>:<owner:mode>` — owner + mode.
- `trust:<file>:<entry>` — each normalized trust entry.

A `+` token (wildcard host/user) is the highest-signal — it
grants passwordless access from anywhere; root's `~/.rhosts`
existing is alert-grade by presence alone.

## Cadence

`OnBootSec=32min` + `OnCalendar=*-*-* 08:45:00` — extends the
staggered ladder after capability-conf (08:40). A wildcard trust
is live for the next rlogin/rsh attempt, so the boot catch
confirms the files after a restart.

## MITRE coverage

- **T1199** Trusted Relationship — `hosts.equiv`/`.rhosts` trust
  is the canonical Unix trusted-relationship mechanism.
- **T1078** Valid Accounts — passwordless access as a valid
  account via the trust file.
- **T1133** External Remote Services (adjacent) — rsh/rlogin is
  the remote service the trust enables.

## Operator workflow

```bash
journalctl -t selfdef-rhosts -n 1 --no-pager
journalctl -t selfdef-rhosts-detail --since "1 day ago"

# Inventory
for f in /etc/hosts.equiv /root/.rhosts /root/.shosts /etc/ssh/shosts.equiv; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"
done

# Investigate a trust_backdoor alert — a `+` or a root .rhosts is
# almost never legitimate; remove it:
sudo rm /root/.rhosts            # or remove the `+` line from hosts.equiv
sudo rm /var/lib/selfdef/rhosts-baseline.tsv
sudo systemctl start selfdef-rhosts.service

# Best posture: remove rsh/rlogin entirely (rsh-telnet-disable) — this
# module then no-ops on the trust files (no_rhosts_files).
```

## Caveats

- **rsh/rlogin is legacy** and usually absent on modern hosts →
  `no_rhosts_files` no-op. The module is cheap insurance for
  legacy/embedded targets and catches an attacker who PLANTS a
  trust file (even when sshd honors `~/.shosts`).
- **`~/.shosts` matters even with ssh** when
  `HostbasedAuthentication yes` — sshd-config-watchdog flags that
  directive; this flags the trust file it reads.
- **Daily+boot cadence** misses a plant-connect-revert within the
  window; an audit-rules watch on these paths is the real-time
  complement.

## Coexistence

- **rsh-telnet-disable**: masks the rsh/rlogin/telnet SERVICE
  (prevention); this DETECTS the trust files that weaponize it.
  Prevention + detection pair.
- **sshd-config-watchdog**: flags `HostbasedAuthentication` /
  `IgnoreRhosts no` (which make `~/.shosts` live); this flags the
  `.shosts` trust content.
- **ssh-authkeys-watchdog**: authorized_keys (the modern
  passwordless-access vector); this covers the legacy rhosts one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the files; this adds the wildcard-trust + presence semantic view.
