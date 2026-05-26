# needrestart-hooks-watchdog

Boot + daily delta of the `needrestart` hook dirs against a learned
baseline, plus an ownership + suspicious-pattern scan. Catches a
script `needrestart` runs as root after every package transaction.
MITRE **T1546**.

## Why this matters

`needrestart` runs every script in these dirs **as root** after
each apt/dpkg transaction — it is wired in via
`/etc/apt/apt.conf.d/99needrestart` (default on Ubuntu 22.04+ and
many Debian hosts) to decide which services to restart:

- `/etc/needrestart/hook.d/*` — collection hooks
- `/etc/needrestart/notify.d/*` — notification hooks
- `/etc/needrestart/restart.d/*` — restart hooks

A dropped script is **root-exec-after-every-package-operation
persistence** — it fires on the attacker's own next package install,
on any admin `apt upgrade`, and on unattended-upgrades runs. The
attacker doesn't even have to wait: installing anything triggers it.

This is distinct from **apt-hooks-watchdog** (apt's own
`DPkg::Pre-Invoke` / `Post-Invoke`) and **dnf-plugins-watchdog**:
`needrestart` is a **separate tool** with its own hook dir set that
apt merely triggers.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any needrestart hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No needrestart hooks present | `ok` | `no_needrestart_hooks` |
| No delta | `ok` | `needrestart_intact` |
| A script added / changed / removed | `warn` | `needrestart_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `needrestart_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=64min` + `OnCalendar=*-*-* 11:25:00` — extends the
staggered ladder after openvpn (11:20). A dropped hook fires on the
next apt/dpkg transaction, so the daily catch bounds dwell time; the
boot catch confirms the hook set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the package transaction is
  the trigger.
- **T1059** — the hook is shell/Perl execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-needrestart -n 1 --no-pager
journalctl -t selfdef-needrestart-detail --since "1 day ago"

# Inventory
ls -la /etc/needrestart/hook.d/ /etc/needrestart/notify.d/ \
       /etc/needrestart/restart.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/needrestart/hook.d/<script>
sudo rm /var/lib/selfdef/needrestart-hooks-baseline.tsv
sudo systemctl start selfdef-needrestart.service
```

## Caveats

- **needrestart ships legitimate hooks** (Perl collectors for
  systemd, sysv, kernel checks); a new root-owned hook with no
  suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **Hosts without needrestart** (most RHEL/Fedora, minimal Debian)
  have no `/etc/needrestart` → `no_needrestart_hooks` no-op.
- **Daily+boot cadence** misses a drop-install-revert inside the
  window; an audit-rules watch on the needrestart dirs' writes is
  the real-time complement. Pair with apt-hooks-watchdog for the
  full package-transaction exec surface.

## Coexistence

- **apt-hooks-watchdog / dnf-plugins-watchdog / dnf-automatic-config /
  unattended-upgrades-config**: the package-manager-native hook
  surfaces; this is the needrestart-specific hook dir set apt
  triggers.
- **kernel-install-hooks-watchdog**: kernel-package transaction
  hooks; needrestart is the userspace-service-restart sibling.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  hooks; this adds the ownership + injection-pattern view.
