# ca-certificates-hooks-watchdog

Boot + daily delta of the `ca-certificates` update-hook dir against
a learned baseline, plus an ownership + suspicious-pattern scan.
Catches a script that runs as root whenever the system CA trust
store is regenerated. MITRE **T1546**.

## Why this matters

`update-ca-certificates` runs every script in
`/etc/ca-certificates/update.d/*` **as root** after the system CA
trust store is regenerated. Regeneration happens:

- on every `ca-certificates` package update,
- whenever a local CA is added or removed (any `update-ca-certificates`
  invocation).

A dropped script here runs as root on those routine events. It is
also notable that **the same trust-store-update flow is exactly
where an attacker installing a rogue root CA already operates** — so
a hook in this dir pairs naturally with CA-implant tradecraft (drop
a malicious CA *and* a persistence hook in one motion).

This watchdog watches the **exec surface** (the update.d scripts),
not the trusted-cert list itself.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any ca-certificates-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No ca-certificates hooks present | `ok` | `no_cacert_hooks` |
| No delta | `ok` | `cacert_hooks_intact` |
| A script added / changed / removed | `warn` | `cacert_hooks_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `cacert_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=56min` + `OnCalendar=*-*-* 10:45:00` — extends the
staggered ladder after acpi-hooks (10:40). A dropped update.d hook
fires on the next CA trust-store regeneration, so the daily catch
bounds dwell time; the boot catch confirms the hook set after a
restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the trust-store
  regeneration is the trigger.
- **T1059.004** — the hook is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-cacert-hooks -n 1 --no-pager
journalctl -t selfdef-cacert-hooks-detail --since "1 day ago"

# Inventory
ls -la /etc/ca-certificates/update.d/ 2>/dev/null

# Pairs well with auditing the trust store itself:
ls -la /usr/local/share/ca-certificates/ 2>/dev/null   # local CAs added here

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/ca-certificates/update.d/<hook>
sudo rm /var/lib/selfdef/ca-certificates-hooks-baseline.tsv
sudo systemctl start selfdef-cacert-hooks.service
```

## Caveats

- **Packages ship legitimate hooks** (`jks-keystore` from
  ca-certificates-java, `runtime` helpers); a new root-owned hook
  with no suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **Hosts without the Debian `ca-certificates` package** (RHEL uses
  `update-ca-trust` + p11-kit, which is a different layout) have no
  `/etc/ca-certificates/update.d` → `no_cacert_hooks` no-op.
- **Daily+boot cadence** misses a drop-trigger-revert inside the
  window; an audit-rules watch on the update.d dir's writes is the
  real-time complement. Auditing the trusted-CA list itself (a
  rogue root CA) is the complementary data-surface check.

## Coexistence

- **apt-hooks / dnf-plugins / kernel-install-hooks**: other
  package-/transaction-triggered root-exec dirs; this is the
  CA-trust-store-update hook surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  hooks and the trusted-cert files; this adds the ownership +
  injection-pattern view of the exec dir.
