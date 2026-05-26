# nsswitch-watchdog

Boot + daily delta of the Name Service Switch map
(`/etc/nsswitch.conf`) against a learned baseline. Catches a
rogue NSS module wired into identity/auth/host resolution.
MITRE **T1556** (Modify Authentication Process) +
**T1574** (Hijack Execution Flow via a planted `libnss_*.so`).

## Why this matters

`nsswitch.conf` maps each name database to an ORDERED list of
lookup sources:

```
passwd:   files systemd
group:    files systemd
shadow:   files
hosts:    files mdns4_minimal [NOTFOUND=return] dns
```

Each source name `X` resolves at runtime to a shared object
`libnss_X.so.2`, dlopen'd into EVERY process that calls
`getpwnam` / `getgrnam` / `gethostbyname` / `getspnam` — i.e.
login, sshd, sudo, cron, systemd. An attacker who appends a
source backed by a trojaned module:

```
cp /tmp/libnss_evil.so.2 /lib/x86_64-linux-gnu/
sed -i 's/^passwd:.*/passwd: files evil/' /etc/nsswitch.conf
```

backdoors identity + auth resolution for the whole host. The
trojaned `libnss_evil` can inject a phantom UID-0 account that
appears in no file, leak every credential lookup, or redirect
`hosts:` to attacker DNS — all without touching `/etc/passwd`,
`/etc/shadow`, or the PAM stack.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any nsswitch change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `nsswitch_intact` |
| File hash changed / a known source added or reordered | `warn` | `nsswitch_changed` |
| A database line REMOVED | `alert` | `nsswitch_db_removed` |
| A source token that is NOT a known-standard NSS provider | `alert` | `nsswitch_rogue_source` (the backdoor signature) |

## What's recorded

- `db:<database>:<sources>` — each database line and its
  normalized, whitespace-collapsed source list (action brackets
  like `[NOTFOUND=return]` preserved). Catches add / remove /
  reorder of a source on any database.
- `file:/etc/nsswitch.conf:<sha12>` — hash of the file (catches
  an edit the db parse normalizes away).

A source token outside the known-standard set
(`files dns db compat systemd mymachines nis nisplus ldap sss
winbind mdns* resolve myhostname …`) means a custom
`libnss_<token>.so` is in the resolution path — flagged hard,
because that is exactly the rogue-module signature.

## Cadence

`OnBootSec=10min` + `OnCalendar=*-*-* 06:55:00` — extends the
staggered ladder after ld-so-conf (06:50); boot catch confirms
the resolver-source map after a restart.

## MITRE coverage

- **T1556** Modify Authentication Process — PRIMARY; a rogue
  `libnss_*` module subverts every `getpwnam`/`getspnam` lookup
  used by login/sshd/sudo.
- **T1574** Hijack Execution Flow — the planted `libnss_*.so`
  is loaded into every name-resolving process.
- **T1098** Account Manipulation — a phantom NSS-injected
  UID-0 account is account manipulation that leaves no file
  artifact (account-watchdog watches `/etc/passwd`; this
  watches the resolver that can fabricate accounts beneath it).
- **T1564** Hide Artifacts — an NSS-injected account is hidden
  from file-based enumeration.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-nsswitch -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-nsswitch-detail --since "1 day ago"

# Manual inventory
cat /etc/nsswitch.conf
# What libnss modules actually exist on disk?
ls -la /lib/*/libnss_*.so* /lib/libnss_*.so* 2>/dev/null

# Investigate a rogue_source alert
# - Is the flagged source backed by a libnss_<name>.so you did
#   not install? → almost certainly a backdoor.
getent passwd        # does a phantom UID-0 / unknown account appear?
# Remove the rogue source + module, then re-baseline:
sudo sed -i 's/ evil//' /etc/nsswitch.conf
sudo rm /lib/x86_64-linux-gnu/libnss_evil.so.2
sudo rm /var/lib/selfdef/nsswitch-baseline.tsv
sudo systemctl start selfdef-nsswitch.service

# Re-baseline after a legit directory integration (sssd/ldap
# install adds `sss`/`ldap` to passwd/group — both known, so
# they fire only `warn`, never the rogue tier)
sudo rm /var/lib/selfdef/nsswitch-baseline.tsv
sudo systemctl start selfdef-nsswitch.service
```

## Caveats

- **Legit directory integrations** (sssd, ldap, winbind,
  systemd-machined) add sources to `passwd`/`group`/`hosts`.
  These are in the known-standard set, so they fire `warn`
  (re-baseline), never the `rogue_source` alert — the alert
  tier stays high-signal.
- **Daily+boot cadence** misses an inject-act-revert within
  the window; an audit-rules watch on `/etc/nsswitch.conf`
  writes is the real-time complement.
- **The trojaned `libnss_*.so` content** is caught by
  aide-bridge / integrity-sentinel; this catches the MAP entry
  that activates it. Both are needed: a module on disk that no
  nsswitch line references is inert.
- **`/etc/nsswitch.conf` only.** Some distros also honor a
  `/usr/etc/nsswitch.conf` fallback; the module watches the
  canonical `/etc/` path (override via `SELFDEF_NSSWITCH_CONF`).

## Coexistence

- **pam-config-watchdog**: the matched sibling on the auth
  side — that watches the PAM module stack + hashes; this
  watches the NSS resolver-source map. An attacker subverting
  login picks one or the other; together they cover both
  authentication substrates.
- **account-watchdog**: watches `/etc/passwd` + `/etc/shadow`
  content; this watches the resolver that can fabricate an
  account ABOVE the files (an NSS-injected UID-0 never appears
  in passwd). Complementary layers.
- **ld-so-conf-watchdog / ld-preload-watchdog**: the
  dynamic-linker hijack family — ld-so-conf watches the linker
  SEARCH PATH that makes a trojaned `libnss_*.so` resolvable;
  this watches the nsswitch MAP that references it by name.
- **aide-bridge + integrity-sentinel**: content integrity on
  the `libnss_*.so` objects; this is the resolver-map semantic
  view.
