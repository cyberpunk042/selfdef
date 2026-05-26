# pkcs11-modules-watchdog

Boot + daily delta of the p11-kit PKCS#11 module configs against a
learned baseline, plus an ownership + module-path scan. Catches a
`.module` that loads attacker code into PKCS#11 consumers. MITRE
**T1574**.

## Why this matters

Every p11-kit consumer — GnuPG/`gpgsm`, `ssh`/`ssh-agent` with
PKCS#11, NSS-using browsers, `libp11`, smartcard middleware — loads
the shared object named in each `/etc/pkcs11/modules/*.module`
file's `module:` line whenever it enumerates PKCS#11 modules:

```
# /etc/pkcs11/modules/opensc.module
module: opensc-pkcs11.so
```

A planted `.module` with `module: /tmp/evil.so` (or a writable
absolute path) loads attacker code into a broad set of
**security-sensitive, often credential-handling** processes — a
quiet code-load into exactly the tools that touch keys and
smartcards.

This is distinct from **ld-preload-watchdog** (`LD_PRELOAD` /
`ld.so.preload`) and **ld-so-conf-watchdog** (the dynamic-linker
search path); this is the p11-kit **module-registration** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any PKCS#11 module change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `/etc/pkcs11/modules` present | `ok` | `no_pkcs11_modules` |
| No delta | `ok` | `pkcs11_modules_intact` |
| A `.module` / `module:` added / changed / removed | `warn` | `pkcs11_modules_changed` |
| A `.module` world-writable/non-root, OR a `module:` path under `/tmp` `/var/tmp` `/dev/shm` `/home` or a relative (non-absolute) `module:` path | `alert` | `pkcs11_modules_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.module`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `mod:<path>:<so>` — the `module:` shared-object path/name.

## Cadence

`OnBootSec=72min` + `OnCalendar=*-*-* 12:15:00` — extends the
staggered ladder after sudo-conf (12:10). A planted `.module` takes
effect the next time any p11-kit consumer enumerates PKCS#11
modules, so the daily catch bounds dwell time; the boot catch
confirms the module set after a restart.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable `module:` path loads
  attacker code into PKCS#11 consumers.
- **T1556** Modify Authentication Process — PKCS#11 sits in the
  smartcard/key-auth path; a rogue module can intercept it.

## Operator workflow

```bash
journalctl -t selfdef-pkcs11-modules -n 1 --no-pager
journalctl -t selfdef-pkcs11-modules-detail --since "1 day ago"

# Inventory + what p11-kit actually resolved
cat /etc/pkcs11/modules/*.module 2>/dev/null
p11-kit list-modules 2>/dev/null | grep -iE 'module:|path:'

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/pkcs11/modules/<file>.module
sudo rm /var/lib/selfdef/pkcs11-modules-baseline.tsv
sudo systemctl start selfdef-pkcs11-modules.service
```

## Caveats

- **A bare `module: opensc-pkcs11.so`** (no slash) resolves from the
  trusted system library path and is not flagged. A new `.module`
  still fires `warn` (re-baseline). The writable/relative-path /
  writable / non-root tiers are the high-confidence alert.
- **/usr/share/p11-kit/modules is not watched** — it is
  package-managed (integrity-sentinel / aide-bridge territory); this
  module watches the admin-droppable `/etc/pkcs11/modules`.
- **Hosts without p11-kit** have no `/etc/pkcs11/modules` →
  `no_pkcs11_modules` no-op.
- **Daily+boot cadence** misses a drop-use-revert inside the window;
  an audit-rules watch on `/etc/pkcs11/modules` writes is the
  real-time complement.

## Coexistence

- **ld-preload-watchdog / ld-so-conf-watchdog**: linker preload and
  search-path hijack; this is the p11-kit module-load surface — the
  same "load attacker .so into trusted processes" idea via a
  different mechanism.
- **sudo-conf-watchdog / xorg-config-watchdog**: other targeted
  plugin/module-load surfaces (sudo, X server); this is the PKCS#11
  one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  `.module` files; this adds the `module:`-path semantic view.
