# openssl-conf-watchdog

Boot + daily delta of the OpenSSL config against a learned baseline,
plus an ownership + engine/provider-module scan. Catches a config
that loads attacker code into every OpenSSL-using process. MITRE
**T1574**.

## Why this matters

The OpenSSL config is read by **every OpenSSL-using process** on the
host — the `openssl` CLI, `curl`, `wget`, and the countless daemons
that link `libcrypto`/`libssl`. It can load code:

- `dynamic_path = /path/engine.so` — an **ENGINE** shared object
  (OpenSSL 1.x).
- `module = /path/provider.so` — a **PROVIDER** shared object
  (OpenSSL 3.x).
- `.include /path/extra.cnf` — pulls in another config file.

searched in `/etc/ssl/openssl.cnf`, `/etc/pki/tls/openssl.cnf`,
`/usr/lib/ssl/openssl.cnf`. A planted `dynamic_path`/`module`
pointing at a **writable/attacker `.so`** loads attacker code into
all of those processes — a near-ubiquitous code-execution foothold
in everything that does TLS/crypto.

This is distinct from **ld-preload-watchdog**,
**pkcs11-modules-watchdog**, and **gss-mech-watchdog**; this is the
OpenSSL **engine/provider load** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any OpenSSL engine/provider change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No openssl.cnf present | `ok` | `no_openssl_conf` |
| No delta | `ok` | `openssl_conf_intact` |
| A config / directive added / changed / removed | `warn` | `openssl_conf_changed` |
| A config world-writable/non-root, OR a `dynamic_path`/`module`/`.include` under `/tmp` `/var/tmp` `/dev/shm` `/home` or relative-with-slash | `alert` | `openssl_conf_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `dynpath:<path>:<so>` — ENGINE `dynamic_path` `.so`.
- `module:<path>:<so>` — PROVIDER `module` `.so`.
- `include:<path>:<inc>` — `.include` target.

`/usr/lib/ssl/openssl.cnf` (often a symlink to `/etc/ssl`) is
de-duplicated by resolved real path.

## Cadence

`OnBootSec=80min` + `OnCalendar=*-*-* 13:00:00` — extends the
staggered ladder after systemd-env (12:50). A planted
`dynamic_path`/`module` takes effect for the next OpenSSL-using
process launch (i.e. almost immediately), so the daily catch bounds
dwell time; the boot catch confirms the config after a restart.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable engine/provider `.so`
  loads attacker code into OpenSSL consumers.
- **T1556** Modify Authentication Process — OpenSSL sits in the
  TLS/crypto path; a rogue provider can weaken or intercept it.

## Operator workflow

```bash
journalctl -t selfdef-openssl-conf -n 1 --no-pager
journalctl -t selfdef-openssl-conf-detail --since "1 day ago"

# Inventory engine/provider/include directives + live providers
grep -inE '^\s*(dynamic_path|module)\s*=|^\s*\.include' \
     /etc/ssl/openssl.cnf /etc/pki/tls/openssl.cnf 2>/dev/null
openssl list -providers 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/ssl/openssl.cnf
sudo rm /var/lib/selfdef/openssl-conf-baseline.tsv
sudo systemctl start selfdef-openssl-conf.service
```

## Caveats

- **Legit providers/engines exist** (the default/legacy/fips
  providers, pkcs11 engine) with standard absolute or bare-name
  paths; a new directive still fires `warn` (re-baseline). The
  writable/relative-path / writable / non-root tiers are the
  high-confidence alert.
- **`OPENSSL_CONF` env override** is a separate (env) vector that
  points OpenSSL at a different config entirely — process-level, not
  watched here; this module watches the on-disk system config.
- **`.include` chains** — this flags a writable `.include` target;
  the included file's own engine/provider lines are seen only if
  that path is also in the watched set.
- **Daily+boot cadence** misses a set-use-revert inside the window;
  an audit-rules watch on the openssl.cnf files' writes is the
  real-time complement.

## Coexistence

- **ld-preload / ld-so-conf / musl-ld-path / pkcs11-modules /
  gss-mech / krb5-plugins watchdogs**: the other `.so`/module-load
  hijack surfaces; this is the OpenSSL engine/provider one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  openssl.cnf files; this adds the engine/provider-path semantic
  view.
