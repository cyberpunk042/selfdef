# musl-ld-path-watchdog

Boot + daily delta of the musl dynamic-linker library path file(s)
against a learned baseline, plus an ownership + path-entry scan.
Catches a writable library directory prepended to the musl loader's
search path. MITRE **T1574.006**.

## Why this matters

On **musl-libc** systems — most importantly **Alpine**, the most
common container base image — the file:

```
/etc/ld-musl-x86_64.path        (or aarch64 / armhf / …)
```

is the **entire library search path** the musl loader uses. It is
the musl analog of glibc's `/etc/ld.so.conf`. Entries are separated
by newline or `:`.

A **prepended writable directory** makes the loader resolve shared
libraries from there first — so an attacker who drops a malicious
`libc.so` / `libcrypto.so` (or any commonly-linked library) into
that dir **hijacks library loads for every dynamically-linked binary
on the host**. On Alpine, where essentially everything is musl-linked,
that is a near-total code-execution foothold.

This is distinct from **ld-so-conf-watchdog** (glibc
`/etc/ld.so.conf[.d]`) and **ld-preload-watchdog** (`LD_PRELOAD` /
`/etc/ld.so.preload`); this is the **musl loader's search-path**
surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any musl path change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `ld-musl-*.path` present | `ok` | `no_musl_path` |
| No delta | `ok` | `musl_path_intact` |
| A path file / entry added / changed / removed | `warn` | `musl_path_changed` |
| A path file world-writable/non-root, OR a library dir under `/tmp` `/var/tmp` `/dev/shm` `/home` | `alert` | `musl_path_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each path file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `dir:<path>:<libdir>` — each library search directory (after
  splitting on newline and `:`).

## Cadence

`OnBootSec=76min` + `OnCalendar=*-*-* 12:35:00` — extends the
staggered ladder after nm-vpn-plugin (12:30). A prepended writable
dir takes effect for the next dynamically-linked process launch
(i.e. almost immediately, for nearly everything), so the daily catch
bounds dwell time; the boot catch confirms the path file after a
restart.

## MITRE coverage

- **T1574.006** Hijack Execution Flow: Dynamic Linker Hijacking —
  the musl search path resolves attacker libraries.
- **T1059** — the hijacked library runs code in every linked
  process.

## Operator workflow

```bash
journalctl -t selfdef-musl-ld-path -n 1 --no-pager
journalctl -t selfdef-musl-ld-path-detail --since "1 day ago"

# Inspect (Alpine)
cat /etc/ld-musl-*.path 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/ld-musl-x86_64.path
sudo rm /var/lib/selfdef/musl-ld-path-baseline.tsv
sudo rc-service selfdef-musl-ld-path start 2>/dev/null || \
  sudo systemctl start selfdef-musl-ld-path.service
```

## Caveats

- **The default musl path** is small and stable (`/lib:/usr/local/lib:/usr/lib`
  or similar); the file is often absent entirely (musl falls back to
  built-in defaults) → `no_musl_path` no-op on glibc-only hosts. Any
  appearance/change is worth a `warn` review; a writable library dir
  is the high-confidence alert.
- **glibc hosts** (Debian/Ubuntu/RHEL) have no `ld-musl-*.path` and
  are covered for the equivalent surface by ld-so-conf-watchdog.
- **musl honors `LD_LIBRARY_PATH`** at runtime too (per-process,
  env-based); this module watches the persistent on-disk system path
  file, not transient env.
- **Daily+boot cadence** misses a prepend-run-revert inside the
  window; an audit-rules watch on `/etc/ld-musl-*.path` writes is the
  real-time complement.

## Coexistence

- **ld-so-conf-watchdog / ld-preload-watchdog**: the glibc
  search-path and preload surfaces; this is the musl search-path
  surface — together they cover dynamic-linker hijacking across both
  libc implementations.
- **pkcs11-modules / gss-mech / krb5-plugins / sudo-conf watchdogs**:
  targeted `.so`-load surfaces; this is the global musl loader path.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  path file; this adds the per-entry writable-dir view.
