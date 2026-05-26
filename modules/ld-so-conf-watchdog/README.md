# ld-so-conf-watchdog

Boot + daily delta of the dynamic-linker search-path
configuration (`/etc/ld.so.conf` + `/etc/ld.so.conf.d/*`)
against a learned baseline. Catches a library-search-path
injection — the persistent cousin of `LD_PRELOAD`. MITRE
**T1574.001** (Shared Library / DLL search-order hijack).

## Why this matters

`ld.so` searches the directories listed in `ld.so.conf` (+
its `.conf.d` drop-ins, compiled into `/etc/ld.so.cache`)
for shared libraries. An attacker who:

```
echo '/opt/.lib' > /etc/ld.so.conf.d/zz-evil.conf
cp /tmp/trojan-libssl.so.3 /opt/.lib/libssl.so.3
ldconfig
```

makes the linker prefer `/opt/.lib/libssl.so.3` over the
real system library for EVERY dynamically-linked program
that loads it — a system-wide code-injection + persistence
that survives reboot (unlike an `LD_PRELOAD` env var, which
`ld-preload-watchdog` covers). Prepending a writable dir
(`/tmp`, an attacker-owned `/opt/x`) to the search path is
the highest-severity variant: the attacker can swap the
malicious lib in at will.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any search-path change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `ld_so_conf_intact` |
| A conf hash changed / a normal path added | `warn` | `ld_so_conf_changed` |
| A search path REMOVED | `alert` | `ld_so_conf_path_removed` |
| A search path that is WORLD-WRITABLE or under /tmp /var/tmp /dev/shm /home | `alert` | `ld_so_conf_writable_path` (the hijack signature) |

## What's recorded

- `path:<dir>` — each search-path directory (comments +
  `include` directives skipped).
- `file:<conf>:<sha12>` — hash of each conf file (catches
  an edit that reorders entries or adds an include without
  changing the dir set).

A path entry under `/tmp`/`/home` or with a world-writable
mode is flagged hard — an attacker-controllable library
directory on the system linker path is effectively root.

## Cadence

`OnBootSec=9min` + `OnCalendar=*-*-* 06:50:00` — extends
the staggered ladder after pci-device (06:45); boot catch
confirms the linker search path after a restart.

## MITRE coverage

- **T1574.001** Hijack Execution Flow: Dynamic Linker
  Hijacking (search-order) — PRIMARY; the ld.so.conf path
  injection is the persistent SO-search-order hijack.
- **T1574.006** Dynamic Linker Hijacking (LD_PRELOAD) —
  sibling; ld-preload-watchdog covers the env-var vector,
  this covers the config-file vector.
- **T1554** Compromise Host Software Binary — a trojaned
  .so on the path is a compromised system library.
- **T1556** Modify Authentication Process — a hijacked
  libpam / libnss .so subverts auth.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-ld-so-conf -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-ld-so-conf-detail --since "1 day ago"

# Manual inventory
cat /etc/ld.so.conf; cat /etc/ld.so.conf.d/*.conf
ldconfig -v 2>/dev/null | grep -E '^/' | head    # effective dirs

# Investigate an alert
# - Is the added dir writable / under /tmp? → almost certainly evil.
ls -ld <added-dir>
ls -la <added-dir>/*.so*        # what libs were planted?
# Remove + rebuild the cache:
sudo rm /etc/ld.so.conf.d/<evil>.conf
sudo ldconfig

# Re-baseline after a legit library install (a package added
# a conf.d entry for its lib dir)
sudo rm /var/lib/selfdef/ld-so-conf-baseline.tsv
sudo systemctl start selfdef-ld-so-conf.service
```

## Caveats

- **Package installs add conf.d entries** (e.g. CUDA adds
  `/usr/local/cuda/lib64`) → legit add fires `warn`;
  re-baseline. A package would NEVER add a /tmp or
  world-writable path, so the alert tier stays high-signal.
- **ldconfig caches** the resolved paths in
  /etc/ld.so.cache; this module watches the SOURCE config
  (the cache is regenerated from it). aide-bridge watching
  /etc/ld.so.cache is the complement.
- **Daily+boot cadence** misses an inject-ldconfig-act-
  revert within the window; audit-rules watching
  /etc/ld.so.conf.d writes is the real-time complement.
- **The trojaned .so itself** is caught by aide-bridge /
  integrity-sentinel (content) + this catches the PATH that
  makes it preferred.

## Coexistence

- **ld-preload-watchdog**: the matched sibling — that
  watches the LD_PRELOAD env-var vector (T1574.006); this
  watches the ld.so.conf config-file vector (T1574.001).
  Together they cover both dynamic-linker hijack paths.
- **aide-bridge + integrity-sentinel**: content integrity
  on the libraries + /etc/ld.so.cache; this is the
  search-PATH semantic view.
- **pam-config-watchdog**: complementary — a hijacked
  libpam .so (via this path) subverts auth; pam-config
  watches the PAM module hashes.
- **hidden-process / kernel-module / ld-preload
  watchdogs**: the rootkit-detection family — SO-search-
  order hijack is a userland-rootkit persistence technique.
