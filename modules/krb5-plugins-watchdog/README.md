# krb5-plugins-watchdog

Boot + daily delta of the MIT Kerberos config plugin registrations
against a learned baseline, plus an ownership + module-path scan.
Catches a `[plugins]` entry that loads attacker code into the
Kerberos auth path. MITRE **T1574** / **T1556**.

## Why this matters

The MIT Kerberos `[plugins]` section registers `.so` plugins loaded
into `kinit`, the KDC (`krb5kdc`), `kadmind`, sshd's GSSAPI, and
`sssd`, from `/etc/krb5.conf` and `/etc/krb5.conf.d/*.conf`:

```
[plugins]
  clpreauth = {
    module = myplugin:/usr/lib/krb5/plugins/preauth/myplugin.so
  }
  kdcpreauth = { module = foo:/path/to/foo.so }
```

Plugin interfaces include `clpreauth`, `kdcpreauth`, `pwqual`,
`kadm5_hook`, `certauth`, `localauth`, `hostrealm`, … A planted
`module = clpreauth:/tmp/evil.so` loads attacker code **directly
into the Kerberos authentication path** — code that runs in `kinit`
(every Kerberos login), the KDC, and `sssd`.

This is distinct from **gss-mech-watchdog** (the GSSAPI mechanism
glue in `/etc/gss/mech`) and **pkcs11-modules-watchdog**; this is the
MIT-krb5 plugin-interface surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any krb5 plugin change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No krb5 config present | `ok` | `no_krb5_config` |
| No delta | `ok` | `krb5_plugins_intact` |
| A module / file added / changed / removed | `warn` | `krb5_plugins_changed` |
| A config world-writable/non-root, OR a module `.so` under `/tmp` `/var/tmp` `/dev/shm` `/home` or relative-with-slash | `alert` | `krb5_plugins_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each krb5 config.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `module:<path>:<name>:<so>` — each `[plugins]` `module` `.so`.

## Cadence

`OnBootSec=74min` + `OnCalendar=*-*-* 12:25:00` — extends the
staggered ladder after gss-mech (12:20). A planted module takes
effect the next time a Kerberos client/service loads its config, so
the daily catch bounds dwell time; the boot catch confirms the
plugin set after a restart.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable module path loads
  attacker code into Kerberos components.
- **T1556** Modify Authentication Process — `clpreauth`/`kdcpreauth`
  plugins sit directly in the Kerberos auth flow.

## Operator workflow

```bash
journalctl -t selfdef-krb5-plugins -n 1 --no-pager
journalctl -t selfdef-krb5-plugins-detail --since "1 day ago"

# Inventory the [plugins] module registrations
grep -rinE '^\s*module\s*=' /etc/krb5.conf /etc/krb5.conf.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/krb5.conf
sudo rm /var/lib/selfdef/krb5-plugins-baseline.tsv
sudo systemctl start selfdef-krb5-plugins.service
```

## Caveats

- **Legit third-party plugins exist** (e.g. SSSD ships
  `sssd_krb5_locator_plugin.so`, FreeIPA registers plugins under
  `/usr/lib*/krb5/plugins/`); a new `module` pointing at a standard
  absolute path fires `warn` (re-baseline). The
  writable/relative-path / writable / non-root tiers are the
  high-confidence alert.
- **Most hosts have no `[plugins]` module lines** (plugins are
  auto-discovered from the plugin dir); the *appearance* of an
  explicit `module = name:path` is itself worth review.
- **Plugin-directory discovery** (the default load of every `.so`
  in `/usr/lib*/krb5/plugins/`) is a package-managed surface
  (integrity-sentinel territory); this module watches the explicit
  config registrations.
- **Daily+boot cadence** misses a drop-auth-revert inside the
  window; an audit-rules watch on `/etc/krb5.conf*` writes is the
  real-time complement.

## Coexistence

- **gss-mech-watchdog / pkcs11-modules-watchdog / sudo-conf-watchdog
  / xorg-config-watchdog / ld-preload-watchdog**: other targeted
  `.so`/plugin/module-load surfaces; this is the MIT-krb5 plugin
  interface.
- **sssd / FreeIPA config**: this watches the krb5 plugin `.so`
  loaded, not the realm/domain config.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  krb5 configs; this adds the `module`-path semantic view.
