# gss-mech-watchdog

Boot + daily delta of the GSSAPI mechanism config against a learned
baseline, plus an ownership + mechanism-path scan. Catches a mech
entry that loads attacker code into GSSAPI/Kerberos consumers. MITRE
**T1574** / **T1556**.

## Why this matters

Every GSSAPI consumer — Kerberized `ssh`/`sshd`, NFSv4 with
`sec=krb5`, OpenLDAP/SASL GSSAPI, `sssd`, `curl --negotiate` —
loads the mechanism shared object named in **field 3** of each line
in:

- `/etc/gss/mech`
- `/etc/gss/mech.d/*.conf`

Line format:

```
# oid_name              oid                       mechanism.so
gssapi_krb5             1.2.840.113554.1.2.2      mech_krb5.so
```

A planted mech entry whose `.so` is a **writable/attacker path**
loads attacker code into auth-handling processes — often running as
root — whenever GSSAPI is initialized. That's code execution inside
exactly the components that establish authenticated sessions.

This is distinct from **ld-preload-watchdog**, **ld-so-conf-watchdog**,
and **pkcs11-modules-watchdog**; this is the **GSSAPI/Kerberos
mechanism-registration** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any GSSAPI mechanism change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `/etc/gss` config present | `ok` | `no_gss_mech` |
| No delta | `ok` | `gss_mech_intact` |
| A mechanism / file added / changed / removed | `warn` | `gss_mech_changed` |
| A mech file world-writable/non-root, OR a mechanism `.so` under `/tmp` `/var/tmp` `/dev/shm` `/home` or relative-with-slash | `alert` | `gss_mech_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each mech file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `mech:<path>:<oidname>:<so>` — each mechanism `.so` (field 3).

## Cadence

`OnBootSec=73min` + `OnCalendar=*-*-* 12:20:00` — extends the
staggered ladder after pkcs11-modules (12:15). A planted mechanism
takes effect the next time any GSSAPI consumer initializes, so the
daily catch bounds dwell time; the boot catch confirms the mech set
after a restart.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable mechanism `.so` loads
  attacker code into GSSAPI consumers.
- **T1556** Modify Authentication Process — the mechanism sits in
  the Kerberos/GSSAPI auth path.

## Operator workflow

```bash
journalctl -t selfdef-gss-mech -n 1 --no-pager
journalctl -t selfdef-gss-mech-detail --since "1 day ago"

# Inventory
cat /etc/gss/mech /etc/gss/mech.d/*.conf 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/gss/mech.d/<file>.conf
sudo rm /var/lib/selfdef/gss-mech-baseline.tsv
sudo systemctl start selfdef-gss-mech.service
```

## Caveats

- **A bare `mech_krb5.so`** (no slash) resolves from the trusted
  GSSAPI mechanism library dir and is not flagged. A new mechanism
  still fires `warn` (re-baseline). The writable/relative-path /
  writable / non-root tiers are the high-confidence alert.
- **Hosts without Kerberos/GSSAPI** have no `/etc/gss` →
  `no_gss_mech` no-op.
- **Daily+boot cadence** misses a drop-auth-revert inside the window;
  an audit-rules watch on `/etc/gss` writes is the real-time
  complement.

## Coexistence

- **ld-preload / ld-so-conf / pkcs11-modules / sudo-conf / xorg-config
  watchdogs**: other targeted `.so`/module-load surfaces; this is the
  GSSAPI/Kerberos mechanism one.
- **krb5 / sssd config**: this watches the mechanism `.so` loaded,
  not the realm/KDC config.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  mech files; this adds the mechanism-`.so` semantic view.
