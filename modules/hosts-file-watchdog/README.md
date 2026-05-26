# hosts-file-watchdog

Boot + daily **entry-level** delta of `/etc/hosts` against a
learned baseline. Catches a name-resolution hijack or blackhole
that lands before DNS is ever consulted. MITRE **T1565.001**
(Stored Data Manipulation) / **T1562.001** (Impair Defenses).

## Why this matters

`/etc/hosts` is consulted **before DNS** (per the nsswitch
`hosts:` order). An attacker who adds or edits an entry silently
controls name resolution host-wide:

```
echo '185.x.x.x  security.ubuntu.com'        >> /etc/hosts  # MITM updates
echo '0.0.0.0    security.debian.org'        >> /etc/hosts  # block patching
echo '10.0.0.9   github.com api.github.com'  >> /etc/hosts  # redirect supply chain
echo '127.0.0.1  telemetry.example.com'      >> /etc/hosts  # blind a security tool
```

Redirecting a package/update/CA host MITMs the software supply
chain; mapping a security-update domain to `0.0.0.0` quietly
**stops patching** (a common ransomware/APT pre-step).

## How it differs from the neighbours

| Module | Watches |
|---|---|
| `nsswitch-watchdog` | the resolver SOURCE MAP (`hosts: files dns …`) |
| `dns-resolver-watchdog` | resolver upstreams + the /etc/hosts line **COUNT** |
| **`hosts-file-watchdog`** | the actual `/etc/hosts` **ENTRIES** (ip→hostname) |

A swap that keeps the line count constant (replace a legit entry
with a hijack) is invisible to the count-only view — this module
catches it.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any /etc/hosts change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No /etc/hosts | `ok` | `no_hosts_file` |
| No delta | `ok` | `hosts_file_intact` |
| Any entry added / removed / changed | `warn` | `hosts_file_changed` |
| An entry maps a sensitive package/security/CA domain (any IP) | `alert` | `hosts_file_sensitive_pin` |

## What's recorded

- `host:<ip>:<hostname>` — one record per (ip, hostname) mapping
  (a multi-name line is split; hostnames lowercased).

## Sensitive-domain alert tier

A hostname matching the curated sensitive set — distro update /
security mirrors (`*.ubuntu.com`, `security.debian.org`,
`*.fedoraproject.org`, …), container/registry/package infra
(`*.docker.com`, `*.github.com`, `*.npmjs.org`, `*.pypi.org`,
`crates.io`, …), CA / OCSP / CRL (`*.letsencrypt.org`,
`*.digicert.com`, `ocsp.`, `crl.`), and OS update services
(`windowsupdate`, `*.microsoft.com`, `*.apple.com`, `dl.google`)
— fires `alert` **regardless of the IP**, because those names
should resolve via DNS and have no business being pinned in
`/etc/hosts`. Pinning them (redirect) or blackholing them
(`0.0.0.0`/`127.0.0.1`) is the hijack signature.

## Cadence

`OnBootSec=17min` + `OnCalendar=*-*-* 07:30:00` — extends the
staggered ladder after boot-script (07:25). A hijack entry takes
effect immediately for every new name lookup, so the boot catch
confirms `/etc/hosts` right after a restart.

## MITRE coverage

- **T1565.001** Stored Data Manipulation — editing `/etc/hosts`
  to alter resolution.
- **T1562.001** Impair Defenses — blackholing security-update /
  telemetry domains to stop patching or blind tooling.
- **T1557**-adjacent — local resolution redirect is a MITM
  position for any service that resolves the pinned name.

## Operator workflow

```bash
journalctl -t selfdef-hosts-file -n 1 --no-pager
journalctl -t selfdef-hosts-file-detail --since "1 day ago"

cat /etc/hosts

# Investigate a sensitive_pin alert
# - Why is a distro/package/CA domain pinned here? Almost never legit.
getent hosts security.ubuntu.com   # what resolution is in effect
# Remove the entry, then re-baseline:
sudo sed -i '/security.ubuntu.com/d' /etc/hosts
sudo rm /var/lib/selfdef/hosts-file-baseline.tsv
sudo systemctl start selfdef-hosts-file.service

# Re-baseline after a legit entry (you pinned an internal host):
sudo rm /var/lib/selfdef/hosts-file-baseline.tsv
sudo systemctl start selfdef-hosts-file.service
```

## Caveats

- **Internal/dev hosts legitimately pinned** in `/etc/hosts` fire
  `warn` on first appearance (re-baseline). The `sensitive_pin`
  alert tier is the high-confidence one and targets only domains
  that should never be pinned.
- **Sensitive-domain list is a curated heuristic**, not
  exhaustive — a niche mirror may not be listed. The entry-delta
  `warn` is the backstop that surfaces every change for review.
- **Daily+boot cadence** misses an inject-resolve-revert within
  the window; an audit-rules watch on `/etc/hosts` writes is the
  real-time complement.

## Coexistence

- **nsswitch-watchdog**: watches the resolver SOURCE order
  (whether `files` is even consulted); this watches the file's
  ENTRIES. An attacker needs `files` ahead of `dns` (the default)
  for a hosts hijack to win — both views together.
- **dns-resolver-watchdog**: resolver upstreams + /etc/hosts
  line count; this is the entry-level complement.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  `/etc/hosts`; this adds the entry-semantic + sensitive-domain
  view.
