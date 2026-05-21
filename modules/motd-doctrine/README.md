# motd-doctrine

Login banner module — replaces `/etc/issue`, `/etc/issue.net`,
`/etc/motd` with a legal-warning + selfdef-presence surface.
verbose profile additionally installs a dynamic
`/etc/update-motd.d/50-selfdef-presence` script that surfaces
fresh status on each interactive login.

## Why this matters

Two distinct purposes:

1. **Legal-warning banner** (`/etc/issue`, `/etc/issue.net`).
   Many jurisdictions (US CFAA, UK Computer Misuse Act, EU GDPR
   misuse provisions) require an unambiguous "authorized use only"
   notice for prosecution of unauthorized access. Without the
   banner, an attacker's defense lawyer argues "no clear notice =
   no clear intent to bypass". The shipped banner is operator-
   tunable (edit the templates) but provides the legally-defensible
   default.

2. **selfdef-presence surface** (`/etc/motd`). When an authorized
   operator ssh's in, they see what selfdef is running + where to
   find dashboards / logs / CLI verbs. Reduces cognitive load
   (operator doesn't have to remember 30 module names).

## Profiles

| Profile | `/etc/{issue,issue.net,motd}` | `/etc/update-motd.d/50-selfdef-presence` | Cadence |
|---|---|---|---|
| `minimal` (default) | Static legal warning + selfdef-presence | not installed | Rendered once at apply time |
| `verbose` | Same | Installed (executable bash script) | pam-motd composes /etc/motd at each interactive login → fresh status every login |

## verbose dynamic-motd content

Each interactive login displays:
- `selfdef IPS status @ <UTC timestamp>`
- `active modules: <count>` (from `/etc/selfdef/modules/*.toml`)
- `alerts (24h): <count>` (greps journal for selfdef-* events
  with severity in (alert, high))
- `fail2ban banned IPs: <count>` (via `fail2ban-client banned`)
- `your last login: <lastlog line>` (operator's previous login)

## Operator originals preserved

apply.sh backs up `/etc/issue`, `/etc/issue.net`, `/etc/motd` to
`.selfdef-backup` on first apply. uninstall.sh restores from
backup if the current file is still selfdef-managed (header
marker check). Operator-replaced files (operator hand-edited
post-install) are LEFT ALONE on uninstall — selfdef respects
operator-redirected ownership.

## Header marker

Every rendered file begins with:
```
# === selfdef motd-doctrine-managed (do not hand-edit) ===
# template=<basename> profile=<profile> rendered=<UTC ts>
```

This is the ownership-check primitive used by uninstall.sh
(matches the auditd-tune + pam-faillock + dns-shield pattern).
The hash-comment is harmless in `/etc/issue` + `/etc/motd`
(both are plain text; the line just displays at login). For
`/etc/issue.net` sshd parses it as content; the hash-line just
appears in the pre-auth banner.

## MITRE coverage

- **T1592** Gather Victim Identity Information (defender side) —
  the banner controls what selfdef-presence info is leaked
  pre-auth.
- **T1078** Valid Accounts — operator situational awareness via
  the verbose-profile dynamic motd surfaces recent alerts +
  banned IPs, helping the operator spot account compromise via
  unfamiliar last-login data.

## Cross-distro support

- **Debian/Ubuntu**: pam-motd in /etc/pam.d/sshd + /etc/pam.d/login
  is enabled by default; verbose profile works out of the box.
- **RHEL/Fedora**: pam-motd not enabled by default. Operator runs:
  `echo 'session optional pam_motd.so' | sudo tee -a /etc/pam.d/sshd`.
- **Arch**: minimal profile works (static /etc/motd). Verbose
  needs operator-installed `update-motd` package + pam-motd
  wiring.

## Operator extension

Templates live in `modules/motd-doctrine/templates/`. Operator
edits at build time + re-applies. For per-host customization,
operator drops a sibling `/etc/update-motd.d/60-operator-*` script
(numbered later → renders after ours). selfdef NEVER touches
operator-prefixed files.

## CFAA-banner language

The shipped templates use language that maps onto the CFAA's
"unauthorized access" prong. Operators in non-US jurisdictions
should edit templates/issue*.txt to reference their local statute
(UK CMA, EU GDPR Art. 32, etc.). The template is a default; not
legal advice.
