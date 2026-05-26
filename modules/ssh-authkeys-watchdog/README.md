# ssh-authkeys-watchdog

Daily + boot delta of every SSH `authorized_keys` file on
the host against a learned baseline. A NEW authorized key
is the MITRE **T1098.004** signature — adding an SSH key is
the single most common Linux backdoor-access persistence
technique.

## Why this matters

An authorized key is a passwordless credential for SSH
access AS that user. An attacker who appends one line to
`~root/.ssh/authorized_keys` gets:
- Persistent root SSH access that **survives password
  changes** (no password involved).
- Access that survives most "rotate the creds" remediation
  (operators rotate passwords, rarely audit every
  authorized_keys).
- A foothold that looks like legitimate key-based auth in
  the logs.

It's one line, it's quiet, and it's the most durable
backdoor on the box. Baselining every authorized_keys +
diffing it catches the injection.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any ADDED key → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| A key REMOVED (only) | `warn` | `authorized_key_removed` (operator cleanup) |
| A key ADDED | `alert` | `authorized_key_added` (the persistence signature) |

## What's recorded

`user  file  keyfingerprint` per key, where the fingerprint
is the sha256 of the **base64 key body** (the `AAAA...`
blob). Hashing the body — not the whole line — means:
- Renaming the key's comment doesn't look like a new key.
- An attacker can't mask an added key by matching an
  existing comment.

Sources scanned:
- Every `~/.ssh/authorized_keys` + `authorized_keys2` for
  every user with a home dir in `/etc/passwd`.
- `/etc/ssh/authorized_keys.d/*` (central key store, if
  used).

## Baseline file

`/var/lib/selfdef/ssh-authkeys-baseline.tsv` (mode 0600).
Re-baseline after legitimately adding a key (new operator,
new automation key):
```bash
sudo rm /var/lib/selfdef/ssh-authkeys-baseline.tsv
sudo systemctl start selfdef-ssh-authkeys.service
```
Preserved across uninstall (forensic).

## Cadence

`OnBootSec=7min` + `OnUnitActiveSec=2h` + jitter — a tight
2h cadence because authorized-key injection is high-impact
persistence; boot catch confirms the key set after every
restart (a key added via offline disk-edit appears at
boot).

## MITRE coverage

- **T1098.004** Account Manipulation: SSH Authorized Keys
  — PRIMARY; this is the exact technique.
- **T1098** Account Manipulation — the broader class.
- **T1078** Valid Accounts — the added key IS a valid
  credential.
- **T1556** Modify Authentication Process — key-based auth
  bypasses the password path entirely.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-ssh-authkeys -n 1 --no-pager

# Per-key detail (user + file + fingerprint)
journalctl -t selfdef-ssh-authkeys-detail --since "1 day ago"

# Manual inventory
for h in $(awk -F: '$6 ~ /^\//{print $6}' /etc/passwd | sort -u); do
    [ -f "$h/.ssh/authorized_keys" ] && { echo "== $h =="; ssh-keygen -lf "$h/.ssh/authorized_keys" 2>/dev/null; }
done

# Investigate an alert
sudo cat ~<user>/.ssh/authorized_keys
# Does the operator recognize the key comment / fingerprint?
# If not → REMOVE it + investigate how it got there:
sudo sed -i '/<the-attacker-key-body>/d' ~<user>/.ssh/authorized_keys

# Re-baseline after a legit key add
sudo rm /var/lib/selfdef/ssh-authkeys-baseline.tsv
sudo systemctl start selfdef-ssh-authkeys.service
```

## Caveats

- **Automation that rotates keys** (config management,
  short-lived CA-signed keys) produces legitimate adds →
  re-baseline after each rotation, OR use SSH CA
  certificates (which don't live in authorized_keys) for
  ephemeral access.
- **AuthorizedKeysCommand** (sshd fetching keys from LDAP/
  a script) bypasses authorized_keys files entirely — this
  module can't see those. Hosts using it should monitor
  the key source instead.
- **2h cadence** misses an add-then-remove within the
  window; tetragon's security_file_open eBPF on
  `*/.ssh/authorized_keys` is the real-time complement.
- **Non-/etc/passwd users** (LDAP/SSSD) with home dirs not
  listed in passwd aren't enumerated — extend via the
  central authorized_keys.d or monitor the directory
  server.

## Coexistence

- **ssh-hardening**: complementary — ssh-hardening sets
  PasswordAuthentication=no (making keys the ONLY auth);
  this watches the key set for backdoor additions. Pair
  them: keys-only + key-monitoring.
- **account-watchdog**: complementary — account-watchdog
  catches a new ACCOUNT / sudo grant; this catches a new
  KEY on an existing account (a stealthier persistence
  that adds no account).
- **cron-job / kernel-module / listening-ports watchdogs**:
  sibling persistence-surface detectors — authorized_keys
  is arguably the most important one on an SSH-reachable
  host.
- **integrity-sentinel + aide-bridge**: would flag the
  authorized_keys file CHANGE; this is the specialized,
  per-key, fingerprint-level version.
