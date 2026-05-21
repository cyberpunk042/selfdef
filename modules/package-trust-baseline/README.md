# package-trust-baseline

Tightens apt's package-trust settings to block:
- Insecure (unsigned) repositories
- Insecure-downgrade of previously-secure repos
- `AllowUnauthenticated` package installs
- Expired or stale Release files
- (strict) SHA1-signed Release metadata
- (strict) Operator-pull suite/codename/origin changes without
  explicit operator-pull edit of sources.list

Apt-based distros (Debian, Ubuntu, Mint, Pop) only. RHEL/Fedora
use `dnf` (parallel future module: `dnf-trust-baseline`).

## Why this matters

T1195.002 Supply Chain Compromise: Compromise Software Supply
Chain — a long-tail attack class with HIGH defender-cost when
realized. Common patterns:

| Attack | What it does | This module blocks |
|---|---|---|
| Compromise mirror, replace package | Pushes a trojaned `bash` package signed with attacker's key | `AllowInsecureRepositories=false` rejects unknown signatures |
| MITM apt-get update | Downgrades https to http; serves attacker repo | `AllowDowngradeToInsecureRepositories=false` refuses |
| Stale signature replay | Replays last-month's Release file to hide a known-bad CVE-vulnerable package | `Check-Valid-Until=true` rejects expired |
| Repo origin substitution | sources.list points at attacker-controlled mirror that signs valid Debian Release with their key | `AllowReleaseInfoChange::Origin=false` (strict) refuses |

## Profiles

| Profile | Coverage |
|---|---|
| `standard` (default) | Block insecure repos + downgrade + AllowUnauthenticated + stale Release + seccomp sandbox + deprecated apt-key off |
| `strict` | standard + reject SHA1 + max Valid-Until 7d + forbid operator-pull suite/codename/origin/label/version changes |

## What this does NOT block

- **Attacker has the upstream signing key** — if Debian/Ubuntu's
  master key is compromised, all signatures verify normally.
  Mitigation: defense-in-depth via aide-bridge (catches the
  resulting binary diff).
- **Pre-installed package backdoors** — package was correctly
  signed by the legitimate maintainer who is themselves
  compromised. Mitigation: clamav-cron + rkhunter-cron may flag
  known-bad signatures.
- **Out-of-band installs** (`dpkg -i ./operator-downloaded.deb`)
  — operator-pull installs bypass the repo + signature chain.
  Operator's responsibility.

## MITRE coverage

- **T1195.002** Supply Chain Compromise: Compromise Software
  Supply Chain — primary; multiple sub-patterns above.
- **T1556** Modify Authentication Process — apt-key disable
  forces per-repo signed-by= which is a stronger trust model
  than the single legacy ring.

## Operator workflow

```bash
# Verify effective config (composed across all apt.conf.d/)
sudo apt-config dump | grep -E 'AllowInsecure|AllowUnauthenticated|Check-Valid'

# Test that an insecure repo gets rejected
sudo bash -c 'echo "deb http://archive.example.invalid/repo bookworm main" > /etc/apt/sources.list.d/test-insecure.list'
sudo apt-get update
# Expected: "E: Repository ... is no longer signed" OR
#           "W: ... NO_PUBKEY" — the install FAILS

# Operator-extension: trust an additional per-repo key (modern
# pattern; signed-by= instead of apt-key add):
sudo install -m 0644 /tmp/operator-vendor.gpg /etc/apt/keyrings/operator-vendor.gpg
sudo bash -c 'echo "deb [signed-by=/etc/apt/keyrings/operator-vendor.gpg] https://vendor.example.com/repo stable main" \
              > /etc/apt/sources.list.d/operator-vendor.list'
sudo apt-get update
```

## Coexistence

- **unattended-upgrades-config**: AUTO-installs security-pocket
  updates ONLY. With package-trust-baseline, those updates ALSO
  require valid signatures — defense-in-depth.
- **kernel-lockdown strict**: kernel updates land but
  `kernel.modules_disabled=1` blocks late module loading. Pair
  with reboot-after-kernel-update policy.
- **aide-bridge**: AIDE diff captures binary changes after a
  package update. Operator runs `aide --update` post-upgrade to
  rebaseline.

## Operator extension

`/etc/apt/apt.conf.d/60-operator-trust.conf` (lex-order LATER →
overrides selfdef's defaults). For operator-pull exemptions only.
selfdef NEVER touches operator-prefixed files.

## Caveats

- **First-time signature errors after apply**: a host with an
  operator-installed third-party repo that was added via
  `apt-key add` (no signed-by=) may start failing
  `apt-get update` after the strict profile applies. Fix: migrate
  to signed-by= pattern per the operator workflow example.
- **Some repos publish only SHA1-signed metadata** (older Ubuntu
  PPAs, abandoned community repos). Standard profile allows
  them; strict profile REJECTS them — operator must replace or
  drop the repo.
- **PPA + custom repo workflows** may need
  `AllowReleaseInfoChange::Suite=true` for `do-release-upgrade`
  to work. Standard profile leaves this default-permissive;
  strict explicitly forbids — operator runs do-release-upgrade
  before applying strict OR temporarily downgrades to standard.
