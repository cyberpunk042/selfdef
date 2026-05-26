# ssh-hostkey-watchdog

Boot + daily delta of the SSH host-key fingerprints
(`/etc/ssh/ssh_host_*_key.pub`) against a learned
baseline. A CHANGED host key means the server's
cryptographic identity was swapped — MITM-preparation, an
unauthorized reinstall, or key-theft-then-rotate. Distinct
from `ssh-authkeys-watchdog`, which watches the CLIENT
access keys.

## Why this matters

The SSH host key is the server's IDENTITY — the thing
clients verify (and trust-on-first-use pin) to know
they're connecting to the real box, not an impostor. On a
stable host it NEVER changes. A change is always either
operator-explainable (rotation, reinstall) or an incident:

- **MITM preparation**: an attacker who replaces the host
  key can stand up a proxy with the new key; clients that
  auto-accept the changed fingerprint (or were never
  pinned) connect to the attacker, who relays to the real
  host — capturing credentials + sessions.
- **Unauthorized reinstall / re-image**: a fresh OS gets
  fresh host keys; an unexpected change means someone
  re-provisioned the box.
- **Key theft then rotate**: an attacker who exfiltrated
  the private host key (to impersonate the host elsewhere)
  may rotate to cover the theft.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any host-key change/add/removal → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `hostkeys_intact` |
| A key-type added (e.g. ed25519 enabled) or removed (retired) | `warn` | `hostkey_set_changed` |
| An EXISTING key-type's fingerprint CHANGED | `alert` | `hostkey_changed` (identity swap) |

## What's recorded

`keyfile  type  SHA256-fingerprint` for every
`/etc/ssh/ssh_host_*_key.pub`, via `ssh-keygen -lf`. The
fingerprint is the SHA256 the client sees — so a changed
fingerprint is exactly what would trigger a client's
"REMOTE HOST IDENTIFICATION HAS CHANGED" warning.

## Cadence

`OnBootSec=6min` + `OnCalendar=*-*-* 06:35:00` — host keys
change rarely; a daily check plus a boot catch (a reinstall
reboots) is ample.

## MITRE coverage

- **T1557** Adversary-in-the-Middle — PRIMARY; a swapped
  host key is the setup for SSH MITM.
- **T1563.001** Remote Service Session Hijacking: SSH
  Hijacking — narrowly; a key swap enables session
  interception.
- **T1098.004** — sibling SSH-persistence (this is identity
  vs ssh-authkeys' access).
- **T1552.004** Unsecured Credentials: Private Keys — host
  private-key theft is the motive for a cover-rotation.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-ssh-hostkey -n 1 --no-pager

# Was/now fingerprints
journalctl -t selfdef-ssh-hostkey-detail --since "1 day ago"

# Manual fingerprints
for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$k"; done

# Investigate an alert
# - Did the operator rotate keys / reinstall? If yes → re-baseline.
# - If NOT → INCIDENT: the host identity changed unexpectedly.
#   Notify clients, rotate again under control, investigate access.

# Re-baseline after a legit rotation/reinstall
sudo rm /var/lib/selfdef/ssh-hostkey-baseline.tsv
sudo systemctl start selfdef-ssh-hostkey.service
```

## Caveats

- **First-boot key generation**: cloud images regenerate
  host keys on first boot (cloud-init). Install this module
  AFTER first boot, or expect a one-time baseline at the
  post-regeneration state.
- **Legit rotation**: operators who rotate host keys on a
  schedule fire `hostkey_changed` each time → re-baseline
  as part of the rotation runbook.
- **Adding ed25519** to an RSA-only host is a `warn`
  (new key-type), not an alert — that's a hardening
  improvement, not an identity swap.
- **Daily+boot cadence** is fine because host keys are
  near-static; integrity-sentinel/aide watching /etc/ssh
  is the content-level complement.

## Coexistence

- **ssh-authkeys-watchdog**: the matched sibling — that
  watches CLIENT access keys (who may log in); this
  watches the SERVER identity key (who the host claims to
  be). Access vs identity.
- **ssh-hardening + ssh-moduli-harden**: those harden the
  SSH protocol config + KEX; this watches the identity key
  underneath.
- **integrity-sentinel + aide-bridge**: file-content
  integrity on /etc/ssh; this is the fingerprint-semantic
  version (reports the actual SHA256 a client would see).
- **pam-config / sudoers / account watchdogs**: sibling
  auth-surface detectors.
