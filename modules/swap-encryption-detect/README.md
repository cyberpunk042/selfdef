# swap-encryption-detect

Verifies every active `/proc/swaps` entry is encrypted via
dm-crypt. Catches the case where an operator's host has
swap configured but the swap is on an UNENCRYPTED block
device — meaning kernel memory pages (including
cryptographic key material, passwords typed at the shell,
decrypted secrets) can be evicted to disk in cleartext.

## Why this matters

Linux swap is invisible to most operators. Distros that
do full-disk encryption usually encrypt swap as part of
the install — but plenty of common patterns leave swap
unencrypted:

- **Cloud-VM-default**: cloud-init enables a swap file in
  `/var` (or `/swapfile`) that is NOT inside an
  encrypted filesystem — provider takes a disk snapshot,
  attacker reads keys from the snapshot.
- **Operator-added emergency swap**: `dd if=/dev/zero
  of=/swap bs=1M count=8192 && mkswap /swap && swapon
  /swap` — quick, common, totally unencrypted.
- **Swap on a raw partition** (`/dev/sda5`) on a host
  where root is LUKS-encrypted but swap was forgotten.
- **zswap-with-disk-backing**: zswap caches compressed
  pages in RAM but evicts to backing swap when full.
  If backing swap is unencrypted, the pages land on disk
  unencrypted regardless of zswap's RAM-side compression.

Risk realized: anyone with disk-level access (cloud-provider
snapshot, stolen laptop, post-mortem disk forensics,
warranty-return drive) can recover anything the kernel
ever evicted — including freshly-decrypted SSH keys,
gpg-agent unlocked secrets, browser memory.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on any unsafe swap → systemd unit failed |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| No swap | `ok` | `no_swap` |
| All swap is encrypted (dm-crypt or zram) | `ok` | `all_swap_encrypted` |
| 1 unsafe swap | `warn` | `unsafe_swap_found` |
| 2+ unsafe swap | `alert` | `bulk_unsafe_swap` |
| zswap enabled + ≥1 unsafe backing swap | `alert` | `zswap_with_unsafe_backing` |

## Detection logic

Per `/proc/swaps` entry, classify:

| Name pattern | Safe iff |
|---|---|
| `/dev/zram*` / `/dev/zd*` | Always (in-RAM only) |
| `/dev/mapper/<x>` | `dmsetup table <x>` shows `crypt` target OR `/etc/crypttab` mentions `<x>` |
| `/dev/sd*`, `/dev/nvme*`, `/dev/vd*` | `lsblk -no FSTYPE,TYPE` shows `crypto_LUKS` or `crypt` somewhere up the parent chain |
| File-backed (Type=file) | The filesystem containing the file resolves (via `df`) to a parent block device that is encrypted |
| anything else | UNSAFE (unknown type) |

## Cadence

| Trigger | Why |
|---|---|
| `OnBootSec=5min` | Catch a swap that came up unencrypted on this boot (e.g. crypttab entry failed silently) |
| `OnUnitActiveSec=12h` | Catch operator-added emergency swap (`swapon /tmp/swp`) |
| `RandomizedDelaySec=5min` | Avoid herd-collision |
| `Persistent=true` | Catch up missed runs after host downtime |

## MITRE coverage

- **T1003.008** OS Credential Dumping: /etc/passwd and
  /etc/shadow — narrowly related; swap can hold shadow-
  file decrypted PAM context.
- **T1552.004** Unsecured Credentials: Private Keys —
  primary; private keys (SSH, gpg, X.509) decrypted in
  memory can be evicted to unencrypted swap.
- **T1565.001** Stored Data Manipulation — defender-side
  visibility into a data-at-rest exposure.
- **T1005** Data from Local System — anything-in-memory
  is reachable via swap-disk-forensics if swap is
  unencrypted.

## Operator workflow

```bash
# Inspect current swap
cat /proc/swaps
swapon --show

# Inspect last scan event
journalctl -t selfdef-swap-encryption -n 1 --no-pager

# Investigate a flagged entry
sudo lsblk -f /dev/sda5    # check parent encryption
sudo dmsetup table swap    # check dm-crypt target

# Remediation A — disable unencrypted swap entirely
sudo swapoff /dev/sda5     # AND remove from /etc/fstab
# (acceptable on hosts with enough RAM)

# Remediation B — re-create as encrypted
sudo swapoff /swap
sudo rm /swap
sudo dd if=/dev/urandom of=/dev/mapper/cryptswap bs=1M count=4096
sudo cryptsetup luksFormat /dev/sda5
sudo cryptsetup open /dev/sda5 cryptswap
sudo mkswap /dev/mapper/cryptswap
sudo swapon /dev/mapper/cryptswap
# Add to /etc/crypttab + /etc/fstab for persistence

# Remediation C — switch to zram (RAM-only swap)
sudo apt install zram-tools     # OR dnf install zram-generator
sudo systemctl enable --now zramswap
# AND swapoff the disk swap
```

## Caveats

- **`dmsetup` may not be installed** on minimal containers
  — falls back to /etc/crypttab grep, which can miss
  hand-configured dm-crypt mappings.
- **Multi-disk RAID-backed swap** with mixed encryption
  status (one RAID member encrypted, one not): the scan
  flags as unsafe because parent-walk only checks the
  union view; correct behavior — operator should fix the
  inconsistency.
- **Hibernate/suspend-to-disk**: writes the entire RAM
  image to swap. Unencrypted swap with hibernate enabled
  is the WORST case (full memory dump on disk). This
  module flags it; operator decides whether to disable
  hibernate, encrypt swap, or both.
- **Container hosts**: containers usually share the host's
  swap; this module is host-scope. Containers themselves
  have no separate swap to check.

## Coexistence

- **kdump-disable**: complementary — both modules address
  data-at-rest leak vectors. kdump-disable kills the
  kernel-crash dump path; this module covers swap.
- **kernel-lockdown**: orthogonal hardening; this module
  is detection-side.
- **tmpfs-baseline**: complementary — tmpfs-baseline
  ensures /tmp etc. are noexec/nosuid; this module
  ensures swap isn't a data-leak channel.
- **coredumpd-redirect**: complementary; coredumpd-
  redirect controls user-process core dumps, this
  controls kernel-page swap. Both prevent cleartext
  memory landing in unintended on-disk locations.
- **secure-boot-status**: complementary visibility —
  secure-boot-status reports the trust-chain at boot,
  this reports data-at-rest hygiene.
