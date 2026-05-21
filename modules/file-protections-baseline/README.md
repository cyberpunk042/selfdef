# file-protections-baseline

Renders `/etc/sysctl.d/50-selfdef-file-protections.conf`
enabling the four `fs.protected_*` kernel sysctls.
Defeats the canonical /tmp-race privilege-escalation
class — symlink races, hardlink-to-shadow,
FIFO-redirect-to-root, regular-file race-and-replace.

## Why this matters

`/tmp` is world-writable + sticky. An attacker who lands
as unprivileged user X exploits race conditions against
root-owned processes that operate on /tmp:

| Race | Without protection | With protection |
|---|---|---|
| **Symlink race**: drop `/tmp/foo → /etc/shadow` while root tools open `/tmp/foo` | root tool reads/writes /etc/shadow | EACCES — kernel refuses to follow attacker-owned symlink for non-owner |
| **Hardlink race**: hard-link a root-owned file into /tmp under operator-readable name | operator reads sensitive root file | EPERM — kernel refuses hardlink to file user doesn't own |
| **FIFO race**: drop a FIFO `/tmp/log` then have root tool open it for writing | attacker reads root-tool output (passwords, keys) | EACCES — kernel refuses FIFO open for non-owner in sticky dirs |
| **Regular-file race**: replace /tmp/operator-file between root's stat() and open() | root opens attacker-owned file | EACCES — same as FIFO, for regular files |

Modern distros default these to ON. This module
**guarantees** they stay on across drift (a clueless
operator running `sysctl fs.protected_symlinks=0`
because they read an outdated tutorial).

## Profiles

| Profile | Effect |
|---|---|
| `baseline` (default) | All four ON at kernel-max value |
| `strict` | Same — kernel has no higher level. Reserved for future kernel additions. |

## Files installed

| Path | Purpose |
|---|---|
| `/etc/sysctl.d/50-selfdef-file-protections.conf` | Renders the four sysctls |
| `/etc/selfdef/modules/file-protections-baseline.toml` | Profile selector |

Header marker on the rendered drop-in for uninstall
ownership check.

## Sysctls set

| Sysctl | Value | What it does |
|---|---|---|
| `fs.protected_hardlinks` | 1 | Refuse `link()` to file user doesn't own |
| `fs.protected_symlinks` | 1 | Refuse `open()`-followed symlink in sticky dirs when symlink owner ≠ follower's uid |
| `fs.protected_fifos` | 2 | Refuse `open()` on FIFO in sticky dirs when FIFO owner ≠ opener (mode 2 = applies even to sticky-bit dir owner) |
| `fs.protected_regular` | 2 | Same as fifos but for regular files |

## MITRE coverage

- **T1574.012** Hijack Execution Flow: COR_PROFILER —
  conceptual parallel for the file-race class of
  injection.
- **T1068** Exploitation for Privilege Escalation —
  /tmp-race is one of the oldest local-priv-esc chains.
  Direct defense.
- **T1222.002** File and Directory Permissions
  Modification: Linux and Mac File and Directory
  Permissions Modification — narrowly related;
  hardlink-to-shadow gives the attacker the same effect
  as modifying permissions without doing so.
- **T1083** File and Directory Discovery — narrowly;
  hardlink-create can read file even when traversal-
  permissions deny `ls`.

## Operator workflow

```bash
# Inspect live values
sysctl fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular

# Verify drop-in present
cat /etc/sysctl.d/50-selfdef-file-protections.conf

# Test enforcement (as non-root user)
mkdir /tmp/test
cd /tmp/test
ln -s /etc/shadow shadowlink
cat shadowlink            # EACCES expected (with fs.protected_symlinks=1)

ln /etc/shadow myhardlink  # EPERM expected (with fs.protected_hardlinks=1)

mkfifo /tmp/myfifo
# … now have root try to open /tmp/myfifo for writing → EACCES with =2
```

## Caveats

- **Older kernels (<3.6) lack fs.protected_hardlinks +
  fs.protected_symlinks**. Older kernels (<4.19) lack
  fs.protected_fifos + fs.protected_regular. apply.sh
  soft-fails per missing key; check.sh logs unreadable
  keys.
- **Legitimate non-root processes that hardlink across
  uid boundaries** break (rare — modern build systems
  use cp instead).
- **Some Java / Ruby legacy build scripts** depended on
  /tmp-race-symlink shortcuts for fast file ops. Modern
  versions use mkstemp/mktemp APIs that are race-safe
  and unaffected.
- **Containers**: these sysctls are GLOBAL (host
  scope); containers inherit from host. Setting them in
  a container is usually a no-op (kernel namespace
  restrictions).

## Coexistence

- **sysctl-network-baseline + kernel-yama-baseline +
  kernel-lockdown**: all-orthogonal sysctl families
  (network, ptrace, kernel-info-leak). All four ship
  separate drop-ins (different filename prefixes); no
  conflict.
- **tmpfs-baseline**: tmpfs-baseline mounts /tmp on
  tmpfs with noexec/nosuid/nodev; this module makes
  the tmpfs CONTENT safer.
- **proc-hidepid**: orthogonal — proc visibility
  restriction, not /tmp safety.
- **audit-rules**: complementary — auditd's path
  watches can detect race-attempt patterns, this
  module prevents the race from succeeding.
- **agent-guard + integrity-sentinel**: complementary
  detection layer; this is prevention.
