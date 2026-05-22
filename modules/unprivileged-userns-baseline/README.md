# unprivileged-userns-baseline

Controls `kernel.unprivileged_userns_clone` — the sysctl
that decides whether unprivileged users may call
`clone(CLONE_NEWUSER)` to create a new user namespace.
The default (=1) is the post-2013 Linux norm and is
REQUIRED for rootless containers + bubblewrap-based
sandboxing. The hardened (=0) value defeats a class of
local privilege-escalation kernel CVEs at the cost of
breaking rootless container workflows.

## Why this matters (both directions)

**Why allow (=1) is legitimate**:
- Rootless `podman` / `docker` / `nerdctl` REQUIRE it
  to create their container's user namespace.
- `bubblewrap` (used by Flatpak, Firefox renderer
  sandbox, Chromium renderer sandbox, Steam) REQUIRES
  it for app sandboxing.
- Container-from-scratch tools like
  `unshare --user --map-root-user` are operator-useful
  development primitives.

**Why deny (=0) is hardening**:
Many kernel privilege-escalation CVEs require attacker
to first create an unprivileged user namespace, then
exploit a kernel bug from inside it (where they're
"root" in the userns and can poke at kernel surfaces
normally root-only):
- **CVE-2022-0185** (fs_context heap overflow): exploited
  via unprivileged_userns_clone.
- **CVE-2023-2640** (OverlayFS use-after-free): same chain.
- **CVE-2022-25636** (nftables OOB write): same.
- **CVE-2023-4147** (nftables UAF): same.
- … pattern repeats every quarter or so.

Disabling unprivileged_userns_clone defeats the
entire chain for hosts that don't need rootless
container workflows (most servers + IPS hosts).

## Profiles

| Profile | Value | Use |
|---|---|---|
| `allow` (default) | 1 | Open posture; matches distro default. Documents the state for drift detection. Compatible with everything. |
| `deny` | 0 | Hardened; breaks rootless containers + bubblewrap. Requires `acknowledge_no_rootless = true` in config. |

## Refuse-to-brick gate

The `deny` profile requires explicit attestation:

```bash
sudo cat > /etc/selfdef/modules/unprivileged-userns-baseline.toml <<EOF
profile = "deny"
acknowledge_no_rootless = true
EOF
sudo selfdefctl modules apply unprivileged-userns-baseline
```

This is the 11th refuse-to-brick gate across the module
ecosystem (joining visudo, sshd-t, kernel-yama
acknowledge_paranoid, etc.).

## File

`/etc/sysctl.d/50-selfdef-userns.conf` rendered per-
profile with selfdef header marker. Loaded at boot via
`sysctl --system`; apply.sh also writes live.

## MITRE coverage

- **T1068** Exploitation for Privilege Escalation —
  PRIMARY; the user-namespace-as-PE-stepping-stone
  class.
- **T1611** Escape to Host — narrowly mitigated; some
  container escape paths leverage the same primitive.
- **T1014** Rootkit — secondary; rootkit installs
  sometimes use the same kernel-CVE chain that
  unprivileged userns enables.

## Operator decision tree

```
Q1: Does this host run any of:
    - rootless podman / docker / nerdctl
    - Flatpak / Steam / Firefox sandbox / Chromium sandbox
    - bubblewrap-based sandboxing
    - operator-development containers via unshare --user
    YES → profile = "allow" (default; this module documents
                            the posture, no behavior change)
    NO  → continue to Q2

Q2: Is this a server / IPS / minimal host with no
    container runtime + no GUI app sandboxing?
    YES → profile = "deny" (set acknowledge_no_rootless = true;
                           defeats a major kernel-PE class)
    UNCERTAIN → profile = "allow" and re-evaluate later
```

## Operator workflow

```bash
# Inspect live value
sysctl kernel.unprivileged_userns_clone

# Verify with the canonical PoC (should fail under deny)
unshare --user --map-root-user echo "userns clone succeeded"

# Switch to deny on a hardened server
sudo cat > /etc/selfdef/modules/unprivileged-userns-baseline.toml <<EOF
profile = "deny"
acknowledge_no_rootless = true
EOF
sudo selfdefctl modules apply unprivileged-userns-baseline

# Revert
sudo sed -i 's/^profile.*/profile = "allow"/' \
    /etc/selfdef/modules/unprivileged-userns-baseline.toml
sudo selfdefctl modules apply unprivileged-userns-baseline
```

## Caveats

- **Some distros (RHEL/CentOS) don't ship the sysctl
  at all** — userns is controlled differently (CONFIG_
  USER_NS=n at kernel-build time OR fully open via
  CAP_SYS_ADMIN). apply.sh's sysctl-write fails on
  those; check.sh logs "unreadable" + treats as no-op.
- **kernel.unprivileged_userns_clone applies only to
  CHILD process creation**. Already-created user
  namespaces stay alive until their last process
  exits.
- **Container hosts running rootless**: do NOT apply
  deny. The setting is GLOBAL — no container-by-
  container exception.
- **Some browser sandboxes degrade gracefully** when
  user namespaces are unavailable — they fall back to
  setuid-helper sandboxing. Firefox + Chromium both
  do this; Flatpak does not (refuses to launch).

## Coexistence

- **kernel-yama-baseline + kernel-lockdown + sysctl-
  network-baseline + file-protections-baseline**:
  orthogonal kernel-feature controls in different
  sysctl families. All apply together with no
  conflict.
- **apparmor-baseline + tetragon**: complementary
  defense layer; userns control limits which kernel
  paths an attacker can reach, MAC/EBPF limit what
  they can do once there.
- **rare-network-protocols-disable + rare-filesystems-
  disable**: complementary — those reduce KERNEL
  attack surface (modules NEVER load), this controls
  whether attackers can REACH kernel paths from
  unprivileged context.
- **proc-hidepid**: orthogonal — proc visibility, not
  userns.
- **agent-guard + integrity-sentinel**: complementary
  detection layer.
