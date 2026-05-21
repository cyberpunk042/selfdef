# unattended-upgrades-config

Configures `unattended-upgrades` (apt-based distros) to auto-
install security-pocket updates. Foundational CVE-mitigation
layer for the IPS host — kernel + glibc + sshd CVE patches land
within hours of upstream release without operator-action.

## Why this is foundational

Every other selfdef hardening module (kernel-lockdown,
audit-rules, host-sentinel, etc.) assumes the underlying packages
are reasonably current. A host running an `sshd` from 2021 has
all the post-2021 CVEs unpatched — selfdef's TracingPolicies +
audit rules can DETECT exploitation, but the operator-better
defense is to never let the CVE-vulnerable binary linger.

unattended-upgrades-config is the "patch the holes" companion to
the rest of the stack.

## Profiles

| Profile | Behavior |
|---|---|
| `security-only` (default) | Auto-install security-pocket updates; never auto-reboot. Operator chooses reboot window. |
| `security-and-reboot` | Same + auto-reboot at 02:00 if kernel/libc update requires it. Won't reboot with interactive users logged in. |

Both profiles:
- Restrict updates to security-pocket origins (Debian-Security,
  Ubuntu-security) only. Feature pockets stay manual.
- Suppress apt's own mail notifications (selfdef-notifier-engine
  is the canonical operator-notify path).
- Keep package downloads on disk for resumable installs.
- Auto-remove unused old kernels (avoids /boot fill-up).

## Files

| Path | Purpose |
|---|---|
| `/etc/apt/apt.conf.d/50selfdef-unattended-upgrades` | Base config (origins, mail, reboot=false, blacklist, retention) |
| `/etc/apt/apt.conf.d/60selfdef-unattended-reboot` | Reboot override (security-and-reboot profile only; numbered higher to override the base file's `false`) |
| `/etc/apt/apt.conf.d/20selfdef-periodic` | Schedule enable (Periodic::Unattended-Upgrade=1) |

Apt loads files in lex order; later-numbered drop-ins override
earlier ones. Operators can layer additional overrides at
`60operator-uu-blacklist.conf` (etc) — selfdef NEVER touches
operator-prefixed files.

## MITRE coverage

Foundational — patches the surface area where every other
technique relies on a CVE:
- **T1190** Exploit Public-Facing Application (sshd CVEs)
- **T1068** Exploitation for Privilege Escalation (kernel + libc CVEs)
- **T1133** External Remote Services (vpn / web-server CVEs)
- **T1059** Command and Scripting Interpreter (shell + interpreter
  CVEs)

When `selfdef-friction-audit` + Tetragon emit detection events,
the operator-readable severity depends on WHETHER the
vulnerability is patched. unattended-upgrades-config keeps the
"patched" half of that question answered.

## Operator workflow

```bash
# Manual check the last UU run.
sudo cat /var/log/unattended-upgrades/unattended-upgrades.log | tail -20

# Force a dry-run (operator inspects what would be installed).
sudo unattended-upgrade --dry-run --debug

# Add an operator-specific package to the blacklist (e.g.
# operator-pinned to a specific version of `containerd.io`):
cat > /etc/apt/apt.conf.d/60operator-uu-blacklist <<EOF
Unattended-Upgrade::Package-Blacklist {
    "containerd.io";
};
EOF
```

## Cross-distro support

apt-based only (Debian / Ubuntu / Mint / Pop / Raspberry Pi OS).
For RHEL/CentOS/Fedora, the future `dnf-automatic-config` module
applies the same pattern with `dnf-automatic`. For Arch, no
direct equivalent exists (Arch's philosophy is operator-driven
upgrades); a future `arch-update-watchdog` module would emit
"updates available" events without installing.

## Interaction with other selfdef modules

- **kernel-lockdown strict**: kernel updates land but
  `kernel.modules_disabled=1` prevents new kernel modules until
  reboot. Operator should reboot promptly OR use the
  security-and-reboot profile.
- **aide-bridge**: legitimate package updates trigger AIDE diffs
  (changed binaries). Operator runs `aide --update` after the
  next UU cycle to rebaseline.
- **integrity-sentinel**: doesn't watch package paths; UU activity
  is invisible to it.
