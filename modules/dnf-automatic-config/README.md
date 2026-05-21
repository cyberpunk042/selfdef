# dnf-automatic-config

RHEL/Fedora/Rocky/Alma companion to `unattended-upgrades-config`
(apt-based distros). Configures `dnf-automatic` to install only
security advisory updates + optionally auto-reboot when a
kernel/glibc update requires it.

## Why this matters

Same rationale as unattended-upgrades-config: every selfdef
hardening module assumes the underlying packages are current.
Without auto-patching, a host running an `sshd` from 2022 has
every post-2022 CVE unpatched.

dnf-automatic is the dnf-ecosystem auto-patching primitive.
This module configures it to ship security-only updates by
default (matching unattended-upgrades-config's default
posture).

## Profiles

| Profile | Behavior |
|---|---|
| `security-only` (default) | Auto-install dnf security advisories; never auto-reboot. Operator reboots manually. |
| `security-and-reboot` | Same + auto-reboot via `shutdown -r +5` warning when kernel/glibc update requires it. |

Both profiles:
- `upgrade_type = security` — restricts to advisories tagged
  type=security by upstream (RHEL Security Advisory, Fedora
  FEDORA-YYYY-NNNN advisories tagged Security).
- `random_sleep = 0` — predictable run window (operator-pull
  scheduled via dnf-automatic.timer's OnCalendar).
- `emit_via = stdio` — suppress dnf-automatic's own email
  emitter (selfdef-notifier-engine + journald-collector own
  the operator-notify path).

## File

REPLACES `/etc/dnf/automatic.conf` entirely (dnf-automatic
has no conf.d). On first apply backs up operator's original
to `.selfdef-backup`. Header marker for uninstall ownership
check.

## MITRE coverage

Same as unattended-upgrades-config:
- **T1190** Exploit Public-Facing Application — sshd CVEs.
- **T1068** Exploitation for Privilege Escalation — kernel +
  glibc CVEs.
- **T1133** External Remote Services — vpn / web-server CVEs.
- **T1059** Command and Scripting Interpreter — shell +
  interpreter CVEs.

## Operator workflow

```bash
# Manual check the last dnf-automatic run
sudo journalctl -u dnf-automatic.service -n 30

# Force a dry-run (what would be installed)
sudo dnf-automatic --installupdates --downloadupdates --conf=/etc/dnf/automatic.conf

# Inspect which packages are at security-advisory levels
sudo dnf updateinfo list security

# Add an operator-pinned exclude (e.g. containerd.io held at
# a specific version)
sudo bash -c 'cat >> /etc/dnf/automatic.conf <<EOF

[base]
exclude=containerd.io
EOF'
```

## Coexistence

- **unattended-upgrades-config** (apt-based parallel): operator
  on a cross-distro fleet ships both. Each runs on its native
  distro.
- **package-trust-baseline** (apt-only): RHEL parallel is
  built-in to dnf (signed-by-default; gpgcheck=1 in repo
  configs). A future `dnf-trust-baseline` module would tighten
  this further. For now, dnf-automatic's `upgrade_type=
  security` + RHEL's gpgcheck default suffice.
- **kernel-lockdown** strict: kernel updates land but
  `kernel.modules_disabled=1` blocks late module loading until
  reboot. Pair with security-and-reboot OR operator-pull
  reboot policy.

## Cross-distro support

apt-based: not applicable — use `unattended-upgrades-config`.
dnf-based: Fedora 32+, RHEL 8+, Rocky 8+, AlmaLinux 8+.
Older yum-based hosts (RHEL 7 EOL'd 2024) use `yum-cron` —
separate (future) module.

## Caveats

- **First-time dnf install on a host** with security backlog
  may install many packages on first auto-run. Operator should
  pre-run `dnf upgrade --security` once before flipping this
  module to ensure first-auto-run is bounded.
- **Reboot timing** in security-and-reboot uses `shutdown -r
  +5`. Operator-interactive sessions get a 5min warning. To
  schedule reboot for a quiet window, edit the rendered
  /etc/dnf/automatic.conf's `reboot_command` to invoke `at`
  or systemd-run for delayed execution.
