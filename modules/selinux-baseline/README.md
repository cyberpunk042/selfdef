# selinux-baseline

SELinux Mandatory Access Control posture baseline for
RHEL / Fedora / Rocky / AlmaLinux. The RHEL-side parallel
of `apparmor-baseline` (Debian/Ubuntu). Verifies and sets
the SELinux mode (enforcing / permissive / audit-only)
with a refuse-to-brick gate on the dangerous
disabled→enforcing transition.

## Why this matters

SELinux is the kernel LSM that confines processes to a
mandatory policy — even a root-compromised service is
boxed by its domain's type-enforcement rules. The three
operational modes:

| Mode | Behavior |
|---|---|
| Enforcing | Policy violations BLOCKED + logged. The secure target. |
| Permissive | Violations LOGGED but allowed. Tuning / pre-enforcement. |
| Disabled | No policy at all. The insecure state — and the one operators leave behind after a "just make it work" debugging session. |

A host that should be enforcing but silently drifted to
permissive or disabled has lost an entire defense layer.
This module makes the posture explicit + drift-detectable.

## Profiles

| Profile | Effect |
|---|---|
| `audit` (default) | REPORT live mode + persisted config + recent AVC denial count. No changes. Safe anywhere. |
| `permissive` | Set `SELINUX=permissive` + live `setenforce 0`. Always safe (never bricks). For pre-enforcement tuning. |
| `enforcing` | Set `SELINUX=enforcing` + live `setenforce 1` — but ONLY if currently permissive/enforcing. disabled→enforcing is gated. |

## Refuse-to-brick gate (disabled→enforcing)

Going from **disabled** to **enforcing** requires a full
filesystem **autorelabel** + reboot. Without correct
labels, an enforcing boot can fail (services can't access
their own files; sometimes the host won't boot). So the
enforcing profile, when the host is currently disabled,
refuses unless the config carries:

```toml
profile = "enforcing"
acknowledge_relabel = true
```

With the ack, apply.sh sets `SELINUX=enforcing` + touches
`/.autorelabel` + tells the operator to reboot. The relabel
runs at next boot; the host enters enforcing afterward.
This is the 12th refuse-to-brick gate in the module
ecosystem.

(From permissive→enforcing, no relabel is needed — labels
already exist — so the live `setenforce 1` is applied
directly with no gate.)

## conflicts = apparmor-baseline

A host runs SELinux OR AppArmor, not both. The manifest
declares `conflicts = ["apparmor-baseline"]` so the
install-plan surfaces the mutex. On a Debian/Ubuntu host
(no SELinux), this module is a clean no-op + points the
operator at apparmor-baseline.

## MITRE coverage

- **T1068** Exploitation for Privilege Escalation — SELinux
  type-enforcement confines a compromised service's domain,
  blocking many privilege-escalation primitives.
- **T1611** Escape to Host — SELinux confinement of
  container runtimes (container_t) is a key escape barrier.
- **T1562.001** Impair Defenses: Disable or Modify Tools —
  detecting drift to permissive/disabled catches an
  attacker (or careless operator) who turned SELinux off.
- **T1505.003** Server Software Component: Web Shell —
  SELinux's httpd_t confinement blocks many web-shell
  file-write + exec paths.

## Operator workflow

```bash
# Audit current posture
sudo selfdefctl modules apply selinux-baseline   # audit profile
getenforce
sestatus
sudo ausearch -m AVC -ts recent | audit2why | head

# Tune in permissive first (see what WOULD be denied)
sudo sed -i 's/^profile.*/profile = "permissive"/' \
    /etc/selfdef/modules/selinux-baseline.toml
sudo selfdefctl modules apply selinux-baseline
# ... run workloads, collect denials, write policy with audit2allow ...

# Then enforce (from permissive — no relabel needed)
sudo sed -i 's/^profile.*/profile = "enforcing"/' \
    /etc/selfdef/modules/selinux-baseline.toml
sudo selfdefctl modules apply selinux-baseline

# From a DISABLED host (needs relabel + reboot)
sudo tee /etc/selfdef/modules/selinux-baseline.toml <<EOF
profile = "enforcing"
acknowledge_relabel = true
EOF
sudo selfdefctl modules apply selinux-baseline
sudo reboot       # relabel runs at boot
```

## Caveats

- **disabled→enforcing is the dangerous path** — gated by
  acknowledge_relabel. Always tune in permissive first on
  a host that's been disabled, since years of unlabeled
  file creation can produce a flood of denials.
- **Custom policy is out of scope** — this module sets the
  MODE, not the policy. Operators author policy with
  `audit2allow` / `semodule`. A future `selinux-policy-*`
  module could ship curated booleans.
- **Uninstall does NOT downgrade** — silently dropping MAC
  enforcement is the opposite of safe; the operator
  changes posture explicitly.
- **Cloud images vary**: AWS AL2 = enforcing; some minimal
  cloud images ship permissive or disabled. audit profile
  surfaces the reality.

## Coexistence

- **apparmor-baseline**: the mutually-exclusive parallel
  (declared via conflicts). One per host by distro.
- **tetragon (host-sentinel + agent-guard)**: complementary
  — Tetragon is the eBPF observability/enforcement layer
  ABOVE the LSM; SELinux is the in-kernel MAC. Defense-in-
  depth, both active.
- **audit-rules + auditd-tune**: complementary — SELinux
  AVC denials flow through auditd; the audit stack
  captures + forwards them.
- **kernel-lockdown**: complementary kernel hardening at a
  different layer (kexec/bpf/module-load vs MAC policy).
