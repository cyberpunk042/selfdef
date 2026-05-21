# auditd-immutable

Caps the auditd ruleset with `-e 2`, which makes the audit
rule set IMMUTABLE until reboot. After `augenrules --load`
applies this rule, every subsequent `auditctl` modification
request is REJECTED by the kernel.

## Why this matters

An attacker who lands root WILL try to silence audit-rules +
auditd-tune + selfdef-collector-auditd's detection pipeline.
Their first attack:

```bash
# Disable audit entirely
sudo auditctl -e 0

# OR delete the rules selfdef installed
sudo auditctl -D

# OR remove a specific high-signal rule
sudo auditctl -d always,exit -F arch=b64 -S execve -k selfdef-exec
```

Without auditd-immutable, all three succeed instantly. The
detection pipeline goes dark while the attacker performs
post-exploitation steps that audit-rules would have flagged.

With `-e 2` loaded:

```bash
sudo auditctl -e 0
# Error: Operation not supported

sudo auditctl -D
# Error: Operation not supported

sudo auditctl -d ...
# Error: Operation not supported
```

The kernel refuses. The ONLY way to silence audit is to reboot —
which itself generates a high-signal event the operator notices
(unexpected reboot of a production host).

## Profiles

| Profile | -e value | Effect | Refuse-to-brick gate |
|---|---|---|---|
| `audit` (default) | `-e 1` | Audit enabled, rules mutable | none |
| `enforce` | `-e 2` | Rules locked until reboot | `acknowledge_immutable=true` required |

The audit-first pattern is intentional. Operator runs apply
once in audit mode while baseline-tuning audit-rules; once
the rule set is stable, flips to enforce.

## Operator workflow

```bash
# Step 1: install audit-rules + auditd-tune first.
sudo selfdefctl modules apply audit-rules
sudo selfdefctl modules apply auditd-tune

# Step 2: install auditd-immutable in audit profile (default).
sudo selfdefctl modules apply auditd-immutable
auditctl -s | grep enabled    # expect: enabled 1

# Step 3: baseline-tune for 1-2 weeks. Confirm no operator
# workflow needs runtime auditctl -d / -D / -e 0.

# Step 4: edit /etc/selfdef/modules/auditd-immutable.toml:
#   profile = "enforce"
#   acknowledge_immutable = true

# Step 5: apply enforce.
sudo selfdefctl modules apply auditd-immutable

# Step 6: verify (after augenrules --load OR daemon restart OR
# reboot, depending on the auditctl version):
auditctl -s | grep enabled    # expect: enabled 2

# Step 7: verify the lock holds.
sudo auditctl -e 0
# Expected: "Error: Operation not supported"
```

## MITRE coverage

- **T1562.001** Impair Defenses: Disable or Modify Tools —
  blocks the attacker's first move after root-landing (silencing
  audit before doing the loud post-exploitation).
- **T1070** Indicator Removal — narrows the attacker's options
  for log/event tampering.
- **T1014** Rootkit — even sophisticated rootkits that drop
  audit kernel modules cannot disable the running audit
  subsystem without reboot.

## Caveats

- **Reboot is the only undo**. Operator who realizes they need
  to add a new audit rule cannot do so live — must edit
  /etc/audit/rules.d/<file>.rules + reboot.
- **augenrules --load** that adds a NEW rule file is silently
  ignored once -e 2 is active. Operator should add all needed
  rules BEFORE enforce + reboot — adding-after means a wasted
  reboot to pick them up.
- **Some operator workflows that test audit rules** (rapid
  test → tune → test cycles via `auditctl -a ...`) become
  impossible until reboot. Operator iterates in audit profile
  during dev, only enforces on prod hosts.
- **The audit subsystem MUST already be running** when this
  rule loads. If auditd.service isn't active at boot,
  augenrules --load fails + the immutability isn't set.
  audit-rules + auditd-tune handle the service-active path.

## Coexistence

- **audit-rules**: ships the actual rule content (base +
  paranoid profiles). auditd-immutable caps them.
- **auditd-tune**: configures the daemon for the rule volume.
  All three apply in dependency order (audit-rules @main →
  auditd-tune @post → auditd-immutable @post via depends_on).
- **kernel-lockdown strict**: kernel.modules_disabled=1 prevents
  loading new kernel modules that could subvert audit at the
  kernel layer. Both together: attacker cannot disable audit
  AND cannot load a kmod that bypasses it.

## Cross-distro

Universal across all distros that ship the audit subsystem
(Debian, Ubuntu, RHEL, Fedora, openSUSE, Arch with optional
audit package). `auditctl -s` + `augenrules --load` are
standardized.
