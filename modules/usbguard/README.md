# usbguard

USB device authorization policy via the [USBGuard](https://usbguard.github.io/)
daemon. Mitigates **T1200 Hardware Additions** — BadUSB,
rubber-ducky HID injectors, malicious U2F-style devices,
unauthorized mass storage attaching.

## Profiles

| Profile | Behavior | When to use |
|---|---|---|
| `permissive` (default) | Allow ALL devices, EMIT a USBGuard event per attach/detach | Default; baseline-gathering; never locks operator out |
| `strict` | DENY ALL, then allow ONLY devices in the operator's baseline | After baseline-generation; production hardening |

**Default is `permissive` to prevent bricking.** A fresh install
of strict mode against an empty baseline locks out the operator's
keyboard. The apply.sh refuse-to-brick guard makes this impossible
by refusing to install strict + empty baseline.

## Baseline generation flow

```bash
# 1. Apply permissive first (default).
selfdefctl modules apply usbguard

# 2. Attach every device the operator legitimately uses
#    (keyboard, mouse, dongles, hubs, headset, storage, etc.).

# 3. Generate the baseline from currently-attached devices.
sudo usbguard generate-policy > /etc/selfdef/usbguard/operator-baseline.rules

# 4. Inspect the baseline. Every line should look like:
#    allow id 046d:c52b serial "..." name "USB Receiver" hash "..."
#    The hash is per-device; identical model + serial → identical hash.

# 5. Switch profile to strict in /etc/selfdef/modules/usbguard.toml
#    and re-apply.
selfdefctl modules apply usbguard
```

## Audit + event flow

The shipped daemon drop-in (`/etc/usbguard/usbguard-daemon.conf.d/
50-selfdef.conf`) sets:
- `AuditBackend=LinuxAudit` — events flow to the kernel audit
  subsystem, which selfdef-collector-auditd already ingests
  (SDD-059).
- `AuditFilePath=/var/log/usbguard/usbguard-audit.log` — also
  written to a dedicated file for operator inspection.
- `PresentDevicePolicy=apply-policy` — already-attached devices
  at daemon start are evaluated against the policy (not
  grandfathered).
- `PresentControllerPolicy=keep` — root hub controllers stay
  allowed across restarts (otherwise USB stack vanishes).

USBGuard's audit events fall under the `USER_ROLE_CHANGE` /
`SYSCALL` auditd record types from a kernel-audit perspective —
the existing 7 typed handlers (SDD-059) capture them in the
generic fallback handler. A future SDD may add a typed USBGuard
handler.

## Operator extension

`/etc/selfdef/usbguard/operator-baseline.rules` is operator-owned.
The module reads it at apply time but NEVER writes to it.
Operator regenerates via `usbguard generate-policy` whenever
device set changes.

## Coexistence

Other USBGuard rules.conf files (operator's hand-edited
`/etc/usbguard/rules.conf` from before module install) are
OVERWRITTEN — the apply step renders a complete new file. If you
had pre-existing rules, copy them into operator-baseline.rules
BEFORE applying the strict profile.

uninstall.sh only deletes `rules.conf` if it carries the selfdef
header marker; operator-replaced files are preserved.

## MITRE coverage

- **T1200** Hardware Additions — direct mitigation.
- **T1052.001** Exfiltration over USB / unauthorized media — denied
  by default in strict mode.
- **T1056.001** Input Capture / Keylogging via HID device — denied
  unless the keylogger device matches a baseline entry (it won't,
  in practice).
