# apport-disable

Masks Ubuntu's apport crash-reporting daemon + the
whoopsie report-uploader, and resets
`kernel.core_pattern` if it pipes crashes to apport.
Removes a recurring local-privilege-escalation surface
on Ubuntu / Ubuntu-derived hosts.

## Why this matters

apport is Ubuntu's automatic crash-collection system.
It registers itself as the kernel's `core_pattern`
handler — meaning the kernel invokes the apport binary
(as a privileged pipe reader) whenever ANY process
crashes. That makes apport a high-value local-PE target,
and it has a recurring CVE history:

- **CVE-2021-3899**: apport reads `/proc/<pid>` of the
  crashing process with a TOCTOU race → local root.
- **CVE-2022-1242 / related**: apport path-traversal in
  container-crash handling.
- **CVE-2023-1326**: apport-related privilege escalation
  via crafted crash in a setuid context.
- Multiple earlier `apport` + `whoopsie` issues
  (symlink races in `/var/crash`, info-leak via
  uploaded reports).

The pattern: apport is privileged code on the crash
path that parses attacker-influenced input (the crashing
process's memory + environment). On servers + IPS hosts
that don't need automatic crash-upload, masking apport
removes the surface entirely.

Pairs with `coredumpd-redirect` (which routes core
dumps to a locked-down preservation dir) — apport-disable
removes the apport-specific handler; coredumpd-redirect
controls what systemd-coredump does instead.

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | stop + disable + mask apport.service + apport-autoreport + whoopsie; reset core_pattern if it pipes to apport |
| `stop` | stop + disable only; operator-pull re-enable easier |

apply.sh probes for unit existence first — no-op on
non-Ubuntu hosts where apport isn't installed.

## Units covered

| Unit | Purpose |
|---|---|
| `apport.service` | crash-collection daemon |
| `apport-autoreport.service/.path/.timer` | automatic report submission |
| `whoopsie.service/.path` | Ubuntu error-report uploader |

## core_pattern reset

If `/proc/sys/kernel/core_pattern` currently begins with
`|/usr/share/apport/apport ...`, apply.sh resets it to
the kernel default `core`. Without this, the kernel would
still invoke the (now-masked-service) apport binary on
every crash — the service mask alone doesn't unhook the
core_pattern pipe.

## MITRE coverage

- **T1068** Exploitation for Privilege Escalation —
  PRIMARY; the apport-crash-handler local-PE class.
- **T1055** Process Injection — narrowly; apport reads
  crashing-process memory, a vector abused in some CVEs.
- **T1005** Data from Local System — apport's uploaded
  reports can leak memory contents (passwords, keys) to
  Ubuntu's error-tracker; masking stops the upload.
- **T1552** Unsecured Credentials — crash reports
  historically captured in-memory secrets.

## Operator workflow

```bash
# Verify apport is silent
systemctl status apport whoopsie 2>/dev/null | grep -E 'Loaded:|Active:'
cat /proc/sys/kernel/core_pattern         # should NOT contain apport

# Inspect any existing crash reports (info-leak review)
ls -la /var/crash/ 2>/dev/null

# Re-enable for one-shot debugging (operator-pull)
sudo systemctl unmask apport
sudo systemctl enable --now apport
sudo dpkg-reconfigure apport               # re-wire core_pattern

# After debugging, re-disable
sudo selfdefctl modules apply apport-disable
```

## Caveats

- **Crash debugging**: with apport masked, automatic
  crash collection stops. Developers debugging crashes
  use `coredumpd-redirect` (systemd-coredump) or set
  core_pattern manually for the session.
- **Non-Ubuntu hosts**: apport isn't installed; module
  is a no-op.
- **/var/crash residue**: existing crash reports remain
  on disk (may contain leaked secrets). Operator reviews
  + clears `/var/crash/*` manually.
- **Ubuntu Pro / ESM telemetry**: whoopsie also feeds
  some Ubuntu telemetry; masking it stops that.

## Coexistence

- **coredumpd-redirect**: complementary — that controls
  systemd-coredump's destination + permissions; this
  removes the apport-specific crash handler. Apply both
  on Ubuntu hosts for full crash-path lockdown.
- **kdump-disable**: complementary — kdump handles
  kernel-crash dumps; apport handles userspace-crash
  reports. Different layers.
- **swap-encryption-detect**: complementary data-at-rest
  hygiene (crash dumps + swap both can hold secrets).
- **nscd-disable + services-disable-printing +
  bluetooth-disable**: same service-mask family;
  orthogonal scopes.
