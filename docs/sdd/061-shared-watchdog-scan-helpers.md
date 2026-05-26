# SDD-061 — Shared watchdog scan helpers in module-lib (v3)

## Implementation status

- [x] D-1 — `module-lib.sh` bumped to v3 with three pure helpers
- [x] D-2 — `selfdef_injection_patterns` canonical pattern set
- [x] D-3 — `selfdef_is_writable_path` writable-location policy
- [x] D-4 — `selfdef_scan_injection` convenience matcher
- [x] D-5 — L2 bats unit coverage (`L2-module-lib-watchdog.bats`)
- [ ] D-6 — incremental migration of existing watchdog modules
      (follow-up; out of scope for this SDD)

## Why now

The detection-watchdog module ecosystem reached ~188 modules. The
~40 newest (skel, sshrc, dhclient/dhcpcd-hooks, kernel-install,
initramfs, systemd-power, acpi, pm-utils, display-manager,
sysusers, tmpfiles, binfmt, ca-certificates, needrestart,
fail2ban-action, bash-completion, fish/csh-config, hosts-allow,
sudo-conf, xorg-config, pkcs11/gss/krb5/nm-vpn/musl/openssl/
kernel-usermodehelper, incron, auditd-plugins, snmpd-exec, autofs,
dhcpd-exec, …) each carry a **byte-identical** copy of the same two
constructs:

1. a `PATTERNS=( … )` array of high-risk command-injection ERE
   patterns (`curl|sh`, `/dev/tcp/`, `bash -i`, `base64 -d`,
   `python -c`, `perl -e`, `eval $(`, `mkfifo`, `setsid`,
   tmp/shm/home exec, …); and
2. a writable-location test (`is_writable` / `is_writable_path`)
   keyed on `/tmp /var/tmp /dev/shm /home`.

Duplication means a refinement to the canonical pattern set (e.g.
adding `ncat -e` or a new LOLBin) must be applied in ~40 places, and
the writable-location policy can drift module-to-module. SDD-006
already established `module-lib.sh` as the single home for shared
module-script logic; this extends it to the watchdog-scan layer.

## Goals

- One source of truth for the injection-pattern set and the
  writable-location policy, sourced from `module-lib.sh`.
- Pure, side-effect-free, independently unit-testable helpers.
- Fully backward compatible: every v1/v2 helper unchanged; the
  version gate lets a module opt in with
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED=3`.

## Non-goals

- Rewriting the existing ~40 watchdog scan scripts to call the
  helpers. They keep their inline copies and continue to pass their
  gates; migration is an incremental follow-up (D-6) done a few
  modules per change with their functional tests re-run each time.
- Changing severity semantics, event JSON shape, or the baseline
  TSV format.

## Design

### D-1 — Version bump to 3 (additive)

`SELFDEF_MODULE_LIB_VERSION` → `3`. The existing version gate
(SDD-006) already lets a caller require a minimum; modules using the
new helpers declare `SELFDEF_MODULE_LIB_VERSION_REQUIRED=3` so an
older install without them fails loud (exit 99) rather than silently
mis-scanning.

### D-2 — `selfdef_injection_patterns`

Prints the canonical high-risk command-injection ERE pattern set,
one per line, to stdout. Callers read it into an array
(`mapfile -t PATTERNS < <(selfdef_injection_patterns)`). The set is
the union actually used across the shipped watchdog modules, so a
migrated module's behavior is identical.

### D-3 — `selfdef_is_writable_path PATH`

Returns 0 iff `PATH` is an absolute path rooted in an
attacker-writable location: `/tmp/`, `/var/tmp/`, `/dev/shm/`, or
`/home/` (the exact policy the modules use today). Returns 1
otherwise (including for the empty string and non-absolute paths —
relative-path suspicion is a separate, module-specific check).

### D-4 — `selfdef_scan_injection TEXT`

Prints the first `selfdef_injection_patterns` entry that matches
`TEXT` (via `grep -E`), or nothing if none match; exit status
reflects match/no-match. Comment-stripping remains the caller's
responsibility (modules strip `^#` lines before scanning, which is
context-specific). This is a convenience matcher for the common
"does this command string contain a known-bad pattern" check.

### D-5 — Test-first

`packaging/test/L2-module-lib-watchdog.bats` asserts each helper's
behavior (pattern set non-empty + contains the load-bearing entries;
writable-path true/false cases incl. empty + relative + the four
roots; scan matches a `curl|sh` payload and rejects a benign line).
Authored before the helpers and observed failing, then green.

## Integration

- `packaging/lib/module-lib.sh` — the helpers land here; shipped to
  `/usr/share/selfdef/lib/module-lib.sh` by the .deb assets list
  (unchanged path).
- L1 `module-contracts` gate and `cargo modules::tests` are
  unaffected (they validate manifests/scripts, not the lib).
- The coherence harness auto-discovers the new
  `packaging/test/L2-*.bats` file by glob.

## Testing

- `bats packaging/test/L2-module-lib-watchdog.bats` — unit coverage
  of the three helpers (red → green).
- `bash scripts/test/L1-module-contracts.sh` — unchanged, stays
  green at 188 modules.
- `cargo test -p selfdef-api --lib modules::tests` — unchanged 16/16.

## References

- SDD-006 — shared module-script lib (the v1/v2 foundation).
- The shipped watchdog modules under `modules/*-watchdog/` whose
  inline `PATTERNS` + writable-path checks this consolidates.
