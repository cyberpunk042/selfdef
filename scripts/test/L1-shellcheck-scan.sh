#!/usr/bin/env bash
# L1-shellcheck-scan.sh — shellcheck gate over the shell-script surface
#
# selfdef's hardening appliers (modules/*/install/*.sh), watchdog scanners
# (modules/*/systemd/*.sh), test gates (scripts/), and packaging helpers are
# all bash — 700+ scripts that, until now, no coherence layer shellchecked.
# Two silent-failure classes this catches:
#   - a PARSE error (e.g. an escaped bracket immediately before `]]` — see the
#     2026-05-27 nsswitch-watchdog fix) makes shellcheck ABORT a file, silently
#     skipping the rest of its checks;
#   - an error-severity defect can make a hardening applier or a watchdog a
#     silent no-op (cf. the 2026-05-27 self-integrity/account/pam-config
#     inventory-capture bug class).
# Running shellcheck at error-severity over every .sh makes both land RED.
#
# The ~186 sourced `install/lib.sh` helpers carry no shebang (they are
# sourced in-context by their apply.sh), so a per-file run would bail with
# SC2148 (unknown dialect) and skip ALL dialect-aware checks on them. We
# instead force `--shell=bash` (every selfdef script is bash — 0 POSIX-sh
# shebangs), which makes SC2148 moot AND actually dialect-checks the helper
# libs, so a real error-severity defect in them lands RED too. Every
# error-severity finding (parse errors, real bugs) fails this gate.
#
# Source: extends the MS045/SDD-030 coherence harness.
set -euo pipefail

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "L1-shellcheck-scan SKIP: shellcheck not installed (CI installs it; local convenience only)"
    exit 0
fi

ROOTS=(modules scripts packaging)
mapfile -t files < <(find "${ROOTS[@]}" -name '*.sh' -type f 2>/dev/null | sort)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "L1-shellcheck-scan FAIL: no .sh files found under ${ROOTS[*]}" >&2
    exit 1
fi

out="$(printf '%s\0' "${files[@]}" | xargs -0 shellcheck --severity=error --shell=bash 2>&1 || true)"
if printf '%s' "${out}" | grep -qE 'SC[0-9]+ \('; then
    echo "L1-shellcheck-scan FAIL: error-severity shellcheck findings (parse errors / real bugs):" >&2
    printf '%s\n' "${out}" >&2
    exit 1
fi

echo "L1-shellcheck-scan PASS: ${#files[@]} shell scripts (bash dialect forced), 0 error-severity findings"
exit 0
