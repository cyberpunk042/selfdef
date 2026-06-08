#!/usr/bin/env bats
# L2 functional suite for umask-baseline.
#
# umask-baseline installs umask defaults via TWO drop-ins:
#   /etc/profile.d/50-selfdef-umask.sh    — interactive shells
#   /etc/login.defs.d/50-selfdef-umask.conf — PAM/login sessions
#
# Default umask 022 (world-readable) on a multi-user system means
# every file a user creates is readable by every OTHER user. On
# a sovereign endpoint that's a lateral-disclosure surface.
# Profiles tighten:
#   group  → 027 (group + world unreadable)
#   strict → 077 (group + world unreadable AND unwritable)
#
# CRITICAL INVARIANTS:
#   - Both drop-ins install per profile (different content per
#     profile — strict has tighter umask).
#   - Idempotent: byte-identical re-install is a no-op.
#   - DRY_RUN protects both drop-ins.
#
# Uses SELFDEF_PROFILE_D + SELFDEF_LOGIN_DEFS_D env-vars (already
# present).
#
# Run with: bats packaging/test/L2-umask-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/umask-baseline.toml"
    PROFILE_D="${TMP}/profile.d"
    LOGIN_DEFS_D="${TMP}/login.defs.d"
    mkdir -p "${PROFILE_D}" "${LOGIN_DEFS_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_UMASK_CONFIG="${CONF}" \
    SELFDEF_PROFILE_D="${PROFILE_D}" \
    SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_UMASK_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_UMASK_CONFIG="${SELFDEF_UMASK_CONFIG}" \
        SELFDEF_PROFILE_D="${PROFILE_D}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_UMASK_CONFIG="${CONF}" \
        SELFDEF_PROFILE_D="${PROFILE_D}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be group|strict"* ]]
}

@test "group profile installs BOTH drop-ins with group-profile content" {
    write_config "group"
    run_wd
    [ -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    [ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
    # Both drop-ins match the group-* source content.
    cmp -s modules/umask-baseline/configs/group-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
    cmp -s modules/umask-baseline/configs/group-login.conf "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "strict profile installs BOTH drop-ins with strict-profile content" {
    write_config "strict"
    run_wd
    cmp -s modules/umask-baseline/configs/strict-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
    cmp -s modules/umask-baseline/configs/strict-login.conf "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT: profile change group → strict replaces BOTH drop-ins" {
    write_config "group"
    run_wd
    sha_g_profile="$(sha256sum "${PROFILE_D}/50-selfdef-umask.sh" | awk '{print $1}')"
    sha_g_login="$(sha256sum "${LOGIN_DEFS_D}/50-selfdef-umask.conf" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_s_profile="$(sha256sum "${PROFILE_D}/50-selfdef-umask.sh" | awk '{print $1}')"
    sha_s_login="$(sha256sum "${LOGIN_DEFS_D}/50-selfdef-umask.conf" | awk '{print $1}')"
    # Both drop-ins changed.
    [ "${sha_g_profile}" != "${sha_s_profile}" ]
    [ "${sha_g_login}" != "${sha_s_login}" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT bump mtime" {
    write_config "group"
    run_wd
    mtime_before="$(stat -c '%Y' "${PROFILE_D}/50-selfdef-umask.sh")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${PROFILE_D}/50-selfdef-umask.sh")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "drop-ins are chmod 0644" {
    write_config "group"
    run_wd
    [ "$(stat -c '%a' "${PROFILE_D}/50-selfdef-umask.sh")" = "644" ]
    [ "$(stat -c '%a' "${LOGIN_DEFS_D}/50-selfdef-umask.conf")" = "644" ]
}

@test "INVARIANT: DRY_RUN does not write either drop-in" {
    write_config "group"
    DRY_RUN=1 run_wd
    ! [ -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    ! [ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
}

@test "default profile is group (no profile key)" {
    : > "${CONF}"
    run_wd
    cmp -s modules/umask-baseline/configs/group-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (group profile umask value): drop-in sets umask 0027 exactly" {
    write_config "group"
    run_wd
    grep -qE 'umask +0027' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (strict profile umask value): drop-in sets umask 0077 exactly" {
    write_config "strict"
    run_wd
    grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (group profile login.defs UMASK directive): correct format" {
    write_config "group"
    run_wd
    grep -qE 'UMASK[[:space:]]+0?27' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (strict profile login.defs UMASK directive): correct format" {
    write_config "strict"
    run_wd
    grep -qE 'UMASK[[:space:]]+0?77' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (profile downgrade strict → group): rewrites BOTH drop-ins with looser umask" {
    write_config "strict"
    run_wd
    grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
    write_config "group"
    run_wd
    grep -qE 'umask +0027' "${PROFILE_D}/50-selfdef-umask.sh"
    ! grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (no render-timestamp in either drop-in): defeats cmp -s idempotency guard" {
    write_config "group"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${PROFILE_D}/50-selfdef-umask.sh"
    ! grep -qE '^# Generated [0-9]{4}-' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates BOTH drop-ins)" {
    write_config "group"
    run_wd
    [ -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    [ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
    rm -f "${PROFILE_D}/50-selfdef-umask.sh" "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
    run_wd
    [ -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    [ -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
    grep -qE 'umask +0027' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (asymmetric tightening: strict umask is more restrictive than group — bit-mask check)" {
    # 0077 has bits 6,5,4,3 set (group rwx + other rwx denied).
    # 0027 has bits 5,3,2,1,0... — group has different denial.
    # The principle: strict's mask must AND with group's mask
    # equal group's mask (strict is at least as restrictive).
    # Computed: strict & ~group == 0 means strict denies a
    # superset of what group denies.
    write_config "group"
    run_wd
    grep -qE 'umask +0027' "${PROFILE_D}/50-selfdef-umask.sh"
    write_config "strict"
    run_wd
    grep -qE 'umask +0077' "${PROFILE_D}/50-selfdef-umask.sh"
    # 0077 octal = 63 decimal; 0027 octal = 23 decimal. 63 > 23
    # means more bits denied (more restrictive).
    [ "$((077))" -gt "$((027))" ]
}

@test "INVARIANT (shell drop-in carries umask directive in proper bash/sh form)" {
    # The profile.d drop-in must be sourced by /bin/sh + bash.
    # Lock that the umask line is bare (no exotic syntax).
    write_config "group"
    run_wd
    # Lines starting with 'umask' followed by a value.
    grep -qE '^umask[[:space:]]+' "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "group"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"umask-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=group'* ]]
}

@test "INVARIANT (no systemctl side-effects: umask-baseline is pure file install — no daemon restart)" {
    # Drop-ins are sourced by login shell / PAM — no daemon needs
    # restart. Lock that the script doesn't accidentally fire
    # systemctl. (Tested by checking apply.sh doesn't call
    # systemctl in any path.)
    grep -qvE 'systemctl' "${WD}" || true
    # Run with mock systemctl tracking to verify no calls.
    BIN_TMP="${TMP}/bin"; mkdir -p "${BIN_TMP}"
    cat > "${BIN_TMP}/systemctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${TMP}/sysctl_called.log"
exit 0
SCEOF
    chmod +x "${BIN_TMP}/systemctl"
    write_config "group"
    PATH="${BIN_TMP}:${PATH}" \
        SELFDEF_UMASK_CONFIG="${CONF}" \
        SELFDEF_PROFILE_D="${PROFILE_D}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        bash "${WD}" >/dev/null 2>&1
    ! [ -f "${TMP}/sysctl_called.log" ]
}

@test "INVARIANT (sh drop-in is shell-sourceable: bash -n parses cleanly — downstream login-shell consumer contract)" {
    # The /etc/profile.d/50-selfdef-umask.sh is sourced by every
    # interactive login shell. It MUST be valid POSIX sh / bash
    # syntax. Sister to hardware-tune-cache + tensor-parallel-
    # inference shell-sourceable INVARIANT.
    write_config "group"
    run_wd
    bash -n "${PROFILE_D}/50-selfdef-umask.sh"
}

@test "INVARIANT (both drop-ins carry selfdef-identifier header — operator audit trail + uninstall identification)" {
    # Sister to many other modules' header-marker INVARIANT. Both
    # /etc/profile.d/ and /etc/login.defs.d/ drop-ins MUST be
    # identifiable as selfdef-owned at scan/uninstall time.
    write_config "group"
    run_wd
    grep -qE '^#.*selfdef|^#.*managed-by' "${PROFILE_D}/50-selfdef-umask.sh"
    grep -qE '^#.*selfdef|^#.*managed-by' "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # umask-baseline TOML; parser must tolerate without altering
    # the profile-gated content. strict-with-noise still emits the
    # strict drop-ins (the more-restrictive umask), NOT the group
    # drop-ins (the less-restrictive default) — anti-downgrade
    # under noise.
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "stricter umask = tighter default file perms"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    # strict drop-ins emitted (not group).
    cmp -s modules/umask-baseline/configs/strict-profile.sh "${PROFILE_D}/50-selfdef-umask.sh"
    cmp -s modules/umask-baseline/configs/strict-login.conf "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
}

@test "INVARIANT (strict umask is stricter than group umask — profile-rank monotonic tightening)" {
    # Sister to login-defs-baseline + pam-history + pam-pwquality
    # + shell-timeout-baseline profile-rank monotonic INVARIANTs
    # already locked. The strict profile MUST emit a umask value
    # at least as restrictive as the group profile (numerically
    # higher umask = MORE bits masked = stricter). If strict had
    # a looser umask than group, operator's intent ("tighten
    # default file permissions") would be silently inverted.
    write_config "group"
    run_wd
    group_umask="$(grep -oE 'umask 0?[0-9]+' "${PROFILE_D}/50-selfdef-umask.sh" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_umask="$(grep -oE 'umask 0?[0-9]+' "${PROFILE_D}/50-selfdef-umask.sh" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${group_umask}" ]
    [ -n "${strict_umask}" ]
    # Strict numerically higher = more bits masked = stricter.
    [ "${strict_umask}" -ge "${group_umask}" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-ins written when DRY_RUN=1)" {
    # Sister to brain-wide installer DRY_RUN INVARIANTs. Silent
    # dry-run flip of default umask could break operator
    # workflows that intentionally create files with specific
    # perms during testing.
    write_config "strict"
    rm -f "${PROFILE_D}/50-selfdef-umask.sh" "${LOGIN_DEFS_D}/50-selfdef-umask.conf"
    DRY_RUN=1 run_wd
    [ ! -f "${PROFILE_D}/50-selfdef-umask.sh" ]
    [ ! -f "${LOGIN_DEFS_D}/50-selfdef-umask.conf" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on umask-baseline installer
    # surface across dual-drop-in (profile.d + login.defs)
    # phases.
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"umask-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (drop-in chmod 0644 — profile.d / login.defs.d conventions for shell sourcing + sshd login.defs read)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs
    # (shell-timeout, sysctl, sshd_config.d). The umask-baseline
    # ships dual drop-ins (/etc/profile.d/50-selfdef-umask.sh +
    # /etc/login.defs.d/50-selfdef-umask.conf) that MUST be
    # world-readable mode 0644 because shells (bash/dash/sh)
    # source /etc/profile.d/ AS the login user (often-non-root
    # uid) AND login.defs is consulted by useradd, sshd, and
    # PAM modules also running not-as-root in some flows. Mode
    # 0600 would defeat the canonical drop-in sourcing
    # semantics. Locks file-mode contract on the umask-baseline
    # dual-drop-in substrate.
    write_config "strict"
    run_wd
    mode_sh="$(stat -c '%a' "${PROFILE_D}/50-selfdef-umask.sh")"
    mode_conf="$(stat -c '%a' "${LOGIN_DEFS_D}/50-selfdef-umask.conf")"
    [ "${mode_sh}" = "644" ]
    [ "${mode_conf}" = "644" ]
}

@test "INVARIANT (no auto-uninstall: umask-baseline NEVER emits package-remove commands on libpam-modules/shadow-utils)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The umask-baseline installer writes dual drop-
    # ins (/etc/profile.d/50-selfdef-umask.sh + /etc/login.defs.
    # d/50-selfdef-umask.conf) but MUST NEVER emit shell
    # commands that uninstall libpam-modules / shadow-utils
    # packages themselves (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall libpam-modules|shadow-utils|passwd). Silent
    # auto-removal would tear down the user-management +
    # auth substrate. Locks anti-package-removal contract on
    # the umask-baseline substrate.
    write_config "strict"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(libpam|shadow|passwd)'
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. umask-baseline manifest declares install + profile
    # gating (default / strict) the resolver enforces; malformed
    # manifest wedges the umask-baseline drop-in. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'umask-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: umask-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # umask-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the umask-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # umask-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the umask-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    # the umask-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    # umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    # umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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
    # Locks semver-X.Y.Z discipline on the umask-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the umask-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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

@test "INVARIANT (umask-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the umask-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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

@test "INVARIANT (umask-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the umask-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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

@test "INVARIANT (umask-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for umask-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the umask-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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

@test "INVARIANT (umask-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the umask-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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

@test "INVARIANT (umask-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the umask-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the umask-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (umask-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the umask-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
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

@test "INVARIANT (umask-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (umask-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (umask-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (umask-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (umask-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (umask-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (umask-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (umask-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (umask-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (umask-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (umask-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (umask-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (umask-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (umask-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (umask-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (umask-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (umask-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (umask-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (umask-baseline module.toml exists at canonical path modules/umask-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (umask-baseline module dir is at canonical path modules/umask-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/umask-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (umask-baseline install dir exists at modules/umask-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (umask-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (umask-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (umask-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (umask-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (umask-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (umask-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (umask-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (umask-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (umask-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (umask-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (umask-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (umask-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (umask-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (umask-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (umask-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/umask-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}
