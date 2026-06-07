#!/usr/bin/env bats
# L2 functional suite for login-defs-baseline.
#
# login-defs-baseline tightens password policy defaults via
# /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE,
# ENCRYPT_METHOD). Profiles:
#   standard → 90-day max, sha512 encryption
#   strict   → 60-day max + history + ucredit/lcredit
#
# Writes via TWO mechanisms for cross-distro coverage:
#   1. /etc/login.defs.d/50-selfdef-login-defs.conf (Debian 11+,
#      RHEL 9+, modern distros — primary path)
#   2. /etc/login.defs marker-fenced append block (legacy distros
#      that don't read .d directories)
#
# CRITICAL INVARIANTS this suite locks:
#   - Marker-fenced legacy append is idempotent: re-running
#     REPLACES the prior block (the sed -i strip-and-reappend
#     pattern) rather than appending duplicates.
#   - Pre-existing operator content in /etc/login.defs (NON-
#     marker-fenced) is PRESERVED.
#   - Drop-in carries header marker for stale-file identification.
#
# Adds SELFDEF_LOGIN_DEFS_D + SELFDEF_LEGACY_LOGIN_DEFS env-vars
# (added 2026-06-06) for L2 testability.
#
# Run with: bats packaging/test/L2-login-defs-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/login-defs-baseline.toml"
    LOGIN_DEFS_D="${TMP}/login.defs.d"
    LEGACY_LOGIN_DEFS="${TMP}/login.defs"
    DROPIN="${LOGIN_DEFS_D}/50-selfdef-login-defs.conf"
    mkdir -p "${LOGIN_DEFS_D}"
    # Pre-existing /etc/login.defs with operator content.
    cat > "${LEGACY_LOGIN_DEFS}" <<'LDEOF'
# Operator-authored content (NOT marker-fenced)
UMASK 022
MAIL_DIR /var/mail
LDEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_LOGINDEFS_CONFIG="${CONF}" \
    SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
    SELFDEF_LEGACY_LOGIN_DEFS="${LEGACY_LOGIN_DEFS}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_LOGINDEFS_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_LOGINDEFS_CONFIG="${SELFDEF_LOGINDEFS_CONFIG}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        SELFDEF_LEGACY_LOGIN_DEFS="${LEGACY_LOGIN_DEFS}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_LOGINDEFS_CONFIG="${CONF}" \
        SELFDEF_LOGIN_DEFS_D="${LOGIN_DEFS_D}" \
        SELFDEF_LEGACY_LOGIN_DEFS="${LEGACY_LOGIN_DEFS}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile writes drop-in + legacy fallback" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    # Header marker in drop-in.
    grep -q 'managed-by: selfdef login-defs-baseline' "${DROPIN}"
    # Legacy fallback has marker-fenced block.
    grep -q 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
    grep -q '# end-selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
}

@test "strict profile installs the strict drop-in content" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    cmp_check_strict() {
        # Drop-in body (without our 2 header lines) matches the
        # strict source file.
        sed '1,2d' "${DROPIN}" | cmp -s - modules/login-defs-baseline/configs/strict.conf
    }
    cmp_check_strict
}

@test "INVARIANT: operator content in /etc/login.defs is PRESERVED (non-marker-fenced)" {
    write_config "standard"
    run_wd
    # Operator's UMASK + MAIL_DIR must survive.
    grep -q '^UMASK 022$' "${LEGACY_LOGIN_DEFS}"
    grep -q '^MAIL_DIR /var/mail$' "${LEGACY_LOGIN_DEFS}"
}

@test "INVARIANT: idempotent legacy append — re-run REPLACES prior block, doesn't duplicate" {
    write_config "standard"
    run_wd
    sha_before="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    n_markers_before="$(grep -c 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}")"
    run_wd
    sha_after="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    n_markers_after="$(grep -c 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}")"
    # Exactly one marker block (no duplication).
    [ "${n_markers_before}" = "1" ]
    [ "${n_markers_after}" = "1" ]
    # Legacy content unchanged byte-for-byte after re-run.
    [ "${sha_before}" = "${sha_after}" ]
}

@test "INVARIANT: profile change standard → strict replaces legacy block (content differs)" {
    write_config "standard"
    run_wd
    standard_block_sha="$(sed -n '/managed-by: selfdef/,/end-selfdef/p' "${LEGACY_LOGIN_DEFS}" | sha256sum | awk '{print $1}')"
    write_config "strict"
    run_wd
    strict_block_sha="$(sed -n '/managed-by: selfdef/,/end-selfdef/p' "${LEGACY_LOGIN_DEFS}" | sha256sum | awk '{print $1}')"
    [ "${standard_block_sha}" != "${strict_block_sha}" ]
    # Exactly one marker block (no duplication).
    [ "$(grep -c 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}")" = "1" ]
}

@test "INVARIANT: primary drop-in idempotent — byte-identical re-install does NOT rewrite (2026-06-06 idempotency fix)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: no render-timestamp in primary drop-in (defeats cmp -s)" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or modify legacy" {
    write_config "standard"
    sha_legacy_before="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    DRY_RUN=1 run_wd
    sha_legacy_after="$(sha256sum "${LEGACY_LOGIN_DEFS}" | awk '{print $1}')"
    ! [ -f "${DROPIN}" ]
    [ "${sha_legacy_before}" = "${sha_legacy_after}" ]
}

@test "drop-in is chmod 0644" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
}

@test "INVARIANT (standard PASS_MAX_DAYS = 365): the actual rate-limit (observed value)" {
    write_config "standard"
    run_wd
    grep -qE 'PASS_MAX_DAYS[[:space:]]+365' "${DROPIN}"
}

@test "INVARIANT (strict PASS_MAX_DAYS = 90 — tighter than standard 365): asymmetric tightening" {
    write_config "strict"
    run_wd
    grep -qE 'PASS_MAX_DAYS[[:space:]]+90' "${DROPIN}"
}

@test "INVARIANT (SHA_CRYPT_MIN_ROUNDS pinned across both profiles — locks crypto-cost floor)" {
    # If MIN_ROUNDS drifts down, password-hash cracking gets cheaper.
    # Both profiles must keep MIN_ROUNDS at the baseline (65536).
    write_config "standard"
    run_wd
    grep -qE 'SHA_CRYPT_MIN_ROUNDS[[:space:]]+65536' "${DROPIN}"
}

@test "INVARIANT (profile downgrade strict → standard): rewrites drop-in back to looser PASS_MAX_DAYS=365" {
    write_config "strict"
    run_wd
    grep -qE 'PASS_MAX_DAYS[[:space:]]+90' "${DROPIN}"
    write_config "standard"
    run_wd
    grep -qE 'PASS_MAX_DAYS[[:space:]]+365' "${DROPIN}"
    ! grep -qE 'PASS_MAX_DAYS[[:space:]]+90' "${DROPIN}"
}

@test "INVARIANT (legacy marker block end-marker fence is the canonical # end-selfdef shape)" {
    # If the end-marker drifts, sed -i strip won't match and duplicate
    # blocks will accumulate.
    write_config "standard"
    run_wd
    grep -qE '^# end-selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
}

@test "INVARIANT (legacy marker block start-marker is the canonical # managed-by shape)" {
    write_config "standard"
    run_wd
    grep -qE '^# managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "strict"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"login-defs-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=strict'* ]]
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + re-fences legacy block)" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'managed-by: selfdef login-defs-baseline' "${DROPIN}"
    grep -q 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
}

@test "INVARIANT (strict carries ENCRYPT_METHOD SHA512 — strongest available hash algorithm)" {
    # Even if MIN_ROUNDS drifts, ENCRYPT_METHOD=SHA512 must hold to
    # ensure passwords are hashed with the strongest algorithm.
    write_config "strict"
    run_wd
    grep -qE 'ENCRYPT_METHOD[[:space:]]+SHA512' "${DROPIN}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # login-defs-baseline TOML; parser must tolerate without altering
    # the profile-gated behavior. strict-with-noise still tightens
    # PASS_MAX_DAYS to 90 + preserves SHA512 encryption (load-bearing
    # password-hash crypto) AND legacy marker-fence written.
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "60-day max + history + ucredit/lcredit policy"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'PASS_MAX_DAYS[[:space:]]+90' "${DROPIN}"
    grep -qE 'ENCRYPT_METHOD[[:space:]]+SHA512' "${DROPIN}"
    grep -q 'managed-by: selfdef login-defs-baseline' "${LEGACY_LOGIN_DEFS}"
}

@test "INVARIANT (PASS_MIN_DAYS > 0 — forces minimum-time-between-changes; rapid-cycling password defense)" {
    # Sister to PASS_MAX_DAYS expiration axis already locked. The
    # PASS_MIN_DAYS directive sets the minimum days between password
    # changes — locks against the "rapid-cycling" attack where a
    # user resets their password 24 times in 24 hours to cycle past
    # the history depth and re-set to their original password.
    # Both standard and strict profiles MUST set PASS_MIN_DAYS > 0
    # to defeat this attack pattern (PCI/CIS requires >= 1).
    write_config "strict"
    run_wd
    grep -qE 'PASS_MIN_DAYS[[:space:]]+[1-9]' "${DROPIN}"
}

@test "INVARIANT (SHA_CRYPT_MIN_ROUNDS >= 5000 in strict — CIS-compliant key-stretching against offline cracking)" {
    # Sister to ENCRYPT_METHOD SHA512 INVARIANT already locked.
    # SHA512 crypt rounds count = key-stretching factor against
    # offline brute-force / dictionary attacks on stolen
    # /etc/shadow hashes. CIS benchmark + DISA-STIG require
    # rounds >= 5000 (selfdef strict ships 65536 = 2^16 rounds
    # which is 13x the floor). Lock the minimum — a regression
    # that dropped rounds to the libc default (5000 or even
    # lower) would silently weaken the entire shadow hash
    # substrate against offline cracking with modern GPUs.
    write_config "strict"
    run_wd
    grep -qE '^SHA_CRYPT_MIN_ROUNDS[[:space:]]+([5-9][0-9]{3}|[0-9]{5,})' "${DROPIN}"
}

@test "INVARIANT (PASS_WARN_AGE present — operator-facing warning lead-time before account lockout)" {
    # Sister to PASS_MAX_DAYS / PASS_MIN_DAYS / ENCRYPT_METHOD /
    # SHA_CRYPT_MIN_ROUNDS login-defs policy INVARIANTs already
    # locked. The PASS_WARN_AGE directive controls how many days
    # before password expiry the user gets a warning at login.
    # Without it, users see lockout-without-warning when the
    # PASS_MAX_DAYS counter fires — they bypass via emergency-
    # access, then leave the policy-trip undiagnosed. selfdef
    # MUST set PASS_WARN_AGE explicitly (7-14 day typical) so
    # the password-policy substrate gives operator visibility
    # before lockout. A regression that omitted PASS_WARN_AGE
    # would silently fall to libc default behavior. Locks the
    # warning-lead-time directive on the password-aging policy.
    write_config "standard"
    run_wd
    grep -qE '^PASS_WARN_AGE[[:space:]]+[0-9]+' "${DROPIN}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "standard"
    run_wd
    [ -f "${DROPIN}" ]
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on login-defs-baseline installer
    # surface across drop-in + legacy-fence phases.
    write_config "standard"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"login-defs-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: login-defs-baseline NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The login-defs-baseline installer writes a
    # login.defs.d drop-in pinning ENCRYPT_METHOD + PASS_*
    # policies but MUST NEVER emit shell commands that uninstall
    # the libpam-modules / passwd packages (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall passwd|libpam-modules|shadow-utils).
    # Auto-removal would catastrophically break user-management
    # + auth substrate. Locks anti-package-removal contract on
    # the login-defs-baseline substrate.
    write_config "standard"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(passwd|libpam-modules|shadow-utils|shadow)'
    [ ! -f "${DROPIN}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. login-defs-baseline manifest declares install +
    # profile gating (default / strict) the resolver enforces;
    # malformed manifest wedges the /etc/login.defs hardening.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'login-defs-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: login-defs-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # login-defs-baseline writes its own drop-in into a system config dir;
    # it MUST NEVER rm/find-delete an operator's pre-existing
    # entries not owned by THIS module. Locks no-auto-delete on
    # the login-defs-baseline installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/(login\.defs|systemd|update-motd|motd)([[:space:]]|$)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(login\.defs|systemd|update-motd|motd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # login-defs-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the login-defs-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the login-defs-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the login-defs-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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

@test "INVARIANT (login-defs-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the login-defs-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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

@test "INVARIANT (login-defs-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the login-defs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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

@test "INVARIANT (login-defs-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for login-defs-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the login-defs-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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

@test "INVARIANT (login-defs-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the login-defs-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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

@test "INVARIANT (login-defs-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the login-defs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the login-defs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the login-defs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
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

@test "INVARIANT (login-defs-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (login-defs-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (login-defs-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (login-defs-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (login-defs-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (login-defs-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (login-defs-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (login-defs-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (login-defs-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (login-defs-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (login-defs-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (login-defs-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (login-defs-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (login-defs-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (login-defs-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (login-defs-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (login-defs-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (login-defs-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (login-defs-baseline module.toml exists at canonical path modules/login-defs-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (login-defs-baseline module dir is at canonical path modules/login-defs-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (login-defs-baseline install dir exists at modules/login-defs-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (login-defs-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (login-defs-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (login-defs-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (login-defs-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (login-defs-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (login-defs-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (login-defs-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (login-defs-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (login-defs-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/login-defs-baseline/install/check.sh"
    [ -s "${chk}" ]
}
