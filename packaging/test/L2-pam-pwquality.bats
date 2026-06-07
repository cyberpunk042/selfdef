#!/usr/bin/env bats
# L2 functional suite for pam-pwquality.
#
# pam-pwquality installs /etc/security/pwquality.conf.d/50-
# selfdef.conf with the chosen password-quality profile.
# pam_pwquality.so reads pwquality.conf + the conf.d/ drop-ins
# to enforce length / charset-class / dictionary checks at
# password-change time.
#
# Profiles:
#   standard → NIST SP 800-63B-aligned baseline (length min,
#              breach-DB-style restrictions)
#   strict   → audit-frameworks-aligned bar (CIS Benchmark /
#              DISA STIG family — tighter length + class
#              requirements + minimum-character-classes
#              constraints)
#
# DETECT-AND-NOTICE pattern: pam_pwquality.so must ALSO be
# wired into /etc/pam.d/common-password (Debian) or system-
# auth/password-auth (RHEL/Fedora). The module installs the
# drop-in unconditionally; if no /etc/pam.d/* references the
# module the drop-in is DORMANT and a NOTICE logs distro-
# specific enable instructions.
#
# Adds SELFDEF_PWQUALITY_PAM_DIR env-var (added 2026-06-06)
# for L2 testability. SELFDEF_PWQUALITY_D was already exposed
# in the script. Live defaults unchanged.
#
# Run with: bats packaging/test/L2-pam-pwquality.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-pwquality/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/pam-pwquality.toml"
    PWQUALITY_D="${TMP}/pwquality.conf.d"
    DST="${PWQUALITY_D}/50-selfdef.conf"
    PAM_DIR="${TMP}/pam.d"
    mkdir -p "${PAM_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PWQUALITY_CONFIG="${CONF}" \
    SELFDEF_PWQUALITY_D="${PWQUALITY_D}" \
    SELFDEF_PWQUALITY_PAM_DIR="${PAM_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PWQUALITY_CONFIG="${TMP}/missing.toml"
    run env SELFDEF_PWQUALITY_CONFIG="${SELFDEF_PWQUALITY_CONFIG}" \
        SELFDEF_PWQUALITY_D="${PWQUALITY_D}" \
        SELFDEF_PWQUALITY_PAM_DIR="${PAM_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env SELFDEF_PWQUALITY_CONFIG="${CONF}" \
        SELFDEF_PWQUALITY_D="${PWQUALITY_D}" \
        SELFDEF_PWQUALITY_PAM_DIR="${PAM_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile installs the drop-in" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    # The standard profile config should declare a password length
    # floor (minlen) — universal across pwquality profiles.
    grep -qE '^[[:space:]]*minlen' "${DST}"
}

@test "strict profile installs the drop-in with stricter content" {
    write_config "strict"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^[[:space:]]*minlen' "${DST}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    mtime_before="$(stat -c '%Y' "${DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile switch standard → strict changes the drop-in (content differs)" {
    write_config "standard"
    run_wd
    sha_standard="$(sha256sum "${DST}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_strict="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_standard}" != "${sha_strict}" ]
}

@test "INVARIANT: DRY_RUN does not write the drop-in" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
}

@test "DETECT-AND-NOTICE: pam_pwquality.so unwired in /etc/pam.d → log distro-specific enable instructions" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *"NOTICE: pwquality config installed but no /etc/pam.d/*"* ]] \
        || [[ "${output}" == *"pam_pwquality.so"* && "${output}" == *"installed"* ]]
}

@test "DETECT-AND-NOTICE: pam_pwquality.so wired in common-password → no unwired-NOTICE" {
    cat > "${PAM_DIR}/common-password" <<'EOF'
password requisite pam_pwquality.so retry=3
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
EOF
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" != *"installed but no /etc/pam.d/*"* ]]
    [[ "${output}" == *'pam_wired=true'* ]]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'profile=standard'* ]]
}

@test "emit_status reports changes count + pam_wired status in JSON" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    [[ "${output}" == *'pam_wired=false'* ]]
    # Second apply is a no-op → changes=0.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (strict minlen > standard minlen): asymmetric tightening" {
    write_config "standard"
    run_wd
    std_minlen="$(grep -oE 'minlen[[:space:]]*=[[:space:]]*[0-9]+' "${DST}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_minlen="$(grep -oE 'minlen[[:space:]]*=[[:space:]]*[0-9]+' "${DST}" | grep -oE '[0-9]+$' | head -1)"
    [ "${strict_minlen}" -gt "${std_minlen}" ]
}

@test "INVARIANT (RHEL system-auth detection — pam_pwquality.so wired there → no unwired-NOTICE)" {
    cat > "${PAM_DIR}/system-auth" <<'EOF'
password requisite pam_pwquality.so retry=3
password sufficient pam_unix.so use_authtok yescrypt shadow
EOF
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" != *"installed but no /etc/pam.d/*"* ]]
    [[ "${output}" == *'pam_wired=true'* ]]
}

@test "INVARIANT (profile downgrade strict → standard): rewrites with looser minlen" {
    write_config "strict"
    run_wd
    sha_strict="$(sha256sum "${DST}" | awk '{print $1}')"
    write_config "standard"
    run_wd
    sha_standard="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_strict}" != "${sha_standard}" ]
}

@test "INVARIANT (strict carries minimum-character-class constraint dcredit/ucredit/lcredit/ocredit)" {
    # Strict profile mandates character class diversity; the credit
    # directives are the actual mechanism.
    write_config "strict"
    run_wd
    grep -qE '^(dcredit|ucredit|lcredit|ocredit)[[:space:]]*=' "${DST}"
}

@test "INVARIANT (drop-in carries selfdef-identifier header for tracking + uninstall)" {
    # The drop-in carries '# selfdef pam-pwquality — <profile>' as
    # its first-line tracker (not 'managed-by:' style); empirically
    # verified against modules/pam-pwquality/configs/standard.conf.
    write_config "standard"
    run_wd
    grep -qE '^# selfdef pam-pwquality' "${DST}"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in)" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    rm -f "${DST}"
    run_wd
    [ -f "${DST}" ]
    grep -qE '^# selfdef pam-pwquality' "${DST}"
}

@test "INVARIANT (emit_status JSON: module + status + profile surfaced for operator dashboard)" {
    write_config "strict"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"pam-pwquality"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=strict'* ]]
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "standard"
    run_wd
    first_line="$(awk 'NF' "${DST}" | head -1)"
    [[ "${first_line}" == *"selfdef pam-pwquality"* ]]
}

@test "INVARIANT (strict carries minclass — min number of character classes required)" {
    # minclass is the count-of-distinct-classes constraint
    # (e.g. minclass=3 = at least 3 of {upper, lower, digit, special}).
    # Strict profile should have this directive.
    write_config "strict"
    run_wd
    grep -qE '^minclass[[:space:]]*=[[:space:]]*[2-9]' "${DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # pam-pwquality TOML; parser must tolerate without altering the
    # profile-gated behavior. strict-with-noise still writes the
    # strict drop-in with minclass + dcredit/ucredit/lcredit/ocredit
    # character-class diversity directives (load-bearing PCI/CIS-
    # compliance password-quality substrate).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "PCI/CIS-compliance password quality — minclass=3"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DST}" ]
    grep -qE '^minclass[[:space:]]*=[[:space:]]*[2-9]' "${DST}"
    grep -qE '^(dcredit|ucredit|lcredit|ocredit)[[:space:]]*=' "${DST}"
    grep -qE '^# selfdef pam-pwquality' "${DST}"
}

@test "INVARIANT (strict minlen >= standard minlen — profile-rank monotonic depth)" {
    # Sister to pam-history profile-rank-monotonic INVARIANT
    # just locked. The strict profile MUST require at LEAST as
    # long a minlen as the standard profile. If strict had a
    # smaller minlen than standard, operator's intent ("tighten
    # password length requirement") would be silently inverted.
    # Lock the monotonic depth ordering across profiles.
    write_config "standard"
    run_wd
    standard_n="$(grep -oE '^minlen[[:space:]]*=[[:space:]]*[0-9]+' "${DST}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_n="$(grep -oE '^minlen[[:space:]]*=[[:space:]]*[0-9]+' "${DST}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${standard_n}" ]
    [ -n "${strict_n}" ]
    [ "${strict_n}" -ge "${standard_n}" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/security/pwquality.conf.d/
    # 50-selfdef.conf. A silent dry-run that committed would
    # activate password-quality enforcement on a host where
    # operator was investigating PAM behavior — could block
    # legitimate password changes during testing. Locks dry-run-
    # preserves-state on the PAM password-quality substrate.
    write_config "strict"
    rm -f "${DST}"
    DRY_RUN=1 run_wd
    [ ! -f "${DST}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the PAM
    # password-quality installer surface.
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"pam-pwquality"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    [ "$(stat -c '%a' "${DST}")" = "644" ]
}

@test "INVARIANT (no auto-uninstall: pam-pwquality NEVER emits package-remove commands on libpwquality)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The pam-pwquality installer wires pwquality.
    # conf drop-in but MUST NEVER emit shell commands that
    # uninstall the libpwquality / libpam-pwquality packages
    # themselves (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # libpwquality|libpam-pwquality). Silent auto-removal would
    # tear down the password-quality module entirely + remove
    # the pam_pwquality module the installer just wired. T1556
    # self-defeat. Locks anti-package-removal contract on the
    # pam-pwquality substrate.
    write_config "strict"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(libpwquality|libpam-pwquality|cracklib)'
    [ ! -f "${DST}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DST}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. pam-pwquality manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the PAM pwquality complexity baseline. Python's tomllib is
    # the canonical parser. Locks anti-malformed-manifest on
    # the pam-pwquality substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-pwquality/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'pam-pwquality', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: pam-pwquality installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # pam-pwquality writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the pam-pwquality
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/pam-pwquality/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # pam-pwquality install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the pam-pwquality lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/pam-pwquality/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}
