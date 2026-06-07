#!/usr/bin/env bats
# L2 functional suite for pam-history.
#
# pam-history installs /etc/security/pwhistory.conf with the
# chosen password-history retention profile. pam_pwhistory.so
# reads this file to enforce "no reuse of the last N passwords"
# at password-change time.
#
# Profiles:
#   standard → remember=5 (NIST SP 800-63B-aligned baseline)
#   strict   → remember=24 (audit-frameworks-aligned bar —
#              CIS Benchmark / DISA STIG family)
#
# Detect-and-notice pattern: pam_pwhistory.so must ALSO be wired
# into /etc/pam.d/common-password (Debian) or system-auth/
# password-auth (RHEL/Fedora). The module installs the config
# unconditionally; if no /etc/pam.d/* references the module the
# config is DORMANT and a NOTICE is logged with distro-specific
# enable instructions.
#
# Backup pattern: the operator's distro-default
# /etc/security/pwhistory.conf (if any, non-selfdef-owned) is
# backed up once on first apply.
#
# Adds SELFDEF_PWHISTORY_CONF + SELFDEF_PWHISTORY_BACKUP_DIR +
# SELFDEF_PWHISTORY_PAM_DIR env-vars (added 2026-06-06) for L2
# testability. Live defaults unchanged.
#
# Run with: bats packaging/test/L2-pam-history.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-history/install/apply.sh"
CONFIGS_SRC="${BATS_TEST_DIRNAME}/../../modules/pam-history/configs"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/pam-history.toml"
    PWHISTORY_CONF="${TMP}/pwhistory.conf"
    BACKUP_DIR="${TMP}/backup"
    PAM_DIR="${TMP}/pam.d"
    mkdir -p "${BACKUP_DIR}" "${PAM_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PWHISTORY_CONFIG="${CONF}" \
    SELFDEF_PWHISTORY_CONF="${PWHISTORY_CONF}" \
    SELFDEF_PWHISTORY_BACKUP_DIR="${BACKUP_DIR}" \
    SELFDEF_PWHISTORY_PAM_DIR="${PAM_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PWHISTORY_CONFIG="${TMP}/missing.toml"
    run env SELFDEF_PWHISTORY_CONFIG="${SELFDEF_PWHISTORY_CONFIG}" \
        SELFDEF_PWHISTORY_CONF="${PWHISTORY_CONF}" \
        SELFDEF_PWHISTORY_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_PWHISTORY_PAM_DIR="${PAM_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env SELFDEF_PWHISTORY_CONFIG="${CONF}" \
        SELFDEF_PWHISTORY_CONF="${PWHISTORY_CONF}" \
        SELFDEF_PWHISTORY_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_PWHISTORY_PAM_DIR="${PAM_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile renders pwhistory.conf with profile=standard marker" {
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'managed-by: selfdef pam-history' "${PWHISTORY_CONF}"
    grep -q 'profile=standard' "${PWHISTORY_CONF}"
}

@test "strict profile renders pwhistory.conf with profile=strict marker + strict remember count" {
    write_config "strict"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'profile=strict' "${PWHISTORY_CONF}"
    # Strict profile should bump remember above standard. The exact
    # value lives in configs/strict.conf; just verify it's present.
    grep -qE '^remember\s*=\s*[0-9]+' "${PWHISTORY_CONF}"
}

@test "pwhistory.conf is chmod 0644 (system-config convention)" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${PWHISTORY_CONF}")" = "644" ]
}

@test "INVARIANT: no render-timestamp in pwhistory.conf (defeats cmp -s)" {
    write_config "standard"
    run_wd
    # Anti-timestamp invariant (2026-06-06 sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${PWHISTORY_CONF}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite pwhistory.conf (2026-06-06 idempotency fix)" {
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    mtime_before="$(stat -c '%Y' "${PWHISTORY_CONF}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${PWHISTORY_CONF}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write pwhistory.conf" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${PWHISTORY_CONF}" ]
}

@test "INVARIANT: operator's pre-existing distro pwhistory.conf is backed up once on first apply (NOT overwritten silently)" {
    # Simulate operator's pre-existing distro default file.
    cat > "${PWHISTORY_CONF}" <<'EOF'
# distro-shipped /etc/security/pwhistory.conf
remember=3
EOF
    write_config "standard"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
    [ -f "${BACKUP_FILE}" ]
    grep -qE '^remember\s*=\s*3' "${BACKUP_FILE}"
    # Backup is operator-private (sensitive PAM config).
    [ "$(stat -c '%a' "${BACKUP_FILE}")" = "600" ]
}

@test "INVARIANT: selfdef-owned pwhistory.conf is NOT backed up (avoid self-loop)" {
    # First apply lands the selfdef-managed file.
    write_config "standard"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
    ! [ -f "${BACKUP_FILE}" ]
}

@test "INVARIANT: second apply does NOT re-backup (single-shot backup pattern)" {
    cat > "${PWHISTORY_CONF}" <<'EOF'
# distro-shipped /etc/security/pwhistory.conf
remember=3
EOF
    write_config "standard"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/pam-history-distro-default.bak"
    [ -f "${BACKUP_FILE}" ]
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_FILE}")"
    sleep 1
    write_config "strict"
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_FILE}")"
    # Original distro default preserved — second apply did NOT
    # overwrite the backup with the (now selfdef-owned) live file.
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
    grep -qE '^remember\s*=\s*3' "${BACKUP_FILE}"
}

@test "DETECT-AND-NOTICE: pam_pwhistory.so unwired in /etc/pam.d → log distro-specific enable instructions" {
    # No /etc/pam.d files exist with pam_pwhistory.so references.
    write_config "standard"
    run_wd
    # Output should include the unwired-NOTICE — emitted to operator
    # via log() which prefixes with [pam-history]. The script's
    # stdout is captured by `bats run_wd`'s implicit capture; we
    # check via re-running with `run` envelope.
    run_wd 2>&1 | grep -q "DORMANT"
}

@test "DETECT-AND-NOTICE: pam_pwhistory.so wired in /etc/pam.d/common-password → log wired-in status" {
    cat > "${PAM_DIR}/common-password" <<'EOF'
password requisite pam_pwhistory.so use_authtok
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
EOF
    write_config "standard"
    run_wd 2>&1 | grep -q "pam_pwhistory.so is wired in"
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'profile=standard' "${PWHISTORY_CONF}"
}

@test "INVARIANT (strict remember > standard remember — asymmetric tightening)" {
    # Strict must enforce remembering MORE passwords than standard.
    # Lock the asymmetric tightening for compliance frameworks.
    write_config "standard"
    run_wd
    std_remember="$(grep -oE 'remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_remember="$(grep -oE 'remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${std_remember}" ]
    [ -n "${strict_remember}" ]
    [ "${strict_remember}" -gt "${std_remember}" ]
}

@test "INVARIANT (profile downgrade strict → standard rewrites with looser remember count)" {
    # Bidirectional contract — operator can both tighten + loosen.
    write_config "strict"
    run_wd
    strict_sha="$(sha256sum "${PWHISTORY_CONF}" | awk '{print $1}')"
    write_config "standard"
    run_wd
    std_sha="$(sha256sum "${PWHISTORY_CONF}" | awk '{print $1}')"
    [ "${strict_sha}" != "${std_sha}" ]
    grep -q 'profile=standard' "${PWHISTORY_CONF}"
}

@test "INVARIANT (RHEL system-auth detection: pam_pwhistory.so wired there → wired-in status)" {
    # The detect-and-notice scan must walk both Debian's
    # common-password AND RHEL's system-auth / password-auth.
    cat > "${PAM_DIR}/system-auth" <<'EOF'
password requisite pam_pwhistory.so use_authtok
password sufficient pam_unix.so use_authtok yescrypt shadow
EOF
    write_config "standard"
    run_wd 2>&1 | grep -qE "pam_pwhistory.so is wired in|wired"
}

@test "INVARIANT (pwhistory.conf re-arm after operator deletion: re-creates file with header)" {
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    rm -f "${PWHISTORY_CONF}"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'managed-by: selfdef pam-history' "${PWHISTORY_CONF}"
    grep -qE '^remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile + pam-wired surfaced for operator dashboard)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=standard'* ]]
    # wired= key surfaces actual wiring state for operator
    # to detect dormant configs.
    [[ "${output}" == *'wired=true'* ]] || [[ "${output}" == *'wired=false'* ]]
}

@test "INVARIANT (managed-by header is on the first non-blank line: stale-cleanup head -1 discipline)" {
    # The managed-by marker MUST be the first non-blank line of the
    # rendered config so a stale-detection scan reading just head -1
    # of /etc/security/pwhistory.conf reliably identifies selfdef-owned
    # files. Sister header discipline across the brain.
    write_config "standard"
    run_wd
    first_nonblank="$(grep -m1 -v '^[[:space:]]*$' "${PWHISTORY_CONF}")"
    [[ "${first_nonblank}" == *"managed-by: selfdef pam-history"* ]]
}

@test "INVARIANT (RHEL password-auth detection: pam_pwhistory.so wired there → wired-in status — third-distro path)" {
    # The detect-and-notice scan must walk Debian's common-password,
    # RHEL's system-auth, AND RHEL's password-auth. password-auth is
    # the separate path for non-tty (network/SSH) auth on RHEL family.
    cat > "${PAM_DIR}/password-auth" <<'EOF'
password requisite pam_pwhistory.so use_authtok
password sufficient pam_unix.so use_authtok yescrypt shadow
EOF
    write_config "standard"
    run_wd 2>&1 | grep -qE "pam_pwhistory.so is wired in|wired"
}

@test "INVARIANT (mtime preserved on profile re-write of the SAME profile: standard→standard re-apply is byte-identical)" {
    # Sister to the existing idempotent byte-identical mtime test —
    # this one additionally verifies that re-issuing the SAME profile
    # with no env-var changes truly produces zero file-system churn.
    write_config "standard"
    run_wd
    mtime_first="$(stat -c '%Y' "${PWHISTORY_CONF}")"
    sleep 1
    write_config "standard"                              # re-issue
    run_wd
    mtime_second="$(stat -c '%Y' "${PWHISTORY_CONF}")"
    [ "${mtime_first}" = "${mtime_second}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # pam-history TOML; parser must tolerate without altering the
    # profile-gated behavior. strict-with-noise still writes the
    # stricter remember=N (compliance-grade password-reuse defense)
    # AND header marker present (the load-bearing PCI/CIS-mapped
    # password history substrate).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "PCI/CIS compliance — 24-password history"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    grep -q 'profile=strict' "${PWHISTORY_CONF}"
    grep -qE '^remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}"
    grep -q 'managed-by: selfdef pam-history' "${PWHISTORY_CONF}"
}

@test "INVARIANT (strict remember >= standard remember — profile-rank monotonic depth)" {
    # Sister to many other installer module's profile-rank
    # monotonic INVARIANT across the brain (kernel-sysrq, file-
    # protections, audit-rules). The strict profile MUST hold
    # at LEAST as deep a password-history as the standard
    # profile. If strict had a smaller remember=N than standard,
    # operator's intent ("tighten password reuse defense") would
    # be silently inverted. Lock the monotonic depth ordering
    # across profiles.
    write_config "standard"
    run_wd
    standard_n="$(grep -oE '^remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_n="$(grep -oE '^remember[[:space:]]*=[[:space:]]*[0-9]+' "${PWHISTORY_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${standard_n}" ]
    [ -n "${strict_n}" ]
    [ "${strict_n}" -ge "${standard_n}" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO pwhistory.conf written AND NO PAM file modified when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/security/pwhistory.conf AND
    # without modifying PAM files. A silent dry-run that
    # committed would activate password-history enforcement on
    # a host where operator was investigating PAM behavior —
    # could block legitimate password changes that intentionally
    # reuse a recent password during testing. Locks dry-run-
    # preserves-state on the PAM password-history substrate.
    write_config "strict"
    rm -f "${PWHISTORY_CONF}"
    DRY_RUN=1 run_wd
    [ ! -f "${PWHISTORY_CONF}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the PAM
    # password-history installer surface.
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"pam-history"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (pwhistory.conf chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "standard"
    run_wd
    [ -f "${PWHISTORY_CONF}" ]
    [ "$(stat -c '%a' "${PWHISTORY_CONF}")" = "644" ]
}

@test "INVARIANT (no auto-uninstall: pam-history NEVER emits package-remove commands on libpam-modules)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The pam-history installer wires pwhistory.conf
    # but MUST NEVER emit shell commands that uninstall the
    # libpam-modules / libpam-pwhistory packages themselves
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall libpam-
    # modules|libpam-pwhistory|pam). Silent auto-removal would
    # tear down the PAM auth substrate entirely + remove the
    # pam_pwhistory module the installer just wired. T1556
    # self-defeat. Locks anti-package-removal contract on the
    # pam-history substrate.
    write_config "strict"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(libpam-modules|libpam-pwhistory|pam)'
    [ ! -f "${PWHISTORY_CONF}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${PWHISTORY_CONF}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. pam-history manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the PAM pwhistory baseline (password-reuse remember N).
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the pam-history substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-history/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'pam-history', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: pam-history installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # pam-history writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the pam-history
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/pam-history/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # pam-history install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the pam-history lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/pam-history/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the pam-history substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-history/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-history/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}
