#!/usr/bin/env bats
# L2 functional suite for dnf-automatic-config.
#
# dnf-automatic-config REPLACES /etc/dnf/automatic.conf to
# configure auto-installed security updates on Fedora/RHEL hosts
# (the dnf equivalent of unattended-upgrades-config for Debian).
# Auto-updates are foundational CVE defense.
#
# Profiles:
#   security-only       → install security updates only
#   security-and-reboot → ALSO reboot when kernel update applied
#
# CRITICAL INVARIANTS this suite locks:
#   - First apply backs up operator's automatic.conf to .selfdef-
#     backup; second apply does NOT re-backup.
#   - Idempotent: byte-identical re-install fires NO timer
#     re-enable (timestamp-removal fix from ec1d60a locked here).
#   - DRY_RUN protects file install + timer enable.
#
# Uses SELFDEF_DNF_AUTO_CONF env-var (already present) for L2
# testability.
#
# Run with: bats packaging/test/L2-dnf-automatic-config.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            dnf-automatic.timer)
                if [[ "${DNFAUTO_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\n%s   disabled\n' "$2"
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/dnf-automatic-config.toml"
    DNF_AUTO_CONF="${TMP}/dnf-automatic.conf"
    # Pre-existing operator automatic.conf.
    cat > "${DNF_AUTO_CONF}" <<'OCONF'
# Operator-original
[commands]
upgrade_type = default
apply_updates = no
OCONF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_DNF_AUTO_CONFIG="${CONF}" \
    SELFDEF_DNF_AUTO_CONF="${DNF_AUTO_CONF}" \
    DNFAUTO_PRESENT="${DNFAUTO_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_DNF_AUTO_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DNF_AUTO_CONFIG="${SELFDEF_DNF_AUTO_CONFIG}" \
        SELFDEF_DNF_AUTO_CONF="${DNF_AUTO_CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DNF_AUTO_CONFIG="${CONF}" \
        SELFDEF_DNF_AUTO_CONF="${DNF_AUTO_CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be security-only|security-and-reboot"* ]]
}

@test "INVARIANT: first apply backs up operator's automatic.conf" {
    write_config "security-only"
    run_wd
    [ -f "${DNF_AUTO_CONF}.selfdef-backup" ]
    grep -q '^apply_updates = no$' "${DNF_AUTO_CONF}.selfdef-backup"
}

@test "INVARIANT: second apply does NOT re-backup" {
    write_config "security-only"
    run_wd
    sha_backup_before="$(sha256sum "${DNF_AUTO_CONF}.selfdef-backup" | awk '{print $1}')"
    run_wd
    sha_backup_after="$(sha256sum "${DNF_AUTO_CONF}.selfdef-backup" | awk '{print $1}')"
    [ "${sha_backup_before}" = "${sha_backup_after}" ]
}

@test "security-only profile installs selfdef-managed automatic.conf" {
    write_config "security-only"
    run_wd
    head -1 "${DNF_AUTO_CONF}" | grep -qF '=== selfdef dnf-automatic-config-managed'
    grep -q 'profile=security-only' "${DNF_AUTO_CONF}"
}

@test "security-and-reboot profile installs the reboot-enabled body" {
    write_config "security-and-reboot"
    run_wd
    grep -q 'profile=security-and-reboot' "${DNF_AUTO_CONF}"
}

@test "dnf-automatic.timer enable fires when present" {
    write_config "security-only"
    run_wd
    grep -q 'systemctl enable --now dnf-automatic.timer' "${SYSEOF_LOG}"
}

@test "dnf-automatic.timer NOT present → NOTICE logged, no enable invoked" {
    write_config "security-only"
    DNFAUTO_PRESENT=0 run_wd
    ! grep -q 'systemctl enable --now dnf-automatic.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite automatic.conf" {
    write_config "security-only"
    run_wd
    mtime_before="$(stat -c '%Y' "${DNF_AUTO_CONF}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DNF_AUTO_CONF}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change rewrites automatic.conf" {
    write_config "security-only"
    run_wd
    sha_before="$(sha256sum "${DNF_AUTO_CONF}" | awk '{print $1}')"
    write_config "security-and-reboot"
    run_wd
    sha_after="$(sha256sum "${DNF_AUTO_CONF}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
}

@test "INVARIANT: DRY_RUN does not install automatic.conf or enable timer" {
    write_config "security-only"
    DRY_RUN=1 run_wd
    ! head -1 "${DNF_AUTO_CONF}" 2>/dev/null | grep -qF 'selfdef dnf-automatic'
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "default profile is security-only (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'profile=security-only' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (security-only carries apply_updates = yes — the actual auto-apply mechanism)" {
    write_config "security-only"
    run_wd
    grep -qE 'apply_updates\s*=\s*yes' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (security-only carries upgrade_type = security — the actual scope-restriction)" {
    write_config "security-only"
    run_wd
    grep -qE 'upgrade_type\s*=\s*security' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (security-and-reboot carries reboot = when-needed): asymmetric profile content" {
    write_config "security-and-reboot"
    run_wd
    grep -qE 'reboot\s*=\s*(when-needed|when-changed|yes)' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (security-only does NOT carry reboot directive): asymmetric content lock" {
    write_config "security-only"
    run_wd
    ! grep -qE '^reboot\s*=\s*(when-needed|when-changed|yes)' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (profile downgrade security-and-reboot → security-only): rewrites without reboot" {
    write_config "security-and-reboot"
    run_wd
    grep -q 'profile=security-and-reboot' "${DNF_AUTO_CONF}"
    write_config "security-only"
    run_wd
    grep -q 'profile=security-only' "${DNF_AUTO_CONF}"
    ! grep -q 'profile=security-and-reboot' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (no render-timestamp in automatic.conf): defeats cmp -s idempotency" {
    write_config "security-only"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates automatic.conf + enables timer)" {
    write_config "security-only"
    run_wd
    [ -f "${DNF_AUTO_CONF}" ]
    rm -f "${DNF_AUTO_CONF}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${DNF_AUTO_CONF}" ]
    grep -q 'profile=security-only' "${DNF_AUTO_CONF}"
    grep -q 'systemctl enable --now dnf-automatic.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "security-and-reboot"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"dnf-automatic-config"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=security-and-reboot'* ]]
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "security-only"
    run_wd
    first_line="$(awk 'NF' "${DNF_AUTO_CONF}" | head -1)"
    [[ "${first_line}" == *"selfdef dnf-automatic-config"* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # dnf-automatic-config TOML; parser must tolerate without
    # altering the profile-gated behavior. security-and-reboot-with-
    # noise still installs the reboot-enabled body (foundational
    # CVE-defense auto-update mechanism on RHEL/Fedora hosts).
    cat > "${CONF}" <<'TOMLEOF'
profile = "security-and-reboot"
operator_note = "kernel-update auto-reboot = CVE-defense substrate"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'profile=security-and-reboot' "${DNF_AUTO_CONF}"
    grep -qE 'reboot\s*=\s*(when-needed|when-changed|yes)' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (security-only does NOT carry apply_updates=no — explicit asymmetric gate)" {
    # The default operator-shipped dnf-automatic.conf carries
    # apply_updates=no (download-only, advisory mode). selfdef's
    # security-only profile MUST set this to yes (actually apply
    # updates) — otherwise the install is a no-op (download CVE
    # patches but never apply). Locks the asymmetric gate against
    # accidental regression to the operator-shipped default.
    write_config "security-only"
    run_wd
    grep -qE '^apply_updates[[:space:]]*=[[:space:]]*yes' "${DNF_AUTO_CONF}"
    ! grep -qE '^apply_updates[[:space:]]*=[[:space:]]*no' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (security-only carries upgrade_type=security — actually narrows to CVE patch axis)" {
    # Sister to security-only apply_updates=yes INVARIANT above
    # (the actual-execute half of the asymmetric gate). The
    # selfdef security-only profile must explicitly narrow the
    # dnf-automatic transaction to security advisories only,
    # NOT the full upgrade_type=default which would auto-apply
    # ALL repo updates (including potential regression-risk
    # feature updates the operator hasn't tested). Locks
    # upgrade_type=security so the security-only label
    # honestly reflects the chosen scope.
    write_config "security-only"
    run_wd
    grep -qE '^upgrade_type[[:space:]]*=[[:space:]]*security' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO automatic.conf written AND NO timer enable fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/dnf/automatic.conf AND without
    # enabling dnf-automatic.timer. A silent dry-run that
    # committed would enable recurring auto-update on a host
    # where operator was investigating package-management
    # behavior. Locks dry-run-preserves-state on the dnf-
    # automatic config substrate.
    write_config "security-only"
    rm -f "${DNF_AUTO_CONF}"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DNF_AUTO_CONF}" ]
    ! grep -qE 'systemctl (enable|start) dnf-automatic' "${SYSEOF_LOG}"
}

@test "INVARIANT (automatic.conf chmod 0644 — system-config convention)" {
    write_config "security-only"
    run_wd
    [ -f "${DNF_AUTO_CONF}" ]
    [ "$(stat -c '%a' "${DNF_AUTO_CONF}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on dnf-automatic-config installer
    # surface across automatic.conf + timer-enable phases.
    write_config "security-only"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"dnf-automatic-config"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: dnf-automatic-config NEVER emits package-remove commands on dnf-automatic)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The dnf-automatic-config installer writes
    # automatic.conf + enables timer but MUST NEVER emit shell
    # commands that uninstall the dnf-automatic package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall dnf-
    # automatic). Silent auto-removal would leave the host
    # with no automatic patching mechanism — degrading the
    # CVE-patch defense substrate. Locks anti-package-removal
    # contract on the dnf-automatic-config substrate.
    write_config "security-only"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+dnf-automatic'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DNF_AUTO_CONF}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. dnf-automatic-config manifest declares install +
    # profile gating (security-only / all-updates) the resolver
    # enforces at install-time; malformed manifest wedges
    # dnf-automatic baseline. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the dnf-automatic-
    # config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'dnf-automatic-config', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: dnf-automatic-config installer NEVER deletes operator-pre-existing automatic.conf — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # dnf-automatic-config writes its own /etc/dnf/automatic.conf;
    # it MUST NEVER rm/find-delete an operator's pre-existing
    # automatic.conf or dnf.conf entries not owned by THIS
    # module. Locks no-auto-delete on the dnf-automatic-config
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/dnf/(dnf\.conf|automatic\.conf)' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/dnf.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # dnf-automatic-config install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the dnf-automatic-config lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}
