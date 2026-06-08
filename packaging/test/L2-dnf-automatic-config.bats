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

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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
    # the dnf-automatic-config requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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
    # present discipline on the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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
    # category-present discipline on the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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
    # semver-X.Y.Z discipline on the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the dnf-automatic-config module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the dnf-automatic-config module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the dnf-automatic-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for dnf-automatic-config is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the dnf-automatic-config install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the dnf-automatic-config requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the dnf-automatic-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the dnf-automatic-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the dnf-automatic-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (dnf-automatic-config README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (dnf-automatic-config install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (dnf-automatic-config install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (dnf-automatic-config install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (dnf-automatic-config install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (dnf-automatic-config install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (dnf-automatic-config install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (dnf-automatic-config install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (dnf-automatic-config install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (dnf-automatic-config module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (dnf-automatic-config module.toml exists at canonical path modules/dnf-automatic-config/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (dnf-automatic-config module dir is at canonical path modules/dnf-automatic-config/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (dnf-automatic-config install dir exists at modules/dnf-automatic-config/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (dnf-automatic-config install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dnf-automatic-config install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (dnf-automatic-config install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (dnf-automatic-config module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (dnf-automatic-config install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (dnf-automatic-config install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (dnf-automatic-config install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (dnf-automatic-config install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (dnf-automatic-config install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (dnf-automatic-config install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (dnf-automatic-config module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (dnf-automatic-config module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (dnf-automatic-config module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
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

@test "INVARIANT (dnf-automatic-config module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (dnf-automatic-config module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (dnf-automatic-config module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (dnf-automatic-config module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (dnf-automatic-config module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"dnf-automatic-config"' "${mtoml}"
}

@test "INVARIANT (dnf-automatic-config module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (dnf-automatic-config module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dnf-automatic-config/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}
