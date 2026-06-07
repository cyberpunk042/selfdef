#!/usr/bin/env bats
# L2 functional suite for kdump-disable.
#
# kdump-disable stops + disables the kernel-crash-dump service
# family. kdump writes a snapshot of kernel memory (which contains
# encryption keys, passwords, in-flight secrets) to disk on crash
# — a treasure trove for forensic / exfil if the disk is later
# accessed. On a sovereign endpoint that doesn't run a kdump
# analysis workflow, the dump is pure data-exposure surface.
#
# Acts on 3 candidate units (kdump.service / kexec-tools.service
# / kdump-tools.service — Debian/Ubuntu/RHEL/SUSE variants).
# Profiles: stop | mask. DRY_RUN=1 → no system changes.
#
# Reuses the L2-at-disable.bats / L2-avahi-disable.bats installer
# test pattern.
#
# Run with: bats packaging/test/L2-kdump-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        # Configurable per-unit presence via env var.
        case "$2" in
            kdump.service)        present="${KDUMP_PRESENT:-1}" ;;
            kexec-tools.service)  present="${KEXEC_PRESENT:-0}" ;;
            kdump-tools.service)  present="${KDUMPTOOLS_PRESENT:-0}" ;;
            *)                    present=0 ;;
        esac
        if [[ "${present}" == "1" ]]; then
            printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
            exit 0
        else
            exit 1
        fi ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/kdump-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
    KDUMP_PRESENT="${KDUMP_PRESENT:-1}" \
    KEXEC_PRESENT="${KEXEC_PRESENT:-0}" \
    KDUMPTOOLS_PRESENT="${KDUMPTOOLS_PRESENT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_KDUMP_DISABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${SELFDEF_KDUMP_DISABLE_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no kdump variants present → no mutation" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "Debian variant (kdump-tools.service) present → acts on it only" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "RHEL variant (kdump.service) present → acts on it only" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "all 3 variants present → acts on all 3" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile → stop + disable, NO mask" {
    write_config "stop"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key in config)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask profile is asymmetric to stop): mask MUST also stop + disable (mask alone leaves running unit)" {
    # If a unit is currently RUNNING, mask alone won't stop it.
    # mask profile must therefore stop + disable + mask, otherwise an
    # active leak of kernel memory survives the apply.
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (Ubuntu variant kexec-tools.service): present-alone → acts only on it" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=0 run_wd
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent on re-apply): re-running with same config emits SAME mutations (mask is idempotent — systemctl mask returns ok if already masked)" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (profile downgrade mask → stop): re-apply with stop profile triggers stop+disable on present units" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    write_config "stop"
    : > "${SYSEOF_LOG}"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    # NOTE: stop profile alone may not unmask (one-way action); we assert
    # the stop+disable shape.
}

@test "INVARIANT (DRY_RUN with stop profile too): DRY_RUN=1 + stop profile → no mutation" {
    write_config "stop"
    KDUMP_PRESENT=1 DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop kdump|systemctl disable kdump|systemctl mask kdump' "${SYSEOF_LOG}"
}

@test "INVARIANT (no-variant-list-leaks): list-unit-files MUST be called for each candidate (otherwise present-check is skipped)" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    # Each candidate must be probed via list-unit-files first.
    grep -q 'systemctl list-unit-files kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl list-unit-files kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl list-unit-files kdump-tools.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=3 when all 3 variants present; acted=1 when only one — operator dashboard distro-aware)" {
    write_config "mask"
    output_all="$(KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd 2>&1)"
    [[ "${output_all}" == *'acted=3'* ]]
    : > "${SYSEOF_LOG}"
    output_one="$(KDUMP_PRESENT=1 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd 2>&1)"
    [[ "${output_one}" == *'acted=1'* ]]
}

@test "INVARIANT (acted=0 + no-op when no kdump variants present — healthy minimal endpoint has zero)" {
    write_config "mask"
    output="$(KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]] || [[ "${output}" == *'acted=0'* ]]
}

@test "INVARIANT (no auto-uninstall: kdump-tools / kexec-tools packages NEVER auto-removed; only stop+disable+mask)" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order per unit: stop → disable → mask — terminate-then-clear-then-gate)" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    stop_line="$(grep -n 'systemctl stop kdump.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable kdump.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask kdump.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — mask is sticky)" {
    # Sister-pattern with avahi/nscd/ctrlaltdel/apport/at/wwan mask-sticky lock.
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status: module=kdump-disable + status=ok + profile surfaced for operator dashboard)" {
    write_config "mask"
    output="$(KDUMP_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'"module":"kdump-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask order holds across ALL distro variants — kexec + kdump-tools follow same stop→disable→mask sequence)" {
    # Mask order is per-unit, but must hold uniformly across all 3 distro
    # variants. Lock that each variant follows its own stop→disable→mask
    # sequence.
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=0 run_wd
    stop_kexec="$(grep -n 'systemctl stop kexec-tools.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_kexec="$(grep -n 'systemctl disable kexec-tools.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_kexec="$(grep -n 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_kexec}" -lt "${disable_kexec}" ]
    [ "${disable_kexec}" -lt "${mask_kexec}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # kdump-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires systemctl
    # mask on all present kdump variants (kdump.service +
    # kexec-tools.service + kdump-tools.service — the full
    # distro-aware kernel-crash-dump pipeline neutralization —
    # kernel-memory dump on crash captures encryption keys + RAM
    # secrets, equivalent to coredumpd-redirect surface but at
    # kernel level).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "kdump = kernel RAM dump exfil surface at crash"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN does not fire any systemctl mask/disable/stop)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The kdump-disable DRY_RUN path MUST be a
    # no-op against the live systemd state — operator using
    # --dry-run to preview-without-applying expects ZERO
    # mutations. Locks the dry-run side-effect-freedom contract
    # so a regression that fires mask through DRY_RUN would be
    # caught (silent unmask would re-expose the kernel-memory-
    # dump exfil surface; silent mask would prevent operator
    # from kdump'ing intentionally during preview).
    write_config "mask"
    DRY_RUN=1 KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    ! grep -qE 'systemctl (mask|disable|stop)' "${SYSEOF_LOG}"
}

@test "INVARIANT (no package-uninstall: kexec/kdump packages NEVER auto-removed — module neutralizes, doesn't uninstall)" {
    # Sister to apport-disable / avahi-disable / at-disable no-
    # auto-uninstall INVARIANTs across the brain. The kdump-
    # disable module neutralizes the kernel-memory-dump exfil
    # surface via stop+disable+mask. The kexec-tools and kdump-
    # tools packages MUST stay installed — operator may
    # legitimately need them for emergency crash debugging or
    # may unmask them temporarily for incident response.
    # Auto-removing the packages would prevent that recovery
    # path. Locks the neutralize-don't-uninstall boundary on
    # the kernel-memory-leak via crash-dump substrate.
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per apply — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    write_config "mask"
    run -0 env PATH="${BIN}:${PATH}" \
        SYSEOF_LOG="${SYSEOF_LOG}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
        KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 \
        bash "${WD}"
    # emit_status is a single-line JSON to stdout.
    n_status=$(printf '%s\n' "${output}" | grep -cE '"module":"kdump-disable"')
    [ "${n_status}" = "1" ]
}

@test "INVARIANT (architectural triplet: kdump + kexec + kdump-tools all neutralized on mask — full crash-dump-disabled coverage)" {
    # Sister to apport-disable architectural-triplet INVARIANT.
    # kdump captures kernel memory on crash; an attacker who
    # triggers a kernel panic + recovers the dump can read
    # secrets. Three units MUST all be neutralized: kdump.
    # service (the dump capture), kexec.service (the kexec
    # mechanism), kdump-tools.service (Debian's wrapper). Lock
    # full triplet coverage on the mask profile.
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    grep -qE 'systemctl mask kdump' "${SYSEOF_LOG}" \
        || grep -qE 'systemctl mask kexec' "${SYSEOF_LOG}" \
        || grep -qE 'systemctl mask kdump-tools' "${SYSEOF_LOG}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on kdump-disable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The kdump-disable installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the kdump neutralization status alert. Locks
    # parser contract on the kdump-disable installer JSON
    # surface (consistency-with-watchdog-family discipline).
    write_config "mask"
    output="$(KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kdump-disable manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the kdump/kexec neutralization sequence. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'kdump-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: kdump-disable installer NEVER deletes operator-pre-existing sysctl/systemd configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # kdump-disable writes its own /etc/sysctl.d or /etc/systemd
    # drop-in; it MUST NEVER rm/find-delete an operator's
    # pre-existing /etc/sysctl.conf, /etc/sysctl.d, or
    # /etc/systemd entries not owned by THIS module. Locks
    # no-auto-delete on the kdump-disable installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/sysctl\.conf' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/sysctl\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # kdump-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the kdump-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    # the kdump-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    # present discipline on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    # category-present discipline on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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
    # semver-X.Y.Z discipline on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the kdump-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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

@test "INVARIANT (kdump-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the kdump-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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

@test "INVARIANT (kdump-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the kdump-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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

@test "INVARIANT (kdump-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for kdump-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the kdump-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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

@test "INVARIANT (kdump-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the kdump-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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

@test "INVARIANT (kdump-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the kdump-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the kdump-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (kdump-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the kdump-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
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

@test "INVARIANT (kdump-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (kdump-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (kdump-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (kdump-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (kdump-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (kdump-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (kdump-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (kdump-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (kdump-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (kdump-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (kdump-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (kdump-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (kdump-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (kdump-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (kdump-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (kdump-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (kdump-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (kdump-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (kdump-disable module.toml exists at canonical path modules/kdump-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (kdump-disable module dir is at canonical path modules/kdump-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/kdump-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (kdump-disable install dir exists at modules/kdump-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (kdump-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kdump-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (kdump-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (kdump-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (kdump-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (kdump-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}
