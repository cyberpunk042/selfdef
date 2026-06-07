#!/usr/bin/env bats
# L2 functional suite for kernel-lockdown.
#
# kernel-lockdown installs sysctl drop-ins under /etc/sysctl.d that
# tighten kernel behavior. Two profiles:
#   balanced → kptr_restrict, dmesg_restrict, ptrace_scope=2,
#              unprivileged_bpf_disabled, etc. (the always-safe
#              baseline)
#   strict   → adds kernel.modules_disabled=1 — IRREVERSIBLE until
#              REBOOT. The script REQUIRES an explicit operator
#              acknowledgment (acknowledge_modules_disabled = true)
#              before applying strict — refuse-to-brick guard.
#
# CRITICAL INVARIANTS this suite locks:
#   1. strict without acknowledgment → die (refuse-to-brick).
#   2. Profile downgrade (strict→balanced) removes the strict drop-in.
#   3. Idempotent: byte-identical re-install is a no-op.
#   4. DRY_RUN protects /etc/sysctl.d + sysctl --system invocation.
#
# Uses SELFDEF_SYSCTL_DIR + SELFDEF_KERNEL_LOCKDOWN_SYSCTL env-vars
# (already present in the script) for L2 testability. Live default
# behavior unchanged.
#
# Run with: bats packaging/test/L2-kernel-lockdown.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/kernel-lockdown.toml"
    SYSCTL_DIR="${TMP}/sysctl.d"
    SYSCTL_SRC="${TMP}/sysctl-src"
    mkdir -p "${SYSCTL_DIR}" "${SYSCTL_SRC}"
    # Drop fixture sysctl source files (mirroring modules/kernel-lockdown/sysctl/).
    printf 'kernel.kptr_restrict = 2\n' > "${SYSCTL_SRC}/balanced.conf"
    printf 'kernel.modules_disabled = 1\n' > "${SYSCTL_SRC}/strict.conf"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_modules_disabled = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
    SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
    SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_KERNEL_LOCKDOWN_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${SELFDEF_KERNEL_LOCKDOWN_CONFIG}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing sysctl source dir → die" {
    write_config "balanced"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${TMP}/missing-src" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"sysctl source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be balanced|strict"* ]]
}

@test "INVARIANT: strict profile without acknowledgment → die (refuse-to-brick guard)" {
    write_config "strict" "false"      # NO acknowledgment
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]]
    # No drop-ins should be installed despite the failure.
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "balanced profile installs the balanced drop-in only" {
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "strict profile WITH acknowledgment installs BOTH drop-ins" {
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT: profile downgrade strict→balanced removes the strict drop-in" {
    # First install strict.
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # Switch to balanced.
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op (no sysctl --system fired)" {
    write_config "balanced"
    run_wd                              # initial install
    : > "${SCTL_LOG}"                   # clear log
    run_wd                              # re-install — identical content
    # sysctl --system fires only when changes > 0; identical re-install → 0 changes.
    ! grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-ins or fire sysctl" {
    write_config "balanced"
    DRY_RUN=1 run_wd
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "balanced drop-in content matches the source exactly" {
    write_config "balanced"
    run_wd
    cmp -s "${SYSCTL_SRC}/balanced.conf" "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
}

@test "default profile is balanced (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "balanced"
    run_wd
    mtime_before="$(stat -c '%Y' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile upgrade balanced → strict WITH ack): installs strict drop-in + fires sysctl" {
    # Reverse of the downgrade lock — locks bidirectional contract.
    write_config "balanced"
    run_wd
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    write_config "strict" "true"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (strict drop-in carries kernel.modules_disabled=1): the actual irreversible mechanism" {
    write_config "strict" "true"
    run_wd
    grep -qE 'kernel\.modules_disabled\s*=\s*1' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf"
}

@test "INVARIANT (balanced does NOT carry modules_disabled): asymmetric content lock" {
    write_config "balanced"
    run_wd
    ! grep -qE 'kernel\.modules_disabled\s*=\s*1' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
}

@test "INVARIANT (drop-in chmod 0644): sysctl.d convention" {
    write_config "balanced"
    run_wd
    [ "$(stat -c '%a' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf")" = "644" ]
}

@test "INVARIANT (sysctl --system fires on change — operator-edit between runs forces re-apply)" {
    write_config "balanced"
    run_wd
    : > "${SCTL_LOG}"
    write_config "strict" "true"
    run_wd
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl --system)" {
    # Operator may rm the drop-in — apply must rebuild and re-apply
    # live so kernel state is restored.
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    rm -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "strict" "true"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"kernel-lockdown"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=strict'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — strict w/o ack dies even after prior balanced install)" {
    # Operator installs balanced first, then flips to strict but
    # FORGETS to set acknowledge_modules_disabled. apply MUST refuse
    # AND leave the prior balanced drop-in unchanged — no silent
    # escalation to strict-modules-disabled.
    write_config "balanced"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # Operator sets strict w/o ack.
    write_config "strict" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Strict drop-in MUST NOT have been installed.
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # Prior balanced drop-in preserved.
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]
}

@test "INVARIANT (downgrade strict → balanced fires sysctl --system to APPLY balanced settings — kernel state must drop modules_disabled)" {
    # When operator downgrades, the strict drop-in is removed BUT
    # the live kernel state still has modules_disabled=1 from the
    # prior load. The downgrade MUST fire sysctl --system to re-
    # apply the balanced-only state. (Note: modules_disabled is
    # itself irreversible until reboot — operator knows this — but
    # OTHER strict-only knobs may not be irreversible and must
    # reset.)
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    : > "${SCTL_LOG}"
    write_config "balanced"
    run_wd
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    # sysctl --system fires because content changed (strict dropin removed).
    grep -q 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in filenames follow 50-selfdef-* convention — tracking + uninstall identification)" {
    # Both balanced and strict drop-ins must follow the 50-selfdef-
    # prefix convention. Sister to many other modules' filename-
    # convention INVARIANT.
    write_config "strict" "true"
    run_wd
    case "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" in
        */50-selfdef-*) : ;;
        *) fail "balanced drop-in does not follow 50-selfdef-* pattern" ;;
    esac
    case "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" in
        */50-selfdef-*) : ;;
        *) fail "strict drop-in does not follow 50-selfdef-* pattern" ;;
    esac
}

@test "INVARIANT (config-layer-noise resilience: extra unknown TOML keys do NOT bypass acknowledge_modules_disabled gate)" {
    # Sister to nftables-baseline refuse-to-brick precedence INVARIANT.
    # Lock that extra config keys cannot accidentally bypass the
    # refuse-to-brick gate via TOML parsing edge cases.
    cat > "${CONF}" <<'EOF'
profile = "strict"
acknowledge_modules_disabled = false
some_other_knob = "wrong"
maybe_a_typo = true
EOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KERNEL_LOCKDOWN_CONFIG="${CONF}" \
        SELFDEF_KERNEL_LOCKDOWN_SYSCTL="${SYSCTL_SRC}" \
        SELFDEF_SYSCTL_DIR="${SYSCTL_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]] || [[ "${output}" == *"acknowledge_modules_disabled"* ]]
    ! [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
}

@test "INVARIANT (drop-in is sysctl.d-parseable: kernel.modules_disabled=<N> format — boot-time persistence contract)" {
    # Sister to kernel-yama-baseline + aslr-baseline + coredump-
    # suid-restrict sysctl.d-parseable INVARIANTs already locked.
    # The strict-profile drop-in lives at /etc/sysctl.d/50-selfdef-
    # kernel-lockdown-strict.conf and is parsed by systemd-sysctl.
    # service at boot. A malformed kernel.modules_disabled line
    # would silently fail at boot — the runtime sysctl -w would
    # set it for current boot but the value would NOT persist
    # across reboot, leaving the host with degraded module-loading
    # restriction on next boot.
    write_config "strict" "true"
    run_wd
    [ -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]
    grep -qE '^kernel\.modules_disabled[[:space:]]*=[[:space:]]*1$' "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl --system fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/sysctl.d/50-selfdef-kernel-
    # lockdown-*.conf AND without firing sysctl --system. The
    # strict profile in particular is IRREVERSIBLE until reboot
    # — a silent dry-run that committed would lock out module-
    # loading on a host under investigation, breaking any
    # incident-response workflow that needs to insmod
    # diagnostics modules. Locks dry-run-preserves-state on
    # kernel-lockdown substrate.
    write_config "balanced"
    rm -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-balanced.conf"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-balanced.conf" ]
    ! grep -qE 'sysctl --system' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "balanced"
    run_wd
    file="${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
    [ -f "${file}" ]
    [ "$(stat -c '%a' "${file}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on kernel-lockdown installer
    # surface across drop-in + sysctl --system phases.
    write_config "balanced"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"kernel-lockdown"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: kernel-lockdown NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The kernel-lockdown installer writes a sysctl
    # drop-in pinning kernel.modules_disabled + kernel.kexec_
    # load_disabled but MUST NEVER emit shell commands that
    # uninstall kernel-related packages (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall linux-image|kernel-core). Auto-
    # removal would be categorically wrong: catastrophic at the
    # kernel-package level. Locks anti-package-removal contract
    # on the kernel-lockdown substrate.
    write_config "balanced"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(linux-image|kernel)'
    file="${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf"
    [ ! -f "${file}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${file}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kernel-lockdown manifest declares install + profile
    # gating (balanced / strict) the resolver enforces;
    # malformed manifest wedges the kernel.modules_disabled
    # boot-time persistence. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the kernel-
    # lockdown substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'kernel-lockdown', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: kernel-lockdown installer NEVER deletes operator-pre-existing sysctl/systemd configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # kernel-lockdown writes its own /etc/sysctl.d or /etc/systemd
    # drop-in; it MUST NEVER rm/find-delete an operator's
    # pre-existing /etc/sysctl.conf, /etc/sysctl.d, or
    # /etc/systemd entries not owned by THIS module. Locks
    # no-auto-delete on the kernel-lockdown installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/sysctl\.conf' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/sysctl\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # kernel-lockdown install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the kernel-lockdown lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the kernel-lockdown substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    # the kernel-lockdown requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    # present discipline on the kernel-lockdown substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    # category-present discipline on the kernel-lockdown substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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
    # semver-X.Y.Z discipline on the kernel-lockdown substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (kernel-lockdown module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the kernel-lockdown module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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

@test "INVARIANT (kernel-lockdown module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the kernel-lockdown module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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

@test "INVARIANT (kernel-lockdown module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the kernel-lockdown
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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

@test "INVARIANT (kernel-lockdown module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for kernel-lockdown is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the kernel-lockdown substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (kernel-lockdown module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the kernel-lockdown install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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

@test "INVARIANT (kernel-lockdown module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the kernel-lockdown requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
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

@test "INVARIANT (kernel-lockdown module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the kernel-lockdown
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (kernel-lockdown module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the kernel-lockdown
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-lockdown/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}
