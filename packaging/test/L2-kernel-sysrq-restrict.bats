#!/usr/bin/env bats
# L2 functional suite for kernel-sysrq-restrict.
#
# kernel-sysrq-restrict writes /etc/sysctl.d/50-selfdef-sysrq.conf
# pinning kernel.sysrq to a known value + applies it live via
# sysctl -w. The SysRq key is a kernel "magic key" that bypasses
# normal access controls: holding ALT+SysRq+<key> from any tty
# triggers privileged operations (reboot, kill all processes,
# dump kernel state, even spawn a root shell on some configs).
#
# Profiles:
#   off         → kernel.sysrq=0 (disable entirely)
#   safe-subset → kernel.sysrq=132 (only sync + remount-ro + reboot)
#   full        → kernel.sysrq=1 (all SysRq commands enabled —
#                  generally NOT recommended on a sovereign endpoint)
#
# Physical SysRq from a keyboard or serial console is a privilege
# escalation surface for anyone with that access — janitor, evil
# maid, or someone-with-an-IPMI-console.
#
# Adds SELFDEF_SYSRQ_DROPIN env-var (added 2026-06-06) for L2
# testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-kernel-sysrq-restrict.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/kernel-sysrq-restrict.toml"
    DROPIN="${TMP}/50-selfdef-sysrq.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SYSRQ_CONFIG="${CONF}" \
    SELFDEF_SYSRQ_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SYSRQ_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SYSRQ_CONFIG="${SELFDEF_SYSRQ_CONFIG}" \
        SELFDEF_SYSRQ_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SYSRQ_CONFIG="${CONF}" \
        SELFDEF_SYSRQ_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be off|safe-subset|full"* ]]
}

@test "off profile → sysctl -w kernel.sysrq=0" {
    write_config "off"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.sysrq=0' "${SCTL_LOG}"
    grep -q 'profile=off' "${DROPIN}"
    grep -q '(kernel.sysrq=0)' "${DROPIN}"
}

@test "safe-subset profile → sysctl -w kernel.sysrq=132 (sync+remount-ro+reboot bitmask)" {
    write_config "safe-subset"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.sysrq=132' "${SCTL_LOG}"
    grep -q '(kernel.sysrq=132)' "${DROPIN}"
}

@test "full profile → sysctl -w kernel.sysrq=1" {
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.sysrq=1' "${SCTL_LOG}"
}

@test "drop-in carries the header marker + timestamp" {
    write_config "off"
    run_wd
    grep -q 'managed-by: selfdef kernel-sysrq-restrict' "${DROPIN}"
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"  # no timestamp (2026-06-06 idempotency fix)
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "off"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "off"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "off"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is off (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=off' "${DROPIN}"
}

@test "second run replays sysctl -w (idempotent at the kernel-state layer)" {
    write_config "safe-subset"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.sysrq=132' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition off → safe-subset): rewrites + applies 132 live" {
    write_config "off"
    run_wd
    grep -q 'profile=off' "${DROPIN}"
    write_config "safe-subset"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=safe-subset' "${DROPIN}"
    grep -q 'sysctl -w kernel.sysrq=132' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition safe-subset → full): rewrites + applies =1 live" {
    write_config "safe-subset"
    run_wd
    write_config "full"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=full' "${DROPIN}"
    grep -q 'sysctl -w kernel.sysrq=1' "${SCTL_LOG}"
}

@test "INVARIANT (profile downgrade full → off): rewrites back to most-restrictive + applies 0" {
    write_config "full"
    run_wd
    write_config "off"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=off' "${DROPIN}"
    grep -q 'sysctl -w kernel.sysrq=0' "${SCTL_LOG}"
}

@test "INVARIANT (safe-subset bitmask 132): the actual bitmask value (4=sync + 128=reboot, sum=132)" {
    # The 132 bitmask: sync (4) + reboot (128). The combination matters
    # — if this drifts to 4 or 128 alone, the safe-subset functionality
    # is broken differently (no reboot OR no sync).
    write_config "safe-subset"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*132' "${DROPIN}"
}

@test "INVARIANT (live-knob re-application — even on idempotent disk path)" {
    write_config "off"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.sysrq=' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl)" {
    write_config "off"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'kernel\.sysrq[[:space:]]*=' "${DROPIN}"
    grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (header marker first non-blank line — stale-cleanup head -1 grep)" {
    write_config "off"
    run_wd
    first_line="$(head -1 "${DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef kernel-sysrq-restrict" ]
}

@test "INVARIANT (sysctl mechanism: -w flag for surgical single-key application — NOT -p path)" {
    # -w writes the live kernel value surgically.
    # -p would reload entire sysctl.d directory which would side-
    # effect other modules. Lock the choice.
    write_config "off"
    run_wd
    grep -qE 'sysctl -w' "${SCTL_LOG}"
    ! grep -qE 'sysctl -p' "${SCTL_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "safe-subset"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"kernel-sysrq-restrict"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=safe-subset'* ]]
}

@test "INVARIANT (filename follows 50-selfdef-* convention — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    write_config "off"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (drop-in is sysctl-parseable: each non-comment line matches key=value shape)" {
    # The drop-in is sourced by sysctl --system. Every non-comment
    # non-blank line MUST match the sysctl key=value grammar.
    # Sister to file-protections-baseline + sysctl-network-baseline
    # sysctl-parseable INVARIANT.
    write_config "safe-subset"
    run_wd
    awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} /^[a-zA-Z_][a-zA-Z0-9_.]*[[:space:]]*=[[:space:]]*[0-9]+/ {next} {bad=1; print "malformed: " $0} END{exit bad?1:0}' "${DROPIN}"
}

@test "INVARIANT (profile-rank monotonic: off (0) ≤ safe-subset (132 = sync+reboot) ≤ full (1 means ALL — distinct mode)) — locks bitmask values)" {
    # Lock the THREE specific bitmask values for the THREE
    # profiles. Operator can dashboard-verify the active value
    # against expectations. A regression that swaps values
    # would change the security posture silently.
    write_config "off"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*0' "${DROPIN}"
    write_config "safe-subset"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*132' "${DROPIN}"
    write_config "full"
    run_wd
    grep -qE 'kernel\.sysrq\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # kernel-sysrq-restrict TOML; parser must tolerate without
    # altering the profile-gated behavior. off-with-noise still
    # installs the kernel.sysrq=0 drop-in (the sysrq full-disable
    # — closes the physical-console attack surface that lets
    # anyone with keyboard access send unauthenticated kernel
    # commands).
    cat > "${CONF}" <<'TOMLEOF'
profile = "off"
operator_note = "sysrq = physical-console unauthenticated kernel cmd surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'kernel\.sysrq\s*=\s*0' "${DROPIN}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl -w fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/sysctl.d/50-selfdef-kernel-
    # sysrq.conf AND without firing sysctl -w kernel.sysrq=<N>.
    # A silent dry-run that committed would flip the kernel
    # sysrq mask on a host where operator was investigating
    # console-debugging behavior (incident responder needs sysrq
    # available for emergency stack-trace capture). Locks dry-
    # run-preserves-state on the sysrq-restrict substrate.
    write_config "off"
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN}" ]
    ! grep -qE 'sysctl -w kernel.sysrq' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "off"
    run_wd
    [ -f "${DROPIN}" ]
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on kernel-sysrq-restrict installer
    # surface across drop-in + sysctl-w phases.
    write_config "off"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"kernel-sysrq-restrict"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The kernel-sysrq-restrict drop-in
    # MUST carry a comment marker identifying it as selfdef-
    # managed so a stale-cleanup head -2 grep at uninstall time
    # can identify which files selfdef owns vs which is operator-
    # original. Without a marker, a subsequent uninstaller could
    # not tell apart operator baseline sysctl rules from selfdef-
    # injected kernel.sysrq directives — risking accidental
    # rollback of operator changes. Locks marker-discipline on
    # the kernel-sysrq-restrict sysctl.d substrate.
    write_config "off"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^#.*(selfdef|kernel-sysrq-restrict|managed)' "${DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kernel-sysrq-restrict manifest declares install +
    # profile gating (off / safe-subset / full) the resolver
    # enforces; malformed manifest wedges the kernel.sysrq
    # bitmask. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the kernel-sysrq-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'kernel-sysrq-restrict', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: kernel-sysrq-restrict installer NEVER deletes operator-pre-existing sysctl/systemd configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # kernel-sysrq-restrict writes its own /etc/sysctl.d or /etc/systemd
    # drop-in; it MUST NEVER rm/find-delete an operator's
    # pre-existing /etc/sysctl.conf, /etc/sysctl.d, or
    # /etc/systemd entries not owned by THIS module. Locks
    # no-auto-delete on the kernel-sysrq-restrict installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/sysctl\.conf' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/sysctl\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # kernel-sysrq-restrict install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the kernel-sysrq-restrict lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    # the kernel-sysrq-restrict requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    # present discipline on the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    # category-present discipline on the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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
    # semver-X.Y.Z discipline on the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the kernel-sysrq-restrict module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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

@test "INVARIANT (kernel-sysrq-restrict module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the kernel-sysrq-restrict module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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

@test "INVARIANT (kernel-sysrq-restrict module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the kernel-sysrq-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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

@test "INVARIANT (kernel-sysrq-restrict module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for kernel-sysrq-restrict is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the kernel-sysrq-restrict install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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

@test "INVARIANT (kernel-sysrq-restrict module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the kernel-sysrq-restrict requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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

@test "INVARIANT (kernel-sysrq-restrict module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the kernel-sysrq-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the kernel-sysrq-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the kernel-sysrq-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
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

@test "INVARIANT (kernel-sysrq-restrict module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (kernel-sysrq-restrict README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/kernel-sysrq-restrict/README.md"
    [ -f "${readme}" ]
}
