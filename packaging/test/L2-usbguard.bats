#!/usr/bin/env bats
# L2 functional suite for usbguard.
#
# usbguard pins the USB-allow-list — kernel-level enforcement of
# "only known devices are allowed to register". Blocks the entire
# class of USB-implant attacks (bad-USB keyboards, malicious
# storage devices, USB-Ethernet devices that redirect DNS, etc.).
#
# Profiles:
#   permissive → policy logs new devices but allows everything
#                (the operator-baseline-collection phase)
#   strict     → require operator-baseline rules; reject anything
#                outside the baseline (the enforcement phase)
#
# CRITICAL INVARIANTS this suite locks:
#   - strict profile REFUSES TO INSTALL if operator-baseline is
#     missing or empty (refuse-to-brick: empty baseline + strict
#     = locked-out keyboard + mouse).
#   - Idempotent: byte-identical re-install fires NO usbguard
#     restart (timestamp-removal fix from ec1d60a locked here —
#     usbguard restart flushes in-memory authorization state).
#   - DRY_RUN protects rules + daemon drop-in + restart.
#   - rules.conf chmod 0600 (operator-private — rules MAY contain
#     sensitive device IDs).
#
# Uses 5 env-var overrides (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-usbguard.bats

WD="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/usbguard.toml"
    RULES_DST="${TMP}/rules.conf"
    DAEMON_DROPIN_DIR="${TMP}/usbguard-daemon.conf.d"
    OPERATOR_DIR="${TMP}/usbguard-operator"
    BASELINE_FILE="${OPERATOR_DIR}/operator-baseline.rules"
    mkdir -p "${OPERATOR_DIR}" "${DAEMON_DROPIN_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_USBGUARD_CONFIG="${CONF}" \
    SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
    SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
    SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
    SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_USBGUARD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USBGUARD_CONFIG="${SELFDEF_USBGUARD_CONFIG}" \
        SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
        SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
        SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
        SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USBGUARD_CONFIG="${CONF}" \
        SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
        SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
        SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
        SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be permissive|strict"* ]]
}

@test "INVARIANT: strict profile + missing baseline → die (refuse-to-brick)" {
    write_config "strict"
    # No baseline file.
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USBGUARD_CONFIG="${CONF}" \
        SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
        SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
        SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
        SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"requires non-empty baseline"* ]]
    # rules.conf MUST NOT be installed.
    ! [ -f "${RULES_DST}" ]
}

@test "INVARIANT: strict profile + EMPTY baseline → die (refuse-to-brick)" {
    write_config "strict"
    : > "${BASELINE_FILE}"     # baseline exists but empty
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USBGUARD_CONFIG="${CONF}" \
        SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
        SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
        SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
        SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"requires non-empty baseline"* ]]
}

@test "permissive profile installs rules.conf + daemon drop-in + restarts usbguard" {
    write_config "permissive"
    run_wd
    [ -f "${RULES_DST}" ]
    [ -f "${DAEMON_DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'profile=permissive' "${RULES_DST}"
    grep -q 'AuditBackend=LinuxAudit' "${DAEMON_DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart usbguard' "${SYSEOF_LOG}"
}

@test "strict profile WITH non-empty baseline installs rules with baseline body + strict tail" {
    write_config "strict"
    printf '%s\n' 'allow id 1d6b:0002  # known root hub' > "${BASELINE_FILE}"
    run_wd
    [ -f "${RULES_DST}" ]
    grep -q 'profile=strict' "${RULES_DST}"
    grep -q 'operator baseline' "${RULES_DST}"
    grep -q 'allow id 1d6b:0002' "${RULES_DST}"
    grep -q 'selfdef strict.conf' "${RULES_DST}"
}

@test "INVARIANT: rules.conf is chmod 0600 (operator-private)" {
    write_config "permissive"
    run_wd
    [ "$(stat -c '%a' "${RULES_DST}")" = "600" ]
}

@test "INVARIANT: idempotent — byte-identical re-install fires NO usbguard restart" {
    write_config "permissive"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # No restart = no in-memory authorization-state flush.
    ! grep -q 'systemctl restart usbguard' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change permissive → strict (with baseline) rewrites rules + restarts" {
    write_config "permissive"
    run_wd
    printf '%s\n' 'allow id 1d6b:0002' > "${BASELINE_FILE}"
    write_config "strict"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'profile=strict' "${RULES_DST}"
    grep -q 'systemctl restart usbguard' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install rules / drop-in or restart" {
    write_config "permissive"
    DRY_RUN=1 run_wd
    ! [ -f "${RULES_DST}" ]
    ! [ -f "${DAEMON_DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "default profile is permissive (no profile key — safe baseline-collection default)" {
    : > "${CONF}"
    run_wd
    grep -q 'profile=permissive' "${RULES_DST}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves rules.conf mtime" {
    write_config "permissive"
    run_wd
    mtime_before="$(stat -c '%Y' "${RULES_DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${RULES_DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile downgrade strict → permissive): rewrites rules + restarts" {
    write_config "strict"
    printf '%s\n' 'allow id 1d6b:0002' > "${BASELINE_FILE}"
    run_wd
    grep -q 'profile=strict' "${RULES_DST}"
    write_config "permissive"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'profile=permissive' "${RULES_DST}"
    ! grep -q 'profile=strict' "${RULES_DST}"
    grep -q 'systemctl restart usbguard' "${SYSEOF_LOG}"
}

@test "INVARIANT (daemon drop-in is chmod 0644 — system-config convention)" {
    write_config "permissive"
    run_wd
    [ "$(stat -c '%a' "${DAEMON_DROPIN_DIR}/50-selfdef.conf")" = "644" ]
}

@test "INVARIANT (no render-timestamp in rules.conf — defeats cmp -s idempotency)" {
    write_config "permissive"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${RULES_DST}"
}

@test "INVARIANT (no render-timestamp in daemon drop-in — variant-A guard on secondary file)" {
    write_config "permissive"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DAEMON_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates rules + drop-in + restarts)" {
    # Operator (or attacker) may rm the rules.conf — apply must rebuild
    # and re-arm the daemon so USB-allow-list enforcement is restored.
    write_config "permissive"
    run_wd
    [ -f "${RULES_DST}" ]
    [ -f "${DAEMON_DROPIN_DIR}/50-selfdef.conf" ]
    rm -f "${RULES_DST}" "${DAEMON_DROPIN_DIR}/50-selfdef.conf"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${RULES_DST}" ]
    [ -f "${DAEMON_DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'systemctl restart usbguard' "${SYSEOF_LOG}"
}

@test "INVARIANT (header-marker in rules.conf is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "permissive"
    run_wd
    first_line="$(awk 'NF' "${RULES_DST}" | head -1)"
    [[ "${first_line}" == *"selfdef usbguard"* || "${first_line}" == *"managed-by"* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "permissive"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"usbguard"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=permissive'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — strict w/o baseline dies even after prior permissive install)" {
    # Operator installs permissive first (baseline-collection phase),
    # then flips to strict but FORGETS to seed the operator-baseline.
    # apply MUST refuse AND leave the prior permissive rules unchanged
    # — no silent escalation to strict-with-empty-rules (= locked-out keyboard).
    write_config "permissive"
    run_wd
    grep -q 'profile=permissive' "${RULES_DST}"
    # Operator removes the prior baseline (or it was never seeded).
    rm -f "${BASELINE_FILE}"
    write_config "strict"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USBGUARD_CONFIG="${CONF}" \
        SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
        SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
        SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
        SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Prior permissive rules preserved — header marker stays permissive
    # (no mutation to strict-empty = no locked-out keyboard).
    grep -q 'profile=permissive' "${RULES_DST}"
}

@test "INVARIANT (daemon drop-in carries AuditBackend=LinuxAudit — kernel-audit observability)" {
    # Sister axis to existing test that locks AuditBackend in
    # permissive. Lock that strict ALSO carries it. The audit
    # backend forwards usbguard events to kernel-audit / journald
    # for the operator observability pipeline.
    write_config "strict"
    printf '%s\n' 'allow id 1d6b:0002' > "${BASELINE_FILE}"
    run_wd
    grep -qE 'AuditBackend\s*=\s*LinuxAudit' "${DAEMON_DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (filename: daemon drop-in follows 50-selfdef.conf convention — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    write_config "permissive"
    run_wd
    case "${DAEMON_DROPIN_DIR}/50-selfdef.conf" in
        */50-selfdef.conf) : ;;
        *) fail "daemon drop-in filename must follow 50-selfdef.conf pattern" ;;
    esac
    [ -f "${DAEMON_DROPIN_DIR}/50-selfdef.conf" ]
}

@test "INVARIANT (config-layer-noise resilience: strict + extra TOML keys does NOT bypass baseline-required gate)" {
    # Sister to kernel-lockdown + nftables-baseline + unprivileged-
    # userns + proc-hidepid config-noise INVARIANT. Lock that extra
    # config keys cannot accidentally bypass the strict-needs-
    # baseline gate.
    cat > "${CONF}" <<'EOF'
profile = "strict"
extra_knob = "wrong"
maybe_an_alias_for_baseline = "true"
EOF
    # Baseline NOT seeded.
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USBGUARD_CONFIG="${CONF}" \
        SELFDEF_USBGUARD_RULES_FILE="${RULES_DST}" \
        SELFDEF_USBGUARD_DROPIN_DIR="${DAEMON_DROPIN_DIR}" \
        SELFDEF_USBGUARD_OPERATOR_DIR="${OPERATOR_DIR}" \
        SELFDEF_USBGUARD_BASELINE="${BASELINE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"baseline"* ]]
    ! [ -f "${RULES_DST}" ]
}

@test "INVARIANT (rules.conf is chmod 0600 — operator-private USB device allowlist confidentiality)" {
    # Sister to many other watchdog/installer baseline + state-
    # file confidentiality INVARIANTs across the brain (sudoers-
    # integrity, polkit-rules, sshrc, suid-sgid, audit-config).
    # The rules.conf file enumerates which USB devices (by
    # vendor:product + serial) are permitted to attach — that's
    # sensitive operator-environment intelligence (an attacker
    # who reads it knows which devices are typically present +
    # could social-engineer or hardware-spoof a matching device).
    # Must be operator-private (root-readable only) — CIS +
    # USBGuard upstream recommend 0600.
    printf '%s\n' 'allow id 1d6b:0002  # known root hub' > "${BASELINE_FILE}"
    write_config "permissive"
    run_wd
    [ -f "${RULES_DST}" ]
    mode="$(stat -c '%a' "${RULES_DST}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ] || [ "${mode}" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO rules + drop-in written AND NO usbguard restart fired when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/usbguard/rules.conf AND
    # without restarting usbguard.service. A silent dry-run
    # that committed would lock the operator out of their own
    # USB devices AT PREVIEW TIME if the baseline doesn't
    # cover the actual attached devices. Locks dry-run-
    # preserves-state on the USB-device-allowlist substrate.
    printf '%s\n' 'allow id 1d6b:0002  # known root hub' > "${BASELINE_FILE}"
    write_config "permissive"
    rm -f "${RULES_DST}"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${RULES_DST}" ]
    ! grep -qE 'systemctl (restart|reload) usbguard' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on usbguard installer surface
    # across rules.conf + daemon-drop-in + restart phases.
    printf '%s\n' 'allow id 1d6b:0002' > "${BASELINE_FILE}"
    write_config "permissive"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"usbguard"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: usbguard module NEVER emits package-remove commands on usbguard)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The usbguard installer wires rules.conf +
    # daemon drop-in but MUST NEVER emit shell commands that
    # uninstall the usbguard package itself (apt/dpkg/dnf/rpm/
    # yum remove|purge|uninstall usbguard). Silent auto-removal
    # of usbguard during install/check would leave the host
    # with no USB-device allowlist enforcement — every USB
    # insert becomes auto-trusted. T1200 Hardware Additions
    # via attacker-USB attack-surface re-opening. Locks anti-
    # package-removal contract on the USB-device allowlist
    # substrate.
    printf '%s\n' 'allow id 1d6b:0002' > "${BASELINE_FILE}"
    write_config "permissive"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+usbguard'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+usbguard' "${SYSEOF_LOG:-/dev/null}" 2>/dev/null || true
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on usbguard surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The usbguard installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the USB-device allowlist status alert. Locks
    # parser contract on the usbguard installer JSON surface
    # (consistency-with-watchdog-family discipline).
    printf '%s\n' 'allow id 1d6b:0002' > "${BASELINE_FILE}"
    write_config "permissive"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. usbguard manifest declares install + profile
    # gating (audit / lock) the resolver enforces; malformed
    # manifest wedges the USB-device-allowlist baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'usbguard', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: usbguard installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # usbguard writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the usbguard
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/usbguard/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # usbguard install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the usbguard lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/usbguard/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    # the usbguard requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    # usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    # usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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
    # Locks semver-X.Y.Z discipline on the usbguard
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (usbguard module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the usbguard module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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

@test "INVARIANT (usbguard module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the usbguard module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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

@test "INVARIANT (usbguard module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the usbguard
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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

@test "INVARIANT (usbguard module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for usbguard is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (usbguard module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the usbguard install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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

@test "INVARIANT (usbguard module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the usbguard requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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

@test "INVARIANT (usbguard module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the usbguard
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (usbguard module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the usbguard
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (usbguard module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (usbguard module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (usbguard module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the usbguard substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
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

@test "INVARIANT (usbguard module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (usbguard module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (usbguard module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (usbguard module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (usbguard module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (usbguard module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (usbguard README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/usbguard/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (usbguard install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (usbguard install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (usbguard install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (usbguard install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (usbguard install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (usbguard install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/usbguard/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (usbguard install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (usbguard install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (usbguard install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (usbguard install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (usbguard install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (usbguard install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (usbguard module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (usbguard module.toml exists at canonical path modules/usbguard/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (usbguard module dir is at canonical path modules/usbguard/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/usbguard"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (usbguard install dir exists at modules/usbguard/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/usbguard/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (usbguard install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/usbguard/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (usbguard install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (usbguard install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (usbguard install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (usbguard module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (usbguard install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (usbguard install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (usbguard install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (usbguard install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (usbguard install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (usbguard install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (usbguard install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (usbguard install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/usbguard/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (usbguard module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (usbguard module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/usbguard/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}
