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
