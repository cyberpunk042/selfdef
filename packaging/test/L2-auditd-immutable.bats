#!/usr/bin/env bats
# L2 functional suite for auditd-immutable.
#
# auditd-immutable installs /etc/audit/rules.d/99-selfdef-
# immutable.rules. The audit profile is the safe option —
# observation only. The enforce profile triggers `-e 2` which
# LOCKS the audit subsystem until reboot: no auditctl -D, no
# auditctl -e 0, no rule additions/removals. Attackers who
# T1562.001-blind audit can't, until reboot. Operators who need
# to tune audit during normal operation also can't.
#
# CRITICAL INVARIANT: enforce profile requires
# acknowledge_immutable=true in config. Without it the script
# REFUSES — refuse-to-brick guard (parallel to kernel-lockdown
# strict + kernel-yama paranoid).
#
# Tests shadow augenrules + auditctl on PATH; uses
# SELFDEF_AUDIT_RULES_D env-var override.
#
# Run with: bats packaging/test/L2-auditd-immutable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/auditd-immutable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/augenrules" <<'AEEOF'
#!/usr/bin/env bash
printf 'augenrules %s\n' "$*" >> "${AUGEN_LOG}"
exit 0
AEEOF
    chmod +x "${BIN}/augenrules"
    cat > "${BIN}/auditctl" <<'ACEOF'
#!/usr/bin/env bash
case "$1" in
    -s) printf 'enabled %s\n' "${LIVE_AUDIT_ENABLED:-1}" ;;
esac
exit 0
ACEOF
    chmod +x "${BIN}/auditctl"
    export AUGEN_LOG="${TMP}/augen.log"
    : > "${AUGEN_LOG}"
    CONF="${TMP}/auditd-immutable.toml"
    RULES_D="${TMP}/audit-rules.d"
    mkdir -p "${RULES_D}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [acknowledge_immutable]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_immutable = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    AUGEN_LOG="${AUGEN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
    SELFDEF_AUDIT_RULES_D="${RULES_D}" \
    LIVE_AUDIT_ENABLED="${LIVE_AUDIT_ENABLED:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AUDITD_IMMUTABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${SELFDEF_AUDITD_IMMUTABLE_CONFIG}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing rules.d → die (auditd not installed)" {
    write_config "audit"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${TMP}/no-such-rules-d" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"audit rules.d missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit|enforce"* ]]
}

@test "INVARIANT: enforce profile without acknowledgment → die (refuse-to-brick)" {
    write_config "enforce" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"locks audit rules until reboot"* ]]
    # The enforce.rules file MUST NOT be installed.
    ! [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
}

@test "audit profile installs audit.rules + reloads via augenrules" {
    write_config "audit"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    # Drop-in chmod 0640 (audit-rules.d convention).
    [ "$(stat -c '%a' "${RULES_D}/99-selfdef-immutable.rules")" = "640" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "enforce profile WITH acknowledgment installs enforce.rules" {
    write_config "enforce" "true"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    cmp -s modules/auditd-immutable/configs/enforce.rules "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO augenrules" {
    write_config "audit"
    run_wd
    : > "${AUGEN_LOG}"
    run_wd
    ! grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT: DRY_RUN does not install rules or fire augenrules" {
    write_config "audit"
    DRY_RUN=1 run_wd
    ! [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    ! grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "default profile is audit (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    # Default audit profile content matches audit.rules.
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
}

@test "profile downgrade enforce→audit replaces drop-in + reloads" {
    write_config "enforce" "true"
    run_wd
    # Verify it's the enforce version first.
    cmp -s modules/auditd-immutable/configs/enforce.rules "${RULES_D}/99-selfdef-immutable.rules"
    # Downgrade.
    write_config "audit"
    : > "${AUGEN_LOG}"
    run_wd
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}
