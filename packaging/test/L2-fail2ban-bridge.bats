#!/usr/bin/env bats
# L2 functional suite for fail2ban-bridge.
#
# fail2ban-bridge installs jail.d drop-ins to pin selfdef's
# fail2ban configuration:
#   standard → 50-selfdef.conf only (ssh + auth-fail bans)
#   broad    → 50-selfdef.conf + 60-selfdef-recidive.conf
#              (recidive = bans IPs that get banned-and-unbanned
#               repeatedly — long-term ban for persistent
#               attackers)
#
# CRITICAL INVARIANTS:
#   - Profile downgrade broad → standard REMOVES 60-selfdef-
#     recidive.conf (no stale recidive jail).
#   - Idempotent: byte-identical re-install fires NO fail2ban-
#     reload (reload triggers in-memory state flush of currently-
#     banned IPs and is operator-visible disruption).
#   - Uses fail2ban-client reload (graceful) before falling back
#     to systemctl restart (catches malformed-config cases).
#
# Uses SELFDEF_FAIL2BAN_JAIL_D env-var (already present) for L2
# testability.
#
# Run with: bats packaging/test/L2-fail2ban-bridge.bats

WD="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    cat > "${BIN}/fail2ban-client" <<'F2BEOF'
#!/usr/bin/env bash
printf 'fail2ban-client %s\n' "$*" >> "${F2B_LOG}"
exit 0
F2BEOF
    chmod +x "${BIN}/fail2ban-client"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export F2B_LOG="${TMP}/f2b.log"
    : > "${SYSEOF_LOG}"
    : > "${F2B_LOG}"
    CONF="${TMP}/fail2ban-bridge.toml"
    JAIL_D="${TMP}/jail.d"
    mkdir -p "${JAIL_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    F2B_LOG="${F2B_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_FAIL2BAN_CONFIG="${CONF}" \
    SELFDEF_FAIL2BAN_JAIL_D="${JAIL_D}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_FAIL2BAN_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FAIL2BAN_CONFIG="${SELFDEF_FAIL2BAN_CONFIG}" \
        SELFDEF_FAIL2BAN_JAIL_D="${JAIL_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FAIL2BAN_CONFIG="${CONF}" \
        SELFDEF_FAIL2BAN_JAIL_D="${JAIL_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|broad"* ]]
}

@test "standard profile installs ONLY 50-selfdef.conf + fail2ban-client reload fires" {
    write_config "standard"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
    [ "$(stat -c '%a' "${JAIL_D}/50-selfdef.conf")" = "644" ]
}

@test "broad profile installs BOTH 50-selfdef.conf + 60-selfdef-recidive.conf" {
    write_config "broad"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
}

@test "INVARIANT: profile downgrade broad → standard REMOVES recidive drop-in" {
    write_config "broad"
    run_wd
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    write_config "standard"
    : > "${F2B_LOG}"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]      # REMOVED
    # Reload fires because the removal IS a change.
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO reload" {
    write_config "standard"
    run_wd
    : > "${F2B_LOG}"
    : > "${SYSEOF_LOG}"
    run_wd
    # Critical: no reload = no in-memory ban-state flush.
    ! grep -q 'fail2ban-client reload' "${F2B_LOG}"
    ! grep -q 'systemctl restart fail2ban' "${SYSEOF_LOG}"
}

@test "INVARIANT: fail2ban-client reload preferred over systemctl restart" {
    write_config "standard"
    run_wd
    # Should call fail2ban-client reload (graceful), NOT systemctl
    # restart (disruptive).
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
    ! grep -q 'systemctl restart fail2ban' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-ins or reload" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! grep -q 'fail2ban-client reload' "${F2B_LOG}"
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
}
