#!/usr/bin/env bats
# L2 functional suite for journal-tune.
#
# journal-tune installs /etc/systemd/journald.conf.d/50-selfdef.
# conf with the chosen profile. Journald is the audit trail —
# tampered / undersized / world-readable journals defeat incident
# forensics. The two profiles tighten different axes:
#   standard  → reasonable retention + size caps (the always-safe
#               baseline)
#   paranoid  → tight retention, forward to remote, strict mode,
#               larger pool for high-volume hosts
#
# CRITICAL INVARIANTS this suite locks:
#   - Idempotent: byte-identical re-install fires NO journald
#     restart (a restart loses the in-memory journal queue —
#     unnecessary restart = potential data loss).
#   - Profile change standard → paranoid replaces drop-in +
#     restarts.
#   - DRY_RUN protects BOTH drop-in AND systemctl restart.
#
# Uses SELFDEF_JOURNAL_DROPIN_DIR env-var (already present) for
# L2 testability.
#
# Run with: bats packaging/test/L2-journal-tune.bats

WD="${BATS_TEST_DIRNAME}/../../modules/journal-tune/install/apply.sh"

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
    CONF="${TMP}/journal-tune.toml"
    DROPIN_DIR="${TMP}/journald.conf.d"
    mkdir -p "${DROPIN_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_JOURNAL_TUNE_CONFIG="${CONF}" \
    SELFDEF_JOURNAL_DROPIN_DIR="${DROPIN_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_JOURNAL_TUNE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_JOURNAL_TUNE_CONFIG="${SELFDEF_JOURNAL_TUNE_CONFIG}" \
        SELFDEF_JOURNAL_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_JOURNAL_TUNE_CONFIG="${CONF}" \
        SELFDEF_JOURNAL_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|paranoid"* ]]
}

@test "standard profile installs drop-in + restarts journald" {
    write_config "standard"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "paranoid profile installs the tighter drop-in" {
    write_config "paranoid"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s modules/journal-tune/configs/paranoid.conf "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO journald restart" {
    write_config "standard"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd                              # byte-identical re-install
    # CRITICAL: no restart = no data loss to in-memory journal queue.
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change standard → paranoid replaces drop-in + restarts" {
    write_config "standard"
    run_wd
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
    write_config "paranoid"
    : > "${SYSEOF_LOG}"
    run_wd
    cmp -s modules/journal-tune/configs/paranoid.conf "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-journald' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write drop-in or restart" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "drop-in is chmod 0644" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DROPIN_DIR}/50-selfdef.conf")" = "644" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    cmp -s modules/journal-tune/configs/standard.conf "${DROPIN_DIR}/50-selfdef.conf"
}
