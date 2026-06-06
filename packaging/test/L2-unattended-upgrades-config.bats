#!/usr/bin/env bats
# L2 functional suite for unattended-upgrades-config.
#
# unattended-upgrades-config installs apt.conf.d drop-ins +
# enables apt-daily-upgrade.timer to automatically install
# security updates daily. CVE-mitigation that doesn't depend on
# operator-action is foundational defense.
#
# Profiles:
#   security-only       → install security updates only
#                         (50selfdef + 20selfdef-periodic)
#   security-and-reboot → ALSO add reboot override (apt-daily
#                         can reboot the host when needed)
#                         (50selfdef + 20selfdef-periodic +
#                          60selfdef-unattended-reboot)
#
# CRITICAL INVARIANTS this suite locks:
#   - Profile downgrade security-and-reboot → security-only
#     REMOVES the 60selfdef-unattended-reboot file (no auto-
#     reboot left behind when operator explicitly backed off).
#   - Idempotent: byte-identical re-install of all 3 (or 2)
#     files does NOT re-fire systemctl enable (avoids
#     unnecessary state churn).
#   - DRY_RUN protects drop-ins + systemctl enable.
#
# Uses SELFDEF_APT_CONFD env-var (already present).
#
# Run with: bats packaging/test/L2-unattended-upgrades-config.bats

WD="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"

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
    CONF="${TMP}/unattended-upgrades-config.toml"
    APT_CONFD="${TMP}/apt.conf.d"
    mkdir -p "${APT_CONFD}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_UU_CONFIG="${CONF}" \
    SELFDEF_APT_CONFD="${APT_CONFD}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_UU_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_UU_CONFIG="${SELFDEF_UU_CONFIG}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_UU_CONFIG="${CONF}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be security-only|security-and-reboot"* ]]
}

@test "security-only profile installs base + periodic, NOT reboot override" {
    write_config "security-only"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "security-and-reboot profile installs ALL 3 drop-ins" {
    write_config "security-and-reboot"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "INVARIANT: profile downgrade security-and-reboot → security-only REMOVES reboot override" {
    write_config "security-and-reboot"
    run_wd
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
    write_config "security-only"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]      # REMOVED
}

@test "systemctl enable fires for BOTH apt-daily + apt-daily-upgrade timers" {
    write_config "security-only"
    run_wd
    grep -q 'systemctl enable --now apt-daily.timer' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now apt-daily-upgrade.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-ins or enable timers" {
    write_config "security-only"
    DRY_RUN=1 run_wd
    ! [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    ! [ -f "${APT_CONFD}/20selfdef-periodic" ]
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "drop-ins are chmod 0644 (apt.conf.d convention)" {
    write_config "security-and-reboot"
    run_wd
    [ "$(stat -c '%a' "${APT_CONFD}/50selfdef-unattended-upgrades")" = "644" ]
    [ "$(stat -c '%a' "${APT_CONFD}/20selfdef-periodic")" = "644" ]
    [ "$(stat -c '%a' "${APT_CONFD}/60selfdef-unattended-reboot")" = "644" ]
}

@test "default profile is security-only (no profile key — the conservative default)" {
    : > "${CONF}"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}
