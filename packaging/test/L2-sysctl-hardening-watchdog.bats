#!/usr/bin/env bats
# L2 bats functional tests for the sysctl-hardening-watchdog scan script.
#
# Watches the security-relevant sysctls in /etc/sysctl.conf + sysctl.d. An
# attacker who weakens one (ASLR off, ptrace_scope 0, kptr_restrict 0,
# suid_dumpable 1, …) is impairing kernel defenses (T1562). Severity:
#   ok    → no delta
#   warn  → any config change
#   alert → a security sysctl set to its WEAK (unsafe) value
#
# Run with: bats packaging/test/L2-sysctl-hardening-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd/sysctl-hardening-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    CONF="${TMP}/99-hardening.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SYSCTLH_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSCTLH_BASELINE="${BASELINE}" \
    SELFDEF_SYSCTLH_FILES="${FILES_V:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'kernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\n' > "${CONF}"
}

@test "no sysctl config → ok / no_sysctl_config" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_sysctl_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hardened sysctls, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sysctls on second run → ok / sysctl_hardening_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sysctl_hardening_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "ASLR disabled (randomize_va_space=0) → alert / sysctl_hardening_weakened" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 0\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sysctl_hardening_weakened"'
    cap | grep -q '"severity":"alert"'
}

@test "suid_dumpable re-enabled → alert" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nfs.suid_dumpable = 1\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign non-security sysctl addition → warn / sysctl_hardening_changed" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\nnet.core.somaxconn = 1024\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"sysctl_hardening_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign hardened config is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a weakened sysctl" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
