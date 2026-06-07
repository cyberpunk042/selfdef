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

@test "baseline is chmod 0600 (confidentiality — sysctl inventory enumerates kernel-hardening posture)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (kptr_restrict weakening): kptr_restrict=0 → alert (kernel pointer leak surface)" {
    seed_benign
    run_wd
    printf 'kernel.kptr_restrict = 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (yama.ptrace_scope weakening): ptrace_scope=0 → alert (any-uid ptrace = credential dump)" {
    seed_benign
    run_wd
    printf 'kernel.yama.ptrace_scope = 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ASLR partial-disable): randomize_va_space=1 (partial) → alert (only full=2 is safe)" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 1\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing weak sysctl): baseline_initial fires alert if sysctl already has a weak value at install-time" {
    printf 'kernel.randomize_va_space = 0\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (multi-weakening composition): multiple weakened sysctls in one file → alert (any one is enough)" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 0\nkernel.kptr_restrict = 0\nkernel.yama.ptrace_scope = 0\nfs.suid_dumpable = 1\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — newly-WEAKENED sysctl key surfaces in JSON sample (operator triage)" {
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'randomize_va_space'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sysctl-hardening -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): sysctl-hardening-watchdog DOES auto-refresh baseline on weakening detection" {
    # CONTRAST against no-auto-trust family. After alert,
    # baseline updates so next-run sees intact. Locks the
    # architectural choice.
    seed_benign
    run_wd
    printf 'kernel.randomize_va_space = 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed → ok
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (commented sysctl NOT counted: # prefix filtered from inventory)" {
    # /etc/sysctl.conf supports # comments. Operator notes about
    # hypothetical weakening must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'kernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\n# kernel.randomize_va_space = 0 — example of bad config\n' > "${CONF}"
    run_wd
    # Commented weakening must NOT trigger alert.
    ! cap | grep -q '"event":"sysctl_hardening_weakened"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'kernel.randomize_va_space  =  0' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces to evade naive grep-based
    # detection. Lock whitespace-tolerant parser.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'kernel.randomize_va_space    =    0\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: sysctl.d drop-in axis — weakened sysctl in any of the watched files → alert)" {
    # /etc/sysctl.d/*.conf drop-ins are honored by systemd-sysctl
    # alongside /etc/sysctl.conf. Attackers may plant weakening
    # in drop-in to avoid main file. Lock multi-file axis.
    CONF2="${TMP}/50-weakening.conf"
    seed_benign
    FILES_V="${CONF} ${CONF2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant weakening in drop-in.
    printf 'kernel.randomize_va_space = 0\n' > "${CONF2}"
    FILES_V="${CONF} ${CONF2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dmesg_restrict weakening: kernel.dmesg_restrict=0 → alert — kernel-log info disclosure axis)" {
    # dmesg_restrict=1 hides kernel ring buffer from unprivileged
    # users. Setting to 0 exposes kernel pointers + driver state
    # (T1592 reconnaissance). Sister axis to kptr_restrict.
    seed_benign
    run_wd
    printf 'kernel.dmesg_restrict = 0\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names offending sysctl key in JSON — operator triage routing)" {
    # When weakening alert fires, sample MUST surface the specific
    # sysctl key name. Sister contract: many other watchdogs'
    # sample-naming pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Use a distinctive weakening for forensics trail.
    printf 'kernel.randomize_va_space = 0\nfs.suid_dumpable = 1\n' > "${CONF}"
    run_wd
    # Both weakened keys surface in sample for forensics.
    cap | grep -qE 'randomize_va_space|suid_dumpable'
}

@test "INVARIANT (severity precedence: weakened + benign-change in same scan → alert wins over warn)" {
    # Sister to other watchdogs' severity precedence INVARIANTs.
    # When a weakening AND a benign change coexist in same scan,
    # alert (weakening) wins over warn (benign change).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Both weakening AND benign change.
    printf 'kernel.randomize_va_space = 0\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\nnet.core.somaxconn = 4096\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"sysctl_hardening_weakened"'
    cap | grep -q '"severity":"alert"'
}
