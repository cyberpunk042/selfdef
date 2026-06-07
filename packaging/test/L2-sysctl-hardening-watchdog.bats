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

@test "INVARIANT (net.ipv4.ip_forward=1 weakening: enabled IP forwarding → alert — accidental-router pivot axis)" {
    # Sister to other sysctl-hardening weakening axes already
    # locked. net.ipv4.ip_forward=1 turns the host into an IP
    # router — an attacker with foothold can use this to route
    # traffic between attacker-controlled networks via the
    # compromised host (T1090.001 — Internal Proxy via accidental-
    # router). Lock weakening detection on the ip_forward axis.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'kernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\nnet.ipv4.ip_forward = 1\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (kernel.unprivileged_userns_clone=1 weakening: enabling unprivileged user namespaces → alert — container-escape primitive axis)" {
    # Sister to other sysctl-hardening weakening axes. kernel.
    # unprivileged_userns_clone=1 lets unprivileged users create
    # user namespaces — substrate for many privilege-escalation
    # exploits (CVE-2022-0185, CVE-2022-25636, et al). On
    # hardened hosts this is set to 0; an attacker who manages
    # to flip back to 1 unlocks a large CVE surface. Lock
    # weakening detection on the unprivileged-userns-clone
    # axis (T1611 — Escape to Host via user-namespace creation).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'kernel.randomize_va_space = 2\nkernel.kptr_restrict = 2\nkernel.yama.ptrace_scope = 1\nkernel.unprivileged_userns_clone = 1\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (net.ipv4.conf.all.rp_filter=0 weakening: reverse-path filter disabled → alert — IP-spoofing-acceptance axis)" {
    # Sister to brain-wide sysctl-hardening weakening axes
    # (randomize_va_space, kptr_restrict, ptrace_scope, dmesg_
    # restrict, ip_forward, unprivileged_userns_clone). reverse-
    # path filter (rp_filter) is the kernel's anti-spoofing
    # network defense — when active (rp_filter=1 or 2), packets
    # received on an interface MUST match the route the kernel
    # would use to reply back. Disabling rp_filter=0 lets
    # spoofed-source-IP packets through, enabling reflection
    # attacks AND giving attackers ability to receive responses
    # to spoofed-source probes. Lock weakening detection on
    # rp_filter axis (T1565.002 transmitted-data-manipulation
    # spoofed-source variant).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'kernel.randomize_va_space = 2\nnet.ipv4.conf.all.rp_filter = 0\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on sysctl-hardening surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The sysctl-hardening-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the T1562.001 Impair Defenses: Disable
    # or Modify Tools (sysctl-weakening) alert. Locks parser
    # contract on the sysctl-hardening detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'kernel.randomize_va_space = 0\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-fix: sysctl-hardening-watchdog NEVER edits sysctl files to revert weakened directives — surveillance not remediation)" {
    # Sister to brain-wide no-auto-fix / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # sysctl-hardening-watchdog DETECTS T1562.001 Impair
    # Defenses via sysctl weakening but MUST NEVER emit sed/
    # awk commands to auto-revert the weakened directive. The
    # detected weakening may be operator-legitimate (operator
    # intentionally tweaked sysctl for a specific workload,
    # e.g., kernel.unprivileged_userns_clone=1 for rootless
    # containers). Silent auto-revert would break operator's
    # intended workload. Surveillance, never remediation.
    # Locks anti-data-loss contract on the sysctl-hardening
    # surveillance substrate.
    ! grep -qE 'sed[[:space:]]+-i.*sysctl' "${WD}"
    ! grep -qE 'sysctl[[:space:]]+-w' "${WD}"
    ! grep -qE 'echo[[:space:]]+.*>[[:space:]]*/proc/sys/' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # sysctl-hardening-watchdog runs ON the timer's scheduled
    # fire — scans /etc/sysctl.conf + sysctl.d/* for weakening
    # of canonical hardening sysctls (kptr_restrict, dmesg_restrict,
    # rp_filter, etc.), emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the sysctl-hardening-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd/selfdef-sysctl-hardening.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sysctl-hardening-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # sysctl-hardening-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # sysctl-hardening-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'sysctl-hardening-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: sysctl-hardening-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. sysctl-hardening-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the sysctl-hardening-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (sysctl-hardening-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the sysctl-hardening-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysctl-hardening-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # sysctl-hardening-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # sysctl-hardening-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the sysctl-hardening-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
