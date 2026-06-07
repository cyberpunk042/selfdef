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

@test "INVARIANT (sysctl-hardening-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # sysctl-hardening-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysctl-hardening-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the sysctl-hardening-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sysctl-hardening-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the sysctl-hardening-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the sysctl-hardening-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the sysctl-hardening-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the sysctl-hardening-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the sysctl-hardening-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (sysctl-hardening-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the sysctl-hardening-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    [ -f "${script_dir}/sysctl-hardening-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (sysctl-hardening-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (sysctl-hardening-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (sysctl-hardening-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script tag selfdef-sysctl-hardening matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-sysctl-hardening
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (sysctl-hardening-watchdog .timer file exists at canonical path modules/sysctl-hardening-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sysctl-hardening-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}
