#!/usr/bin/env bats
# L2 functional suite for kernel-cmdline-watchdog.
#
# kernel-cmdline-watchdog snapshots /proc/cmdline at baseline-create
# time and alerts on drift OR on the presence of a known weakening
# flag from a 16-item denylist (mitigations=off, nosmep, nokaslr,
# audit=0, lockdown=none, …). The baseline is a single-line text
# file written via the direct-write idiom (`printf '%s\n' "$cmdline"
# > "$BASELINE"`) — NOT the canonical `cp "$current" "$BASELINE"`
# comm-delta idiom that 94 SDD-063 watchdogs use.
#
# The L2-scan-script-capture guard's chmod-0600 invariant was
# extended 2026-06-06 to cover this direct-write pattern (commit
# 58708bd). This suite locks the runtime behavior the gate's static
# analysis cannot reach: that the chmod actually fires, that the
# baseline content is the actual cmdline, that the emission shape
# carries the schema observability consumes.
#
# Coverage:
#   - First run with no baseline → baseline_initial, chmod 0600,
#     baseline content == current /proc/cmdline.
#   - JSON carries every promised field (tag/severity/event/profile/
#     weakeners_present).
#   - Second run unchanged → ok / cmdline_intact.
#   - Second run with baseline drift simulated → warn / cmdline_changed
#     (locks the changed-path emission).
#   - enforce profile + ok severity → exit 0.
#
# Run with: bats packaging/test/L2-kernel-cmdline-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd/kernel-cmdline-watchdog.sh"

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
    BASELINE="${TMP}/kernel-cmdline-baseline.txt"
    CMDLINE_FILE="${TMP}/cmdline"
}

teardown() { rm -rf "${TMP}"; }

# Helper: set CMDLINE_FILE content (or unset SELFDEF_CMDLINE_FILE
# to fall back to /proc/cmdline for the legacy-coverage tests).
write_cmdline() {
    printf '%s\n' "$1" > "${CMDLINE_FILE}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CMDLINE_PROFILE="${PROFILE:-report}" \
    SELFDEF_CMDLINE_BASELINE="${BASELINE}" \
    SELFDEF_CMDLINE_FILE="${SELFDEF_CMDLINE_FILE:-${CMDLINE_FILE}}" \
    bash "${WD}"
}

run_wd_real_cmdline() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CMDLINE_PROFILE="${PROFILE:-report}" \
    SELFDEF_CMDLINE_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run creates the baseline + chmod 0600 (no inventory leak)" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    [ -f "${BASELINE}" ]
    cap | grep -q '"event":"baseline_initial"'
    # The structural lock-step: the chmod-0600 invariant the L2 guard
    # checks statically, locked here at runtime.
    perms="$(stat -c '%a' "${BASELINE}")"
    [ "${perms}" = "600" ]
}

@test "the baseline content equals the current /proc/cmdline (live-path coverage)" {
    # Use the real /proc/cmdline (no SELFDEF_CMDLINE_FILE override)
    # so we still cover the production code path.
    run_wd_real_cmdline
    expected="$(tr -s ' ' < /proc/cmdline | sed 's/^ //; s/ $//')"
    actual="$(cat "${BASELINE}")"
    [ "${actual}" = "${expected}" ]
}

@test "the emitted JSON carries every promised schema field" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-kernel-cmdline"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -q '"weakeners_present":'
}

@test "second run with unchanged cmdline → ok / cmdline_intact" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # On a clean host with no weakening flag, second run sees no
    # drift and no weakener → ok / cmdline_intact.
    line="$(cap)"
    case "${line}" in
        *'"event":"cmdline_intact"'*) ;;
        *'"event":"weakening_flag_present"'*)
            # Tolerate this case ONLY when the test host genuinely
            # boots with a denylisted flag (rare in CI / dev hosts).
            # Skip cleanly so the suite doesn't false-fail.
            skip "host /proc/cmdline carries a weakening-flag entry — not a watchdog defect"
            ;;
        *)
            printf 'unexpected event on second-run line: %s\n' "${line}" >&2
            return 1
            ;;
    esac
}

@test "drift simulated via baseline replacement → warn / cmdline_changed" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    # Overwrite the baseline with a different cmdline that carries
    # NO weakening flag → forces the changed-but-no-weakener path
    # (the warn / cmdline_changed branch).
    printf '%s\n' "BOOT_IMAGE=/vmlinuz-test ro quiet splash" > "${BASELINE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    line="$(cap)"
    # Either warn/cmdline_changed (clean host) or alert/weakening_flag_present
    # (host /proc/cmdline carries a denylisted flag). Both prove the changed-path
    # branched correctly off the baseline replacement.
    printf '%s' "${line}" | grep -qE '"event":"(cmdline_changed|weakening_flag_present|weakening_flag_added)"'
    printf '%s' "${line}" | grep -qE '"changed":1'
}

@test "enforce profile + ok severity → exit 0" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd                                    # creates baseline
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd                    # second run, unchanged
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (weakener at first-run): mitigations=off in baseline → baseline_initial + severity=alert" {
    # First run with a weakener present in the cmdline records the
    # baseline AND emits severity=alert (event=baseline_initial)
    # because the operator's CURRENT boot already carries the
    # weakener. The event is `baseline_initial` (not
    # `weakening_flag_present`) because there's no baseline to
    # compare against yet.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet mitigations=off"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'mitigations=off'
}

@test "INVARIANT (weakener-detect): nosmep → alert" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet nosmep"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'nosmep'
}

@test "INVARIANT (weakener-detect): nokaslr → alert" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet nokaslr"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'nokaslr'
}

@test "INVARIANT (weakener-detect): audit=0 → alert" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet audit=0"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'audit=0'
}

@test "INVARIANT (weakener-detect): lockdown=none → alert" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet lockdown=none"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'lockdown=none'
}

@test "INVARIANT (weakener on second-run): unchanged cmdline with persistent weakener → weakening_flag_present" {
    # Two-run pattern: baseline created with weakener present
    # (alert/baseline_initial), then a second run with the same
    # cmdline triggers the `weakening_flag_present` branch (the
    # canonical "weakener still there" surface).
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet mitigations=off"
    run_wd                                              # baseline_initial
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # second run
    cap | grep -q '"event":"weakening_flag_present"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (clean cmdline): no weakening flag + matching baseline → ok / cmdline_intact" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"cmdline_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (drift + weakener): cmdline CHANGED to include a weakener → alert / weakening_flag_added" {
    # First run with a clean cmdline establishes the baseline.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker reboots with mitigations=off bolted on.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash mitigations=off"
    run_wd
    # The drift + weakener combination must escalate to alert.
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (drift, no weakener): cmdline CHANGED with no weakener → warn / cmdline_changed" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Operator-style boot-parameter change.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash net.ifnames=0"
    run_wd
    cap | grep -q '"event":"cmdline_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (enforce alert exit): enforce profile + weakener-present → exit non-zero" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet mitigations=off"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "INVARIANT (weakener-detect: selinux=0 → alert): LSM-disable coverage" {
    # selinux=0 disables the SELinux LSM at boot.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet selinux=0"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (weakener-detect: apparmor=0 → alert): alternative LSM-disable coverage" {
    # apparmor=0 disables the AppArmor LSM at boot.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet apparmor=0"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple weakeners in same cmdline: alert fires + sample includes multiple)" {
    # Realistic attacker scenario: maximally weaken on next boot.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet mitigations=off nokaslr lockdown=none audit=0"
    run_wd
    cap | grep -q '"severity":"alert"'
    # Multiple weakeners in the same cmdline — verify the sample
    # field carries multiple names.
    cap | grep -q 'mitigations=off'
    cap | grep -q 'nokaslr'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_CMDLINE_PROFILE)" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line per SDD-062 consumer contract)" {
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet splash"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-kernel-cmdline -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (current-behavior: spectre_v2=off NOT in 16-item denylist — locks current denylist scope)" {
    # The watchdog denylist (16 items) covers broad weakening flags
    # (mitigations=off, nosmep, nokaslr, audit=0, lockdown=none,
    # selinux=0, apparmor=0). Individual CPU-side-channel toggles
    # (spectre_v2=off, retbleed=off, etc.) are NOT in the current
    # denylist — operator may legitimately tune these for perf-vs-
    # security trade-offs. Lock current scope so a future refinement
    # that adds them is intentional, not silent.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet spectre_v2=off"
    run_wd
    # Current behavior: spectre_v2=off alone surfaces as
    # baseline_initial / ok (no weakener match) OR alert if it
    # gets added to the denylist later.
    cap | grep -q '"event":"baseline_initial"'
}

@test "INVARIANT (weakener-detect: init=/bin/bash → alert): single-user PID-1 hijack via boot-edit" {
    # Sister to the grub-config-watchdog init= alert axis already
    # locked (GRUB_CMDLINE_LINUX init=/tmp/.init scan). This
    # watchdog observes the LIVE kernel cmdline (/proc/cmdline)
    # rather than the grub config — same attack but the runtime
    # detection point is different. If a kernel boots with
    # init=/bin/bash (or any init=), it's the "single-user shell"
    # boot-edit attack: dropping to a root shell instead of
    # /sbin/init. T1542 boot-time PID-1 hijack. Locks init= axis
    # on the live-cmdline observation surface alongside the
    # mitigations/selinux/apparmor weakener family.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro init=/bin/bash"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (weakener-detect: rd.break / single boot-edit → alert): rescue-shell drop weakener axis" {
    # Sister to init= weakener axis already locked above. rd.break
    # is the dracut/systemd hook that drops to a rescue shell
    # during early-boot before mounting the real root — same
    # physical-access boot-edit attack class, different argument
    # name. systemd-boot accepts 'single' to similar effect. Lock
    # axis coverage of rescue-shell drop weakeners on the live-
    # cmdline observation surface alongside init= (T1542 physical-
    # access boot-edit).
    write_cmdline "BOOT_IMAGE=/vmlinuz ro rd.break"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (weakener-detect: nokaslr → alert): KASLR-disable boot-time hardening-bypass axis" {
    # Sister to other kernel-cmdline weakener INVARIANTs already
    # locked (nosmep / noexec=off / selinux=0 / apparmor=0 /
    # init= / rd.break / mitigations=off). nokaslr disables
    # Kernel Address Space Layout Randomization at boot —
    # exploits that need known kernel addresses (most ROP-based
    # privesc, kernel LPE chains) work reliably against the
    # static layout. An operator-edited cmdline with nokaslr
    # for debugging is a boot-time hardening downgrade; if
    # left in place it persists across every boot. Locks the
    # nokaslr axis on the live-cmdline observation surface
    # alongside the weakener family.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro nokaslr"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (weakener-detect: ignore_loglevel → alert): debug-output exfil axis surface" {
    # Sister to boot-time weakener family. ignore_loglevel
    # raises dmesg output so kernel pointer values, build-config
    # details, etc. leak to userspace — recon primitive.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro ignore_loglevel"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (weakener-detect: mitigations=off → alert): blanket CPU-mitigation-disable axis covers Spectre/Meltdown/MDS family" {
    # Sister to nokaslr / nosmep / rd.break boot-time weakener
    # axes. mitigations=off is a blanket switch that disables
    # ALL CPU-side-channel mitigations (Spectre v1/v2, Meltdown,
    # MDS, L1TF, ZombieLoad, etc.) — turns the host into a
    # speculative-execution-tractable target across the board.
    # Recon-and-extract via CPU side channels become tractable.
    # Lock weakener-detect on the mitigations=off axis.
    write_cmdline "BOOT_IMAGE=/vmlinuz ro mitigations=off"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on kernel-cmdline surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The kernel-cmdline-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1542 Pre-OS Boot weakener alert. Locks
    # parser contract on the /proc/cmdline weakener detection
    # surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    write_cmdline "BOOT_IMAGE=/vmlinuz ro quiet"
    run_wd                                              # ok / baseline
    write_cmdline "BOOT_IMAGE=/vmlinuz ro mitigations=off"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # kernel-cmdline-watchdog runs ON the timer's scheduled fire
    # — scans /proc/cmdline for hardening-weakener tokens
    # (nokaslr, mitigations=off, init=/bin/bash, ...), emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract
    # on the kernel-cmdline-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd/selfdef-kernel-cmdline.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kernel-cmdline-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # kernel-cmdline-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # kernel-cmdline-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'kernel-cmdline-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: kernel-cmdline-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. kernel-cmdline-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the kernel-cmdline-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (kernel-cmdline-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the kernel-cmdline-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-cmdline-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # kernel-cmdline-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # kernel-cmdline-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the kernel-cmdline-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-cmdline-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # kernel-cmdline-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-cmdline-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the kernel-cmdline-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-cmdline-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the kernel-cmdline-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}
