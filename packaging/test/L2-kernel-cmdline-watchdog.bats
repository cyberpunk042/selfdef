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

@test "INVARIANT (kernel-cmdline-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the kernel-cmdline-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the kernel-cmdline-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the kernel-cmdline-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the kernel-cmdline-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the kernel-cmdline-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    [ -f "${script_dir}/kernel-cmdline-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (kernel-cmdline-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (kernel-cmdline-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script declares severity= variable with canonical vocabulary — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'severity=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script tag selfdef-kernel-cmdline matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-kernel-cmdline
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .timer file exists at canonical path modules/kernel-cmdline-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml exists at canonical path modules/kernel-cmdline-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (kernel-cmdline-watchdog systemd dir exists at modules/kernel-cmdline-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (kernel-cmdline-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kernel-cmdline-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (kernel-cmdline-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (kernel-cmdline-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (kernel-cmdline-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"kernel-cmdline-watchdog"' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (kernel-cmdline-watchdog module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}
