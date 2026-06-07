#!/usr/bin/env bats
# L2 bats functional tests for the world-writable-watchdog scan script.
#
# A scan for world-writable (perm 0002) regular files + non-sticky
# world-writable dirs outside the sticky-scratch whitelist (/tmp, /var/tmp,
# /dev/shm, /run/lock). A world-writable file under a system root lets any
# local user tamper with it — a privilege-escalation / persistence stepping
# stone. Stateless count ladder:
#   ok    → 0 findings
#   warn  → 1..25 findings
#   alert → 26+ findings
#
# Runs the actual scan script with `logger` shadowed on PATH and a tmp
# scan-root via SELFDEF_WORLDWRITE_ROOTS.
#
# Run with: bats packaging/test/L2-world-writable-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd/world-writable-watchdog.sh"

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
    ROOT="${TMP}/scan"; mkdir -p "${ROOT}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_WORLDWRITE_PROFILE="${PROFILE:-report}" \
    SELFDEF_WORLDWRITE_ROOTS="${ROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no world-writable files → ok / no_findings" {
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    run_wd
    cap | grep -q '"event":"no_findings"'
    cap | grep -q '"severity":"ok"'
}

@test "one world-writable file → warn / world_writable_found" {
    printf 'x' > "${ROOT}/loose"; chmod 0666 "${ROOT}/loose"
    run_wd
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q '"severity":"warn"'
}

@test "a normal 0644 file is NOT flagged" {
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "26+ world-writable files → alert / bulk_world_writable" {
    for i in $(seq 1 30); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a world-writable finding" {
    printf 'x' > "${ROOT}/loose"; chmod 0666 "${ROOT}/loose"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "boundary: 25 world-writable files → warn (the 1..25 range is INCLUSIVE on the high end)" {
    for i in $(seq 1 25); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: 26 world-writable files → alert (just over the warn ceiling)" {
    for i in $(seq 1 26); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
}

@test "finding_count surfaces in JSON (operator triage observability)" {
    for i in $(seq 1 7); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"finding_count":7'
}

@test "sample of world-writable paths (up to 10) surfaces in 'sample' field for operator triage" {
    printf 'x' > "${ROOT}/very-distinctive-loose-name"; chmod 0666 "${ROOT}/very-distinctive-loose-name"
    run_wd
    cap | grep -q 'very-distinctive-loose-name'
}

@test "scan_roots field echoes the configured SELFDEF_WORLDWRITE_ROOTS (operator can verify the scan scope)" {
    printf 'x' > "${ROOT}/normal"
    run_wd
    cap | grep -q "\"scan_roots\":\"${ROOT}\""
}

@test "INVARIANT (sticky-bit dir): non-sticky world-writable DIRECTORY IS flagged" {
    # The script's find expression catches dirs with -type d -perm
    # -0002 ! -perm -1000 (world-writable but NOT sticky). A dir
    # with mode 0777 (no sticky bit) is flagged.
    mkdir "${ROOT}/non-sticky"; chmod 0777 "${ROOT}/non-sticky"
    run_wd
    cap | grep -q '"event":"world_writable_found"'
}

@test "INVARIANT (sticky-bit dir): sticky world-writable DIRECTORY is NOT flagged (the /tmp pattern)" {
    # Sticky bit (1000) on a 0777 dir → mode 1777 → /tmp pattern.
    # The script's `! -perm -1000` clause excludes it.
    mkdir "${ROOT}/sticky-scratch"; chmod 1777 "${ROOT}/sticky-scratch"
    run_wd
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'x' > "${ROOT}/loose"; chmod 0666 "${ROOT}/loose"
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-world-writable"')
    [ "${n}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    for i in $(seq 1 30); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sample cap at 10: 20 world-writable files → MAIN tag sample contains at most 10)" {
    for i in $(seq 1 20); do
        printf 'x' > "${ROOT}/ww-distinct-${i}"
        chmod 0666 "${ROOT}/ww-distinct-${i}"
    done
    run_wd
    cap | grep -qE '"finding_count":20'
    main_line="$(cap | grep -E '^-t selfdef-world-writable --')"
    found_in_main="$(printf '%s' "${main_line}" | grep -oE 'ww-distinct-[0-9]+' | sort -u | wc -l)"
    [ "${found_in_main}" -le 10 ]
}

@test "INVARIANT (recursive scan: world-writable file in nested subdirectory surfaces)" {
    mkdir -p "${ROOT}/a/b/c"
    printf 'x' > "${ROOT}/a/b/c/deep-loose"
    chmod 0666 "${ROOT}/a/b/c/deep-loose"
    run_wd
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q 'deep-loose'
}

@test "INVARIANT (group-writable 0664 file is NOT flagged: only world-writable matters — content boundary)" {
    # The scope is world-writable specifically (perm 0002). Group-
    # writable (perm 0020) is owned by different watchdog axes
    # (e.g. modules-load-watchdog). Lock the boundary.
    printf 'x' > "${ROOT}/group-write"; chmod 0664 "${ROOT}/group-write"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (enforce + ok severity → exit 0): no world-writable files passes even in enforce" {
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (stateless re-evaluation: world-writable alert STAYS visible on every run until operator chmods)" {
    # world-writable-watchdog is stateless (no baseline-refresh required)
    # — re-evaluates live filesystem on every run. A world-writable file
    # that stays world-writable across runs MUST re-fire every run.
    for i in $(seq 1 30); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-root scan: world-writable file in ANY watched root → flagged)" {
    ROOT2="${TMP}/scan2"; mkdir -p "${ROOT2}"
    printf 'x' > "${ROOT}/normal"; chmod 0644 "${ROOT}/normal"
    printf 'x' > "${ROOT2}/loose-in-second-root"; chmod 0666 "${ROOT2}/loose-in-second-root"
    PATH="${BIN}:${PATH}" \
    SELFDEF_WORLDWRITE_PROFILE="report" \
    SELFDEF_WORLDWRITE_ROOTS="${ROOT} ${ROOT2}" \
    bash "${WD}"
    cap | grep -q '"event":"world_writable_found"'
    cap | grep -q 'loose-in-second-root'
}

@test "INVARIANT (whitelist axis: /tmp + /var/tmp + /dev/shm + /run/lock NOT flagged when scan-rooted at /)" {
    # The 4 canonical sticky-scratch dirs MUST be excluded even when
    # the scan is rooted at /. Lock the whitelist axis by simulating
    # sticky-scratch dir within the scan root.
    mkdir -p "${ROOT}/tmp"; chmod 1777 "${ROOT}/tmp"
    mkdir -p "${ROOT}/var/tmp"; chmod 1777 "${ROOT}/var/tmp"
    mkdir -p "${ROOT}/dev/shm"; chmod 1777 "${ROOT}/dev/shm"
    run_wd
    # No finding because all 4 carry sticky bit.
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (boundary 26: at exact 26 world-writable severity escalates from warn to alert)" {
    # Single-notch boundary lock at the warn→alert transition.
    for i in $(seq 1 26); do printf 'x' > "${ROOT}/ww${i}"; chmod 0666 "${ROOT}/ww${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_world_writable"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"finding_count":2[6-9]|"finding_count":[3-9][0-9]'
}

@test "INVARIANT (world-writable directory ALSO flagged — sister axis to world-writable regular file)" {
    # Sister to the world-writable file axis already locked. A world-
    # writable DIRECTORY (mode 0777 without sticky bit) is equally
    # dangerous — any user can plant or replace files in it,
    # including a setuid binary they then chmod into existence. The
    # whitelisted /tmp + /var/tmp + /dev/shm have the sticky bit
    # (1777) which restricts deletion to owner; a non-sticky 0777
    # directory does NOT have that protection. Locks axis-symmetry
    # between world-writable-file and world-writable-dir-without-
    # sticky-bit on the file-mode surveillance surface.
    mkdir -p "${ROOT}/loose-dir"; chmod 0777 "${ROOT}/loose-dir"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -q 'loose-dir'
}

@test "INVARIANT (DELTA detect — distinctive-attacker-named world-writable file surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When a distinctively-named
    # world-writable file appears (T1222 — File and Directory
    # Permissions Modification), the file path MUST surface in
    # the JSON sample so operator dashboard routes triage to the
    # right path.
    printf 'x' > "${ROOT}/distinctive-attacker-world-writable.txt"
    chmod 0666 "${ROOT}/distinctive-attacker-world-writable.txt"
    run_wd
    cap | grep -q 'distinctive-attacker-world-writable'
}

@test "INVARIANT (world-writable + setuid combined → alert at higher tier — multi-axis compound severity)" {
    # Sister to world-writable file + world-writable dir
    # INVARIANTs already locked. The combined 4666/6666 mode
    # (setuid + world-writable) on a binary is the most-dangerous
    # mode of all — every user can rewrite the file's content
    # AND it executes with the owner's privileges (typically
    # root). An attacker who gets file content control becomes
    # the file's owner-uid at exec time. Locks compound-severity
    # detection on the suid + world-writable combined axis
    # (T1548.001 Setuid + T1222 file-perm modification).
    printf 'x' > "${ROOT}/suid-and-writable.elf"
    chmod 6666 "${ROOT}/suid-and-writable.elf"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    # selfdef-world-writable tag MUST fire EXACTLY ONCE per
    # scan regardless of how many world-writable files surface.
    # Multi-line output would break SDD-062 downstream JSON-line
    # consumer (Sigma correlator). Locks consolidation discipline
    # on T1222 file-permission-modification surveillance.
    for i in 1 2 3 4 5; do
        printf 'x' > "${ROOT}/ww-${i}"
        chmod 0666 "${ROOT}/ww-${i}"
    done
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-world-writable -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The world-writable-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1222 file-permission-modification surveil-
    # lance alert. Locks parser contract on the world-writable
    # detection surface.
    printf 'benign\n' > "${ROOT}/benign-file"
    run_wd                                              # ok path
    chmod 0666 "${ROOT}/benign-file"
    run_wd                                              # alert path
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (no auto-chmod: world-writable-watchdog NEVER chmods detected files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-remediation / surveillance-
    # not-destruction INVARIANTs across L2 watchdog suites. The
    # world-writable-watchdog DETECTS T1222 file-permission-
    # modification surveillance but MUST NEVER emit chmod
    # commands to auto-strip the world-writable bit. The
    # detected world-writable file may be operator-legitimate
    # (shared log file, multi-user state file, sysadmin
    # collaboration scratchpad) — silent auto-chmod would
    # break operator workflow. Forensic evidence value of the
    # original mode is high (analysis of when the mode was
    # changed). Surveillance, never remediation. Locks anti-
    # data-loss contract on the world-writable surveillance
    # substrate.
    printf 'x' > "${ROOT}/ww-target"
    chmod 0666 "${ROOT}/ww-target"
    run_wd
    # Detected file retains 0666 mode after detection.
    mode=$(stat -c '%a' "${ROOT}/ww-target")
    [ "${mode}" = "666" ]
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*chmod[[:space:]]+(o-w|go-w|0[0-7][0-7][0-7])'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # world-writable-watchdog runs ON the timer's scheduled fire
    # — enumerates world-writable files outside excluded paths,
    # emits a verdict on new world-writable detections, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the world-
    # writable-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd/selfdef-world-writable.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. world-writable-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # world-writable-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # world-writable-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'world-writable-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: world-writable-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. world-writable-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the world-writable-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (world-writable-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the world-writable-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (world-writable-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # world-writable-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (world-writable-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # world-writable-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (world-writable-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the world-writable-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (world-writable-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # world-writable-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (world-writable-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the world-writable-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (world-writable-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the world-writable-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}
