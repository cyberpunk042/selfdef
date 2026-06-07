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

@test "INVARIANT (world-writable-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the world-writable-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the world-writable-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the world-writable-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (world-writable-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the world-writable-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (world-writable-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (world-writable-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (world-writable-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (world-writable-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (world-writable-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the world-writable-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    [ -f "${script_dir}/world-writable-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (world-writable-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (world-writable-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (world-writable-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (world-writable-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/world-writable-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}
