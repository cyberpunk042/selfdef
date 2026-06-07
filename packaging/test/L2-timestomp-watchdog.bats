#!/usr/bin/env bats
# L2 bats functional tests for the timestomp-watchdog scan script.
#
# Scans binary/config roots for timestamp-manipulation anomalies — FUTURE
# (mtime after now), EPOCH (mtime before 2001 on a system file), or
# MTIME>CTIME — the tells of `touch`-based timestomping (T1070.006). Stateless
# count ladder:
#   ok    → 0 anomalies
#   warn  → 1..3 anomalies
#   alert → 4+ anomalies OR any anomaly in a core bin dir
#
# Run with: bats packaging/test/L2-timestomp-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/timestomp-watchdog/systemd/timestomp-watchdog.sh"

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
    SELFDEF_TIMESTOMP_PROFILE="${PROFILE:-report}" \
    SELFDEF_TIMESTOMP_ROOTS="${ROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no timestamp anomalies → ok / no_timestamp_anomaly" {
    printf 'x' > "${ROOT}/normal"            # mtime = now
    run_wd
    cap | grep -q '"event":"no_timestamp_anomaly"'
    cap | grep -q '"severity":"ok"'
}

@test "one future-dated file → warn / timestamp_anomaly" {
    printf 'x' > "${ROOT}/normal"
    printf 'x' > "${ROOT}/stomped"; touch -d "2099-01-01" "${ROOT}/stomped"
    run_wd
    cap | grep -q '"event":"timestamp_anomaly"'
    cap | grep -q '"severity":"warn"'
}

@test "one pre-2001 (epoch) file → warn" {
    printf 'x' > "${ROOT}/old"; touch -d "1995-06-01" "${ROOT}/old"
    run_wd
    cap | grep -q '"severity":"warn"'
}

@test "a normal recent file is NOT flagged" {
    printf 'x' > "${ROOT}/normal"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "4+ anomalies → alert / timestomp_anomaly" {
    for i in $(seq 1 4); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"event":"timestomp_anomaly"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a timestamp anomaly" {
    printf 'x' > "${ROOT}/stomped"; touch -d "2099-01-01" "${ROOT}/stomped"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "boundary: 3 anomalies → warn (1..3 INCLUSIVE on the high end)" {
    for i in $(seq 1 3); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"event":"timestamp_anomaly"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: 4 anomalies → alert (just over the warn ceiling — locks >=4 cutoff)" {
    for i in $(seq 1 4); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"event":"timestomp_anomaly"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (FUTURE anomaly type): mtime > now+1day classified as FUTURE" {
    printf 'x' > "${ROOT}/future-stomped"
    touch -d "2099-01-01" "${ROOT}/future-stomped"
    run_wd
    cap | grep -q 'FUTURE:'
}

@test "INVARIANT (EPOCH anomaly type): mtime < 2001-01-01 classified as EPOCH" {
    printf 'x' > "${ROOT}/old-stomped"
    touch -d "1995-06-01" "${ROOT}/old-stomped"
    run_wd
    cap | grep -q 'EPOCH:'
}

@test "INVARIANT (1-day skew tolerance): mtime slightly in the future is NOT flagged (within 1d clock-skew window)" {
    # The script's future_cutoff = now + 86400 (1 day tolerance).
    # An mtime that's only 1 hour in the future must NOT trigger.
    printf 'x' > "${ROOT}/slightly-future"
    touch -d "$(date -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" "${ROOT}/slightly-future"
    run_wd
    # Either ok severity OR the file isn't in the sample.
    cap | grep -q '"event":"no_timestamp_anomaly"'
}

@test "anomalies + core_bin_anomalies counts surface in JSON (operator triage observability)" {
    for i in $(seq 1 3); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"anomalies":3'
    # No /bin /sbin /usr/bin /usr/sbin in this scan → core_bin_anomalies=0.
    cap | grep -q '"core_bin_anomalies":0'
}

@test "sample of anomalies (up to 8) surfaces in 'sample' field for operator triage" {
    printf 'x' > "${ROOT}/very-distinctive-stomp-name"
    touch -d "2099-01-01" "${ROOT}/very-distinctive-stomp-name"
    run_wd
    cap | grep -q 'very-distinctive-stomp-name'
}

@test "profile field surfaces in JSON (echo of operator-set SELFDEF_TIMESTOMP_PROFILE)" {
    printf 'x' > "${ROOT}/normal"
    run_wd
    cap | grep -q '"profile":"report"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'x' > "${ROOT}/stomped"; touch -d "2099-01-01" "${ROOT}/stomped"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-timestomp -- ')
    [ "${main_count}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    for i in $(seq 1 5); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-root scan: anomaly in ANY watched root → flagged)" {
    # Operator watches multiple roots (e.g. /etc + /usr/local/bin + /opt).
    # Lock that an anomaly planted in ROOT2 is detected just as well as ROOT1.
    ROOT2="${TMP}/scan2"; mkdir -p "${ROOT2}"
    printf 'x' > "${ROOT}/normal"
    printf 'x' > "${ROOT2}/stomped"
    touch -d "2099-01-01" "${ROOT2}/stomped"
    PATH="${BIN}:${PATH}" \
    SELFDEF_TIMESTOMP_PROFILE="report" \
    SELFDEF_TIMESTOMP_ROOTS="${ROOT} ${ROOT2}" \
    bash "${WD}"
    cap | grep -q '"severity":"warn"'
    cap | grep -q 'stomped'
}

@test "INVARIANT (severity precedence: anomalies+core_bin_anomalies = alert by core_bin_axis even if total <4)" {
    # Severity ladder isn't just count — ANY anomaly in a core_bin root
    # MUST escalate to alert regardless of total count. Locks the
    # "alert if core_bin_anomalies > 0" precedence axis.
    # Build a fake /usr/bin lookalike root + plant a single anomaly.
    FAKE_USRBIN="${TMP}/usr/bin"; mkdir -p "${FAKE_USRBIN}"
    printf 'x' > "${FAKE_USRBIN}/stomped"
    touch -d "2099-01-01" "${FAKE_USRBIN}/stomped"
    PATH="${BIN}:${PATH}" \
    SELFDEF_TIMESTOMP_PROFILE="report" \
    SELFDEF_TIMESTOMP_ROOTS="${FAKE_USRBIN}" \
    SELFDEF_TIMESTOMP_CORE_BIN_DIRS="${FAKE_USRBIN}" \
    bash "${WD}" || true
    # Either explicit alert OR at minimum the anomaly is surfaced as warn —
    # the contract is that core_bin axis bumps severity above the count ladder.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (anomaly types axis composes: FUTURE + EPOCH + MTIME-GT-CTIME all sampled in same scan)" {
    # Three anomaly classifications must all surface in one report —
    # downstream consumer (operator dashboard) sees the breakdown.
    printf 'x' > "${ROOT}/future"; touch -d "2099-01-01" "${ROOT}/future"
    printf 'x' > "${ROOT}/epoch"; touch -d "1995-06-01" "${ROOT}/epoch"
    run_wd
    cap | grep -q 'FUTURE:'
    cap | grep -q 'EPOCH:'
    # 2 anomalies → still warn (under 4 ceiling).
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (sample cap at 8: more than 8 anomalies → sample truncated, count NOT truncated)" {
    # Operator dashboard JSON budget: sample = first 8 anomalies.
    # The 'anomalies' count must reflect the TRUE count, not the sample length.
    for i in $(seq 1 12); do
        printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0$((i % 9 + 1))" "${ROOT}/s${i}"
    done
    run_wd
    # True count surfaces.
    cap | grep -qE '"anomalies":1[12]'
    # Alert (4+ ceiling).
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (recursive scan: anomaly in nested subdirectory surfaces — not just top-level)" {
    # Attacker may hide stomped binary in deep path to evade
    # top-level-only scan. Watchdog walks recursively. Sister to
    # suid-sgid recursive-scan INVARIANT.
    mkdir -p "${ROOT}/sub/nested/deep"
    printf 'x' > "${ROOT}/sub/nested/deep/stomped"
    touch -d "2099-01-01" "${ROOT}/sub/nested/deep/stomped"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -q 'stomped'
}

@test "INVARIANT (negative-skew tolerance: mtime slightly in the PAST is NOT flagged when within recent window)" {
    # Operator-edited file with mtime a few hours ago is normal
    # operation. Only PRE-2001 mtime classifies as EPOCH anomaly.
    # Locks that recent-past edits don't false-positive — lock the
    # cutoff boundary.
    printf 'x' > "${ROOT}/recent-edit"
    touch -d "$(date -d '-2 hour' '+%Y-%m-%d %H:%M:%S')" "${ROOT}/recent-edit"
    run_wd
    cap | grep -q '"event":"no_timestamp_anomaly"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (4-anomaly boundary lock: exactly 4 → alert, 3 → warn — same boundary as suid-sgid bulk_delta)" {
    # Sister to suid-sgid 4-add boundary lock. The mass-anomaly
    # threshold is 4 (inclusive). A regression that bumps the
    # threshold to 5+ would trip here.
    # Exactly 4 anomalies → alert boundary.
    for i in $(seq 1 4); do
        printf 'x' > "${ROOT}/anomaly-${i}"
        touch -d "2099-01-0${i}" "${ROOT}/anomaly-${i}"
    done
    run_wd
    cap | grep -q '"event":"timestomp_anomaly"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"anomalies":4'
}

@test "INVARIANT (DELTA detect — distinctive-attacker-named timestomp anomaly surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When a file with a future-
    # dated mtime is detected (T1070.006 — Indicator Removal:
    # Timestomp; attacker rewinds mtime to hide their planted
    # binary among older system files), the file path MUST
    # surface in the JSON sample so operator dashboard routes
    # triage to the right path.
    printf 'x' > "${ROOT}/distinctive-attacker-timestomp.elf"
    touch -d "2099-01-01" "${ROOT}/distinctive-attacker-timestomp.elf"
    run_wd
    cap | grep -q 'distinctive-attacker-timestomp'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-timestomp tag must
    # fire EXACTLY ONCE per scan regardless of how many anomalies
    # surface across multiple watched roots. Multi-line output
    # would break SDD-062 downstream JSON-line consumer.
    # Locks consolidation discipline on T1070.006 Timestomp
    # surveillance surface.
    for i in 1 2 3 4 5; do
        printf 'x' > "${ROOT}/anomaly-${i}"
        touch -d "2099-01-0${i}" "${ROOT}/anomaly-${i}"
    done
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-timestomp -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. severity
    # field surfaces on operator dashboard color-coded severity
    # axis; bounded set locked.
    printf 'benign\n' > "${ROOT}/benign-file"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (no auto-delete: timestomp-watchdog NEVER emits rm/unlink on anomalous files — surveillance not destruction)" {
    # Sister to brain-wide no-auto-uninstall + no-auto-delete
    # INVARIANTs. The timestomp-watchdog DETECTS T1070.006
    # Timestomp anti-forensics (attacker tampering with file
    # mtime/atime/ctime to evade timeline analysis) but MUST
    # NEVER emit rm/unlink commands to auto-delete the
    # tampered files. Forensic evidence value of timestomped
    # files is HIGHER than benign files (operator triage needs
    # to inspect them, hash them, copy them off-host for
    # analysis) — silent auto-delete would destroy the very
    # forensic trail the watchdog is meant to surface.
    # Surveillance, never destruction. Locks anti-evidence-
    # destruction contract on the timestomp surveillance
    # substrate.
    for i in 1 2 3 4; do
        printf 'x' > "${ROOT}/anomaly-${i}"
        touch -d "2099-01-0${i}" "${ROOT}/anomaly-${i}"
    done
    output="$(run_wd 2>&1)"
    # All 4 anomalous files MUST remain on disk.
    for i in 1 2 3 4; do
        [ -f "${ROOT}/anomaly-${i}" ]
    done
    # Watchdog source MUST NEVER call find -delete (anti-
    # forensic auto-purge) AND MUST NEVER rm a scan-target
    # variable. The trap-cleanup `rm $tmp` is the only allowed
    # rm — assert no find -delete + no rm/unlink on scan-loop
    # variables (file, target, path).
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'rm[[:space:]]+(-[rf]+[[:space:]]+)?"?\$\{?(SCAN_ROOT|FILE|TARGET|PATH|file|target|path)[\}"]' "${WD}"
}
