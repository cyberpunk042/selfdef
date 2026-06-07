#!/usr/bin/env bats
# L2 bats functional tests for the lynis-cron lynis-audit.sh wrapper.
#
# Wraps `lynis audit system`: reads the hardening_index from the report file
# and maps it to a severity (>=80 ok, 60-79 warn, <60 alert; report missing =
# high). Drives the wrapper with a fake `lynis` (no-op) + a controlled report
# file (SELFDEF_LYNIS_REPORT).
#
# Run with: bats packaging/test/L2-lynis-cron.bats

WD="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/systemd/lynis-audit.sh"

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
    FAKE_LYNIS="${TMP}/lynis"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${FAKE_LYNIS}"; chmod +x "${FAKE_LYNIS}"
    REPORT="${TMP}/lynis-report.dat"
}

teardown() { rm -rf "${TMP}"; }

mk_report() {  # hardening_index
    printf 'hardening_index=%s\nwarning[]=PERM-2904|World-writable file found|-|\nsuggestion[]=KRNL-5820|disable core dumps|-|\n' "$1" > "${REPORT}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LYNIS_PROFILE="${PROFILE:-quick}" \
    SELFDEF_LYNIS_BIN="${FAKE_LYNIS}" \
    SELFDEF_LYNIS_REPORT="${REPORT_V:-$REPORT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "report missing → high / report_missing" {
    REPORT_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"report_missing"'
    cap | grep -q '"severity":"high"'
}

@test "hardening_index >= 80 → ok / audit_ok" {
    mk_report 85
    run_wd
    cap | grep -q '"event":"audit_ok"'
    cap | grep -q '"severity":"ok"'
}

@test "hardening_index 60-79 → warn / hardening_moderate" {
    mk_report 72
    run_wd
    cap | grep -q '"event":"hardening_moderate"'
    cap | grep -q '"severity":"warn"'
}

@test "hardening_index < 60 → alert / hardening_low" {
    mk_report 48
    run_wd
    cap | grep -q '"event":"hardening_low"'
    cap | grep -q '"severity":"alert"'
}

@test "boundary: hardening_index = 60 → warn (the 60-79 boundary is INCLUSIVE on the low end)" {
    mk_report 60
    run_wd
    cap | grep -q '"event":"hardening_moderate"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: hardening_index = 59 → alert (just below the warn floor)" {
    mk_report 59
    run_wd
    cap | grep -q '"event":"hardening_low"'
    cap | grep -q '"severity":"alert"'
}

@test "boundary: hardening_index = 80 → ok (the 80+ boundary is INCLUSIVE on the high end)" {
    mk_report 80
    run_wd
    cap | grep -q '"event":"audit_ok"'
    cap | grep -q '"severity":"ok"'
}

@test "boundary: hardening_index = 79 → warn (just below the ok floor)" {
    mk_report 79
    run_wd
    cap | grep -q '"event":"hardening_moderate"'
    cap | grep -q '"severity":"warn"'
}

@test "warnings + suggestions counts surface in JSON (operator-triage observability)" {
    mk_report 72
    run_wd
    # The fixture mk_report emits 1 warning[] + 1 suggestion[] line.
    cap | grep -q '"warnings":1'
    cap | grep -q '"suggestions":1'
}

@test "hardening_index surfaces in JSON (operator can see the score)" {
    mk_report 72
    run_wd
    cap | grep -q '"hardening_index":72'
}

@test "profile field surfaces in JSON (echo of operator-set --profile)" {
    mk_report 85
    PROFILE=full run_wd
    cap | grep -q '"profile":"full"'
}

@test "warning sample (up to 5 lines) surfaces in 'sample' field (operator triage)" {
    # Fixture has 1 warning[] line — sample should contain its body.
    mk_report 72
    run_wd
    cap | grep -q 'PERM-2904'
}

@test "JSON record is emitted as a SINGLE logger line (downstream JSON-line consumer contract)" {
    mk_report 72
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-lynis"')
    [ "${n}" = "1" ]
}

@test "wrapper exit code is 0 even on alert severity (Lynis findings are advisory, not enforcement)" {
    mk_report 48
    PATH="${BIN}:${PATH}" \
        SELFDEF_LYNIS_PROFILE="${PROFILE:-quick}" \
        SELFDEF_LYNIS_BIN="${FAKE_LYNIS}" \
        SELFDEF_LYNIS_REPORT="${REPORT}" \
        bash "${WD}"
    # bats fails if rc != 0; this test asserts rc=0 even on alert.
}

@test "INVARIANT (warning sample is capped at 5 in MAIN tag — log volume control)" {
    # Lynis can emit 50+ warnings on a fresh install. Sample
    # must cap at 5 to keep log volume bounded; the FULL report
    # lives on disk for operator forensics.
    {
        printf 'hardening_index=72\n'
        for i in 01 02 03 04 05 06 07 08 09 10; do
            printf 'warning[]=W-%s|warning_body|-|\n' "${i}"
        done
    } > "${REPORT}"
    run_wd
    cap | grep -q '"warnings":10'
    # Sample cap: first 5 warnings present, 6-10 absent. Use the
    # full cap content (the JSON record may span lines if fixture
    # contains embedded newlines in warning bodies).
    cap | grep -q 'W-01'
    cap | grep -q 'W-05'
    ! cap | grep -q 'W-06'
    ! cap | grep -q 'W-10'
}

@test "INVARIANT (boundary: hardening_index=100 → ok — perfect score upper bound)" {
    mk_report 100
    run_wd
    cap | grep -q '"event":"audit_ok"'
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"hardening_index":100'
}

@test "INVARIANT (boundary: hardening_index=0 → alert — minimum score lower bound)" {
    mk_report 0
    run_wd
    cap | grep -q '"event":"hardening_low"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"hardening_index":0'
}

@test "INVARIANT (defensive parse: report without hardening_index line — wrapper does not crash, emits JSON)" {
    # Lynis versions vary; a report without hardening_index= must
    # not crash the wrapper. Lock that some JSON record still
    # emits.
    printf 'warning[]=PERM-2904|World-writable file found|-|\n' > "${REPORT}"
    run_wd
    cap | grep -q '"tag":"selfdef-lynis"'
}

@test "INVARIANT (lynis_rc surfaces in JSON — operator can see raw exit code)" {
    mk_report 85
    run_wd
    cap | grep -qE '"lynis_rc":[0-9]+'
}

@test "INVARIANT (lynis bin non-zero exit: wrapper still emits JSON + still rc=0 — advisory contract holds even on lynis crash)" {
    # Lynis itself may exit non-zero (parse error, missing dep,
    # crashed plugin). The wrapper MUST still emit a JSON record
    # so the operator dashboard sees the run + still exit 0 (the
    # wrapper is advisory, not enforcement — operator owns the
    # response, not the cron).
    printf '#!/usr/bin/env bash\nexit 17\n' > "${FAKE_LYNIS}"
    mk_report 85                                            # legacy report from prior run
    run_wd
    cap | grep -q '"tag":"selfdef-lynis"'
}

@test "INVARIANT (report-missing exit code is 0 — high severity does NOT propagate as wrapper rc)" {
    # Lynis-cron's wrapper is advisory; even a 'report_missing'
    # severity=high MUST not exit non-zero (cron would mark the
    # unit failed and operator would chase a phantom incident).
    # Severity is for the dashboard; rc is for cron.
    REPORT_V="${TMP}/nonexistent" \
    PATH="${BIN}:${PATH}" \
        SELFDEF_LYNIS_PROFILE="quick" \
        SELFDEF_LYNIS_BIN="${FAKE_LYNIS}" \
        SELFDEF_LYNIS_REPORT="${TMP}/nonexistent" \
        bash "${WD}"
    # bats fails on rc != 0; this line confirms rc=0 by reaching it.
    cap | grep -q '"severity":"high"'
}

@test "INVARIANT (large-warning fixture: warnings count reflects ALL warnings even though sample is capped at 5)" {
    # The cap is on log volume (the inline sample), NOT on the
    # warnings counter. Operator dashboard should still see the
    # full count so triage knows how big the haystack is.
    {
        printf 'hardening_index=55\n'
        for i in $(seq -w 1 50); do
            printf 'warning[]=W-%s|body|-|\n' "${i}"
        done
    } > "${REPORT}"
    run_wd
    cap | grep -q '"warnings":50'
    cap | grep -q '"severity":"alert"'                      # 55 < 60
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_LYNIS_PROFILE — operator-dashboard distinguishes quick from full)" {
    # Sister to L2-aide-bridge / L2-clamav-cron / L2-rkhunter-cron
    # / L2-listening-ports profile-echo INVARIANTs across the
    # brain. Downstream operator dashboard / triage pipeline must
    # see the profile value the wrapper ran under (quick scan vs
    # full scan) so it can interpret the warnings count + sample
    # appropriately. A 'quick' run with N warnings is a different
    # signal than a 'full' run with the same N warnings. Closes
    # the profile-surfacing axis on the lynis advisory wrapper.
    mk_report 85
    run_wd
    cap | grep -qE '"profile":"(quick|full|report)"'
}

@test "INVARIANT (sample names distinctive warning ID in JSON for operator-triage routing — DELTA-detect sample-naming axis)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain (clamav-cron FOUND-file,
    # aide-bridge sample). When lynis fires a distinctively-
    # named warning, the warning ID MUST surface in the JSON
    # sample so operator dashboard routes triage to the right
    # finding — operators MUST be able to tell WHICH warning
    # fired without re-running the scan or scrolling the
    # full report.
    cat > "${REPORT}" <<'EOF'
warning[]=DISTINCTIVE-ATTACKER-FINDING|This is a specific tamper signal|/etc|none
warning[]=BENIGN-CHECK|operator review needed|/var|low
hardening_index=80
EOF
    run_wd
    cap | grep -q 'DISTINCTIVE-ATTACKER-FINDING'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert,high} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. The
    # severity field surfaces on the operator dashboard's
    # color-coded severity axis (green/yellow/red/triage). If a
    # future refactor introduced a fifth value (e.g. 'critical'
    # or 'info'), the dashboard's color-mapping would silently
    # bucket it as unknown. Lock the bounded set so any new
    # severity value is intentional + dashboard-mapped, not a
    # silent regression.
    cat > "${REPORT}" <<'EOF'
warning[]=W1|first|/etc|low
hardening_index=85
EOF
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"'|'"severity":"high"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert,high}" ;;
    esac
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. The selfdef-lynis logger tag
    # must fire EXACTLY ONCE per scan regardless of how many
    # warnings the lynis report surfaces. Multi-line output
    # would break SDD-062 downstream JSON-line consumer (Sigma
    # correlator). Locks consolidation discipline on lynis
    # hardening-audit surveillance surface.
    cat > "${REPORT}" <<'EOF'
warning[]=W1|first|/etc|low
warning[]=W2|second|/var|low
warning[]=W3|third|/usr|low
warning[]=W4|fourth|/boot|low
warning[]=W5|fifth|/home|low
hardening_index=50
EOF
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-lynis -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (report-path surfaces in JSON for report_missing event — operator triage)" {
    # Sister to brain-wide observability INVARIANTs. When the
    # Lynis report file is missing, the wrapper emits event=
    # report_missing AND MUST surface the report_path so
    # operator can correlate which file was expected.
    rm -f "${REPORT}"
    run_wd
    cap | grep -q '"event":"report_missing"'
    cap | grep -qE '"report_path":"[^"]+"'
}
