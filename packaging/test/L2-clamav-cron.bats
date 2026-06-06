#!/usr/bin/env bats
# L2 bats functional tests for the clamav-cron clamav-scan.sh wrapper.
#
# Wraps `clamscan`: maps its exit code to a severity (ok=clean, alert=infected,
# high=error). Drives the wrapper with a fake `clamscan` (SELFDEF_CLAMSCAN_BIN)
# emitting a controlled summary + exit code; freshclam pointed at /bin/true.
#
# Run with: bats packaging/test/L2-clamav-cron.bats

WD="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/systemd/clamav-scan.sh"

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
    FAKE_CLAM="${TMP}/clamscan"
}

teardown() { rm -rf "${TMP}"; }

# mk_clam <rc> <stdout>
mk_clam() {
    { printf '#!/usr/bin/env bash\n'; printf 'cat <<'\''OUT'\''\n%s\nOUT\n' "$2"; printf 'exit %s\n' "$1"; } > "${FAKE_CLAM}"
    chmod +x "${FAKE_CLAM}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CLAMAV_PROFILE="${PROFILE:-home}" \
    SELFDEF_CLAMSCAN_BIN="${FAKE_CLAM}" \
    SELFDEF_FRESHCLAM_BIN="/bin/true" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "clean scan (rc 0) → ok / no_findings" {
    mk_clam 0 "Infected files: 0
Scanned files: 1234"
    run_wd
    cap | grep -q '"event":"no_findings"'
    cap | grep -q '"severity":"ok"'
}

@test "infected files (rc 1) → alert / infected_files" {
    mk_clam 1 "/home/u/x.sh: Unix.Trojan.Test FOUND
Infected files: 1
Scanned files: 1234"
    run_wd
    cap | grep -q '"event":"infected_files"'
    cap | grep -q '"severity":"alert"'
}

@test "clamscan error (rc 2) → high / clamscan_error" {
    mk_clam 2 "ERROR: could not access database"
    run_wd
    cap | grep -q '"event":"clamscan_error"'
    cap | grep -q '"severity":"high"'
}

@test "unknown clamscan rc → high / clamscan_unknown_rc" {
    mk_clam 5 "weird"
    run_wd
    cap | grep -q '"event":"clamscan_unknown_rc"'
    cap | grep -q '"severity":"high"'
}

@test "unknown profile → high / unknown_profile" {
    mk_clam 0 "Infected files: 0"
    PROFILE=bogus run_wd
    cap | grep -q '"event":"unknown_profile"'
    cap | grep -q '"severity":"high"'
}

@test "infected count surfaces in JSON (operator triage)" {
    mk_clam 1 "/var/x: Test.Trojan FOUND
/var/y: Other.Test FOUND
/var/z: Third.Test FOUND
Infected files: 3
Scanned files: 1234"
    run_wd
    cap | grep -q '"infected":3'
    cap | grep -q '"scanned":1234'
}

@test "FOUND-line sample (up to 5) surfaces in 'sample' field for operator triage" {
    mk_clam 1 "/home/u/x.sh: Unix.Trojan.Specific FOUND
Infected files: 1
Scanned files: 1234"
    run_wd
    cap | grep -q 'Unix.Trojan.Specific'
}

@test "profile field surfaces in JSON (echo of operator-set profile)" {
    mk_clam 0 "Infected files: 0
Scanned files: 1"
    PROFILE=home run_wd
    cap | grep -q '"profile":"home"'
}

@test "full profile is accepted (the second canonical profile)" {
    mk_clam 0 "Infected files: 0
Scanned files: 1"
    PROFILE=full run_wd
    cap | grep -q '"profile":"full"'
    cap | grep -q '"event":"no_findings"'
}

@test "JSON record is emitted as a SINGLE logger line (downstream JSON-line consumer contract)" {
    mk_clam 0 "Infected files: 0
Scanned files: 1"
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-clamav"')
    [ "${n}" = "1" ]
}

@test "INVARIANT (advisory exit): wrapper exits 0 even on alert severity (findings are advisory)" {
    mk_clam 1 "/var/x: Test.Trojan FOUND
Infected files: 1
Scanned files: 1234"
    PATH="${BIN}:${PATH}" \
        SELFDEF_CLAMAV_PROFILE="${PROFILE:-home}" \
        SELFDEF_CLAMSCAN_BIN="${FAKE_CLAM}" \
        SELFDEF_FRESHCLAM_BIN="/bin/true" \
        bash "${WD}"
    # bats fails if rc != 0; this test asserts rc=0 even on alert.
}

@test "INVARIANT (advisory exit): wrapper exits 0 even on clamscan-error severity (system-error is advisory)" {
    mk_clam 2 "ERROR: could not access database"
    PATH="${BIN}:${PATH}" \
        SELFDEF_CLAMAV_PROFILE="${PROFILE:-home}" \
        SELFDEF_CLAMSCAN_BIN="${FAKE_CLAM}" \
        SELFDEF_FRESHCLAM_BIN="/bin/true" \
        bash "${WD}"
}

@test "freshclam-missing → wrapper still proceeds with scan (best-effort signature refresh)" {
    mk_clam 0 "Infected files: 0
Scanned files: 1"
    SELFDEF_FRESHCLAM_BIN="/nonexistent/freshclam" run_wd
    cap | grep -q '"event":"no_findings"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (FOUND-line sample is capped at 5 lines for log volume — 10 FOUNDs → only first 5 in sample)" {
    # The script's grep ' FOUND\$' | head -5 cap limits sample to 5
    # entries even when 10+ FOUNDs are present. Lock that — the
    # -detail companion tag still emits all 10 for journal
    # forensics.
    mk_clam 1 "/v/1: Trojan.A FOUND
/v/2: Trojan.B FOUND
/v/3: Trojan.C FOUND
/v/4: Trojan.D FOUND
/v/5: Trojan.E FOUND
/v/6: Trojan.F FOUND
/v/7: Trojan.G FOUND
/v/8: Trojan.H FOUND
/v/9: Trojan.I FOUND
/v/10: Trojan.J FOUND
Infected files: 10
Scanned files: 1234"
    run_wd
    cap | grep -q '"infected":10'
    # The MAIN tag record's sample must NOT contain Trojan.F-J
    # (capped at 5).
    main_line=$(cap | grep -E '^-t selfdef-clamav --')
    ! printf '%s' "${main_line}" | grep -q 'Trojan.F'
    ! printf '%s' "${main_line}" | grep -q 'Trojan.J'
    # First 5 ARE in the sample.
    printf '%s' "${main_line}" | grep -q 'Trojan.A'
    printf '%s' "${main_line}" | grep -q 'Trojan.E'
}

@test "INVARIANT (degenerate empty stdout — rc 0, blank stdout → still ok)" {
    # Defensive parse: clamscan exits 0 with no summary block.
    # Wrapper should treat as ok / no_findings, not crash on
    # empty parse.
    mk_clam 0 ""
    run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (infected + scanned default to 0 when summary block is missing — defensive parse)" {
    # When the summary lines aren't present, the awk parse returns
    # empty → the wrapper's ${infected:-0} fallback locks the JSON
    # field at 0. Critical for downstream consumers that expect
    # numeric fields.
    mk_clam 0 "no summary block here"
    run_wd
    cap | grep -q '"infected":0'
    cap | grep -q '"scanned":0'
}

@test "INVARIANT (clamscan_rc surfaces in JSON — operator sees the raw exit code)" {
    mk_clam 2 "ERROR: x"
    run_wd
    cap | grep -q '"clamscan_rc":2'
}

@test "INVARIANT (freshclam_rc surfaces in JSON — sig-DB-update health for operator dashboard)" {
    mk_clam 0 "Infected files: 0
Scanned files: 1"
    run_wd
    cap | grep -q '"freshclam_rc":'
}

@test "INVARIANT (sample is pipe-separated for multiple FOUNDs — downstream parser contract)" {
    # The script does '| tr "\\n" "|"' to flatten multi-line FOUND
    # samples into a single JSON-safe field. Pipe IS the
    # separator. Downstream alerting hooks split on | to render
    # the operator email.
    mk_clam 1 "/v/x: First.Trojan FOUND
/v/y: Second.Trojan FOUND
Infected files: 2
Scanned files: 1234"
    run_wd
    main_line=$(cap | grep -E '^-t selfdef-clamav --')
    printf '%s' "${main_line}" | grep -q 'First.Trojan'
    printf '%s' "${main_line}" | grep -q 'Second.Trojan'
    # And both are joined by '|'.
    printf '%s' "${main_line}" | grep -qE 'First.Trojan FOUND\|.*Second.Trojan FOUND'
}
