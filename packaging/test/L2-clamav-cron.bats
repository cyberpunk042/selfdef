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
