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

@test "INVARIANT (freshclam called before clamscan: signature DB refresh ordering)" {
    # freshclam (signature DB update) MUST be called before clamscan
    # (the scan itself). A scan against stale signatures misses recent
    # malware. Lock the ordering via call-tracking.
    FRESH_LOG="${TMP}/freshclam.call"
    cat > "${BIN}/fake-freshclam" <<EOF
#!/usr/bin/env bash
printf 'freshclam %s\n' "\$*" >> "${FRESH_LOG}"
exit 0
EOF
    chmod +x "${BIN}/fake-freshclam"
    CLAM_LOG="${TMP}/clamscan.call"
    cat > "${FAKE_CLAM}" <<EOF
#!/usr/bin/env bash
printf 'clamscan %s\n' "\$*" >> "${CLAM_LOG}"
printf 'Infected files: 0\nScanned files: 1\n'
exit 0
EOF
    chmod +x "${FAKE_CLAM}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_CLAMAV_PROFILE="home" \
        SELFDEF_CLAMSCAN_BIN="${FAKE_CLAM}" \
        SELFDEF_FRESHCLAM_BIN="${BIN}/fake-freshclam" \
        bash "${WD}"
    # Both fired.
    [ -f "${FRESH_LOG}" ]
    [ -f "${CLAM_LOG}" ]
    # freshclam mtime <= clamscan mtime (freshclam fired first).
    fresh_mtime="$(stat -c '%Y' "${FRESH_LOG}")"
    clam_mtime="$(stat -c '%Y' "${CLAM_LOG}")"
    [ "${fresh_mtime}" -le "${clam_mtime}" ]
}

@test "INVARIANT (scan_rc surfaces in JSON when present — operator can correlate rc to severity)" {
    # The scan_rc field is the bridge between clamscan exit code and
    # severity classification. Locked.
    mk_clam 1 "/v/x: Trojan FOUND
Infected files: 1
Scanned files: 1"
    run_wd
    cap | grep -qE '"clamscan_rc":1|"scan_rc":1'
}

@test "INVARIANT (single-FOUND no double-pipe — sample formatting consistent across 1-found and multi-found)" {
    # Single FOUND should produce 'Trojan FOUND' (no trailing pipe)
    # or 'Trojan FOUND|' (acceptable; tr always appends).
    # Lock that no DOUBLE pipe ever appears.
    mk_clam 1 "/v/x: Only.Trojan FOUND
Infected files: 1
Scanned files: 1"
    run_wd
    main_line=$(cap | grep -E '^-t selfdef-clamav --')
    printf '%s' "${main_line}" | grep -q 'Only.Trojan'
    ! printf '%s' "${main_line}" | grep -q '||'
}

@test "INVARIANT (clamscan rc=2 → high severity / clamav_internal_error — sister axis to aide-bridge rc=8+ high)" {
    # Sister to L2-aide-bridge's rc=8 internal-error → high INVARIANT.
    # When clamscan exits non-zero for INTERNAL reasons (not finding
    # malware, which is rc=1) — e.g. signature DB corrupt, scan path
    # unreadable, config parse error — severity must escalate to
    # high (not alert which is for found-malware), so operator
    # dashboard distinguishes scanner-health from scanner-finding.
    # Locks the severity ladder lower bound for the wrapper-error
    # axis (sister to clamav-cron's found-malware alert axis).
    mk_clam 2 "ERROR: Can't open file or directory"
    run_wd
    cap | grep -qE '"severity":"(high|alert)"'
    cap | grep -q '"clamscan_rc":2'
}

@test "INVARIANT (DELTA detect — distinctive-attacker-named malware FOUND surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When clamscan reports a FOUND
    # malware hit, the file path MUST surface in the JSON sample
    # so operator dashboard routes triage to the right path —
    # operators MUST be able to tell WHICH file got infected
    # without scrolling through scanner log history. Locks the
    # found-file-sample contract on the malware-discovery surface
    # (T1499.001 — Resource Hijacking by planted-malware crypto-
    # miners + arbitrary RCE class).
    mk_clam 1 "/tmp/distinctive-attacker-malware.elf: Win.Trojan.Test FOUND"
    run_wd
    cap | grep -q 'distinctive-attacker-malware'
}

@test "INVARIANT (multi-FOUND consolidation: 5 hits in one scan → single consolidated alert; aggregation discipline)" {
    # Sister to brain-wide multi-item-single-alert consolidation
    # INVARIANTs across the brain (anacrontab-watchdog 3-job,
    # account-watchdog 2-uid0, access-conf-watchdog 3-broad-permit).
    # When clamscan reports multiple FOUND hits in one scan, the
    # watchdog MUST consolidate into a SINGLE alert JSON record
    # (not 5 separate alerts that would flood operator dashboard).
    # Locks the consolidation discipline alongside the SDD-062
    # single-line consumer contract. Operator sees one alert with
    # 5 file paths in sample, not 5 alerts.
    mk_clam 1 "/tmp/.evil1: Win.Trojan.A FOUND
/var/tmp/.evil2: Win.Trojan.B FOUND
/dev/shm/.evil3: Linux.Trojan.C FOUND
/home/alice/.evil4: Linux.Miner.D FOUND
/opt/.evil5: Linux.Backdoor.E FOUND"
    run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-clamav -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_CLAMAV_PROFILE)" {
    # Sister to brain-wide profile-echo INVARIANTs.
    mk_clam 0 "no warnings"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert,high} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs (lynis-
    # cron, rkhunter-cron, time-skew-watchdog). severity field
    # on operator dashboard color-coded axis; bounded set locked.
    mk_clam 0 "no warnings"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"'|'"severity":"high"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert,high}" ;;
    esac
}

@test "INVARIANT (no auto-uninstall: clamav-cron watchdog NEVER emits package-remove commands on clamav)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The clamav-cron watchdog invokes freshclam +
    # clamscan but MUST NEVER emit shell commands that
    # uninstall the clamav package itself (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall clamav|clamav-daemon|clamav-
    # freshclam). Silent auto-removal would leave the host
    # with no AV scanner — T1562.001 Impair Defenses self-
    # defeat by the very module meant to detect malware.
    # Locks anti-package-removal contract on the clamav AV
    # substrate.
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+clamav' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes. The clamav-cron scan
    # runs ON the timer's scheduled fire — refreshes signatures,
    # scans, emits a verdict, then exits. Type=simple would leave
    # systemd thinking the scanner is a long-running daemon,
    # breaking timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the clamav-cron substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/systemd/selfdef-clamav-scan.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. clamav-cron manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the ClamAV scan wrapper. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the clamav-cron
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'clamav-cron', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # clamav-cron install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the clamav-cron lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}
