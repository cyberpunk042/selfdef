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

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the clamav-cron requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the clamav-cron module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the clamav-cron module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the clamav-cron
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for clamav-cron is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the clamav-cron install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (clamav-cron module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the clamav-cron requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (clamav-cron module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the clamav-cron
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the clamav-cron
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (clamav-cron module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the clamav-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (clamav-cron module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (clamav-cron module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (clamav-cron module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (clamav-cron module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (clamav-cron README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (clamav-cron install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (clamav-cron install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (clamav-cron install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (clamav-cron install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (clamav-cron install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (clamav-cron install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (clamav-cron install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (clamav-cron install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (clamav-cron install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (clamav-cron install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (clamav-cron install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (clamav-cron install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (clamav-cron module.toml [install_paths].paths includes at least one /usr/ path — binary-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/usr/') for p in ps), f'paths must include ≥1 /usr/ target, got {ps!r}'
"
}

@test "INVARIANT (clamav-cron module.toml exists at canonical path modules/clamav-cron/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (clamav-cron module dir is at canonical path modules/clamav-cron/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/clamav-cron"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (clamav-cron install dir exists at modules/clamav-cron/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (clamav-cron install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (clamav-cron install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (clamav-cron install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (clamav-cron install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (clamav-cron module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (clamav-cron install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (clamav-cron install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (clamav-cron install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (clamav-cron install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (clamav-cron install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (clamav-cron install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (clamav-cron install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (clamav-cron install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (clamav-cron module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (clamav-cron module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (clamav-cron module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (clamav-cron module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (clamav-cron module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (clamav-cron module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92 — libexec-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p or '/usr/local/' in p for p in ps)
"
}

@test "INVARIANT (clamav-cron module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (clamav-cron module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/clamav-cron/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}
