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

@test "INVARIANT (no auto-uninstall: lynis-cron watchdog NEVER emits package-remove commands on lynis)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The lynis-cron watchdog invokes the lynis
    # security-audit tool but MUST NEVER emit shell commands
    # that uninstall the lynis package itself (apt/dpkg/dnf/
    # rpm/yum remove|purge|uninstall lynis). Silent auto-
    # removal would tear down the security-audit substrate —
    # T1562.001 Impair Defenses self-defeat by the wrapper
    # meant to invoke the audit. Locks anti-package-removal
    # contract on the lynis-cron substrate.
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+lynis' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # lynis-cron runs ON the timer's scheduled fire — invokes
    # lynis audit, parses report, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the lynis-cron substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/systemd/selfdef-lynis-audit.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. lynis-cron manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # lynis-cron scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # lynis-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'lynis-cron', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # lynis-cron install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the lynis-cron lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the lynis-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    # the lynis-cron requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    # present discipline on the lynis-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    # category-present discipline on the lynis-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
    # semver-X.Y.Z discipline on the lynis-cron substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (lynis-cron module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the lynis-cron module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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

@test "INVARIANT (lynis-cron module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the lynis-cron module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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

@test "INVARIANT (lynis-cron module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the lynis-cron
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/lynis-cron/module.toml"
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
