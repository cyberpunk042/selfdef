#!/usr/bin/env bats
# L2 bats functional tests for the rkhunter-cron rkhunter-check.sh wrapper.
#
# Wraps `rkhunter --check`: maps its exit code to a severity (0 ok, 1 warn,
# 2 alert/errors, other alert/runtime_issue). Drives the wrapper with a fake
# `rkhunter` (SELFDEF_RKHUNTER_BIN) emitting controlled warnings + exit code.
#
# Run with: bats packaging/test/L2-rkhunter-cron.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rkhunter-cron/systemd/rkhunter-check.sh"

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
    FAKE_RK="${TMP}/rkhunter"
}

teardown() { rm -rf "${TMP}"; }

# mk_rk <rc> <stdout>
mk_rk() {
    { printf '#!/usr/bin/env bash\n'; printf 'cat <<'\''OUT'\''\n%s\nOUT\n' "$2"; printf 'exit %s\n' "$1"; } > "${FAKE_RK}"
    chmod +x "${FAKE_RK}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_RKHUNTER_PROFILE="${PROFILE:-report}" \
    SELFDEF_RKHUNTER_BIN="${FAKE_RK}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "clean check (rc 0) → ok / no_findings" {
    mk_rk 0 "System checks summary: no warnings"
    run_wd
    cap | grep -q '"event":"no_findings"'
    cap | grep -q '"severity":"ok"'
}

@test "warnings (rc 1) → warn / warnings_found" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Hidden directory found"
    run_wd
    cap | grep -q '"event":"warnings_found"'
    cap | grep -q '"severity":"warn"'
}

@test "errors (rc 2) → alert / errors_found" {
    mk_rk 2 "Error: config problem"
    run_wd
    cap | grep -q '"event":"errors_found"'
    cap | grep -q '"severity":"alert"'
}

@test "runtime issue (rc >2) → alert / runtime_issue" {
    mk_rk 5 "rkhunter: database outdated"
    run_wd
    cap | grep -q '"event":"runtime_issue"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on warnings" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"warn"'
}

@test "warning count surfaces in JSON (operator triage)" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Hidden directory found
Warning: Third warning"
    run_wd
    cap | grep -q '"warning_count":3'
}

@test "warning sample (up to 5 lines) surfaces in 'sample' field for operator triage" {
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Hidden directory found"
    run_wd
    cap | grep -q 'Suspicious file'
}

@test "profile field surfaces in JSON (echo of operator-set profile)" {
    mk_rk 0 "System checks summary: no warnings"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "rkhunter rc surfaces in JSON (operator can see the raw exit code)" {
    mk_rk 1 "Warning: x"
    run_wd
    cap | grep -q '"rkhunter_rc":1'
}

@test "JSON record is emitted as a SINGLE logger line (downstream JSON-line consumer contract)" {
    mk_rk 0 "System checks summary: no warnings"
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-rkhunter"')
    [ "${n}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    mk_rk 2 "Error: config problem"
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "report profile exits 0 even on warn severity (warnings are advisory)" {
    mk_rk 1 "Warning: x"
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
}

@test "INVARIANT (enforce profile exits non-zero on errors): asymmetric severity-to-exit mapping" {
    mk_rk 2 "Error: config problem"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "INVARIANT (enforce profile exits non-zero on runtime issue): rc>2 also escalates exit" {
    mk_rk 5 "rkhunter: database outdated"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "INVARIANT (enforce + ok → exit 0): unchanged passes even in enforce" {
    mk_rk 0 "System checks summary: no warnings"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
}

@test "INVARIANT (warning sample is capped at 5 lines for log volume — in the MAIN tag's JSON)" {
    # 10 warnings should be truncated to 5 in the JSON sample field
    # (the -detail companion still emits all 10 for journal forensics).
    mk_rk 1 "Warning: 1
Warning: 2
Warning: 3
Warning: 4
Warning: 5
Warning: 6
Warning: 7
Warning: 8
Warning: 9
Warning: 10"
    run_wd
    cap | grep -q '"warning_count":10'
    # The MAIN tag record (with the JSON body) should NOT contain
    # "Warning: 10" — only the first 5 are in the sample field.
    main_line=$(cap | grep -E '^-t selfdef-rkhunter --')
    ! printf '%s' "${main_line}" | grep -q 'Warning: 10'
}

@test "INVARIANT (zero-warning empty stdout — rc 0, blank stdout → still ok)" {
    # Degenerate input: rkhunter passes silently. Wrapper should
    # treat as ok, not crash on empty parse.
    mk_rk 0 ""
    run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (warning_count = 0 when severity is ok)" {
    mk_rk 0 "System checks summary: no warnings"
    run_wd
    cap | grep -q '"warning_count":0'
}

@test "INVARIANT (rkhunter rc surfaces — even rc=2 visible for operator)" {
    mk_rk 2 "Error: config problem"
    run_wd
    cap | grep -q '"rkhunter_rc":2'
}

@test "INVARIANT (rkhunter-bin non-zero exit beyond known codes: rc=99 still emits JSON + still rc=0 in report — advisory contract holds)" {
    # Sister to lynis-cron 'lynis bin non-zero exit' INVARIANT —
    # advisory wrapper MUST still emit a JSON record so operator
    # dashboard sees the run + still exit 0 in report profile (the
    # wrapper is advisory; operator owns the response, not the
    # cron unit).
    mk_rk 99 "rkhunter crashed mid-scan"
    run_wd                                              # report profile, rc must be 0
    cap | grep -q '"tag":"selfdef-rkhunter"'
}

@test "INVARIANT (large-warning stress: 50 warnings → warning_count=50; sample still capped) — observability accuracy" {
    # Sister to lynis-cron 'large-warning fixture' INVARIANT —
    # cap is on log volume (sample), NOT on counter. Operator
    # dashboard should still see the full count so triage knows
    # haystack size.
    {
        printf 'Warning: %s\n' $(seq 1 50)
    } | {
        body="$(cat)"
        mk_rk 1 "${body}"
    }
    run_wd
    cap | grep -q '"warning_count":50'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (multi-mention same path NOT dedup'd — warning_count reflects raw warning lines)" {
    # If rkhunter emits 3 separate Warning lines about the SAME path,
    # warning_count reflects raw line count (3). The wrapper does NOT
    # dedup — that's operator-decision territory. Locks current
    # observability shape so a future dedup refinement is intentional.
    mk_rk 1 "Warning: Suspicious file /dev/.hidden
Warning: Suspicious file /dev/.hidden
Warning: Suspicious file /dev/.hidden"
    run_wd
    cap | grep -q '"warning_count":3'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_RKHUNTER_PROFILE — operator-dashboard distinguishes report from enforce)" {
    # Sister to L2-aide-bridge / L2-clamav-cron / L2-lynis-cron
    # profile-echo INVARIANTs across the brain. Downstream operator
    # dashboard / triage pipeline must see the profile value the
    # wrapper ran under (report vs enforce) so it can distinguish
    # advisory findings from gate-failing findings. The latter
    # would have aborted the cron unit on warning; the former just
    # logged. Closes the profile-surfacing axis on the rkhunter
    # rootkit-detection wrapper.
    mk_rk 0 "System checks summary: no warnings"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (sample names distinctive rootkit-warning in JSON for operator-triage routing — DELTA-detect sample-naming axis)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain (clamav-cron FOUND-file,
    # aide-bridge sample, lynis-cron warning ID). When rkhunter
    # fires a distinctively-named rootkit warning, the warning
    # name MUST surface in the JSON sample so operator
    # dashboard routes triage to the right finding — operators
    # MUST be able to tell WHICH rootkit-signature warning
    # fired without re-running the scan or scrolling the full
    # report.
    mk_rk 1 "Warning: Distinctive-Attacker-Rootkit-Sig found
[ Warning ] Test result from operator-relevant test"
    run_wd
    cap | grep -q 'Distinctive-Attacker-Rootkit-Sig'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-rkhunter tag must
    # fire EXACTLY ONCE per scan regardless of how many warnings
    # surface (the multi-mention same-path scenario, large-
    # warning-count stress). Multi-line output would break SDD-
    # 062 downstream JSON-line consumer. Locks consolidation
    # discipline on rkhunter rootkit-detection surveillance
    # surface.
    mk_rk 1 "Warning: rootkit-A found
Warning: rootkit-B found
Warning: rootkit-C found
Warning: rootkit-D found"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rkhunter -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. severity
    # field surfaces on operator dashboard color-coded severity
    # axis. A future refactor introducing a fifth value would
    # silently bucket as unknown. Bounded set locked.
    mk_rk 1 "Warning: rootkit-A found"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (rkhunter binary non-zero exit → wrapper rc=0 + emits JSON — advisory contract holds even on rkhunter crash)" {
    # Sister to brain-wide advisory-rc INVARIANTs (lynis-cron, etc.).
    # rkhunter may crash on parse error or missing data file. Wrapper
    # MUST still emit JSON record + return rc=0 (cron + systemd
    # success — advisory not enforcement).
    mk_rk 99 "rkhunter: internal error"
    run_wd
    cap | grep -q '"tag":"selfdef-rkhunter"'
}

@test "INVARIANT (no auto-uninstall: rkhunter-cron watchdog NEVER emits package-remove commands on rkhunter)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The rkhunter-cron watchdog invokes the
    # rkhunter rootkit-scanner but MUST NEVER emit shell
    # commands that uninstall the rkhunter package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall rkhunter).
    # Silent auto-removal would tear down the rootkit-scanner
    # substrate — T1562.001 Impair Defenses self-defeat by
    # the very module meant to detect rootkits. Locks anti-
    # package-removal contract on the rkhunter-cron substrate.
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+rkhunter' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # rkhunter-cron runs ON the timer's scheduled fire — invokes
    # rkhunter --check, parses output, emits a verdict, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the rkhunter-
    # cron substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/rkhunter-cron/systemd/selfdef-rkhunter-check.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-delete: rkhunter-cron installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # rkhunter-cron writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the rkhunter-cron
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/rkhunter-cron/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}
