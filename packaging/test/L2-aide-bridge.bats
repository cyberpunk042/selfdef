#!/usr/bin/env bats
# L2 bats functional tests for the aide-bridge aide-check.sh wrapper.
#
# Wraps `aide --check`: maps AIDE's exit bitmask + summary table to a
# severity (ok=no diff, warn=adds only, alert=removals/changes, high=internal
# error / missing config). Drives the wrapper with a fake `aide` binary
# (SELFDEF_AIDE_BIN) emitting a controlled summary + exit code, and `logger`
# shadowed on PATH.
#
# Run with: bats packaging/test/L2-aide-bridge.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd/aide-check.sh"

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
    CONF="${TMP}/aide.conf"; printf '# aide config\n' > "${CONF}"
    FAKE_AIDE="${TMP}/aide"
}

teardown() { rm -rf "${TMP}"; }

# mk_aide <rc> <summary-stdout>
mk_aide() {
    { printf '#!/usr/bin/env bash\n'; printf 'cat <<'\''OUT'\''\n%s\nOUT\n' "$2"; printf 'exit %s\n' "$1"; } > "${FAKE_AIDE}"
    chmod +x "${FAKE_AIDE}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_AIDE_PROFILE="${PROFILE:-baseline}" \
    SELFDEF_AIDE_BIN="${FAKE_AIDE}" \
    SELFDEF_AIDE_CONF="${CONF_V:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "missing aide config → high / config_missing" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"config_missing"'
    cap | grep -q '"severity":"high"'
}

@test "no differences (rc 0) → ok / no_diff" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"event":"no_diff"'
    cap | grep -q '"severity":"ok"'
}

@test "adds only → warn / diff_added_only" {
    mk_aide 1 "Added entries: 3
Removed entries: 0
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_added_only"'
    cap | grep -q '"severity":"warn"'
}

@test "removals/changes → alert / diff_changed_or_removed" {
    mk_aide 6 "Added entries: 0
Removed entries: 1
Changed entries: 2"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "aide internal error (rc >= 8) → high / aide_internal_error" {
    mk_aide 8 "fatal: database read error"
    run_wd
    cap | grep -q '"event":"aide_internal_error"'
    cap | grep -q '"severity":"high"'
}

@test "enforce profile exits non-zero on a diff" {
    mk_aide 6 "Removed entries: 1
Changed entries: 2"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "bitmask added/removed/changed surface in JSON (operator can verify the AIDE rc semantics)" {
    # rc 7 = 1|2|4 = added + removed + changed bits all set.
    mk_aide 7 "Added entries: 5
Removed entries: 3
Changed entries: 11"
    run_wd
    cap | grep -q '"added_bit":1'
    cap | grep -q '"removed_bit":1'
    cap | grep -q '"changed_bit":1'
    cap | grep -q '"aide_rc":7'
}

@test "summary-table counts surface in JSON (operator triage observability)" {
    mk_aide 7 "Added entries: 5
Removed entries: 3
Changed entries: 11"
    run_wd
    cap | grep -q '"added":5'
    cap | grep -q '"removed":3'
    cap | grep -q '"changed":11'
}

@test "profile field surfaces in JSON (echo of operator-set --profile)" {
    mk_aide 0 "AIDE found NO differences"
    PROFILE=enforce run_wd
    cap | grep -q '"profile":"enforce"'
}

@test "INVARIANT (removals+changes win over adds): rc=3 (added+removed) → alert (not warn — removals tip the severity)" {
    # rc 3 = 1|2 = added + removed bits set. The script's severity
    # ladder: if removed>0 OR changed>0 → alert. The presence of
    # adds alongside the removal must NOT downgrade to warn.
    mk_aide 3 "Added entries: 2
Removed entries: 1
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (parse-defensive): missing summary table → all counts default to 0 + still emit JSON" {
    # AIDE versions differ in summary-table format; the script
    # falls back to 0 counts when the awk patterns don't match.
    # The wrapper must still emit a valid JSON record (not crash).
    mk_aide 1 "AIDE 0.16 — unusual output format with no Added entries: header"
    run_wd
    cap | grep -q '"tag":"selfdef-aide"'
    cap | grep -q '"added":0'
    cap | grep -q '"removed":0'
    cap | grep -q '"changed":0'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    # The wrapper emits two logger calls: one with tag
    # `selfdef-aide` (the JSON record) and one with tag
    # `selfdef-aide-detail` (the head of AIDE output). Count
    # only the main `-t selfdef-aide --` line, distinct from
    # `-t selfdef-aide-detail --`.
    main_count=$(cap | grep -cE '^-t selfdef-aide -- ')
    [ "${main_count}" = "1" ]
}

@test "baseline profile exits 0 even on alert severity (findings are operator-pull advisory)" {
    mk_aide 6 "Removed entries: 1
Changed entries: 2"
    PROFILE=baseline run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline profile exits 0 even on high severity (config_missing is advisory in baseline mode)" {
    CONF_V="${TMP}/nonexistent" \
        PROFILE=baseline run run_wd
    [ "${status}" = "0" ]
}

@test "INVARIANT (rc=0 + no_diff: all count fields = 0 in JSON)" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"added":0'
    cap | grep -q '"removed":0'
    cap | grep -q '"changed":0'
}

@test "INVARIANT (current behavior: enforce profile on internal-error (rc>=8) exits 0 — wrapper-level vs diff-level distinction)" {
    # Internal error is wrapper-level (AIDE itself failed to run);
    # the enforce gate targets diff-level events (added/removed/
    # changed). Current behavior: wrapper exits 0 + emits high
    # severity JSON; operator alerting hooks the high severity,
    # not the exit code. Locks current contract so future
    # refactor doesn't accidentally couple enforce-exit-non-zero
    # to wrapper-level failures.
    mk_aide 8 "fatal: database read error"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"high"'
}

@test "INVARIANT (enforce profile on adds-only (warn) → exit non-zero — strict baseline integrity)" {
    # Adds-only is warn severity in baseline profile (operator-
    # pull advisory). Under enforce, even adds break the strict
    # baseline-integrity contract and must exit non-zero.
    mk_aide 1 "Added entries: 3"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (enforce profile on no_diff → exit 0): unchanged baseline passes even in enforce" {
    mk_aide 0 "AIDE found NO differences"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
}

@test "INVARIANT (rc surfaces in JSON across diff-tier + high-tier — diff-tier uses aide_rc, high-tier uses rc)" {
    # Current schema: the diff-tier JSON path uses 'aide_rc' field
    # name; the high-tier internal-error path uses 'rc' field.
    # Lock both surfaces — downstream consumers must handle both
    # names. (Future refinement could unify to aide_rc across
    # both paths, but for now this is the contract.)
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"aide_rc":0'
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_aide 12 "fatal: bad signature"
    run_wd
    # Internal-error path uses 'rc':12 not 'aide_rc':12.
    cap | grep -qE '"rc":12'
    cap | grep -q '"severity":"high"'
}

@test "INVARIANT (-detail companion tag emits AIDE output for journal forensics — operator can journalctl -t selfdef-aide-detail)" {
    # The -detail tag must surface AIDE's stdout so operator can
    # journal-grep specific changed paths. The MAIN tag carries
    # only the JSON summary — the detail is the forensics channel.
    mk_aide 6 "Added entries: 0
Removed entries: 1
Changed entries: 2
F: /etc/passwd
F: /etc/shadow"
    run_wd
    detail_count=$(cap | grep -cE '^-t selfdef-aide-detail -- ')
    [ "${detail_count}" -ge 1 ]
}

@test "INVARIANT (changed-only rc=4 → alert without adds/removes — changed bit alone tips severity)" {
    # rc=4 (changed bit only set) must alert. Sister axis to the
    # rc=6 (removed+changed) test and rc=3 (added+removed) test.
    # Locks that EACH dangerous bit independently triggers alert,
    # not only combinations.
    mk_aide 4 "Added entries: 0
Removed entries: 0
Changed entries: 5"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (removed-only rc=2 → alert without changes/adds — removed bit alone tips severity)" {
    # Sister to changed-only test. rc=2 (removed bit only) must
    # alert. Locks each dangerous bit individually.
    mk_aide 2 "Added entries: 0
Removed entries: 4
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (combined-all rc=7 → alert with adds+removes+changed all bits set)" {
    # Sister to each-bit-individual axes locked above. When AIDE
    # surfaces an attacker's full filesystem-rewrite (rc=7 — adds +
    # removed + changed bits all set), severity stays alert (highest
    # — the changed/removed bits win), not warn (which would happen
    # if combined-rc was misclassified as adds-dominated). Locks the
    # severity-ladder precedence: changed/removed beat adds in any
    # combined finding. Closes the rc-bitmask combinatorial coverage
    # axis on the file-integrity surveillance surface (T1565.001 —
    # Stored Data Manipulation via mass filesystem rewrite).
    mk_aide 7 "Added entries: 2
Removed entries: 3
Changed entries: 4"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (high-volume adds-only: 100 adds still warn — adds-only never escalates to alert; bit-mask precedence holds at scale)" {
    # Sister to suid-sgid 4-add boundary INVARIANT and many other
    # watchdog count-vs-bit precedence INVARIANTs across the
    # brain. AIDE's bitmask (1=added, 2=removed, 4=changed)
    # determines severity REGARDLESS of count magnitude. A
    # 100-add scan rc=1 (adds-only bit set) MUST stay warn — the
    # adds-only bit defines the severity ceiling. If the wrapper
    # silently escalated to alert at high counts, the operator
    # would lose the change/remove signal (which is qualitatively
    # different: changes/removes are tamper signals, adds are
    # legit-ops signals at any scale). Locks the bit-precedence-
    # over-count invariant on the file-integrity surveillance
    # surface (T1565.001 — Stored Data Manipulation tamper class).
    mk_aide 1 "Added entries: 100
Removed entries: 0
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_added_only"'
    cap | grep -q '"severity":"warn"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rc=5 added+changed — adds-with-tamper → alert; closes the rc-bitmask combinatorial slot)" {
    # Sister to rc=3 (added+removed), rc=7 (all 3) and changed-only
    # / removed-only / adds-only individual-bit INVARIANTs already
    # locked above. Closes the remaining rc-bitmask combinatorial
    # coverage: rc=5 (1+4 = added bit + changed bit). Severity must
    # be alert — the changed bit tips severity ladder over the
    # adds-only baseline. This is the "attacker added new files +
    # tampered existing files" pattern (eg. dropped a malicious
    # /etc/cron.d/.evil AND modified /etc/passwd in the same scan).
    # If the wrapper misclassified rc=5 as adds-dominated, the
    # operator would lose the tamper signal underneath the adds.
    # Locks the changed-bit-tips-severity invariant on the
    # file-integrity surveillance surface (T1565.001).
    mk_aide 5 "Added entries: 3
Removed entries: 0
Changed entries: 2"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

