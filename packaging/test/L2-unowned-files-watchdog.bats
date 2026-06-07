#!/usr/bin/env bats
# L2 bats functional tests for the unowned-files-watchdog scan script.
#
# A scan for files whose uid or gid does not resolve to a passwd/group entry.
# Unowned files often appear after a user is deleted but their files linger
# (a re-created uid then inherits them) or after sloppy archive extraction —
# a privilege/ownership-confusion surface. Stateless count ladder:
#   ok    → 0 unowned
#   warn  → 1..50 unowned
#   alert → 51+ unowned (typical of a bulk uid-deletion incident)
#
# Tests chown files to an unresolved uid/gid, so they must run as root (true
# in the CI/root sandbox).
#
# Run with: bats packaging/test/L2-unowned-files-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd/unowned-files-watchdog.sh"

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
    SELFDEF_UNOWNED_PROFILE="${PROFILE:-report}" \
    SELFDEF_UNOWNED_ROOTS="${ROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no unowned files → ok / no_unowned" {
    printf 'x' > "${ROOT}/owned"            # root-owned, resolvable
    run_wd
    cap | grep -q '"event":"no_unowned"'
    cap | grep -q '"severity":"ok"'
}

@test "one unowned file → warn / unowned_found" {
    printf 'x' > "${ROOT}/orphan"; chown 99999:99999 "${ROOT}/orphan"
    run_wd
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q '"severity":"warn"'
}

@test "a normally-owned file is NOT flagged" {
    printf 'x' > "${ROOT}/owned"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "51+ unowned files → alert / bulk_unowned" {
    for i in $(seq 1 55); do printf 'x' > "${ROOT}/orphan${i}"; chown 99999:99999 "${ROOT}/orphan${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_unowned"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on an unowned finding" {
    printf 'x' > "${ROOT}/orphan"; chown 99999:99999 "${ROOT}/orphan"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "boundary: 50 unowned files → warn (the 1..50 range is INCLUSIVE on the high end)" {
    for i in $(seq 1 50); do printf 'x' > "${ROOT}/orphan${i}"; chown 99999:99999 "${ROOT}/orphan${i}"; done
    run_wd
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: 51 unowned files → alert (just over the warn ceiling)" {
    for i in $(seq 1 51); do printf 'x' > "${ROOT}/orphan${i}"; chown 99999:99999 "${ROOT}/orphan${i}"; done
    run_wd
    cap | grep -q '"event":"bulk_unowned"'
    cap | grep -q '"severity":"alert"'
}

@test "unowned-count surfaces in JSON (operator triage observability)" {
    for i in $(seq 1 7); do printf 'x' > "${ROOT}/orphan${i}"; chown 99999:99999 "${ROOT}/orphan${i}"; done
    run_wd
    cap | grep -q '"unowned_count":7'
}

@test "sample of unowned paths (up to 10) surfaces in 'sample' field for operator triage" {
    printf 'x' > "${ROOT}/very-distinctive-orphan-name"; chown 99999:99999 "${ROOT}/very-distinctive-orphan-name"
    run_wd
    cap | grep -q 'very-distinctive-orphan-name'
}

@test "scan_roots field echoes the configured SELFDEF_UNOWNED_ROOTS (operator can verify the scan scope)" {
    printf 'x' > "${ROOT}/owned"
    run_wd
    cap | grep -q "\"scan_roots\":\"${ROOT}\""
}

@test "nogroup-only file (uid resolves, gid does not) IS flagged" {
    # nouser is the standard case; nogroup-only (gid unresolved
    # but uid OK) is the parallel case the find expression catches
    # via the \( -nouser -o -nogroup \) disjunction.
    printf 'x' > "${ROOT}/bad-gid-only"
    chown root:99999 "${ROOT}/bad-gid-only"
    run_wd
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q '"severity":"warn"'
}

@test "nouser-only file (gid resolves, uid does not) IS flagged" {
    printf 'x' > "${ROOT}/bad-uid-only"
    chown 99999:root "${ROOT}/bad-uid-only"
    run_wd
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q '"severity":"warn"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'x' > "${ROOT}/orphan"; chown 99999:99999 "${ROOT}/orphan"
    run_wd
    n=$(cap | grep -c '"tag":"selfdef-unowned-files"')
    [ "${n}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    for i in $(seq 1 55); do printf 'x' > "${ROOT}/orphan${i}"; chown 99999:99999 "${ROOT}/orphan${i}"; done
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sample cap at 10: 20 orphans → MAIN tag sample contains only first 10 — log volume control)" {
    # Operator dashboards need the count; the -detail companion
    # (if any) carries full forensics. Sample MUST be capped.
    for i in $(seq 1 20); do
        printf 'x' > "${ROOT}/orphan-distinct-${i}"
        chown 99999:99999 "${ROOT}/orphan-distinct-${i}"
    done
    run_wd
    cap | grep -qE '"unowned_count":20'
    # Verify orphan-distinct-15 + 20 NOT in main sample (capped at
    # first 10). Note: find ordering may not be deterministic, so
    # we just verify the count of distinct orphan-distinct-* IDs
    # in the cap doesn't exceed 10.
    # The -detail companion tag emits all paths for forensics;
    # the MAIN selfdef-unowned-files tag carries the capped
    # sample of 10. Lock by checking the MAIN line.
    main_line="$(cap | grep -E '^-t selfdef-unowned-files --')"
    found_in_main="$(printf '%s' "${main_line}" | grep -oE 'orphan-distinct-[0-9]+' | sort -u | wc -l)"
    [ "${found_in_main}" -le 10 ]
}

@test "INVARIANT (recursive scan: orphan in nested subdirectory also surfaces)" {
    # Attacker may hide orphan in a deep path. Watchdog walks
    # recursively.
    mkdir -p "${ROOT}/a/b/c"
    printf 'x' > "${ROOT}/a/b/c/deep-orphan"
    chown 99999:99999 "${ROOT}/a/b/c/deep-orphan"
    run_wd
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q 'deep-orphan'
}

@test "INVARIANT (enforce + ok severity → exit 0): no orphans passes even in enforce" {
    printf 'x' > "${ROOT}/owned"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_UNOWNED_PROFILE)" {
    printf 'x' > "${ROOT}/orphan"; chown 99999:99999 "${ROOT}/orphan"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (stateless re-evaluation: orphan-found alert STAYS visible on every run until operator fixes)" {
    # unowned-files-watchdog is stateless (no baseline-refresh required) —
    # re-evaluates live filesystem on every run. An orphan that stays
    # unowned across runs MUST re-fire every run, not decay to ok.
    for i in $(seq 1 55); do
        printf 'x' > "${ROOT}/orphan${i}"
        chown 99999:99999 "${ROOT}/orphan${i}"
    done
    run_wd
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"bulk_unowned"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-root scan: orphan in ANY watched root → flagged)" {
    # Operator may watch multiple roots (e.g. /etc + /home + /opt).
    # Lock multi-root axis.
    ROOT2="${TMP}/scan2"; mkdir -p "${ROOT2}"
    printf 'x' > "${ROOT}/owned"
    printf 'x' > "${ROOT2}/orphan-in-second-root"
    chown 99999:99999 "${ROOT2}/orphan-in-second-root"
    PATH="${BIN}:${PATH}" \
    SELFDEF_UNOWNED_PROFILE="report" \
    SELFDEF_UNOWNED_ROOTS="${ROOT} ${ROOT2}" \
    bash "${WD}"
    cap | grep -q '"event":"unowned_found"'
    cap | grep -q 'orphan-in-second-root'
}

@test "INVARIANT (boundary 51: at exact 51 orphans severity escalates from warn to alert)" {
    # The ladder transition is exactly at 51 (50 = warn ceiling, 51 = alert).
    # Single-notch boundary lock.
    for i in $(seq 1 51); do
        printf 'x' > "${ROOT}/orphan${i}"
        chown 99999:99999 "${ROOT}/orphan${i}"
    done
    run_wd
    cap | grep -q '"event":"bulk_unowned"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"unowned_count":5[1-9]|"unowned_count":[6-9][0-9]|"unowned_count":1[0-9][0-9]'
}

@test "INVARIANT (unowned-by-gid-only also flagged — sister axis to unowned-by-uid)" {
    # The "uid resolves, gid does not" case is just as much an
    # ownership-confusion vector as "uid does not resolve" — the
    # file's gid being unresolved means group-membership tied to
    # that gid is undefined; if the gid gets reused for a new
    # group, the file silently joins that group's ACL surface
    # (a routine post-incident remediation issue). Locks coverage
    # of the gid-only-unowned axis alongside the uid-only-unowned
    # axis already locked.
    # File with resolvable uid (root=0) but unresolved gid.
    printf 'x' > "${ROOT}/gid-only-orphan"
    chown 0:99999 "${ROOT}/gid-only-orphan"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
    cap | grep -qE '"event":"(unowned_found|bulk_unowned)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named orphan surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an unowned (deleted-user-
    # remnant or sloppy-archive-extraction) file appears, the file
    # path MUST surface in the JSON sample so operator dashboard
    # routes triage to the right path. Locks the new-file-
    # discovered operator-visibility contract on the ownership-
    # confusion surface (post-uid-deletion lingering files +
    # post-incident remediation traceability).
    printf 'x' > "${ROOT}/distinctive-attacker-orphan"
    chown 99999:99999 "${ROOT}/distinctive-attacker-orphan"
    run_wd
    cap | grep -q 'distinctive-attacker-orphan'
}

@test "INVARIANT (recursive scan: orphan in nested subdirectory also surfaces — not just top-level)" {
    # Sister to suid-sgid + timestomp recursive-scan INVARIANTs.
    # Real-world host hierarchies have nested directories.
    # Attacker may plant orphans in subdirs to dodge a top-only
    # scan. The watchdog MUST recurse into subdirectories. Locks
    # the recursive-traversal contract on the unowned-files
    # detection surface (T1070 — Indicator Removal; orphans
    # left over from compromised-user-deletion may sit anywhere
    # in /opt /var /srv subtree).
    mkdir -p "${ROOT}/deep/nested/path"
    printf 'x' > "${ROOT}/deep/nested/path/nested-orphan"
    chown 99999:99999 "${ROOT}/deep/nested/path/nested-orphan"
    run_wd
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. selfdef-
    # unowned-files tag must fire EXACTLY ONCE per scan regardless
    # of how many orphans surface. Lock consolidation on T1070
    # Indicator Removal surveillance surface.
    for i in 1 2 3 4 5; do
        printf 'x' > "${ROOT}/orphan-${i}"
        chown 99999:99999 "${ROOT}/orphan-${i}"
    done
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-unowned-files -- ')
    [ "${main_count}" = "1" ]
}
