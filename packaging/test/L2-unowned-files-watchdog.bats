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

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. severity
    # field on operator dashboard color-coded axis; bounded set
    # locked.
    printf 'benign\n' > "${ROOT}/benign-file"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (no auto-delete: unowned-files-watchdog NEVER chowns/chmods/deletes orphans — surveillance not remediation)" {
    # Sister to brain-wide no-auto-uninstall + no-auto-delete +
    # no-auto-trust INVARIANTs across L2 surveillance suites.
    # The unowned-files-watchdog DETECTS files owned by deleted
    # UIDs/GIDs (T1070 forensic-anti-trail OR legitimate-orphan
    # post-deluser) but MUST NEVER emit chown/chmod/rm/unlink
    # commands to auto-remediate. Auto-chown to root would
    # destroy the forensic evidence chain (operator can't tell
    # which UID originally owned the file post-fix); auto-
    # delete would destroy the forensic file itself. Operator
    # triage MUST inspect orphans before remediation —
    # surveillance, never remediation. Locks anti-evidence-
    # destruction contract on the unowned-files surveillance
    # substrate.
    for i in 1 2 3; do
        printf 'x' > "${ROOT}/orphan-${i}"
        chown 99999:99999 "${ROOT}/orphan-${i}"
    done
    run_wd
    # All 3 orphans MUST remain on disk with original UID/GID.
    for i in 1 2 3; do
        [ -f "${ROOT}/orphan-${i}" ]
        uid="$(stat -c '%u' "${ROOT}/orphan-${i}")"
        [ "${uid}" = "99999" ]
    done
    # Watchdog source MUST NEVER call chown / find -delete /
    # rm on scan targets.
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'chown[[:space:]]+root' "${WD}"
}

@test "INVARIANT (sample names offending orphan path in JSON — operator triage routing)" {
    # Sister to brain-wide DELTA-detect sample-naming axis
    # INVARIANTs across L2 surveillance suites. When orphans
    # are detected, the path of at least one orphan MUST surface
    # in the JSON sample field so operator dashboard routes
    # triage to the right file. Without sample naming, operator
    # only sees a count and must manually walk the filesystem
    # to find the orphans — degrading MTTR. Locks operator-
    # observability contract on the unowned-files surveillance
    # substrate.
    printf 'x' > "${ROOT}/distinctive-attacker-orphan-name"
    chown 99999:99999 "${ROOT}/distinctive-attacker-orphan-name"
    run_wd
    cap | grep -q 'distinctive-attacker-orphan-name'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # unowned-files-watchdog runs ON the timer's scheduled fire
    # — enumerates files with no matching uid/gid in /etc/passwd
    # /etc/group, emits a verdict on orphan-file inventory delta,
    # then exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the unowned-
    # files-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd/selfdef-unowned-files.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. unowned-files-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # unowned-files-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # unowned-files-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'unowned-files-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: unowned-files-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. unowned-files-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the unowned-files-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (unowned-files-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the unowned-files-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (unowned-files-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # unowned-files-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (unowned-files-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # unowned-files-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (unowned-files-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the unowned-files-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
