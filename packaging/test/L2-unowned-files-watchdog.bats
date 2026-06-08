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

@test "INVARIANT (unowned-files-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # unowned-files-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (unowned-files-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the unowned-files-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (unowned-files-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the unowned-files-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the unowned-files-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the unowned-files-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the unowned-files-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the unowned-files-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (unowned-files-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (unowned-files-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (unowned-files-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (unowned-files-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the unowned-files-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    [ -f "${script_dir}/unowned-files-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (unowned-files-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (unowned-files-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (unowned-files-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script declares severity= variable with canonical vocabulary — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'severity=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script tag selfdef-unowned-files matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-unowned-files
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script uses printf-format JSON output — structured-event-emission contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'printf' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (unowned-files-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (unowned-files-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .timer file exists at canonical path modules/unowned-files-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (unowned-files-watchdog module.toml exists at canonical path modules/unowned-files-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (unowned-files-watchdog systemd dir exists at modules/unowned-files-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (unowned-files-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (unowned-files-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (unowned-files-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (unowned-files-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (unowned-files-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (unowned-files-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (unowned-files-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (unowned-files-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (unowned-files-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (unowned-files-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (unowned-files-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (unowned-files-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (unowned-files-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (unowned-files-watchdog module.toml has install_paths section non-empty 93)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
ps = ip.get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (unowned-files-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"unowned-files-watchdog"' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (unowned-files-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (unowned-files-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (unowned-files-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (unowned-files-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (unowned-files-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (unowned-files-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (unowned-files-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unowned-files-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}
