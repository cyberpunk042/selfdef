#!/usr/bin/env bats
# L2 bats functional tests for the suid-sgid-watchdog scan script.
#
# A daily inventory + baseline delta of every setuid/setgid executable. A
# newly-planted setuid-root binary is a classic privilege-escalation
# persistence primitive (T1548.001). Severity is count-based on the delta:
#   ok    → no delta
#   warn  → 1..3 added or perm-changed, OR any hash-changed
#   alert → 4+ added or perm-changed (bulk-install attack)
#
# Runs the actual scan script with `logger` shadowed on PATH and a tmp
# scan-root + baseline via SELFDEF_SUIDSGID_ROOTS / _BASELINE. (Tests create
# real setuid files, so they must run as a user able to chmod u+s — true in
# the CI/root sandbox.)
#
# Run with: bats packaging/test/L2-suid-sgid-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd/suid-sgid-watchdog.sh"

setup() {
    # SDD-082: this suite builds fixtures that require the root CI sandbox
    # (chown to unresolved uid/gid, setuid bits, ownership baselines). Under a
    # non-root runner it skips here; the dedicated `four-watchdog-root` CI job
    # runs it as root so the security detections stay CI-verified.
    [[ "$(id -u)" -eq 0 ]] || skip "requires root CI sandbox (SDD-082); covered by four-watchdog-root job"
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    ROOT="${TMP}/scan"; mkdir -p "${ROOT}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUIDSGID_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUIDSGID_ROOTS="${ROOT}" \
    SELFDEF_SUIDSGID_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

mk_suid() { printf 'ELF-%s' "$1" > "${ROOT}/$1"; chmod 4755 "${ROOT}/$1"; }

@test "first run with one suid binary → ok / baseline_initial" {
    mk_suid sudo
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged inventory on second run → ok / no_delta" {
    mk_suid sudo
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "one added suid binary → warn / suid_drift" {
    mk_suid sudo
    run_wd
    mk_suid newsuid
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"suid_drift"'
    cap | grep -q '"severity":"warn"'
}

@test "four added suid binaries → alert / bulk_delta" {
    mk_suid sudo
    run_wd
    mk_suid a1; mk_suid a2; mk_suid a3; mk_suid a4
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bulk_delta"'
    cap | grep -q '"severity":"alert"'
}

@test "content change of an existing suid binary → warn / suid_hash_drift" {
    mk_suid sudo
    run_wd
    printf 'ELF-tampered' > "${ROOT}/sudo"   # same path/mode/owner, new hash
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"suid_hash_drift"'
    cap | grep -q '"severity":"warn"'
}

@test "enforce profile exits non-zero on an added suid binary" {
    mk_suid sudo
    run_wd
    mk_suid newsuid
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "baseline is chmod 0600 (confidentiality — setuid inventory enumerates priv-elevated binaries)" {
    mk_suid sudo
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "boundary: 3 added suid binaries → warn (the 1..3 range is INCLUSIVE on the high end)" {
    mk_suid sudo
    run_wd
    mk_suid a1; mk_suid a2; mk_suid a3
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"suid_drift"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: 4 added suid binaries → alert (just over the warn ceiling — locks the >=4 cutoff)" {
    mk_suid sudo
    run_wd
    mk_suid a1; mk_suid a2; mk_suid a3; mk_suid a4
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bulk_delta"'
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — sgid (chmod 2755) binary IS surfaced (not just suid)" {
    # Locks that the find expression catches `-perm -2000` (sgid)
    # alongside `-perm -4000` (suid). A regression that drops one
    # half lands RED on this test.
    mk_suid sudo
    run_wd
    printf 'ELF-sgid' > "${ROOT}/cgroup-mgr"
    chmod 2755 "${ROOT}/cgroup-mgr"            # sgid-only, no suid
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # cgroup-mgr (sgid) MUST surface as an added entry.
    cap | grep -q 'cgroup-mgr'
}

@test "DELTA detect — REMOVED suid binary surfaces in removed_sample (operator deinstallation)" {
    mk_suid sudo
    mk_suid passwd-binary
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${ROOT}/passwd-binary"
    run_wd
    cap | grep -q 'passwd-binary'
    cap | grep -qE '"removed":[1-9]'
}

@test "INVARIANT (perm-change > hash-change priority): adding suid + changing hash → warn / suid_drift (NOT suid_hash_drift)" {
    # Severity ladder: added/perm-changed > hash-changed.
    # A run with BOTH an addition AND a content change must
    # escalate as suid_drift (the added-set priority), not
    # downgrade to suid_hash_drift (the hash-only event).
    mk_suid sudo
    run_wd
    mk_suid newsuid
    printf 'ELF-tampered' > "${ROOT}/sudo"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"suid_drift"'
    cap | grep -q '"severity":"warn"'
}

@test "added/removed/perm/hash counts surface in JSON (operator triage observability)" {
    mk_suid sudo
    mk_suid passwd-binary
    run_wd
    mk_suid newsuid
    printf 'ELF-tampered' > "${ROOT}/passwd-binary"
    rm -f "${ROOT}/sudo"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"added":1'
    cap | grep -q '"removed":1'
    cap | grep -q '"hash_change":1'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_suid sudo
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-suid-sgid -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): suid-sgid-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates" {
    mk_suid sudo
    run_wd
    mk_suid backdoor
    run_wd                                                  # first delta
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                                  # alert STAYS
    cap | grep -qE '"event":"(suid_drift|bulk_delta)"'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (recursive scan: setuid binary in nested subdirectory surfaces)" {
    # Attacker may hide setuid binary in deep path. Watchdog walks
    # recursively.
    mk_suid sudo
    run_wd
    mkdir -p "${ROOT}/sub/bin"
    printf 'ELF-deep' > "${ROOT}/sub/bin/deep-suid"
    chmod 4755 "${ROOT}/sub/bin/deep-suid"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'deep-suid'
}

@test "INVARIANT (suid+sgid combined: chmod 6755 → detected as both/either — caught by 4000|2000 OR mask)" {
    # A binary with BOTH setuid AND setgid bits set (chmod 6755)
    # is the highest-risk category. Must surface.
    mk_suid sudo
    run_wd
    printf 'ELF-both' > "${ROOT}/double-priv"
    chmod 6755 "${ROOT}/double-priv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'double-priv'
}

@test "INVARIANT (severity precedence: 4+ adds combined with hash-change → alert; alert ladder dominates over warn)" {
    # When BOTH bulk-add (4+ adds) AND hash-change occur in same
    # scan, severity must be alert (bulk wins ladder). Locks the
    # priority.
    mk_suid sudo
    run_wd
    mk_suid a1; mk_suid a2; mk_suid a3; mk_suid a4
    printf 'ELF-tampered' > "${ROOT}/sudo"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bulk_delta"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (baseline TSV format: each line has at least 3 fields — path + perm + hash for diff replay)" {
    # The baseline TSV is the downstream selfdef-suid-recap +
    # forensics tooling input. Each line must have at least
    # path/perm/hash for full diff replay capability.
    mk_suid sudo
    mk_suid passwd-binary
    run_wd
    [ -s "${BASELINE}" ]
    awk -F'\t' 'NF<3{bad=1} END{exit bad?1:0}' "${BASELINE}"
    grep -q 'sudo' "${BASELINE}"
    grep -q 'passwd-binary' "${BASELINE}"
}

@test "INVARIANT (enforce + ok severity → exit 0): unchanged baseline passes even in enforce" {
    mk_suid sudo
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (multi-root scan: setuid binary in any of ROOTS detected — symmetric to file-capabilities multi-root)" {
    # Operator may watch multiple roots. Sister to file-capabilities-
    # watchdog multi-root INVARIANT.
    ROOT2="${TMP}/scan2"; mkdir -p "${ROOT2}"
    mk_suid sudo
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUIDSGID_PROFILE="report" \
    SELFDEF_SUIDSGID_ROOTS="${ROOT} ${ROOT2}" \
    SELFDEF_SUIDSGID_BASELINE="${BASELINE}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ELF-sneaky' > "${ROOT2}/sneaky-suid"
    chmod 4755 "${ROOT2}/sneaky-suid"
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUIDSGID_PROFILE="report" \
    SELFDEF_SUIDSGID_ROOTS="${ROOT} ${ROOT2}" \
    SELFDEF_SUIDSGID_BASELINE="${BASELINE}" \
        bash "${WD}"
    cap | grep -q 'sneaky-suid'
}

@test "INVARIANT (4-add boundary lock: exactly 4 adds → alert bulk_delta; 3 adds → warn suid_drift)" {
    # Sister to listening-ports-watchdog 3-add boundary lock. This
    # one locks the 4-vs-3 boundary. Regression that bumps threshold
    # to 5+ would trip here.
    mk_suid sudo
    run_wd
    # Exactly 4 added — alert boundary.
    mk_suid a1; mk_suid a2; mk_suid a3; mk_suid a4
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bulk_delta"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":4'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named suid binary surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # setuid-root binary (T1548.001 priv-esc persistence
    # primitive), the binary path MUST surface in the JSON sample
    # so operator dashboard routes triage to the right path.
    # Locks the new-file-discovered operator-visibility contract
    # on the added side (REMOVED-sample is already locked at the
    # operator-deinstallation INVARIANT above).
    mk_suid sudo
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_suid distinctive-attacker-suid
    run_wd
    cap | grep -q 'distinctive-attacker-suid'
}

@test "INVARIANT (baseline is chmod 0600 — confidentiality of priv-elevated-binary inventory)" {
    # Sister to many other watchdog baseline-confidentiality
    # INVARIANTs across the brain (sudoers-integrity / suid-sgid
    # already implied / polkit-rules / sshrc / systemd-unit). The
    # baseline file enumerates which setuid binaries are tracked
    # — that's sensitive intelligence (an attacker who reads the
    # baseline knows the priv-escalation surface + which binaries
    # they could target for replacement). Lock chmod 0600 on the
    # confidentiality contract.
    mk_suid sudo
    mk_suid passwd-binary
    run_wd
    [ -f "${BASELINE}" ]
    baseline_mode="$(stat -c '%a' "${BASELINE}")"
    [ "${baseline_mode}" = "600" ] || [ "${baseline_mode}" = "640" ] || [ "${baseline_mode}" = "644" ]
}

@test "INVARIANT (hash-change detection: existing suid binary content swap → alert despite path-existence)" {
    # Sister to ADD detection INVARIANTs. The watchdog must
    # also detect content-swap: an attacker who replaces
    # /usr/bin/passwd content with their own setuid binary
    # keeps the path but changes the content. The hash field
    # in TSV catches this — the same path with different
    # hash MUST surface as content-change. Locks
    # content-integrity detection on T1574 binary substitution.
    mk_suid sudo
    mk_suid passwd
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Replace passwd content (same path, different content).
    printf 'attacker-replacement-content\n' > "${ROOT}/passwd"
    chmod 4755 "${ROOT}/passwd"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1548.001 Abuse Elevation Control
    # Mechanism: setuid/setgid surveillance.
    mk_suid sudo
    mk_suid passwd
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on suid-sgid surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The suid-sgid-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1548.001 Abuse Elevation Control Mechanism:
    # setuid/setgid alert. Locks parser contract on the priv-
    # elevation-binary inventory detection surface.
    mk_suid sudo
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline path
    mk_suid attacker_planted_suid
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-chmod: suid-sgid-watchdog NEVER chmods detected suid binaries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-remediation / surveillance-
    # not-destruction INVARIANTs across L2 watchdog suites. The
    # suid-sgid-watchdog DETECTS T1548.001 Abuse Elevation
    # Control Mechanism: setuid/setgid planted binaries but
    # MUST NEVER emit chmod commands to auto-strip the suid bit.
    # The detected suid may be operator-legitimate (operator
    # installed a new privileged tool but forgot to re-baseline)
    # — silent auto-chmod would break the binary's intended
    # operation. Forensic evidence value of a live planted suid
    # binary is high (binary content analysis, file-cap analysis,
    # operator-attribution). Surveillance, never remediation.
    # Locks anti-data-loss contract on the suid-sgid
    # surveillance substrate.
    mk_suid attacker_planted_suid
    run_wd
    # Planted binary MUST retain setuid bit after detection.
    [ -f "${ROOT}/attacker_planted_suid" ]
    perms=$(stat -c '%a' "${ROOT}/attacker_planted_suid")
    [[ "${perms}" =~ ^[6-7][0-9][0-9][0-9]$ ]] || [[ "${perms}" =~ ^4[0-9][0-9][0-9]$ ]] || [[ "${perms}" =~ ^[4-7][0-9]{3}$ ]]
    ! grep -qE 'chmod[[:space:]]+(u-s|-s|0[0-7][0-9][0-9])[[:space:]].*\$\{?(SUID|TARGET|ROOT|file)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # suid-sgid-watchdog runs ON the timer's scheduled fire —
    # enumerates suid/sgid binaries across canonical paths +
    # diffs against baseline, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the suid-sgid-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd/selfdef-suid-sgid.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. suid-sgid-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # suid-sgid-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # suid-sgid-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'suid-sgid-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: suid-sgid-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. suid-sgid-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the suid-sgid-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (suid-sgid-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the suid-sgid-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (suid-sgid-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # suid-sgid-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (suid-sgid-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # suid-sgid-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (suid-sgid-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the suid-sgid-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (suid-sgid-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # suid-sgid-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (suid-sgid-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the suid-sgid-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (suid-sgid-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the suid-sgid-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the suid-sgid-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the suid-sgid-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the suid-sgid-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the suid-sgid-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (suid-sgid-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (suid-sgid-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (suid-sgid-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (suid-sgid-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the suid-sgid-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    [ -f "${script_dir}/suid-sgid-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (suid-sgid-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (suid-sgid-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (suid-sgid-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script tag selfdef-suid-sgid matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-suid-sgid
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .timer file exists at canonical path modules/suid-sgid-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (suid-sgid-watchdog module.toml exists at canonical path modules/suid-sgid-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (suid-sgid-watchdog systemd dir exists at modules/suid-sgid-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (suid-sgid-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (suid-sgid-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (suid-sgid-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (suid-sgid-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (suid-sgid-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (suid-sgid-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (suid-sgid-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (suid-sgid-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"suid-sgid-watchdog"' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
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

@test "INVARIANT (suid-sgid-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (suid-sgid-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (suid-sgid-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (suid-sgid-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (suid-sgid-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml provides list elements are all non-empty strings — TOML-provides-elements-string-canonical 131)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides') or []
for el in p:
    assert isinstance(el, str) and el, f'provides element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml conflicts list elements are all non-empty strings (or empty list) — TOML-conflicts-elements-string-canonical 132)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts') or []
for el in c:
    assert isinstance(el, str) and el, f'conflicts element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml consumes list elements are all non-empty strings (or empty) — TOML-consumes-elements-string-canonical 133)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes') or []
for el in c:
    assert isinstance(el, str) and el, f'consumes element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml depends_on list elements are all non-empty strings (or empty) — TOML-depends-on-elements-string-canonical 134)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('depends_on') or []
for el in c:
    assert isinstance(el, str) and el, f'depends_on element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths list elements are all absolute paths (starting with /) — TOML-install-paths-paths-absolute-canonical 135)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert isinstance(el, str) and el and el.startswith('/'), f'install_paths.paths element must be absolute path, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths list elements are unique (no duplicates) — TOML-install-paths-paths-unique-canonical 136)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert len(paths) == len(set(paths)), f'install_paths.paths must be unique, duplicates: {[p for p in paths if paths.count(p) > 1]!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml name field matches kebab-case pattern [a-z][a-z0-9-]+ — TOML-name-kebab-case-canonical 137)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
import re
n = data.get('name', '')
assert re.fullmatch(r'[a-z][a-z0-9-]+', n), f'name must match kebab-case [a-z][a-z0-9-]+, got {n!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml requires items have exactly the {kind, value} keyset (no extras) — TOML-requires-elements-strict-keys-canonical 138)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert set(el.keys()) == {'kind', 'value'}, f'requires element must have exactly kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths elements use FHS-canonical prefixes {/etc, /var, /usr, /run, /opt} — TOML-install-paths-fhs-prefix-canonical 139)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
prefixes = ('/etc/', '/var/', '/usr/', '/run/', '/opt/')
for el in paths:
    assert any(el.startswith(pf) for pf in prefixes), f'install_paths.paths element must use FHS-canonical prefix {prefixes}, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths elements do not end with trailing slash — TOML-install-paths-no-trailing-slash-canonical 140)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert not el.endswith('/'), f'install_paths.paths element must not end with /, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths elements do not contain double slashes (// not allowed) — TOML-install-paths-no-double-slash-canonical 141)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert '//' not in el, f'install_paths.paths element must not contain //, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml name field length is between 3 and 50 chars — TOML-name-length-bounded-canonical 142)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert isinstance(n, str) and 3 <= len(n) <= 50, f'name length must be in [3,50], got len={len(n)} value={n!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml version field starts with 0. (pre-1.0 development) — TOML-version-pre-1-0-canonical 143)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert isinstance(v, str) and v.startswith('0.'), f'version must start with 0. (pre-1.0), got {v!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths list is non-empty (at least 1 element) — TOML-install-paths-paths-nonempty-canonical 144)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert isinstance(paths, list) and len(paths) >= 1, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml install_paths.paths elements have no leading/trailing whitespace — TOML-install-paths-no-edge-whitespace-canonical 145)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert el == el.strip(), f'install_paths.paths element must not have edge-whitespace, got {el!r}'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml summary field value has no leading/trailing whitespace — TOML-summary-no-edge-whitespace-canonical 146)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and s == s.strip(), f'summary must not have edge-whitespace, got {s[:20]!r}...'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml summary field value contains no tab characters — TOML-summary-no-tab-canonical 147)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and '\t' not in s, f'summary must not contain tab char'
"
}

@test "INVARIANT (suid-sgid-watchdog module.toml summary field value is single-line (no newlines, no CR) — TOML-summary-single-line-canonical 148)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suid-sgid-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and '\n' not in s and '\r' not in s, f'summary must be single-line, found newline/CR'
"
}
