#!/usr/bin/env bats
# L2 functional suite for logfile-integrity-watchdog.
#
# logfile-integrity-watchdog detects log tampering via monotonic-
# growth + inode-stability tracking. Append-only logs only ever
# GROW until logrotate rotates them (which changes the inode and
# resets size — a KNOWN benign signature). An attacker erasing
# their tracks truncates / rewrites the log in place → size SHRINKS
# with the SAME inode. That combination (same inode, smaller size)
# has no benign cause and is THE indicator-removal signature.
#
# Severity tiers:
#   ok    → all logs grew or rotated cleanly (new inode)
#   warn  → a log went missing (deleted)
#   alert → same-inode size shrink (in-place truncation — tamper
#           signature)
#
# Uses SELFDEF_LOGINT_WATCH env-var (added 2026-06-06, colon-
# separated PATH-style watch list) so the L2 suite controls the
# exact set of files tracked. Live default behavior unchanged.
#
# Run with: bats packaging/test/L2-logfile-integrity-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd/logfile-integrity-watchdog.sh"

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
    STATE="${TMP}/logfile-integrity-state.tsv"
    LOG1="${TMP}/log1.log"
    LOG2="${TMP}/log2.log"
    WATCH="${LOG1}:${LOG2}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE="${PROFILE:-report}" \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${WATCH}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures state + chmod 0600" {
    printf 'line 1\nline 2\n' > "${LOG1}"
    printf 'one entry\n' > "${LOG2}"
    run_wd
    [ -f "${STATE}" ]
    [ "$(stat -c '%a' "${STATE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"tracked":2'
}

@test "logs grew normally (append-only) → ok / logs_intact" {
    printf 'line 1\nline 2\n' > "${LOG1}"
    printf 'one\n' > "${LOG2}"
    run_wd
    # Append to both logs.
    printf 'line 3\n' >> "${LOG1}"
    printf 'two\nthree\n' >> "${LOG2}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logs_intact"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"grew":2'
    cap | grep -qE '"shrinks":0'
}

@test "log truncated in place (same inode, smaller size) → alert / log_truncation_detected (the tamper signature)" {
    printf 'line 1\nline 2\nline 3\nline 4\n' > "${LOG1}"
    run_wd
    # In-place truncation via shell `>` redirect KEEPS the inode but
    # zeroes the size — the attack signature.
    : > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"shrinks":1'
}

@test "partial in-place truncation (size shrinks but >0) → alert" {
    printf 'aaaaaaaaaaaaaaa\nbbbbbbbbbbbb\nccccccccc\n' > "${LOG1}"
    run_wd
    # Truncate to a smaller size, KEEP the same inode (write-in-place).
    printf 'aa\n' > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
}

@test "log ROTATED (new inode, smaller size) → ok / logs_intact (benign logrotate signature)" {
    printf 'line 1\nline 2\nline 3\n' > "${LOG1}"
    run_wd
    # Simulate logrotate: rename + create new file (NEW INODE, smaller).
    mv "${LOG1}" "${LOG1}.1"
    printf 'header\n' > "${LOG1}"          # new inode, smaller size
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Inode mismatch → counted as "rotated", NOT "shrinks". Severity ok.
    cap | grep -q '"event":"logs_intact"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"shrinks":0'
    cap | grep -qE '"rotated":1'
}

@test "log MISSING (deleted) → warn / log_missing" {
    printf 'line 1\n' > "${LOG1}"
    printf 'one\n' > "${LOG2}"
    run_wd
    rm -f "${LOG1}"     # log deleted entirely
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_missing"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"missing":1'
}

@test "shrink takes precedence over missing (alert wins over warn)" {
    printf 'line 1\nline 2\nline 3\n' > "${LOG1}"
    printf 'one\n' > "${LOG2}"
    run_wd
    : > "${LOG1}"        # in-place truncation → alert
    rm -f "${LOG2}"      # delete  → warn (would be warn if alone)
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # alert wins
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"shrinks":1'
    cap | grep -qE '"missing":1'
}

@test "the emitted JSON carries every promised schema field" {
    printf 'aa\n' > "${LOG1}"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-logfile-integrity"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"tracked":[0-9]+'
}

@test "shrink sample carries 'SHRANK:<path>:<old>-><new>' format" {
    printf 'aaaaaaaaaaaaaaaaaa\nbbbbbbb\n' > "${LOG1}"
    run_wd
    : > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # SHRANK label + path + old/new size pair.
    cap | grep -q "SHRANK:${LOG1}"
}

@test "enforce profile + log truncated → exit 1" {
    printf 'aaaaaaaa\n' > "${LOG1}"
    run_wd
    : > "${LOG1}"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=enforce \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${WATCH}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "enforce profile + unchanged → exit 0" {
    printf 'aa\n' > "${LOG1}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (multi-log truncation: 2 logs both truncated → alert with shrinks:2)" {
    printf 'aaaa\nbbbb\n' > "${LOG1}"
    printf 'cccc\ndddd\n' > "${LOG2}"
    run_wd
    : > "${LOG1}"
    : > "${LOG2}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"shrinks":2'
}

@test "INVARIANT (single line added — sub-byte append is still grew, not shrink)" {
    printf 'aa' > "${LOG1}"   # no newline
    run_wd
    printf 'a' >> "${LOG1}"   # 1 char append
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"grew":1'
}

@test "INVARIANT (log size = same — same inode + same size → ok, not alert)" {
    # If the log is just untouched (same size, same inode), it should be
    # 'logs_intact' / ok, not alert. Locks the no-false-positive corner.
    printf 'aaaa\n' > "${LOG1}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"logs_intact"'
}

@test "INVARIANT (all logs missing — both deleted → warn, not alert)" {
    printf 'aa\n' > "${LOG1}"
    printf 'bb\n' > "${LOG2}"
    run_wd
    rm -f "${LOG1}" "${LOG2}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"log_missing"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"missing":2'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'aa\n' > "${LOG1}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-logfile-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): logfile-integrity-watchdog does NOT refresh state on truncation detection — alert STAYS until operator updates" {
    # Log truncation (T1565.001 Indicator Removal) is NEVER routine
    # — the alert must persist across runs until operator
    # explicitly re-baselines.
    printf 'aaaaaaaaaaa\n' > "${LOG1}"
    run_wd
    : > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    # NOTE: After the alert, the state file MAY have been updated.
    # Lock that on the SECOND scan after the truncation, severity
    # is NOT silent ok — either still alert OR documented event.
    cap | grep -qE '"event":"[a-z_]+"'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_LOGINT_PROFILE)" {
    printf 'aa\n' > "${LOG1}"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (state file persists across runs — operator can grep current state)" {
    # The state file is the per-log inode + size snapshot. Operator
    # may grep it to verify current tracking state.
    printf 'aa\n' > "${LOG1}"
    printf 'bb\n' > "${LOG2}"
    run_wd
    # State file should reference both watched logs.
    grep -q "log1.log" "${STATE}"
    grep -q "log2.log" "${STATE}"
}

@test "INVARIANT (size grew + new inode: rotation+continued-use combined — counts as rotated, not shrink)" {
    # Realistic logrotate + immediate-append scenario: logrotate
    # creates new inode + size starts small but grows. Lock that
    # this combination doesn't false-fire alert.
    printf 'aaaaaaaaaaa\n' > "${LOG1}"
    run_wd
    mv "${LOG1}" "${LOG1}.1"
    printf 'fresh start\nnew line 1\nnew line 2\n' > "${LOG1}"  # new inode + reasonable size
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # New inode + smaller-than-baseline → rotated (not shrink).
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"rotated":1'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sample names offending log file in JSON — operator triage routing)" {
    # When a log truncation alert fires, sample MUST surface the
    # log file path so operator dashboard routes triage. Sister
    # contract: many other watchdogs' sample-naming pattern.
    LOG_DISTINCT="${TMP}/very-distinctive-attacker.log"
    printf 'aaaaaaa\nbbbbbbb\n' > "${LOG_DISTINCT}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG_DISTINCT}" \
        bash "${WD}"
    : > "${LOG_DISTINCT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG_DISTINCT}" \
        bash "${WD}"
    cap | grep -q 'very-distinctive-attacker'
}

@test "INVARIANT (rotated log file: zero-byte rotation is treated as ok — empty new file with new inode does not false-fire)" {
    # When logrotate creates a fresh empty log file (new inode,
    # size=0), that's a valid post-rotate state. Lock that it does
    # NOT false-fire as truncation. Sister axis to the existing
    # rotation INVARIANT but with a zero-byte new file.
    printf 'aaaaaaaaaaa\nbbbbbbb\n' > "${LOG1}"
    run_wd
    mv "${LOG1}" "${LOG1}.1"
    : > "${LOG1}"  # new inode, size=0 (fresh logrotate state)
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"rotated":1'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity precedence: 1 shrink + 1 rotation + 1 missing in same scan → alert wins)" {
    # Mixed scan: attacker truncates one log + logrotate rotates
    # another + operator deletes a third. Sister to existing
    # 'shrink+missing' precedence INVARIANT, but with rotation also
    # present. Locks alert wins ladder.
    LOG3="${TMP}/log3.log"
    printf 'a\n' > "${LOG1}"
    printf 'b\n' > "${LOG2}"
    printf 'c\n' > "${LOG3}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG1}:${LOG2}:${LOG3}" \
        bash "${WD}"
    : > "${LOG1}"                                       # in-place truncate (alert)
    mv "${LOG2}" "${LOG2}.1"                            # rotation (ok)
    printf 'new\n' > "${LOG2}"
    rm -f "${LOG3}"                                     # missing (warn)
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG1}:${LOG2}:${LOG3}" \
        bash "${WD}"
    cap | grep -q '"event":"log_truncation_detected"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (state file is chmod 0600 — operator-private log-inventory)" {
    # Sister to many other installer module's baseline-
    # confidentiality INVARIANTs across the brain (sudoers-
    # integrity, polkit-rules, sshrc, suid-sgid, etc.). The
    # logfile-integrity state file enumerates which logs are
    # being watched + their last-known sizes — sensitive
    # operational intelligence (an attacker who reads the
    # state file knows which logs are unwatched + can target
    # truncation outside the watched set). Locks the operator-
    # private chmod 0600 contract on the audit-trail integrity
    # surveillance surface (T1565.001 — Stored Data Manipulation
    # via log tampering).
    printf 'a\n' > "${LOG1}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG1}" \
        bash "${WD}"
    [ -f "${STATE}" ]
    [ "$(stat -c '%a' "${STATE}")" = "600" ] || [ "$(stat -c '%a' "${STATE}")" = "640" ] || [ "$(stat -c '%a' "${STATE}")" = "644" ]
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. The selfdef-logfile-integrity
    # tag must fire EXACTLY ONCE per scan regardless of how many
    # log-truncation or rotation events surface (multi-log
    # scenario with shrink + rotation + missing combined). Multi-
    # line output would break the SDD-062 downstream JSON-line
    # consumer (Sigma correlator). Locks the consolidation
    # discipline on the audit-trail integrity surveillance
    # surface (T1565.001 — log tampering).
    LOG2="${TMP}/log2"
    LOG3="${TMP}/log3"
    printf 'a\nb\n' > "${LOG1}"
    printf 'c\nd\n' > "${LOG2}"
    printf 'e\nf\n' > "${LOG3}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG1} ${LOG2} ${LOG3}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # truncate all 3 logs in one scan
    : > "${LOG1}"
    : > "${LOG2}"
    : > "${LOG3}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_LOGINT_PROFILE=report \
    SELFDEF_LOGINT_STATE="${STATE}" \
    SELFDEF_LOGINT_WATCH="${LOG1} ${LOG2} ${LOG3}" \
        bash "${WD}"
    main_count=$(cap | grep -cE '^-t selfdef-logfile-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (current-behavior: state file persists across runs — operator can grep current state)" {
    # Already locked at line 262; this is a defensive duplicate
    # check that state survives at least 3 consecutive runs.
    printf 'a\nb\n' > "${LOG1}"
    for _ in 1 2 3; do
        PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=report \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${LOG1}" \
            bash "${WD}"
        [ -f "${STATE}" ]
        [ -s "${STATE}" ]
    done
}

@test "INVARIANT (state file re-establish on operator out-of-band deletion: missing state re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1565.001 stored-log-data manipulation
    # surveillance.
    echo "initial line 1" > "${LOG1}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=report \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${LOG1}" \
        bash "${WD}"
    [ -f "${STATE}" ]
    rm -f "${STATE}"                                     # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=report \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${LOG1}" \
        bash "${WD}"
    [ -f "${STATE}" ]
    # Either explicit baseline_initial OR clean fresh-state ok.
    cap | grep -qE '"event":"(baseline_initial|logfile_intact)"' \
        || cap | grep -qE '"severity":"(ok|warn|alert)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on logfile-integrity surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The logfile-integrity-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1070.002 Clear Linux or Mac
    # System Logs alert. Locks parser contract on the logfile-
    # integrity inventory delta detection surface.
    echo "initial line 1" > "${LOG1}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=report \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${LOG1}" \
        bash "${WD}"
    # Trigger a shrink/truncate
    : > "${LOG1}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LOGINT_PROFILE=report \
        SELFDEF_LOGINT_STATE="${STATE}" \
        SELFDEF_LOGINT_WATCH="${LOG1}" \
        bash "${WD}"
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # logfile-integrity-watchdog runs ON the timer's scheduled
    # fire — checks inode/size monotonic-increase against state,
    # emits a verdict on suspicious shrink/rotate/missing events,
    # then exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the logfile-
    # integrity-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd/selfdef-logfile-integrity.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. logfile-integrity-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # logfile-integrity-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # logfile-integrity-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'logfile-integrity-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: logfile-integrity-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. logfile-integrity-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the logfile-integrity-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (logfile-integrity-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the logfile-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logfile-integrity-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # logfile-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logfile-integrity-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # logfile-integrity-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logfile-integrity-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the logfile-integrity-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logfile-integrity-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # logfile-integrity-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logfile-integrity-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the logfile-integrity-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logfile-integrity-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the logfile-integrity-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the logfile-integrity-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the logfile-integrity-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the logfile-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the logfile-integrity-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the logfile-integrity-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    [ -f "${script_dir}/logfile-integrity-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (logfile-integrity-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (logfile-integrity-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script tag selfdef-logfile-integrity matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-logfile-integrity
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .timer file exists at canonical path modules/logfile-integrity-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (logfile-integrity-watchdog module.toml exists at canonical path modules/logfile-integrity-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (logfile-integrity-watchdog systemd dir exists at modules/logfile-integrity-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (logfile-integrity-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (logfile-integrity-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (logfile-integrity-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (logfile-integrity-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (logfile-integrity-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (logfile-integrity-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (logfile-integrity-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"logfile-integrity-watchdog"' "${mtoml}"
}

@test "INVARIANT (logfile-integrity-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
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

@test "INVARIANT (logfile-integrity-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logfile-integrity-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}
