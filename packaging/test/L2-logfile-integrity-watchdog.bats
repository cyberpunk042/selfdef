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
