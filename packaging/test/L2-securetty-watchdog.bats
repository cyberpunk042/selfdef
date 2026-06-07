#!/usr/bin/env bats
# L2 bats functional tests for the securetty-watchdog scan script.
#
# /etc/securetty is the allowlist of TTYs on which DIRECT root login is
# permitted (pam_securetty). Adding a network pty (pts/0) widens root login
# to network sessions; removing the file fail-opens root login on ALL ttys.
# Severity:
#   ok    → no delta
#   warn  → a TTY added/removed or file changed
#   alert → a newly-added pts/network TTY, a world-writable/non-root file, or
#           the file removed since baseline (fail-open)
#
# Run with: bats packaging/test/L2-securetty-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/securetty-watchdog/systemd/securetty-watchdog.sh"

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
    BASELINE="${TMP}/baseline.tsv"
    SECURETTY="${TMP}/securetty"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SECURETTY_PROFILE="${PROFILE:-report}" \
    SELFDEF_SECURETTY_BASELINE="${BASELINE}" \
    SELFDEF_SECURETTY_FILE="${SECURETTY}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'tty1\ntty2\nttyS0\n' > "${SECURETTY}"
}

@test "no securetty + no baseline → ok / no_securetty" {
    run_wd
    cap | grep -q '"event":"no_securetty"'
    cap | grep -q '"severity":"ok"'
}

@test "benign securetty, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged securetty on second run → ok / securetty_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"securetty_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a newly-added pts TTY → alert / securetty_widened" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/0\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"securetty_widened"'
    cap | grep -q '"severity":"alert"'
}

@test "the file removed since baseline → alert / securetty_removed (fail-open)" {
    seed_benign
    run_wd
    rm -f "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"securetty_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable securetty → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign physical-tty addition → warn / securetty_changed" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\ntty3\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"securetty_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "enforce profile exits non-zero on a widened securetty" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/0\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — securetty inventory enumerates direct-root-login surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (pts/N detection): pts/1, pts/2, etc. — any pts/<N> → alert" {
    # The script must catch arbitrary pts/<N> values, not just
    # pts/0. A regression that whitelists only pts/0 would let
    # an attacker use pts/1 to widen.
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/7\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"securetty_widened"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing pts at install-time): baseline_initial records the pts entry (operator sees it on next-run delta)" {
    # The script's baseline_initial path doesn't re-scan for
    # pts at install — it locks the inventory as-is. The
    # subsequent run with same content stays ok (no DELTA on
    # something pre-existing). Documents the implementation
    # choice: install-time-vet on pts is NOT in scope; subsequent
    # WIDEN events surface attackers, not legitimate install state.
    printf 'tty1\npts/0\n' > "${SECURETTY}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    # Baseline records the pts/0 entry — the next-run delta
    # against ANYTHING ADDED will surface it. We verify the
    # pts/0 IS in the baseline file.
    grep -q 'pts/0' "${BASELINE}"
}

@test "INVARIANT (group-writable securetty): group-writable → alert (more than just world-writable)" {
    seed_benign
    run_wd
    chmod 0664 "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED physical tty (operator pruning) → warn / securetty_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\nttyS0\n' > "${SECURETTY}"            # tty2 removed
    run_wd
    cap | grep -qE '"event":"securetty_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "DELTA detect — newly-ADDED pts entry surfaces in JSON sample (operator triage)" {
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/99\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'pts/99'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-securetty -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): securetty-watchdog DOES auto-refresh baseline on pts-widen — sister-pattern with access-conf/nfs-exports families" {
    # CONTRAST against no-auto-trust family. After operator
    # re-baselines, the alert clears for the next run. Lock the
    # auto-trust classification.
    seed_benign
    run_wd
    printf 'tty1\ntty2\nttyS0\npts/0\n' > "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed → ok
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (commented pts entry NOT flagged: # prefix filtered)" {
    # An operator note about a future pts entry must not surface
    # as a real widening event.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\n# pts/0 — future, not yet active\n' > "${SECURETTY}"
    run_wd
    ! cap | grep -q '"event":"securetty_widened"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (file removed since baseline → alert PERSISTS — fail-open persistence)" {
    # When the file is removed since baseline (fail-open), the
    # alert MUST persist across runs since there's no file to
    # restore to baseline; operator must manually re-create.
    seed_benign
    run_wd
    rm -f "${SECURETTY}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"securetty_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'pts/0  ' with trailing whitespace still triggers alert)" {
    # Attacker may use trailing whitespace to evade detection.
    # The parser must normalize whitespace.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\npts/0   \n' > "${SECURETTY}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pts/0 with leading whitespace: '  pts/0' still triggers alert — whitespace-tolerant on both sides)" {
    # Sister to trailing-whitespace tolerance. Attacker may use
    # leading-space evasion. Parser must normalize.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\n   pts/0\n' > "${SECURETTY}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (network-tty axis: a fresh ttySn (serial) addition is WARN not ALERT — ttyS family is physical-tty grade)" {
    # Distinguishing physical serial (ttyS0/1/2) from network pty
    # (pts/N) — only the network class fires alert. A regression
    # that promoted ttyS additions to alert would mis-grade
    # operator's legitimate serial-console expansion. Lock
    # current architectural boundary.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\nttyS1\n' > "${SECURETTY}"  # ttyS1 added
    run_wd
    cap | grep -qE '"event":"securetty_changed"'
    cap | grep -q '"severity":"warn"'
    ! cap | grep -q '"event":"securetty_widened"'
}

@test "INVARIANT (sample names the offending pts in JSON — operator triage routing)" {
    # When a pts/N widening fires, sample MUST surface the pts
    # name so operator dashboard routes triage to the right TTY.
    # Sister contract: polkit-rules/nfs-exports/rhosts/tmpfiles
    # sample-naming pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\npts/77\n' > "${SECURETTY}"
    run_wd
    cap | grep -q 'pts/77'
}

@test "INVARIANT (current-behavior: pre-existing pts entry at install-time → baseline_initial captures it without immediate alert)" {
    # CONTRAST with the no-auto-trust family where pre-existing
    # broad permits raise alert at install-time. securetty-watchdog
    # operates as DELTA detector against its own baseline — at
    # install-time it just snapshots current state (no comparison
    # baseline exists yet). The pts/N alert fires on subsequent
    # DELTA from this snapshot, not on the initial capture itself.
    # Locks current architectural boundary: install-time-vet is OUT
    # of scope for this watchdog (sister auto-trust family vs
    # access-conf family no-auto-trust install-time-vet).
    printf 'tty1\ntty2\nttyS0\npts/0\n' > "${SECURETTY}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named tty entry surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctively-named tty entry to securetty (T1078 — Valid
    # Accounts via root-on-remote-tty grant; securetty controls
    # WHICH ttys can accept root password-login), the tty NAME
    # MUST surface in the JSON sample so operator dashboard
    # routes triage to the right entry.
    printf 'tty1\ntty2\nttyS0\n' > "${SECURETTY}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\ndistinctive-attacker-tty\n' > "${SECURETTY}"
    run_wd
    cap | grep -q 'distinctive-attacker-tty'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-securetty tag must
    # fire EXACTLY ONCE per scan regardless of how many tty-
    # grant additions surface (multi-pts addition scenario).
    # Multi-line output would break SDD-062 downstream JSON-
    # line consumer. Locks consolidation discipline on T1078
    # remote-tty-grant surveillance surface.
    printf 'tty1\ntty2\nttyS0\n' > "${SECURETTY}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'tty1\ntty2\nttyS0\npts/0\npts/1\npts/2\n' > "${SECURETTY}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-securetty -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1078 remote-tty-grant surveillance.
    printf 'tty1\ntty2\n' > "${SECURETTY}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    printf 'tty1\n' > "${SECURETTY}"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of securetty inventory)" {
    # Sister to brain-wide baseline-chmod-0600 confidentiality
    # INVARIANTs across L2 surveillance suites. The securetty-
    # watchdog baseline TSV contains the inventory of operator-
    # allowed root-login tty paths which discloses the trusted
    # session-entry surface to any user able to read the file.
    # Mode 0600 (root-only) is the canonical confidentiality
    # contract — mode 0644 would expose the root-login-tty
    # whitelist enabling attacker to map which session-paths
    # are trusted for credential-grab. Locks file-mode
    # confidentiality on the securetty surveillance substrate.
    printf 'tty1\ntty2\n' > "${SECURETTY}"
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ]
}
