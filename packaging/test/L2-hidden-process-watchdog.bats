#!/usr/bin/env bats
# L2 functional suite for hidden-process-watchdog.
#
# hidden-process-watchdog detects processes hidden from /proc readdir by
# a userland or LKM rootkit. It builds two PID sets:
#   visible = readdir(/proc) → what ps/ls see
#   alive   = direct stat /proc/<pid> across the full PID range
# The set-difference (alive \ visible) is the hidden set. This is the
# two-temp-file pattern (NOT the canonical `current=$(mktemp)` comm-delta
# idiom every watchdog under SDD-063 uses), and the L2-scan-script-capture
# guard correctly skips it at gate-1 (no `current=` declaration). That
# means the structural-correctness invariant is NOT auto-enforced for
# this watchdog — this suite is the only regression lock on its
# enumeration/emission shape.
#
# Coverage (every assertion locks a specific behavior of a real script
# refactor that could silently break the rootkit-detection path):
#   - PROBE_CAP=0 trims the alive-set probe to empty → n_hidden==0
#     regardless of visible-set content. Locks the bound-respect.
#   - Steady-state run on the test host has no hidden processes
#     (cap=200 PIDs, well under typical lowest live PID density).
#     Locks the no-detection emission shape.
#   - JSON contains every promised field: tag / severity / event /
#     profile / pids_visible / pids_alive / hidden / probe_max /
#     hidden_sample. Locks the emission schema observability consumes.
#   - enforce profile + no hidden processes → exit 0. Locks the
#     enforce-doesn't-spuriously-fail invariant.
#
# Run with: bats packaging/test/L2-hidden-process-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/hidden-process-watchdog/systemd/hidden-process-watchdog.sh"

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
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    # Keep the alive-probe bounded so the test runs in <1s. 200 is well
    # under typical first-live-PID density on Linux (PID 1=init), so
    # alive-set will be non-empty in normal hosts and empty when
    # PROBE_CAP=0 is passed.
    PATH="${BIN}:${PATH}" \
    SELFDEF_HIDDENPROC_PROFILE="${PROFILE:-report}" \
    SELFDEF_HIDDENPROC_CAP="${PROBE_CAP:-200}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "steady-state run on the test host emits ok / no_hidden_process" {
    run_wd
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"no_hidden_process"'
}

@test "the emitted JSON carries every promised schema field" {
    run_wd
    line="$(cap)"
    # Every field the SDD-062-style downstream consumer expects.
    printf '%s' "${line}" | grep -q '"tag":"selfdef-hidden-process"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"pids_visible":[0-9]+'
    printf '%s' "${line}" | grep -qE '"pids_alive":[0-9]+'
    printf '%s' "${line}" | grep -qE '"hidden":[0-9]+'
    printf '%s' "${line}" | grep -qE '"probe_max":[0-9]+'
    printf '%s' "${line}" | grep -q '"hidden_sample":'
}

@test "PROBE_CAP=0 trims the alive-set probe → hidden==0 regardless of visible-set" {
    PROBE_CAP=0 run_wd
    # With PROBE_CAP=0 the for-loop runs zero iterations → alive empty →
    # `comm -13 visible alive` = "" (nothing in alive that isn't in visible)
    # → hidden==0. Locks that the probe bound is respected.
    cap | grep -qE '"hidden":0'
    cap | grep -qE '"pids_alive":0'
    cap | grep -q '"event":"no_hidden_process"'
}

@test "enforce profile with no hidden processes → exit 0" {
    PROFILE=enforce run_wd
    # No assertion needed beyond the lack of bats-failure: bats fails
    # the test if the run_wd helper exits non-zero. Locks that the
    # enforce branch doesn't fire-and-exit-non-zero on a clean host.
    cap | grep -q '"severity":"ok"'
}
