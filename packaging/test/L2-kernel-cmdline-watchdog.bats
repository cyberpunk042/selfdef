#!/usr/bin/env bats
# L2 functional suite for kernel-cmdline-watchdog.
#
# kernel-cmdline-watchdog snapshots /proc/cmdline at baseline-create
# time and alerts on drift OR on the presence of a known weakening
# flag from a 16-item denylist (mitigations=off, nosmep, nokaslr,
# audit=0, lockdown=none, …). The baseline is a single-line text
# file written via the direct-write idiom (`printf '%s\n' "$cmdline"
# > "$BASELINE"`) — NOT the canonical `cp "$current" "$BASELINE"`
# comm-delta idiom that 94 SDD-063 watchdogs use.
#
# The L2-scan-script-capture guard's chmod-0600 invariant was
# extended 2026-06-06 to cover this direct-write pattern (commit
# 58708bd). This suite locks the runtime behavior the gate's static
# analysis cannot reach: that the chmod actually fires, that the
# baseline content is the actual cmdline, that the emission shape
# carries the schema observability consumes.
#
# Coverage:
#   - First run with no baseline → baseline_initial, chmod 0600,
#     baseline content == current /proc/cmdline.
#   - JSON carries every promised field (tag/severity/event/profile/
#     weakeners_present).
#   - Second run unchanged → ok / cmdline_intact.
#   - Second run with baseline drift simulated → warn / cmdline_changed
#     (locks the changed-path emission).
#   - enforce profile + ok severity → exit 0.
#
# Run with: bats packaging/test/L2-kernel-cmdline-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-cmdline-watchdog/systemd/kernel-cmdline-watchdog.sh"

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
    BASELINE="${TMP}/kernel-cmdline-baseline.txt"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CMDLINE_PROFILE="${PROFILE:-report}" \
    SELFDEF_CMDLINE_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run creates the baseline + chmod 0600 (no inventory leak)" {
    run_wd
    [ -f "${BASELINE}" ]
    cap | grep -q '"event":"baseline_initial"'
    # The structural lock-step: the chmod-0600 invariant the L2 guard
    # checks statically, locked here at runtime.
    perms="$(stat -c '%a' "${BASELINE}")"
    [ "${perms}" = "600" ]
}

@test "the baseline content equals the current /proc/cmdline" {
    run_wd
    expected="$(tr -s ' ' < /proc/cmdline | sed 's/^ //; s/ $//')"
    actual="$(cat "${BASELINE}")"
    [ "${actual}" = "${expected}" ]
}

@test "the emitted JSON carries every promised schema field" {
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-kernel-cmdline"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -q '"weakeners_present":'
}

@test "second run with unchanged cmdline → ok / cmdline_intact" {
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # On a clean host with no weakening flag, second run sees no
    # drift and no weakener → ok / cmdline_intact.
    line="$(cap)"
    case "${line}" in
        *'"event":"cmdline_intact"'*) ;;
        *'"event":"weakening_flag_present"'*)
            # Tolerate this case ONLY when the test host genuinely
            # boots with a denylisted flag (rare in CI / dev hosts).
            # Skip cleanly so the suite doesn't false-fail.
            skip "host /proc/cmdline carries a weakening-flag entry — not a watchdog defect"
            ;;
        *)
            printf 'unexpected event on second-run line: %s\n' "${line}" >&2
            return 1
            ;;
    esac
}

@test "drift simulated via baseline replacement → warn / cmdline_changed" {
    run_wd
    # Overwrite the baseline with a different cmdline that carries
    # NO weakening flag → forces the changed-but-no-weakener path
    # (the warn / cmdline_changed branch).
    printf '%s\n' "BOOT_IMAGE=/vmlinuz-test ro quiet splash" > "${BASELINE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    line="$(cap)"
    # Either warn/cmdline_changed (clean host) or alert/weakening_flag_present
    # (host /proc/cmdline carries a denylisted flag). Both prove the changed-path
    # branched correctly off the baseline replacement.
    printf '%s' "${line}" | grep -qE '"event":"(cmdline_changed|weakening_flag_present|weakening_flag_added)"'
    printf '%s' "${line}" | grep -qE '"changed":1'
}

@test "enforce profile + ok severity → exit 0" {
    run_wd                                    # creates baseline
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd                    # second run, unchanged
    line="$(cap)"
    # enforce on ok must not exit non-zero — locks the enforce-doesn't-
    # spuriously-fail invariant on a clean second run.
    case "${line}" in
        *'"severity":"ok"'*) ;;
        *'"severity":"alert"'*)
            skip "host /proc/cmdline carries a weakening flag — enforce-exit-1 is intended in that case"
            ;;
        *)
            return 1
            ;;
    esac
}
