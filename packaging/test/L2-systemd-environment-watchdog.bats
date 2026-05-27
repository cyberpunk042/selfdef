#!/usr/bin/env bats
# L2 bats functional tests for the systemd-environment-watchdog scan script.
#
# systemd's manager `DefaultEnvironment=` / `ManagerEnvironment=` (in
# system.conf{,.d} / user.conf{,.d}) is injected into the environment of
# EVERY service the manager spawns. An LD_PRELOAD / LD_AUDIT /
# LD_LIBRARY_PATH there loads attacker code into every service (T1574.006),
# and any value pointing under a writable root is suspicious.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# dir in a tmp sandbox via SELFDEF_SYSTEMDENV_DIRS / _FILES.
#
# Run with: bats packaging/test/L2-systemd-environment-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/systemd-environment-watchdog/systemd/systemd-environment-watchdog.sh"

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
    CONFD="${TMP}/system.conf.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/10-env.conf"
    NOFILES="${TMP}/nonexistent.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SYSTEMDENV_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSTEMDENV_BASELINE="${BASELINE}" \
    SELFDEF_SYSTEMDENV_DIRS="${DIRS:-$CONFD}" \
    SELFDEF_SYSTEMDENV_FILES="${NOFILES}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no systemd env config → ok / no_systemd_env" {
    DIRS="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_systemd_env"'
    cap | grep -q '"severity":"ok"'
}

@test "benign DefaultEnvironment, first run → ok / baseline_initial" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8 EDITOR=vi\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / systemd_env_intact" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_env_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "DefaultEnvironment with LD_PRELOAD → alert / systemd_env_suspicious" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf '[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/x.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_env_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "ManagerEnvironment with LD_AUDIT (even at /usr/lib) → alert" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nManagerEnvironment="LD_AUDIT=/usr/lib/a.so"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an env value pointing under a writable root → alert" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nDefaultEnvironment=HELPER=/tmp/x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign env change → warn / systemd_env_changed" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8 PAGER=less\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_env_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "benign LANG/EDITOR env is NOT flagged" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8 EDITOR=vi TERM=xterm\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out LD_PRELOAD line is NOT flagged" {
    printf '[Manager]\n# DefaultEnvironment=LD_PRELOAD=/tmp/x.so\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an LD_PRELOAD injection" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/x.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
