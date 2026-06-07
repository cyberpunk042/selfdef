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

@test "baseline is chmod 0600 (confidentiality — systemd env inventory enumerates every-service env-injection surface)" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (LD_LIBRARY_PATH → alert): third sibling of LD_PRELOAD + LD_AUDIT" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nDefaultEnvironment=LD_LIBRARY_PATH=/tmp/libs\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LD_PRELOAD even at /usr/lib still triggers — LD_* is itself the signal regardless of location)" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    # /usr/lib is a normal location but LD_PRELOAD set in the
    # MANAGER's environment is itself the attack signature.
    printf '[Manager]\nDefaultEnvironment=LD_PRELOAD=/usr/lib/x.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (env value under /var/tmp): writable-root expansion" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nDefaultEnvironment=HELPER=/var/tmp/x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple confs in conf.d also scanned — both 10-env + 20-extra)" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    # Drop an additional 20-extra.conf with LD_PRELOAD.
    printf '[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/x.so\n' > "${CONFD}/20-extra.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable conf → alert)" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-systemd-env -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): systemd-environment-watchdog does NOT refresh baseline on LD_* injection — alert STAYS until operator updates" {
    # T1574.006 every-service env-injection — LD_* injection alert MUST
    # persist across runs until operator explicitly re-baselines.
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    printf '[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/x.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"systemd_env_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (env value under /dev/shm tmpfs writable-root → alert)" {
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Manager]\nDefaultEnvironment=HELPER=/dev/shm/.attacker\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-config scan: system.conf.d + user.conf.d axes — LD_* in EITHER → alert)" {
    # systemd reads BOTH system.conf.d/* AND user.conf.d/*.
    # Attacker may plant in either. Lock multi-dir axis.
    USERCONFD="${TMP}/user.conf.d"; mkdir -p "${USERCONFD}"
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    DIRS="${CONFD} ${USERCONFD}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant LD_PRELOAD in user.conf.d.
    printf '[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/evil.so\n' > "${USERCONFD}/10-user-env.conf"
    DIRS="${CONFD} ${USERCONFD}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'DefaultEnvironment    =    LD_PRELOAD=...' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces around = to evade naive grep.
    # Lock whitespace-tolerant parser.
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Manager]\nDefaultEnvironment    =    LD_PRELOAD=/tmp/x.so\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (LD_AUDIT injection — sister axis to LD_PRELOAD on the dynamic-linker family)" {
    # Sister to the LD_PRELOAD injection axis already locked.
    # LD_AUDIT loads an "audit library" into every dynamically-
    # linked process — equally powerful as LD_PRELOAD for global
    # in-process code execution but historically less monitored
    # (attackers prefer LD_AUDIT to evade LD_PRELOAD detectors).
    # Locks coverage of the full ld.so dynamic-loader env-injection
    # family on the systemd manager DefaultEnvironment surface
    # (T1574.006 every-service env-injection).
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Manager]\nDefaultEnvironment=LD_AUDIT=/tmp/x.so\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (LD_LIBRARY_PATH injection — sister axis to LD_PRELOAD/LD_AUDIT on dynamic-linker family)" {
    # Sister to LD_PRELOAD + LD_AUDIT axes already locked.
    # LD_LIBRARY_PATH prepends attacker-controlled paths to the
    # library search order — soname collisions (e.g. shipping a
    # malicious libc.so.6 in the named path) hijack every dyn-
    # linked invocation. Equally powerful as LD_PRELOAD for
    # global code execution. Locks the third axis of the ld.so
    # dynamic-loader env-injection family on the systemd manager
    # DefaultEnvironment surface (T1574.006 every-service env-
    # injection).
    printf '[Manager]\nDefaultEnvironment=LANG=en_US.UTF-8\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Manager]\nDefaultEnvironment=LD_LIBRARY_PATH=/tmp/evil-libs\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
