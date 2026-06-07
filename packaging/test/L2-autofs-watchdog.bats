#!/usr/bin/env bats
# L2 bats functional tests for the autofs-watchdog scan script.
#
# Covers the mount-access exec trigger class: autofs runs a `program:`
# map (or an executable map file) AS ROOT to generate mount entries when
# the autofs mountpoint is accessed. A master-map line is
# `<mountpoint> <map> [options]`; the map may be `program:/path` (execed),
# a `/path` map file (run as root if executable), or a network/file map
# (yp:/ldap:/file:, no local exec). A planted program: map or a writable
# executable map file is mount-access-triggered root code execution
# (T1546), fired on demand by anyone who can stat/cd the mountpoint.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# master map + baseline in a tmp sandbox via SELFDEF_AUTOFS_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-autofs-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd/autofs-watchdog.sh"
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
    CONF="${TMP}/auto.master"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_AUTOFS_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUTOFS_BASELINE="${BASELINE}" \
    SELFDEF_AUTOFS_DIRS="${EMPTY}" \
    SELFDEF_AUTOFS_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no autofs master map present → ok / no_autofs" {
    run_wd
    cap | grep -q '"event":"no_autofs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign program + network maps, first run → ok / baseline_initial" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n/net -hosts\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / autofs_intact" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"autofs_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "program: map under a writable root → alert" {
    printf '/mnt/x program:/tmp/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative program: map → alert" {
    printf '/mnt/x program:sub/dir/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "absolute map file under a writable root → alert" {
    printf '/mnt/x /var/tmp/maps/auto.x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign entry added after baseline → warn / autofs_changed" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    printf '/mnt/data program:/usr/sbin/auto.smb\n/mnt/more program:/usr/sbin/auto.net\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"autofs_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "program: map under /usr/sbin is NOT flagged (no alert)" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a network (yp:) map is NOT flagged" {
    printf '/home/guests yp:auto.home\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable program: map is NOT flagged" {
    printf '# /mnt/x program:/tmp/evil.sh\n/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '/mnt/x program:/tmp/evil.sh\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — autofs inventory enumerates mount-access-trigger root-exec surface)" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (program: map under /var/tmp): writable-root expansion" {
    printf '/mnt/x program:/var/tmp/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (program: map under /dev/shm): tmpfs writable-root coverage" {
    printf '/mnt/x program:/dev/shm/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (program: map under /home): user-writable hijack coverage" {
    printf '/mnt/x program:/home/user/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (absolute map file under /tmp): map-file axis writable-root expansion" {
    printf '/mnt/x /tmp/maps/auto.x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (absolute map file under /dev/shm): map-file axis tmpfs coverage" {
    printf '/mnt/x /dev/shm/maps/auto.x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ldap: map is NOT flagged — network map axis): network-map false-positive guard" {
    # ldap: maps (like yp:) are non-local-exec; they shouldn't false-fire.
    printf '/home/guests ldap:auto.home\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (file: map is NOT flagged): file: prefix is non-exec lookup" {
    printf '/home/guests file:/etc/auto.home\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-autofs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): autofs-watchdog does NOT refresh baseline on suspicious-map detection — alert STAYS until operator updates" {
    # T1546 mount-access-triggered root-exec persistence — suspicious-
    # map alert MUST persist across runs until operator explicitly
    # re-baselines. Sister to every other no-auto-trust persistence
    # INVARIANT across the brain (sshrc, cron-job, anacrontab,
    # bash-completion, shell-init, apt-hooks, auditd-plugins).
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    printf '/mnt/x program:/tmp/evil.sh\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (config-layer-noise resilience: extra master-map directives do NOT bypass program: detection)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. autofs master map supports per-
    # entry options after the map (e.g., --timeout=60, --ghost,
    # -browse). Operator may add these forward-compat options;
    # parser must tolerate without altering the program: detection.
    # program-with-noise still alerts (writable-root program path
    # surfaces regardless of surrounding option flags).
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/mnt/x program:/tmp/evil.sh --timeout=60 --ghost -browse\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named master-map entry surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a new
    # autofs master-map entry pointing at a writable program map,
    # the entry detail MUST surface in the JSON sample so
    # operator dashboard routes triage to the right path. Locks
    # the new-entry-discovered operator-visibility contract on
    # the autofs program-map root-exec persistence surface (T1546
    # — autofs runs program-map scripts AS ROOT on every mount
    # request).
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/mnt/distinctive-attacker-mount program:/tmp/.distinctive-attacker-evil\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "INVARIANT (program: map under /var/tmp — writable-root axis-symmetric expansion on autofs map surface)" {
    # Sister to /tmp + /dev/shm + /home program: map writable-root
    # INVARIANTs already locked. /var/tmp is writable by ALL users
    # (sticky-bit doesn't gate exec-from-it) and persists across
    # reboots (unlike /tmp /dev/shm tmpfs). Attackers prefer it
    # for boot-survival persistence. The autofs program-map
    # scanner MUST recognize /var/tmp paths just as firmly as the
    # /tmp + /dev/shm family — locks tmpfs-vs-persistent writable-
    # root axis symmetry on the T1546 autofs program-map root-exec
    # persistence surface.
    printf '/mnt/data program:/var/tmp/.auto.smb\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    printf '/mnt/a program:/tmp/.evil1\n/mnt/b program:/var/tmp/.evil2\n/mnt/c program:/home/x/.evil3\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-autofs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (program: map under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on autofs map surface)" {
    # Sister to /home + /var/tmp + /tmp program: map writable-
    # root INVARIANTs. /dev/shm tmpfs in-RAM writable-root that
    # survives no on-disk forensic trace. autofs invokes program
    # map AS ROOT for each automount trigger; planted attacker
    # binary in /dev/shm fires AS ROOT on every mount-attempt.
    # T1546 autofs program-map root-exec persistence.
    printf '/mnt/data program:/dev/shm/.auto.evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
