#!/usr/bin/env bats
# L2 bats functional tests for the ssh-client-config-watchdog scan script.
#
# A system/root ssh client config can run a program on every outbound ssh:
#   ProxyCommand /tmp/.x %h %p        (runs to set up the connection)
#   LocalCommand /tmp/.x              (runs after connect; needs
#                                      PermitLocalCommand yes)
#   Match exec "/tmp/.probe"          (runs to decide the match)
# A directive whose program is under a writable root, relative-with-slash,
# or carries an injection pattern is alert. Bare PATH-resolved commands
# (nc, corkscrew, cloudflared) are normal and not flagged.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_SSHCLIENT_FILE / _D / _ROOT.
#
# Run with: bats packaging/test/L2-ssh-client-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/systemd/ssh-client-config-watchdog.sh"
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
    CONF="${TMP}/ssh_config"
    CONFD="${TMP}/ssh_config.d"; mkdir -p "${CONFD}"
    NOROOT="${TMP}/nonexistent-root-config"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SSHCLIENT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SSHCLIENT_BASELINE="${BASELINE}" \
    SELFDEF_SSHCLIENT_FILE="${CONF_F:-$CONF}" \
    SELFDEF_SSHCLIENT_D="${CONFD}" \
    SELFDEF_SSHCLIENT_ROOT="${NOROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no ssh client config → ok / no_ssh_client_config" {
    CONF_F="${TMP}/nonexistent" CONFD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_ssh_client_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign ProxyCommand, first run → ok / baseline_initial" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / ssh_client_config_intact" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ssh_client_config_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "ProxyCommand under a writable root → alert / ssh_client_config_exec_directive" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'Host *\n    ProxyCommand /tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ssh_client_config_exec_directive"'
    cap | grep -q '"severity":"alert"'
}

@test "LocalCommand under /dev/shm → alert" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    PermitLocalCommand yes\n    LocalCommand /dev/shm/x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "Match exec with a writable target → alert" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Match host *.internal exec "/tmp/.probe"\n    User root\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash ProxyCommand → alert" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand ./rel/x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign directive change → warn / ssh_client_config_changed" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /usr/bin/nc -X5 %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ssh_client_config_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a bare PATH-resolved ProxyCommand (corkscrew) is NOT flagged" {
    printf 'Host *.internal\n    ProxyCommand corkscrew proxy 8080 %%h %%p\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious directive" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — ssh-client inventory enumerates outbound-ssh exec surface)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (ProxyCommand under /var/tmp): writable-root expansion" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /var/tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LocalCommand under /tmp — symmetric axis to ProxyCommand)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    PermitLocalCommand yes\n    LocalCommand /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Match exec under /var/tmp): writable-root on Match-exec axis" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Match host *.internal exec "/var/tmp/.probe"\n    User root\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (config in ssh_config.d also scanned — not only the main file)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /tmp/.dropin-attacker %%h %%p\n' > "${CONFD}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable ssh_config → alert)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ssh-client-config -- ')
    [ "${main_count}" = "1" ]
}
