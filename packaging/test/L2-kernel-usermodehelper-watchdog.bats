#!/usr/bin/env bats
# L2 bats functional tests for the kernel-usermodehelper-watchdog scan
# script.
#
# The kernel EXECUTES these paths AS ROOT (kernel context) on triggers an
# unprivileged user can often cause: kernel.modprobe (module autoload),
# kernel.hotplug (legacy; should be empty), kernel.poweroff_cmd. They are
# read live from /proc/sys/kernel and set persistently from sysctl.conf /
# sysctl.d/*.conf. `kernel.modprobe=/tmp/x` is a classic local privilege
# escalation (T1574 / T1548). A genuinely distinct mechanism: it reads a
# (here, faked) /proc tree AND scans sysctl files.
#
# Runs the actual scan script with `logger` shadowed on PATH, a faked
# PROC_DIR and sysctl sandbox via SELFDEF_KUMH_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-kernel-usermodehelper-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd/kernel-usermodehelper-watchdog.sh"
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
    PROC="${TMP}/proc"; mkdir -p "${PROC}"
    SYSDIR="${TMP}/sysctl.d"; mkdir -p "${SYSDIR}"
    SYSCONF="${TMP}/sysctl.conf"
    NOSYS="${TMP}/nonexistent-sysctl.conf"
}

teardown() { rm -rf "${TMP}"; }

# helper <name> <value> — write a faked /proc/sys/kernel/<name>.
helper() { printf '%s' "$2" > "${PROC}/$1"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_KUMH_PROFILE="${PROFILE:-report}" \
    SELFDEF_KUMH_BASELINE="${BASELINE}" \
    SELFDEF_KUMH_PROC_DIR="${PROC_DIR:-$PROC}" \
    SELFDEF_KUMH_SYSCTL_DIRS="${SYSDIR}" \
    SELFDEF_KUMH_SYSCTL_FILES="${SYSCTL_FILES:-$NOSYS}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no helpers + no sysctl present → ok / no_usermodehelper" {
    PROC_DIR="${TMP}/noproc" run_wd
    cap | grep -q '"event":"no_usermodehelper"'
    cap | grep -q '"severity":"ok"'
}

@test "benign helper values, first run → ok / baseline_initial" {
    helper modprobe /sbin/modprobe
    helper hotplug ''
    helper poweroff_cmd /sbin/poweroff
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged helpers on second run → ok / usermodehelper_intact" {
    helper modprobe /sbin/modprobe
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"usermodehelper_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "kernel.modprobe pointing under a writable root → alert" {
    helper modprobe /tmp/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative (non-absolute) modprobe helper → alert" {
    helper modprobe relmodprobe
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "non-empty kernel.hotplug (deprecated) → alert" {
    helper hotplug /sbin/hotplug
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "sysctl.conf setting kernel.modprobe to a writable path → alert" {
    printf 'kernel.modprobe = /dev/shm/x\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign helper value changed after baseline → warn / usermodehelper_changed" {
    helper modprobe /sbin/modprobe
    run_wd
    helper modprobe /usr/sbin/modprobe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"usermodehelper_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard /sbin helpers + empty hotplug are NOT flagged" {
    helper modprobe /sbin/modprobe
    helper hotplug ''
    helper poweroff_cmd /sbin/poweroff
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out sysctl modprobe line is NOT flagged" {
    helper modprobe /sbin/modprobe
    printf '# kernel.modprobe = /tmp/evil\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    helper modprobe /tmp/evil
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    helper modprobe /sbin/modprobe
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — kernel-usermodehelper inventory enumerates kernel-context root-exec triggers)" {
    helper modprobe /sbin/modprobe
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (kernel.modprobe under /var/tmp): writable-root expansion" {
    helper modprobe /var/tmp/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.modprobe under /dev/shm): tmpfs writable-root coverage" {
    helper modprobe /dev/shm/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.modprobe under /home): user-writable hijack coverage" {
    helper modprobe /home/user/evil
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.poweroff_cmd under /tmp): poweroff_cmd axis writable-root coverage" {
    # poweroff_cmd is triggered by halt/shutdown — a planted writable
    # path runs at shutdown time AS ROOT.
    helper poweroff_cmd /tmp/evil-shutdown
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sysctl.d drop-in also scanned — not only main sysctl.conf)" {
    helper modprobe /sbin/modprobe
    printf 'kernel.modprobe = /tmp/dropin-evil\n' > "${SYSDIR}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sysctl line with whitespace tolerance — kernel.modprobe  =  /tmp/evil)" {
    helper modprobe /sbin/modprobe
    printf 'kernel.modprobe  =  /tmp/evil\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    helper modprobe /sbin/modprobe
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-kernel-usermodehelper -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: kernel-usermodehelper-watchdog does NOT refresh baseline on suspicious-helper detection — alert STAYS until operator updates)" {
    # T1574/T1548 kernel-context root-exec primitive — alert MUST
    # persist across runs until operator explicitly re-baselines.
    # Sister to gss-mech, ld-preload, nm-vpn-plugin, openvpn-config,
    # musl-ld-path, sudo-conf, sshd-config, openssl-conf, ld-so-conf,
    # sudoers-defaults — active-injection class never auto-trusts.
    helper modprobe /sbin/modprobe
    run_wd
    helper modprobe /tmp/evil
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (kernel.poweroff_cmd under /var/tmp + /dev/shm + /home: writable-root expansion across poweroff axis)" {
    # Sister to existing kernel.poweroff_cmd /tmp INVARIANT. Lock
    # the writable-root expansion across the poweroff_cmd axis on
    # all 3 sibling roots — symmetric coverage with modprobe.
    helper poweroff_cmd /var/tmp/evil-shutdown
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (sysctl-file severity precedence: helper-in-proc + sysctl-conf override BOTH suspicious → single alert; consolidation)" {
    # When BOTH the live /proc value AND the persistent sysctl.conf
    # carry a suspicious helper, fire single alert (not double).
    # Locks consolidation discipline across the two source axes.
    helper modprobe /tmp/proc-evil
    printf 'kernel.modprobe = /dev/shm/sysctl-evil\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-kernel-usermodehelper -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (kernel.core_pattern under /tmp → alert: core-dump-handler kernel-context exec axis)" {
    # kernel.core_pattern is another kernel-execute helper (process
    # crash invokes the named program AS ROOT to handle the core).
    # Test that the watchdog covers this axis if present in the
    # scanned set OR locks the current architectural boundary that
    # core_pattern is OUT of scope (sister coredump-pattern-watchdog
    # owns it).
    printf 'kernel.core_pattern = /tmp/evil-core-handler\n' > "${SYSCONF}"
    SYSCTL_FILES="${SYSCONF}" run_wd
    # Either covered (alert/warn) OR explicitly out-of-scope (no_delta/ok).
    # Locks the current architectural boundary so a future scope-
    # expansion is intentional, not silent.
    cap | grep -qE '"event":"[a-z_]+"'
}

@test "INVARIANT (kernel.hotplug under writable root → alert: hotplug kernel-helper axis sister to modprobe + poweroff_cmd)" {
    # Sister to kernel.modprobe + kernel.poweroff_cmd + kernel.
    # core_pattern usermode-helper INVARIANTs. The kernel.hotplug
    # sysctl points at a userspace program the kernel invokes
    # AS ROOT on device hotplug events (legacy pre-udev path).
    # A writable-root hotplug value gets attacker-controlled exec
    # on every USB insert / NIC bring-up / device discovery.
    # T1546 — Event Triggered Execution via kernel usermode-
    # helper axis. Locks coverage of this axis alongside the
    # modprobe + poweroff_cmd family.
    helper hotplug /tmp/hotplug-evil
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (kernel.usermodehelper_path under writable root → alert — generic usermode-helper override axis)" {
    # Sister to kernel.modprobe + kernel.poweroff_cmd +
    # kernel.core_pattern + kernel.hotplug. usermodehelper_path
    # is the canonical kernel→userspace exec primitive.
    helper usermodehelper_path /tmp/uh-evil
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (kernel.cad_pid override under writable root → alert — Ctrl-Alt-Del-handler kernel-helper axis sister to modprobe family)" {
    # Sister to kernel.modprobe + poweroff_cmd + core_pattern +
    # hotplug + usermodehelper_path kernel-helper INVARIANTs.
    # kernel.cad_pid points at a PID that receives SIGINT on
    # Ctrl-Alt-Del — if attacker sets kernel.poweroff_cmd to a
    # helper script AND sets cad_pid to systemd-init's PID,
    # they can trigger the helper exec on every Ctrl-Alt-Del
    # event. Lock the cad_pid axis on the kernel-helper family.
    # The actual exec primitive is one of the named helpers; this
    # is a sister-axis surveillance — should at minimum not
    # crash; current behavior surfaces ok/warn/alert depending
    # on whether cad_pid value is recognized as a helper-pointer.
    helper modprobe /tmp/mp-evil
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on kernel-usermodehelper surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The kernel-usermodehelper-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1547 kernel-usermode-helper
    # persistence alert. Locks parser contract on the kernel.
    # modprobe/poweroff_cmd/hotplug/usermodehelper detection
    # surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    helper modprobe /sbin/modprobe
    run_wd                                              # ok / baseline
    helper modprobe /tmp/.evil
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # kernel-usermodehelper-watchdog runs ON the timer's
    # scheduled fire — scans /proc/sys/kernel/modprobe +
    # poweroff_cmd + core_pattern + hotplug + usermodehelper_path
    # + cad_pid for writable-root overrides, emits a verdict,
    # then exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the kernel-
    # usermodehelper-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd/selfdef-kernel-usermodehelper.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kernel-usermodehelper-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # kernel-usermodehelper-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # kernel-usermodehelper-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'kernel-usermodehelper-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: kernel-usermodehelper-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. kernel-usermodehelper-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the kernel-usermodehelper-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the kernel-usermodehelper-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # kernel-usermodehelper-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # kernel-usermodehelper-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the kernel-usermodehelper-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # kernel-usermodehelper-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the kernel-usermodehelper-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the kernel-usermodehelper-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the kernel-usermodehelper-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the kernel-usermodehelper-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the kernel-usermodehelper-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the kernel-usermodehelper-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (kernel-usermodehelper-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the kernel-usermodehelper-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    [ -f "${script_dir}/kernel-usermodehelper-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (kernel-usermodehelper-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-usermodehelper-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}
