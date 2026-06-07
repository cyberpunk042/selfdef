#!/usr/bin/env bats
# L2 bats functional tests for the autofs-watchdog scan script.
#
# Covers the mount-access exec trigger class: autofs runs a `program:`
# map (or an executable map file) AS ROOT to generate mount entries when
# the autofs mountpoint is accessed. A master-map line is
# `<mountpoint> <map> [options]`; the map may be `program:/path` (execed),
# a `/path` map file (run as root if executable), or a network/file map
# (yp:/ldap:/file:, no local exec). A planted program: map or a writable
# executable map file is mount-access-triggered root code execution
# (T1546), fired on demand by anyone who can stat/cd the mountpoint.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# master map + baseline in a tmp sandbox via SELFDEF_AUTOFS_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-autofs-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd/autofs-watchdog.sh"
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
    CONF="${TMP}/auto.master"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_AUTOFS_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUTOFS_BASELINE="${BASELINE}" \
    SELFDEF_AUTOFS_DIRS="${EMPTY}" \
    SELFDEF_AUTOFS_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no autofs master map present → ok / no_autofs" {
    run_wd
    cap | grep -q '"event":"no_autofs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign program + network maps, first run → ok / baseline_initial" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n/net -hosts\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / autofs_intact" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"autofs_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "program: map under a writable root → alert" {
    printf '/mnt/x program:/tmp/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative program: map → alert" {
    printf '/mnt/x program:sub/dir/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "absolute map file under a writable root → alert" {
    printf '/mnt/x /var/tmp/maps/auto.x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign entry added after baseline → warn / autofs_changed" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    printf '/mnt/data program:/usr/sbin/auto.smb\n/mnt/more program:/usr/sbin/auto.net\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"autofs_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "program: map under /usr/sbin is NOT flagged (no alert)" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a network (yp:) map is NOT flagged" {
    printf '/home/guests yp:auto.home\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable program: map is NOT flagged" {
    printf '# /mnt/x program:/tmp/evil.sh\n/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '/mnt/x program:/tmp/evil.sh\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — autofs inventory enumerates mount-access-trigger root-exec surface)" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (program: map under /var/tmp): writable-root expansion" {
    printf '/mnt/x program:/var/tmp/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (program: map under /dev/shm): tmpfs writable-root coverage" {
    printf '/mnt/x program:/dev/shm/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (program: map under /home): user-writable hijack coverage" {
    printf '/mnt/x program:/home/user/evil.sh\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (absolute map file under /tmp): map-file axis writable-root expansion" {
    printf '/mnt/x /tmp/maps/auto.x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (absolute map file under /dev/shm): map-file axis tmpfs coverage" {
    printf '/mnt/x /dev/shm/maps/auto.x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ldap: map is NOT flagged — network map axis): network-map false-positive guard" {
    # ldap: maps (like yp:) are non-local-exec; they shouldn't false-fire.
    printf '/home/guests ldap:auto.home\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (file: map is NOT flagged): file: prefix is non-exec lookup" {
    printf '/home/guests file:/etc/auto.home\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-autofs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): autofs-watchdog does NOT refresh baseline on suspicious-map detection — alert STAYS until operator updates" {
    # T1546 mount-access-triggered root-exec persistence — suspicious-
    # map alert MUST persist across runs until operator explicitly
    # re-baselines. Sister to every other no-auto-trust persistence
    # INVARIANT across the brain (sshrc, cron-job, anacrontab,
    # bash-completion, shell-init, apt-hooks, auditd-plugins).
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    printf '/mnt/x program:/tmp/evil.sh\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (config-layer-noise resilience: extra master-map directives do NOT bypass program: detection)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. autofs master map supports per-
    # entry options after the map (e.g., --timeout=60, --ghost,
    # -browse). Operator may add these forward-compat options;
    # parser must tolerate without altering the program: detection.
    # program-with-noise still alerts (writable-root program path
    # surfaces regardless of surrounding option flags).
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/mnt/x program:/tmp/evil.sh --timeout=60 --ghost -browse\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named master-map entry surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a new
    # autofs master-map entry pointing at a writable program map,
    # the entry detail MUST surface in the JSON sample so
    # operator dashboard routes triage to the right path. Locks
    # the new-entry-discovered operator-visibility contract on
    # the autofs program-map root-exec persistence surface (T1546
    # — autofs runs program-map scripts AS ROOT on every mount
    # request).
    printf '/mnt/data program:/usr/sbin/auto.smb\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/mnt/distinctive-attacker-mount program:/tmp/.distinctive-attacker-evil\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "INVARIANT (program: map under /var/tmp — writable-root axis-symmetric expansion on autofs map surface)" {
    # Sister to /tmp + /dev/shm + /home program: map writable-root
    # INVARIANTs already locked. /var/tmp is writable by ALL users
    # (sticky-bit doesn't gate exec-from-it) and persists across
    # reboots (unlike /tmp /dev/shm tmpfs). Attackers prefer it
    # for boot-survival persistence. The autofs program-map
    # scanner MUST recognize /var/tmp paths just as firmly as the
    # /tmp + /dev/shm family — locks tmpfs-vs-persistent writable-
    # root axis symmetry on the T1546 autofs program-map root-exec
    # persistence surface.
    printf '/mnt/data program:/var/tmp/.auto.smb\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    printf '/mnt/a program:/tmp/.evil1\n/mnt/b program:/var/tmp/.evil2\n/mnt/c program:/home/x/.evil3\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-autofs -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (program: map under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on autofs map surface)" {
    # Sister to /home + /var/tmp + /tmp program: map writable-
    # root INVARIANTs. /dev/shm tmpfs in-RAM writable-root that
    # survives no on-disk forensic trace. autofs invokes program
    # map AS ROOT for each automount trigger; planted attacker
    # binary in /dev/shm fires AS ROOT on every mount-attempt.
    # T1546 autofs program-map root-exec persistence.
    printf '/mnt/data program:/dev/shm/.auto.evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on autofs surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The autofs-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 autofs program-map root-exec
    # persistence alert. Locks parser contract on the autofs
    # master-map detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/mnt/data file:/etc/auto.data\n' > "${CONF}"
    run_wd                                              # ok path
    printf '/mnt/data program:/tmp/.evil\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: autofs-watchdog NEVER deletes auto.master entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # autofs-watchdog DETECTS T1546 autofs program-map root-
    # exec persistence but MUST NEVER emit sed/awk/rm commands
    # to auto-clean the program: map. The detected map may be
    # operator-legitimate (custom dynamic-mount handler for
    # cluster filesystems, dynamic NFS provisioner). Silent
    # auto-delete would destroy operator baseline state AND
    # could break operator's intended automount workflow.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the autofs surveillance substrate.
    printf '/mnt/data program:/tmp/.evil\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'program:' "${CONF}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*auto'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # autofs-watchdog runs ON the timer's scheduled fire — scans
    # /etc/auto.master + auto.master.d for program: map references
    # in writable roots, emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the autofs-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd/selfdef-autofs.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: autofs-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. autofs-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the autofs-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (autofs-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The autofs-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the autofs-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (autofs-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the autofs-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (autofs-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The autofs-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the autofs-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (autofs-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the autofs-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (autofs-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # autofs-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (autofs-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the autofs-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (autofs-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The autofs-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the autofs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (autofs-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the autofs-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (autofs-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the autofs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (autofs-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the autofs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (autofs-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the autofs-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/autofs-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}
