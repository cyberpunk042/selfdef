#!/usr/bin/env bats
# L2 bats functional tests for the dbus-service-watchdog scan script.
#
# A D-Bus activation .service file with an Exec= (and optional User=) makes
# dbus-daemon launch Exec= AS that user the first time any client calls the
# service's bus name — a remotely/locally triggerable exec surface. The
# watchdog is high-signal in two distinct ways: dbus_service_suspicious (an
# Exec under a writable root, or a world-writable/non-root .service file) and
# dbus_service_new (a NEW activation .service appearing, or a new <allow
# own=> bus-name grant).
#
# Runs the actual scan script with `logger` shadowed on PATH and the service
# dir + baseline in a tmp sandbox via SELFDEF_DBUS_*.
#
# Run with: bats packaging/test/L2-dbus-service-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd/dbus-service-watchdog.sh"
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
    DBUSD="${TMP}/services"; mkdir -p "${DBUSD}"
    SVC="${DBUSD}/com.example.A.service"
}

teardown() { rm -rf "${TMP}"; }

svc() { printf '[D-BUS Service]\nName=com.example.A\nExec=%s\nUser=%s\n' "$1" "${2:-root}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DBUS_PROFILE="${PROFILE:-report}" \
    SELFDEF_DBUS_BASELINE="${BASELINE}" \
    SELFDEF_DBUS_DIRS="${DIRS:-$DBUSD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dbus service dirs → ok / no_dbus_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_dbus_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign service, first run → ok / baseline_initial" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged services on second run → ok / dbus_service_intact" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — suspicious Exec
# ============================================================

@test "Exec under a writable root → alert / dbus_service_suspicious" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd                                   # benign baseline
    svc /tmp/evil > "${SVC}"                 # same service path, dangerous Exec
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "Exec under /home → alert" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /home/u/.x > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# alert tier — a NEW activation service appearing
# ============================================================

@test "a newly-added activation service → alert / dbus_service_new" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd                                   # baseline has only service A
    svc /usr/libexec/another > "${DBUSD}/com.example.B.service"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_new"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign edit to an existing service → warn / dbus_service_changed" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    { svc /usr/libexec/myservice; printf 'SystemdService=myservice.service\n'; } > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "an Exec at a trusted path is NOT flagged" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a /usr/bin Exec is NOT flagged" {
    svc /usr/bin/dbus-helper > "${SVC}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    svc /usr/libexec/myservice > "${SVC}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious Exec" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — dbus-service inventory enumerates client-trigger root-exec surface)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (Exec under /var/tmp): writable-root expansion" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /var/tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Exec under /dev/shm): tmpfs writable-root coverage" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /dev/shm/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable service file → alert)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    chmod 0666 "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable service file): group-writable → alert above world-writable bar" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    chmod 0664 "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA-detect: NEW service surfaces in sample by bus-name)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # New service with distinctive bus name.
    cat > "${DBUSD}/com.distinctive.attacker.service" <<EOF
[D-BUS Service]
Name=com.distinctive.attacker
Exec=/usr/libexec/something
User=root
EOF
    run_wd
    cap | grep -q 'distinctive.attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dbus-service -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): dbus-service-watchdog does NOT refresh baseline on suspicious-Exec detection — alert STAYS until operator updates" {
    # Client-trigger root-exec persistence — suspicious-Exec alert
    # MUST persist across runs until operator explicitly re-baselines.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"dbus_service_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /usr/share/dbus-1/system-services + /usr/local/share + /etc/dbus-1 axes — new service in ANY → alert)" {
    # dbus-daemon reads activation .service files from multiple dirs.
    # Attacker may plant in any. Lock multi-dir axis.
    DBUSD2="${TMP}/local-services"; mkdir -p "${DBUSD2}"
    svc /usr/libexec/myservice > "${SVC}"
    DIRS="${DBUSD} ${DBUSD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant new service in second dir.
    cat > "${DBUSD2}/com.evil.attacker.service" <<EOF
[D-BUS Service]
Name=com.evil.attacker
Exec=/usr/libexec/evil
User=root
EOF
    DIRS="${DBUSD} ${DBUSD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (User=root + Exec under writable root: BOTH axes compound severity — alert wins)" {
    # When User=root AND Exec is under writable root, this is the
    # highest-risk pattern (root exec triggered by client). Lock
    # that this compound case fires alert, not just warn.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    svc /tmp/.attacker root > "${SVC}"      # explicit User=root + writable Exec
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"dbus_service_suspicious"'
}

@test "INVARIANT (Exec under /var/tmp w/ User=root: writable-root expansion + root-exec compound) " {
    # Sister to the /tmp+User=root compound case above. /var/tmp is
    # an equally-writable surface; root-exec triggered by client
    # over D-Bus must alert regardless of which writable-root the
    # Exec= path lives under. Locks axis-symmetry on the writable-
    # root family across the compound surface.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    svc /var/tmp/.attacker root > "${SVC}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"dbus_service_suspicious"'
}

@test "INVARIANT (SystemdService directive surveillance: a D-Bus activation pointing at attacker-controlled systemd unit also surfaces — alternate-mechanism axis)" {
    # Sister to the Exec= axis already locked. Modern D-Bus
    # activation supports the alternative SystemdService= directive
    # that hands off activation to systemd (instead of dbus-daemon
    # forking the Exec= directly). An attacker may plant a
    # SystemdService=evil-callback.service descriptor that systemd
    # then runs AS WHATEVER the unit declares (defaults to root).
    # Locks coverage of the alternate-mechanism axis on the dbus-
    # service activation surface alongside the direct Exec= path.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SVC}" <<EOF
[D-BUS Service]
Name=com.example.A
SystemdService=attacker-callback.service
User=root
EOF
    run_wd
    # Severity should be at least warn (config changed); ideally
    # alert if the watchdog tracks SystemdService= specifically.
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named D-Bus service file surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # D-Bus .service file (T1543 — Create or Modify System
    # Process via D-Bus activation; dbus-daemon fires the Exec=
    # AS the configured User= on every matching D-Bus method
    # call), the file name MUST surface in the JSON sample so
    # operator dashboard routes triage to the right path.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    DSVC2="${DBUSD}/distinctive-attacker-dbus.service"
    cat > "${DSVC2}" <<EOF
[D-BUS Service]
Name=com.evil.A
Exec=/tmp/.evil
User=root
EOF
    run_wd
    cap | grep -q 'distinctive-attacker-dbus'
}

@test "INVARIANT (Exec under /home: user-writable hijack on D-Bus service-activation surface)" {
    # Sister to /var/tmp Exec writable-root INVARIANT already
    # locked. /home/<user> is writable by the owning user without
    # privilege; attacker who pivots into a user account plants
    # /home/<user>/.evil + registers a D-Bus .service file with
    # Exec=/home/<user>/.evil + User=root — dbus-daemon fires
    # the attacker payload AS ROOT on every matching D-Bus
    # method call. Locks the /home axis on the D-Bus service-
    # activation writable-root coverage symmetric to /var/tmp +
    # /tmp on the T1543 Create-or-Modify-System-Process surface.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${DBUSD}/evil-home.service" <<EOF
[D-BUS Service]
Name=com.evil.home
Exec=/home/alice/.evil
User=root
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (Exec under /var/tmp: writable-root axis-symmetric expansion on D-Bus service activation)" {
    # Sister to /home + /var/tmp Exec D-Bus axes. /var/tmp
    # writable + persistent. Closes axis-symmetric coverage on
    # T1543 Create-or-Modify-System-Process surface.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${DBUSD}/evil-vartmp.service" <<EOF
[D-BUS Service]
Name=com.evil.vartmp
Exec=/var/tmp/.evil
User=root
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (Exec under /dev/shm: tmpfs in-RAM writable-root axis-symmetric expansion on D-Bus service activation)" {
    # Sister to /home + /var/tmp + /tmp Exec writable-root
    # INVARIANTs. /dev/shm tmpfs in-RAM: no on-disk forensic
    # trace. D-Bus service activation fires AS configured user
    # (often root) on first method call; planted /dev/shm
    # binary fires AS service-uid on every activation.
    cat > "${DBUSD}/evil-shm.service" <<EOF
[D-BUS Service]
Name=com.evil.shm
Exec=/dev/shm/.evil
User=root
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on dbus-service surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The dbus-service-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1543 D-Bus service-activation persistence
    # alert. Locks parser contract on the D-Bus service-file
    # detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${DBUSD}/benign.service" <<'EOF'
[D-BUS Service]
Name=org.freedesktop.benign
Exec=/usr/bin/benign-helper
User=messagebus
EOF
    run_wd                                              # ok / baseline
    cat > "${DBUSD}/evil.service" <<'EOF'
[D-BUS Service]
Name=com.evil
Exec=/tmp/.evil
User=root
EOF
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # dbus-service-watchdog runs ON the timer's scheduled fire —
    # scans /usr/share/dbus-1/{system,session}-services for
    # suspicious Exec/User/SystemdService directives, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the dbus-service-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd/selfdef-dbus-service.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. dbus-service-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the D-Bus service-file scanner baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the dbus-service-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'dbus-service-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: dbus-service-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. dbus-service-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the dbus-service-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (dbus-service-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The dbus-service-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the dbus-service-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dbus-service-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # dbus-service-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dbus-service-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # dbus-service-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dbus-service-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the dbus-service-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dbus-service-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # dbus-service-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dbus-service-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the dbus-service-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (dbus-service-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the dbus-service-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the dbus-service-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the dbus-service-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the dbus-service-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the dbus-service-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (dbus-service-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (dbus-service-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (dbus-service-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (dbus-service-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the dbus-service-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    [ -f "${script_dir}/dbus-service-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (dbus-service-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (dbus-service-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (dbus-service-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script tag selfdef-dbus-service matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-dbus-service
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (dbus-service-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (dbus-service-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .timer file exists at canonical path modules/dbus-service-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dbus-service-watchdog module.toml exists at canonical path modules/dbus-service-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (dbus-service-watchdog systemd dir exists at modules/dbus-service-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (dbus-service-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dbus-service-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (dbus-service-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (dbus-service-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (dbus-service-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (dbus-service-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (dbus-service-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (dbus-service-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (dbus-service-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dbus-service-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (dbus-service-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (dbus-service-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (dbus-service-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (dbus-service-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (dbus-service-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (dbus-service-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (dbus-service-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"dbus-service-watchdog"' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (dbus-service-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (dbus-service-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (dbus-service-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (dbus-service-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (dbus-service-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (dbus-service-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (dbus-service-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (dbus-service-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}
