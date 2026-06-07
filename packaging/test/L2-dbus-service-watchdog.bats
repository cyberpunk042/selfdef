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
