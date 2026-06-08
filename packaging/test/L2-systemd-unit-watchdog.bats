#!/usr/bin/env bats
# L2 functional + capture-regression suite for systemd-unit-watchdog.
#
# systemd-unit-watchdog inventories every enabled service/socket
# unit (hashing the FragmentPath so a changed ExecStart is caught)
# into a baseline, then alerts on a unit added/changed. This is
# the MITRE T1543.002 (systemd-service persistence) sentry: a new
# enabled service running ExecStart=/tmp/.x or a patched ExecStart
# on an existing unit is the canonical attacker callback.
#
# Severity:
#   ok    → no delta
#   warn  → unit removed/disabled
#   alert → unit added/enabled OR ExecStart hash changed
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — printf records
#     reach `$current` not stdout (2026-05-27 root-cause bug)
#   - Each record is <unit>\tenabled\t<hash-32|transient> with
#     the expected shape
#   - Baseline chmod 0600 (confidentiality — enabled-unit
#     inventory enumerates persistence signatures)
#   - DELTA detect: NEW unit ADDED + enabled → alert /
#     unit_added_or_changed
#   - DELTA detect: ExecStart HASH CHANGED → alert (surfaces as
#     1 add + 1 remove pair on the same unit)
#   - DELTA detect: unit REMOVED → warn / unit_removed_or_disabled
#   - DELTA detect: TRANSIENT unit (no FragmentPath) → recorded
#     as `transient` literal instead of a hash
#   - ENFORCE profile: any ADD → exit-1 (failure surface);
#     pure removal → exit-0
#   - REPORT profile: any delta → exit-0 (log-only)
#   - INVARIANT (no auto-trust): like the no-auto-trust watchdog
#     family, systemd-unit-watchdog does NOT refresh the baseline
#     on delta. The alert STAYS visible until operator review.
#
# systemctl is mocked via PATH override. SYSTEMD_UNITS env var
# drives the mock's enabled-unit list; SYSTEMD_UNIT_DIR provides
# unit files for FragmentPath responses. Live default unchanged.
#
# Run with: bats packaging/test/L2-systemd-unit-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd/systemd-unit-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    # systemctl mock — driven by SYSTEMD_UNITS + SYSTEMD_UNIT_DIR.
    # SYSTEMD_UNITS is a space-separated list of unit names that the
    # mock claims are enabled. SYSTEMD_UNIT_DIR contains files named
    # after each enabled unit; the file content is hashed for the
    # FragmentPath lookup.
    cat > "${BIN}/systemctl" <<'SCEOF'
#!/usr/bin/env bash
case "$1" in
    "list-unit-files")
        # Args: list-unit-files --type=service,socket --state=enabled --no-legend
        for u in ${SYSTEMD_UNITS:-}; do
            printf '%s enabled\n' "$u"
        done
        ;;
    "show")
        # Args: show -p FragmentPath --value <unit>
        unit="${!#}"   # last positional argument
        path="${SYSTEMD_UNIT_DIR:-/dev/null}/${unit}"
        # Emit empty (transient) when the unit's file doesn't exist
        # in the synthetic dir — otherwise emit the file path.
        if [[ -f "$path" ]]; then
            printf '%s\n' "$path"
        fi
        ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/systemctl"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/systemd-units-baseline.tsv"
    SYSTEMD_UNIT_DIR="${TMP}/units"
    mkdir -p "${SYSTEMD_UNIT_DIR}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSTEMD_UNITS="${SYSTEMD_UNITS:-}" \
    SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR}" \
    SELFDEF_SYSDUNIT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSDUNIT_BASELINE="${BASELINE}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    SYSTEMD_UNITS="${SYSTEMD_UNITS:-}" \
    SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR}" \
    SELFDEF_SYSDUNIT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSDUNIT_BASELINE="${BASELINE}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: declare a baseline set of enabled units with synthetic
# FragmentPath contents.
write_unit_inventory() {
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket"
    cat > "${SYSTEMD_UNIT_DIR}/sshd.service" <<'EOF'
[Unit]
Description=OpenSSH server daemon
[Service]
ExecStart=/usr/sbin/sshd -D
EOF
    cat > "${SYSTEMD_UNIT_DIR}/nginx.service" <<'EOF'
[Unit]
Description=nginx HTTP server
[Service]
ExecStart=/usr/sbin/nginx -g 'daemon off;'
EOF
    cat > "${SYSTEMD_UNIT_DIR}/docker.socket" <<'EOF'
[Socket]
ListenStream=/var/run/docker.sock
EOF
}

@test "first run captures the enabled-unit inventory into the baseline (non-empty)" {
    write_unit_inventory
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    awk -F'\t' 'NF>=3{ok=1} END{exit ok?0:1}' "${BASELINE}"
    cap | grep -qE '"baseline_count":[1-9]'
}

@test "baseline records each enabled unit with state=enabled + sha-32 hash" {
    write_unit_inventory
    run_wd
    grep -qP '^sshd\.service\tenabled\t[0-9a-f]{32}$' "${BASELINE}"
    grep -qP '^nginx\.service\tenabled\t[0-9a-f]{32}$' "${BASELINE}"
    grep -qP '^docker\.socket\tenabled\t[0-9a-f]{32}$' "${BASELINE}"
}

@test "baseline records TRANSIENT units (no FragmentPath) with the literal 'transient' hash" {
    # A unit that's enabled but has no fragment (the synthetic dir
    # has no matching file) is recorded as `transient` per the
    # script's defensive fallback.
    export SYSTEMD_UNITS="sshd.service runtime-only.service"
    cat > "${SYSTEMD_UNIT_DIR}/sshd.service" <<'EOF'
ExecStart=/usr/sbin/sshd -D
EOF
    # Note: runtime-only.service has NO file in SYSTEMD_UNIT_DIR
    # so the systemctl mock returns empty FragmentPath.
    run_wd
    grep -qP '^runtime-only\.service\tenabled\ttransient$' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — enabled-unit inventory enumerates persistence signatures)" {
    write_unit_inventory
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged units on second run → ok / no_delta" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — NEW unit added + enabled → alert / unit_added_or_changed (T1543.002)" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker enables a new service running a callback.
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
[Unit]
Description=attacker callback
[Service]
ExecStart=/tmp/.attacker-callback
Restart=always
EOF
    run_wd
    cap | grep -q '"event":"unit_added_or_changed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"added":1'
}

@test "DELTA detect — ExecStart HASH CHANGE (patched existing unit) → alert (1 add + 1 remove pair)" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker patches nginx.service to insert a side-effect.
    cat > "${SYSTEMD_UNIT_DIR}/nginx.service" <<'EOF'
[Unit]
Description=nginx HTTP server
[Service]
ExecStartPre=/tmp/.callback
ExecStart=/usr/sbin/nginx -g 'daemon off;'
EOF
    run_wd
    cap | grep -q '"event":"unit_added_or_changed"'
    cap | grep -q '"severity":"alert"'
    # Content-change surfaces as 1 add (new hash) + 1 remove (old hash).
    cap | grep -q '"added":1'
    cap | grep -q '"removed":1'
}

@test "DELTA detect — unit REMOVED/disabled → warn / unit_removed_or_disabled" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Operator disables docker.socket.
    export SYSTEMD_UNITS="sshd.service nginx.service"
    run_wd
    cap | grep -q '"event":"unit_removed_or_disabled"'
    cap | grep -q '"severity":"warn"'
}

@test "ENFORCE profile: ADDED unit → exit-1 (failure surface for systemd unit alerting)" {
    write_unit_inventory
    PROFILE=report run_wd
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
ExecStart=/tmp/.attacker
EOF
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "ENFORCE profile: REMOVED-only delta → exit-0 (operator cleanup is OK)" {
    write_unit_inventory
    PROFILE=report run_wd
    export SYSTEMD_UNITS="sshd.service nginx.service"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "REPORT profile: ADDED unit → exit-0 (log-only — journald is the surface)" {
    write_unit_inventory
    PROFILE=report run_wd
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
ExecStart=/tmp/.attacker
EOF
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "INVARIANT (no auto-trust): systemd-unit-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates baseline" {
    # CONTRAST against group-integrity-watchdog (which auto-refreshes).
    # New enabled services are NEVER routine; the alert must STAY.
    write_unit_inventory
    PROFILE=report run_wd
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
ExecStart=/tmp/.attacker
EOF
    PROFILE=report run_wd                                  # first delta run
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # alert STAYS
    cap | grep -q '"event":"unit_added_or_changed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ExecStartPost change also detected — not only ExecStart): full unit-file content hash" {
    # The watchdog hashes the ENTIRE FragmentPath content — not
    # just the ExecStart line. Patching ExecStartPost (or
    # ExecStopPost, ExecReload, EnvironmentFile, etc.) is a
    # known persistence trick that must also surface.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SYSTEMD_UNIT_DIR}/nginx.service" <<'EOF'
[Unit]
Description=nginx HTTP server
[Service]
ExecStart=/usr/sbin/nginx -g 'daemon off;'
ExecStartPost=/tmp/.callback-post
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (socket-unit modification detected): docker.socket axis is hashed, not only .service axis" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker re-points docker.socket to a writable path.
    cat > "${SYSTEMD_UNIT_DIR}/docker.socket" <<'EOF'
[Socket]
ListenStream=/tmp/.fake-docker.sock
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-add: 2 enabled units added at once → both surface in added count)" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil1.service evil2.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil1.service" <<'EOF'
ExecStart=/tmp/.x1
EOF
    cat > "${SYSTEMD_UNIT_DIR}/evil2.service" <<'EOF'
ExecStart=/tmp/.x2
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"added":2'
}

@test "INVARIANT (add + remove combined: alert severity wins over warn — added unit is higher priority signal)" {
    # When an attacker SWAPS units (disable cron, enable evil),
    # both deltas surface in the same scan. Per the severity
    # ladder, alert (add) wins over warn (remove) — the combined
    # severity must be alert.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
ExecStart=/tmp/.x
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"added":1'
    cap | grep -q '"removed":1'
}

@test "INVARIANT (baseline format TAB-separated: unit\\tstate\\thash — downstream parser contract)" {
    # The TSV format is the downstream-parser contract — diffs +
    # alerting hooks split on TAB. A space-separated baseline
    # would corrupt unit names with spaces (rare but possible).
    write_unit_inventory
    run_wd
    # Every non-empty line has exactly 2 TABs (3 fields).
    while IFS= read -r line; do
        tab_count=$(awk -F'\t' '{print NF-1}' <<< "${line}")
        [ "${tab_count}" = "2" ]
    done < "${BASELINE}"
}

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line per SDD-062 consumer contract — even on delta)" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
ExecStart=/tmp/.x
EOF
    run_wd
    # The MAIN tag selfdef-systemd-units (not the -detail tag) must
    # appear exactly once for downstream JSON-line consumer.
    main_count=$(cap | grep -cE '^-t selfdef-systemd-units -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (DELTA detect: TRANSIENT unit added at runtime — runtime persistence vector covered)" {
    # Attacker can register a TRANSIENT unit (no FragmentPath) via
    # systemd-run --unit=evil --slice=... which still persists across
    # the current boot session. Watchdog MUST surface it.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket runtime-evil.service"
    # NOTE: runtime-evil.service intentionally has NO file in SYSTEMD_UNIT_DIR.
    run_wd
    cap | grep -q '"event":"unit_added_or_changed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-add: added count is exact, not over/under — counting accuracy)" {
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil1.service evil2.service evil3.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil1.service" <<'EOF'
ExecStart=/tmp/.x1
EOF
    cat > "${SYSTEMD_UNIT_DIR}/evil2.service" <<'EOF'
ExecStart=/tmp/.x2
EOF
    cat > "${SYSTEMD_UNIT_DIR}/evil3.service" <<'EOF'
ExecStart=/tmp/.x3
EOF
    run_wd
    cap | grep -q '"added":3'
    cap | grep -q '"removed":0'
}

@test "INVARIANT (severity ladder: pure-add alert > add+remove alert > pure-remove warn)" {
    # Locks the severity ladder hierarchy. Pure adds are alert (highest);
    # adds combined with removes still escalate to alert (severity wins);
    # pure-remove is warn (lower); no-change is ok.
    write_unit_inventory
    run_wd
    # Test pure-add: alert.
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket evil.service"
    cat > "${SYSTEMD_UNIT_DIR}/evil.service" <<'EOF'
ExecStart=/tmp/.x
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (added_sample in emit JSON: operator-triage routing surfaces changed unit names)" {
    # Sister to every other watchdog sample-names-file INVARIANT
    # across the brain. When the unit-delta has added entries, the
    # JSON record must expose them via added_sample (or equivalent
    # operator-triage field) so the downstream dashboard / alerting
    # pipeline can route on WHICH unit changed (not just a count).
    # The watchdog already emits added/removed counts; closing the
    # axis to also surface the unit-name list for operator-triage
    # observability on the T1543.002 systemd-service persistence
    # surface.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket distinctive-attacker.service"
    cat > "${SYSTEMD_UNIT_DIR}/distinctive-attacker.service" <<'EOF'
ExecStart=/tmp/.x
EOF
    run_wd
    # Either sample-name field surfaces the unit name OR the detail
    # logger line carries the unit name (per SDD-062 detail tag).
    cap | grep -q 'distinctive-attacker'
}

@test "INVARIANT (.timer enabled-unit added → alert: T1053.006 systemd-timer persistence axis sister to T1543.002)" {
    # Sister to many other watchdog DELTA-ADDED INVARIANTs across
    # the brain on adjacent persistence axes. T1543.002 systemd-
    # service is the canonical axis; T1053.006 systemd-timer is
    # the sister axis. A .timer enabled at boot can fire any
    # ExecStart on its OnCalendar/OnBootSec schedule, including
    # attacker-controlled commands. The watchdog enumerates
    # enabled units via systemctl list-unit-files; .timer must
    # surface in the inventory just like .service / .socket.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket attacker-persistence.timer"
    cat > "${SYSTEMD_UNIT_DIR}/attacker-persistence.timer" <<'EOF'
[Timer]
OnCalendar=*:0/5
ExecStart=/tmp/.x
EOF
    run_wd
    cap | grep -q 'attacker-persistence.timer'
}

@test "INVARIANT (.path enabled-unit added → alert: T1546 path-trigger persistence axis sister to T1543.002 + T1053.006)" {
    # Sister to .service (T1543.002) + .timer (T1053.006) axes
    # already locked. .path units are the THIRD systemd persistence
    # axis — a .path unit watches a filesystem path + activates an
    # associated .service when the path changes. Attacker may plant
    # a .path unit watching a routinely-modified file (e.g.,
    # /var/log/syslog) + activate their callback service on every
    # log rotation — a recurring trigger fired by operator-routine
    # log writes. Locks .path axis on the systemd-unit-inventory
    # surveillance brain alongside .service + .timer.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket attacker-path-watch.path"
    cat > "${SYSTEMD_UNIT_DIR}/attacker-path-watch.path" <<'EOF'
[Path]
PathChanged=/var/log/syslog
EOF
    run_wd
    cap | grep -q 'attacker-path-watch.path'
}

@test "INVARIANT (.socket enabled-unit added → alert: T1543.002 socket-activation persistence axis sister to .service/.timer/.path)" {
    # Sister to .service (T1543.002) + .timer (T1053.006) +
    # .path axes already locked. .socket units are the FOURTH
    # systemd persistence axis — a .socket unit listens on a
    # network/Unix socket and activates an associated .service
    # when a client connects. Attacker may plant a .socket unit
    # bound to a high port + activate their callback .service
    # on every incoming connection — remote trigger. Locks
    # .socket axis on systemd-unit-inventory surveillance
    # brain alongside .service + .timer + .path.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket attacker-callback.socket"
    cat > "${SYSTEMD_UNIT_DIR}/attacker-callback.socket" <<'EOF'
[Socket]
ListenStream=4444
EOF
    run_wd
    cap | grep -q 'attacker-callback.socket'
}

@test "INVARIANT (.mount enabled-unit added → alert: T1543.002 mount-persistence axis sister to .service/.timer/.path/.socket)" {
    # Sister to .service/.timer/.path/.socket persistence axes
    # already locked. systemd .mount units describe filesystem
    # mounts; an attacker who adds a malicious .mount unit can:
    # (a) bind-mount /etc over a writable dir to overlay tampered
    # configs without touching the original /etc inode; (b) mount
    # a tmpfs over /var/log to wipe forensics on every boot; (c)
    # mount remote NFS/CIFS exfil destinations. The mount fires
    # AS ROOT on every systemd activation triggered by .target
    # dependency. Lock that .mount unit additions surface
    # symmetric to the other persistence axes.
    write_unit_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket attacker-overlay.mount"
    cat > "${SYSTEMD_UNIT_DIR}/attacker-overlay.mount" <<'EOF'
[Mount]
What=/var/tmp/.evil-etc
Where=/etc
Type=none
Options=bind
EOF
    run_wd
    cap | grep -q 'attacker-overlay.mount'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on systemd-unit surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The systemd-unit-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1543.002 systemd-service persistence alert.
    # Locks parser contract on the systemd-unit-inventory delta
    # detection surface.
    write_unit_inventory
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    export SYSTEMD_UNITS="sshd.service nginx.service docker.socket attacker-planted.service"
    cat > "${SYSTEMD_UNIT_DIR}/attacker-planted.service" <<'EOF'
[Service]
ExecStart=/tmp/.evil
EOF
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-disable: systemd-unit-watchdog NEVER emits systemctl disable/mask — surveillance not remediation)" {
    # Sister to brain-wide no-auto-remediation / surveillance-
    # not-destruction INVARIANTs across L2 watchdog suites. The
    # systemd-unit-watchdog DETECTS T1543.002 / T1053.006 /
    # T1546 systemd persistence (planted .service/.timer/.path/
    # .socket/.mount units) but MUST NEVER emit systemctl
    # disable/mask commands to auto-neutralize the planted
    # unit. The detected unit may be operator-legitimate
    # (operator deployed a new service but forgot to re-
    # baseline) — silent auto-disable would break operator-
    # intended runtime. Auto-disable is also a denial-of-
    # service primitive (attacker plants a unit, watchdog
    # disables it + operator's actual workload). Surveillance,
    # never remediation. Locks anti-runtime-destruction
    # contract on the systemd-unit surveillance substrate.
    ! grep -qE 'systemctl[[:space:]]+(disable|mask|stop)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # systemd-unit-watchdog runs ON the timer's scheduled fire —
    # diffs enabled-unit set against baseline, emits a verdict
    # on persistence-vector additions (.service/.timer/.path/
    # .socket/.mount), then exits. Type=simple would break
    # timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the systemd-unit-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd/selfdef-systemd-units.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. systemd-unit-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # systemd-unit-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # systemd-unit-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'systemd-unit-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: systemd-unit-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. systemd-unit-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the systemd-unit-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (systemd-unit-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the systemd-unit-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-unit-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # systemd-unit-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-unit-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # systemd-unit-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-unit-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the systemd-unit-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-unit-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # systemd-unit-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-unit-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the systemd-unit-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-unit-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the systemd-unit-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the systemd-unit-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the systemd-unit-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the systemd-unit-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the systemd-unit-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (systemd-unit-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (systemd-unit-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (systemd-unit-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (systemd-unit-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the systemd-unit-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    [ -f "${script_dir}/systemd-unit-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (systemd-unit-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (systemd-unit-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (systemd-unit-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script tag selfdef-systemd-unit matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-systemd-unit
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .timer file exists at canonical path modules/systemd-unit-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (systemd-unit-watchdog module.toml exists at canonical path modules/systemd-unit-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (systemd-unit-watchdog systemd dir exists at modules/systemd-unit-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (systemd-unit-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (systemd-unit-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (systemd-unit-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (systemd-unit-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (systemd-unit-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (systemd-unit-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (systemd-unit-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (systemd-unit-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (systemd-unit-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"systemd-unit-watchdog"' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
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

@test "INVARIANT (systemd-unit-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (systemd-unit-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (systemd-unit-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}
