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
