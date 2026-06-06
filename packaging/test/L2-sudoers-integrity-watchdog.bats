#!/usr/bin/env bats
# L2 functional + capture-regression suite for sudoers-integrity-watchdog.
#
# sudoers-integrity-watchdog parses /etc/sudoers + /etc/sudoers.d/* into
# normalized grant lines, then alerts on:
#   - dangerous grants ADDED (NOPASSWD, blanket ALL=(ALL[:ALL]) ALL) →
#     severity=alert, event=dangerous_sudo_grant_added
#   - non-dangerous grants ADDED → severity=warn, event=sudo_grant_added
#   - grants REMOVED → severity=warn, event=sudo_grant_removed
#
# Defaults lines (sudo-tune tunables) are EXCLUDED — this watchdog
# tracks grants, not tunables.
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — emit_rules writes to
#     `$current` not stdout (2026-05-27 root-cause bug)
#   - Defaults lines are correctly EXCLUDED from the baseline
#   - Comments + blank lines are correctly EXCLUDED
#   - Baseline confidentiality (chmod 0600 — sudoers grant inventory
#     enumerates privileged identities + is sensitive)
#   - DELTA detect: dangerous NOPASSWD ADD → alert (instant priv-esc)
#   - DELTA detect: dangerous ALL=(ALL:ALL) ALL ADD → alert
#   - DELTA detect: ordinary grant ADD → warn (not alert)
#   - DELTA detect: grant REMOVE → warn (post-hoc cleanup)
#   - ENFORCE profile: any ADD → exit-1 (failure surface for systemd
#     unit alerting); pure removal → exit-0 (operator cleanup is OK)
#   - REPORT profile: any delta → exit-0 (log-only)
#   - INVARIANT (no auto-trust): sudoers-integrity-watchdog does NOT
#     refresh the baseline on delta. The alert STAYS visible across
#     every subsequent run until the operator manually updates the
#     baseline. Sudo grants are NEVER routine; auto-trust here would
#     defeat the watchdog's purpose.
#
# Adds SELFDEF_SUDOERS_FILE + SELFDEF_SUDOERS_D_DIR env-var overrides
# (added 2026-06-06) for L2 delta-testability. Live defaults
# unchanged.
#
# Run with: bats packaging/test/L2-sudoers-integrity-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd/sudoers-integrity-watchdog.sh"

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
    BASELINE="${TMP}/sudoers-integrity-baseline.tsv"
    SUDOERS_FILE="${TMP}/sudoers"
    SUDOERS_D_DIR="${TMP}/sudoers.d"
    mkdir -p "${SUDOERS_D_DIR}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUDOERS_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDOERS_BASELINE="${BASELINE}" \
    SELFDEF_SUDOERS_FILE="${SUDOERS_FILE}" \
    SELFDEF_SUDOERS_D_DIR="${SUDOERS_D_DIR}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUDOERS_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDOERS_BASELINE="${BASELINE}" \
    SELFDEF_SUDOERS_FILE="${SUDOERS_FILE}" \
    SELFDEF_SUDOERS_D_DIR="${SUDOERS_D_DIR}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write a baseline sudoers + sudoers.d set.
write_sudo_inventory() {
    cat > "${SUDOERS_FILE}" <<'EOF'
# /etc/sudoers — managed by ops
Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults mailto="root@localhost"

root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
EOF
    cat > "${SUDOERS_D_DIR}/operator-backups" <<'EOF'
# operator's daily backup runner
alice ALL=(root) /usr/local/sbin/run-backup
EOF
}

@test "first run captures the sudoers grants into the baseline (non-empty)" {
    write_sudo_inventory
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # Each record is <file>\t<rule> — at least one well-formed row.
    awk -F'\t' 'NF>=2{ok=1} END{exit ok?0:1}' "${BASELINE}"
    cap | grep -qE '"baseline_count":[1-9]'
}

@test "INVARIANT (Defaults excluded): Defaults lines are NOT recorded in the baseline (sudo-tune owns tunables)" {
    write_sudo_inventory
    run_wd
    ! grep -q 'Defaults env_reset' "${BASELINE}"
    ! grep -q 'Defaults secure_path' "${BASELINE}"
    ! grep -q 'Defaults mailto' "${BASELINE}"
}

@test "INVARIANT (grants captured): root + %sudo + sudoers.d alice grants ARE recorded" {
    write_sudo_inventory
    run_wd
    grep -qP '^sudoers\troot ALL=' "${BASELINE}"
    grep -qP '^sudoers\t%sudo ALL=' "${BASELINE}"
    grep -qP '^operator-backups\talice ALL=' "${BASELINE}"
}

@test "INVARIANT (comments excluded): comment lines + blank lines are NOT recorded" {
    write_sudo_inventory
    run_wd
    ! grep -q '^#' "${BASELINE}"
}

@test "baseline is chmod 0600 (confidentiality — sudoers grant inventory enumerates privileged identities)" {
    write_sudo_inventory
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "unchanged sudoers on second run → ok / no_delta" {
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — DANGEROUS NOPASSWD grant ADD → alert / dangerous_sudo_grant_added (instant priv-esc)" {
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker drops a NOPASSWD grant in /etc/sudoers.d/.
    cat > "${SUDOERS_D_DIR}/backdoor" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"dangerous":1'
}

@test "DELTA detect — DANGEROUS blanket ALL=(ALL:ALL) ALL grant ADD → alert" {
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/backdoor" <<'EOF'
evil ALL=(ALL:ALL) ALL
EOF
    run_wd
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — ordinary (scoped) grant ADD → warn / sudo_grant_added (not alert)" {
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/bob-restart" <<'EOF'
bob ALL=(root) /bin/systemctl restart nginx
EOF
    run_wd
    cap | grep -q '"event":"sudo_grant_added"'
    cap | grep -q '"severity":"warn"'
    cap | grep -q '"dangerous":0'
}

@test "DELTA detect — grant REMOVED → warn / sudo_grant_removed (post-hoc cleanup)" {
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${SUDOERS_D_DIR}/operator-backups"
    run_wd
    cap | grep -q '"event":"sudo_grant_removed"'
    cap | grep -q '"severity":"warn"'
}

@test "ENFORCE profile: ADDED grant → exit-1 (failure surface for systemd unit alerting)" {
    write_sudo_inventory
    PROFILE=report run_wd                                  # baseline init
    cat > "${SUDOERS_D_DIR}/backdoor" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "ENFORCE profile: REMOVED-only delta → exit-0 (operator cleanup is informational)" {
    write_sudo_inventory
    PROFILE=report run_wd
    rm -f "${SUDOERS_D_DIR}/operator-backups"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "REPORT profile: ADDED grant → exit-0 (log-only — journald is the surface)" {
    write_sudo_inventory
    PROFILE=report run_wd
    cat > "${SUDOERS_D_DIR}/backdoor" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "INVARIANT (no auto-trust): sudoers-integrity-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates baseline" {
    # CONTRAST against group-integrity-watchdog (which auto-refreshes).
    # Sudo grants are NEVER routine; the alert must STAY visible.
    write_sudo_inventory
    PROFILE=report run_wd
    cat > "${SUDOERS_D_DIR}/backdoor" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    PROFILE=report run_wd                                  # first delta run
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # alert STAYS
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-grant axis: %group NOPASSWD also tracked, not only user grants)" {
    # Attacker drops a NOPASSWD grant on a %group instead of a
    # user. Watchdog must track the %group form too.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/backdoor-group" <<'EOF'
%evil ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented dangerous grant is NOT flagged: # prefix filtered)" {
    # An operator note about a future grant must not surface
    # as a real grant addition.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/notes" <<'EOF'
# notes: would grant evil ALL=(ALL) NOPASSWD: ALL but operator declined
EOF
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance in grant line: 'evil    ALL=(ALL)' multi-space NOPASSWD detection)" {
    # Operator/attacker may use multi-spaces or tabs. Locks
    # whitespace-tolerant grant parser still catches dangerous
    # patterns.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/ws-attack" <<'EOF'
evil    ALL=(ALL)   NOPASSWD:   ALL
EOF
    run_wd
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-grant single file: multiple ordinary additions in one drop-in surface as added=N)" {
    # When a single new drop-in carries multiple grant lines,
    # the added count must reflect ALL of them, not 1.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/multi-ops" <<'EOF'
bob ALL=(root) /bin/systemctl restart nginx
carol ALL=(root) /bin/systemctl restart redis
EOF
    run_wd
    cap | grep -qE '"added":[2-9]'
    cap | grep -q '"event":"sudo_grant_added"'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line per SDD-062 consumer contract — even on delta)" {
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/backdoor" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sudoers-integrity -- ')
    [ "${main_count}" = "1" ]
}
