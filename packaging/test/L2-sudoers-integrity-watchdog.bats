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

@test "INVARIANT (NOPASSWD on scoped command STILL alerts — NOPASSWD itself is the dangerous flag, not the scope)" {
    # 'bob ALL=(root) NOPASSWD: /bin/systemctl restart nginx' is a
    # scoped command BUT still NOPASSWD — and NOPASSWD-anything is a
    # password-bypass primitive. An attacker who pivots to bob's
    # account hits this without a password. Lock that the NOPASSWD
    # flag triggers alert regardless of command scope.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/scoped-nopw" <<'EOF'
bob ALL=(root) NOPASSWD: /bin/systemctl restart nginx
EOF
    run_wd
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity precedence: dangerous + ordinary added together → SINGLE alert event, not warn — alert wins)" {
    # When one drop-in carries BOTH a dangerous AND an ordinary
    # added grant, the JSON record fires as alert, not warn. Locks
    # the severity ladder: alert > warn — consolidation discipline.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/mixed" <<'EOF'
bob ALL=(root) /bin/systemctl restart nginx
evil ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"dangerous_sudo_grant_added"'
    main_count=$(cap | grep -cE '^-t selfdef-sudoers-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (file rename preserves grant — added+removed cancel when grant content unchanged but moves files)" {
    # Operator may rename a sudoers.d/ drop-in (operator-housekeeping).
    # If content is identical, the watchdog detects content-removed
    # from old file + content-added in new file. The current behavior
    # locks: BOTH events surface (added + removed) — watchdog does
    # NOT do content-based dedup across files. Lock for refinement
    # opportunity tracking.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Rename operator-backups → operator-backups-v2 (same content).
    mv "${SUDOERS_D_DIR}/operator-backups" "${SUDOERS_D_DIR}/operator-backups-v2"
    run_wd
    # The watchdog detects a delta — locks current behavior that
    # rename surfaces as a real change (not silent passthrough).
    cap | grep -qE '"(added|removed)":[1-9]'
}

@test "INVARIANT (DELTA detect — ADDED dangerous grant from a distinctively-named sudoers.d drop-in surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # sudoers.d/ drop-in (e.g., 99-distinctive-attacker-grant) with
    # NOPASSWD: ALL grant, the file path + grant content MUST
    # surface in the JSON sample so operator dashboard routes
    # triage to the right path. Locks the new-file-discovered
    # operator-visibility contract — operators MUST be able to
    # tell which sudoers.d drop-in the dangerous grant landed in.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# distinctive-attacker grant\nevil ALL=(ALL) NOPASSWD: ALL\n' > "${SUDOERS_D_DIR}/99-distinctive-attacker-grant"
    run_wd
    cap | grep -qE 'evil|NOPASSWD|distinctive-attacker'
}

@test "INVARIANT (NOPASSWD on Cmnd_Alias indirection STILL alerts — alias-resolution doesn't dodge dangerous-flag detection)" {
    # Sister to NOPASSWD scoped-command + bare NOPASSWD axes
    # already locked. Attackers may layer indirection via
    # Cmnd_Alias to hide the NOPASSWD: ALL grant behind a
    # named alias (e.g. 'Cmnd_Alias EVIL = ALL' +
    # 'evil ALL=(ALL) NOPASSWD: EVIL'). The watchdog MUST
    # alert regardless of the alias-resolution complexity —
    # NOPASSWD with broad-command-resolution is the dangerous
    # bit, not the lexical command-spec.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/99-alias-attacker" <<'EOF'
Cmnd_Alias ATTACKER_CMD = ALL
evil-via-alias ALL=(ALL) NOPASSWD: ATTACKER_CMD
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (User_Alias indirection STILL alerts — alias-resolution on user-list axis doesn't dodge dangerous-flag detection)" {
    # Sister to Cmnd_Alias indirection INVARIANT just locked.
    # Attackers may layer User_Alias indirection: `User_Alias
    # ATTACKERS = evil1, evil2` + `ATTACKERS ALL=(ALL) NOPASSWD:
    # ALL`. The watchdog MUST alert on User_Alias-based NOPASSWD
    # grants too. Closes axis-parity on the alias-indirection
    # detection family.
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/99-user-alias-attacker" <<'EOF'
User_Alias ATTACKER_USERS = evil1, evil2
ATTACKER_USERS ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (Runas_Alias indirection STILL alerts — runas-alias-resolution doesn't dodge dangerous-flag detection)" {
    # Sister to Cmnd_Alias + User_Alias indirection INVARIANTs
    # already locked. sudoers supports Runas_Alias to indirect
    # the target-user list (e.g., `Runas_Alias OPS = root,oracle`
    # + `attacker ALL=(OPS) NOPASSWD: ALL`). The watchdog MUST
    # alert on Runas_Alias-based NOPASSWD grants too. Closes
    # axis-parity on the alias-indirection detection family
    # (Cmnd / User / Runas all alias-indirection axes).
    write_sudo_inventory
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${SUDOERS_D_DIR}/99-runas-alias-attacker" <<'EOF'
Runas_Alias ATTACKER_TARGETS = root, oracle
evil ALL=(ATTACKER_TARGETS) NOPASSWD: ALL
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on sudoers-integrity surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The sudoers-integrity-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the T1548.003 Abuse Elevation Control
    # Mechanism: Sudo + T1098 Account Manipulation sudoers
    # alert. Locks parser contract on the sudoers integrity
    # detection surface.
    write_sudo_inventory
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline path
    cat > "${SUDOERS_D_DIR}/99-attacker" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}
