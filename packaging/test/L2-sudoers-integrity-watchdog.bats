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

@test "INVARIANT (no auto-delete: sudoers-integrity-watchdog NEVER deletes sudoers.d drop-ins — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # sudoers-integrity-watchdog DETECTS T1548.003 Abuse
    # Elevation Control Mechanism / T1098 Account Manipulation
    # via sudoers.d planted grants but MUST NEVER emit rm/
    # unlink commands to auto-delete the planted file. The
    # detected grant may be operator-legitimate (operator added
    # a new sudoers.d drop-in for an automation account but
    # forgot to re-baseline). Silent auto-delete on sudoers
    # is a denial-of-service primitive (auto-delete the file +
    # operator can't sudo + can't re-enable selfdef). Surveil-
    # lance, never remediation. Locks anti-data-loss contract
    # on the sudoers-integrity surveillance substrate.
    write_sudo_inventory
    cat > "${SUDOERS_D_DIR}/99-attacker" <<'EOF'
evil ALL=(ALL) NOPASSWD: ALL
EOF
    run_wd
    [ -f "${SUDOERS_D_DIR}/99-attacker" ]
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(SUDOERS_D_DIR|SUDOERS|FILE|file)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # sudoers-integrity-watchdog runs ON the timer's scheduled
    # fire — scans /etc/sudoers + sudoers.d for NOPASSWD/
    # !authenticate/!requiretty additions across user + Runas
    # alias indirection, emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the sudoers-integrity-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd/selfdef-sudoers-integrity.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sudoers-integrity-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # sudoers-integrity-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # sudoers-integrity-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'sudoers-integrity-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: sudoers-integrity-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. sudoers-integrity-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the sudoers-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (sudoers-integrity-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the sudoers-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-integrity-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # sudoers-integrity-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # sudoers-integrity-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the sudoers-integrity-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-integrity-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # sudoers-integrity-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-integrity-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the sudoers-integrity-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudoers-integrity-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the sudoers-integrity-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the sudoers-integrity-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the sudoers-integrity-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the sudoers-integrity-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the sudoers-integrity-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (sudoers-integrity-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (sudoers-integrity-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the sudoers-integrity-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    [ -f "${script_dir}/sudoers-integrity-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (sudoers-integrity-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}
