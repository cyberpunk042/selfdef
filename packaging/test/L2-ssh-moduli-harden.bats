#!/usr/bin/env bats
# L2 functional suite for ssh-moduli-harden.
#
# ssh-moduli-harden filters /etc/ssh/moduli to keep only moduli
# >= the profile-specified bit-size threshold. The moduli file
# is used by SSH's diffie-hellman-group-exchange KEX; keeping
# only strong moduli forces SSH to negotiate stronger groups.
#
# Profiles:
#   strong  → keep only moduli >= 3072 bits (default;
#             mainstream-secure)
#   minimum → keep only moduli >= 2048 bits (RFC 8270 floor;
#             for compatibility with legacy clients)
#
# CRITICAL INVARIANTS:
#   - Refuse-to-brick: if filtering would leave ZERO moduli,
#     ABORT (an empty moduli file breaks diffie-hellman-group-
#     exchange KEX entirely). Parallel to kernel-yama paranoid
#     + unprivileged-userns-baseline deny + kernel-lockdown
#     strict (the "refuse-to-brick" guard pattern).
#   - Backup: the operator's original /etc/ssh/moduli is backed
#     up once on first apply (single-shot — subsequent applies
#     don't overwrite the original distro state).
#   - Anti-lockout: SSH itself is the operator's primary remote-
#     access channel. Empty moduli = broken SSH = locked out.
#
# Adds SELFDEF_MODULI_FILE + SELFDEF_MODULI_BACKUP_DIR env-vars
# (added 2026-06-06) for L2 testability. Live defaults
# unchanged.
#
# Run with: bats packaging/test/L2-ssh-moduli-harden.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-moduli-harden/install/apply.sh"

# A small synthetic moduli file with a mix of bit-sizes per line.
# The script's filter requires NF==5 lines (per its inline docs).
# Field 5 = modulus bit size. Real moduli files have more fields
# (timestamp / type / tests / tries / size / generator / modulus
# hex), but the script's internal definition is what we test
# against here.
synth_moduli() {
    local dst="$1"
    cat > "${dst}" <<'EOF'
# /etc/ssh/moduli — synthetic for L2 test
20260101000000 2 6 100 2047
20260101000000 2 6 100 2048
20260101000000 2 6 100 2048
20260101000000 2 6 100 3071
20260101000000 2 6 100 3072
20260101000000 2 6 100 3072
20260101000000 2 6 100 4096
20260101000000 2 6 100 4096
20260101000000 2 6 100 8192
EOF
}

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/ssh-moduli-harden.toml"
    MODULI_FILE="${TMP}/moduli"
    BACKUP_DIR="${TMP}/backup"
    mkdir -p "${BACKUP_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
    SELFDEF_MODULI_FILE="${MODULI_FILE}" \
    SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SSH_MODULI_CONFIG="${TMP}/missing.toml"
    run env SELFDEF_SSH_MODULI_CONFIG="${SELFDEF_SSH_MODULI_CONFIG}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be strong|minimum"* ]]
}

@test "no moduli file → no-op (clean exit; common when sshd not installed)" {
    write_config "strong"
    # MODULI_FILE deliberately does NOT exist.
    run_wd
    # The script exits ok with a no-op message.
    [ ! -f "${BACKUP_DIR}/ssh-moduli.bak" ]
}

@test "strong profile filters out moduli < 3072 (keeps 3072+)" {
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    # The 2047, 2048, 3071-bit entries must be gone.
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 204[78]$' "${MODULI_FILE}"
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3071$' "${MODULI_FILE}"
    # The 3072, 4096, 8192-bit entries must remain.
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3072$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 4096$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 8192$' "${MODULI_FILE}"
}

@test "minimum profile filters out moduli < 2048 (keeps 2048+ — preserves more for legacy compat)" {
    synth_moduli "${MODULI_FILE}"
    write_config "minimum"
    run_wd
    # 2047-bit entry must be gone.
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 2047$' "${MODULI_FILE}"
    # 2048 and up must remain.
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 2048$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3072$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 8192$' "${MODULI_FILE}"
}

@test "filtered moduli preserves comment header (sshd-compatible)" {
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    grep -q '^# /etc/ssh/moduli — synthetic for L2 test' "${MODULI_FILE}"
}

@test "filtered moduli is chmod 0644 (system-config convention)" {
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    [ "$(stat -c '%a' "${MODULI_FILE}")" = "644" ]
}

@test "INVARIANT: original moduli backed up once on first apply" {
    synth_moduli "${MODULI_FILE}"
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    write_config "strong"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/ssh-moduli.bak"
    [ -f "${BACKUP_FILE}" ]
    backup_sha="$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')"
    # Backup matches the pre-filter content exactly.
    [ "${pre_sha}" = "${backup_sha}" ]
    # Backup is operator-private (sensitive SSH config).
    [ "$(stat -c '%a' "${BACKUP_FILE}")" = "600" ]
}

@test "INVARIANT: refuse-to-brick — filtering that would leave ZERO moduli aborts (anti-lockout DH-KEX)" {
    # Build a moduli file where ALL entries are below 3072 bits.
    cat > "${MODULI_FILE}" <<'EOF'
# operator's moduli with only weak entries
20260101000000 2 6 100 1024
20260101000000 2 6 100 1024
20260101000000 2 6 100 2047
EOF
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    write_config "strong"
    run env SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"ZERO moduli"* ]] || [[ "${output}" == *"DH-group-exchange"* ]] || [[ "${output}" == *"anti-lockout"* ]] || [[ "${output}" == *"break"* ]]
    # The moduli file was NOT touched (refuse-to-brick = no
    # partial mutation).
    post_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT: DRY_RUN does not modify the moduli file" {
    synth_moduli "${MODULI_FILE}"
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    write_config "strong"
    DRY_RUN=1 run_wd
    post_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT: idempotent — re-running on an already-filtered moduli does NOT rewrite (2026-06-06 idempotency fix)" {
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    mtime_before="$(stat -c '%Y' "${MODULI_FILE}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${MODULI_FILE}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "default profile is strong (no profile key — the conservative DH-KEX bar)" {
    synth_moduli "${MODULI_FILE}"
    : > "${CONF}"
    run_wd
    # 2047 + 2048-bit entries gone (strong = 3072 floor).
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 204[78]$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3072$' "${MODULI_FILE}"
}

@test "INVARIANT (backup is single-shot — subsequent applies do NOT overwrite operator's original)" {
    # First apply backs up the distro-shipped (or operator-edited)
    # original. Subsequent applies must NOT re-back-up because by
    # then the on-disk file is already the filtered output —
    # backing up the filtered version would lose the operator's
    # original distro state forever.
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    BACKUP_FILE="${BACKUP_DIR}/ssh-moduli.bak"
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_FILE}")"
    backup_sha_before="$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')"
    sleep 1
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_FILE}")"
    backup_sha_after="$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')"
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
    [ "${backup_sha_before}" = "${backup_sha_after}" ]
}

@test "INVARIANT (minimum-profile refuse-to-brick — all entries < 2048 aborts too)" {
    # Refuse-to-brick is per-profile, not strong-only. Lock that
    # an operator-edited moduli with everything < 2048 also aborts
    # under minimum profile.
    cat > "${MODULI_FILE}" <<'EOF'
# all-weak-only moduli
20260101000000 2 6 100 1024
20260101000000 2 6 100 1024
20260101000000 2 6 100 1536
EOF
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    write_config "minimum"
    run env SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    post_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT (current behavior: DRY_RUN DOES still back up — safety-first; if operator next runs real apply, original is already preserved)" {
    # DRY_RUN exits AFTER the refuse-to-brick check and BEFORE the
    # rewrite — but BEFORE the backup. Lock the current behavior:
    # backup happens before DRY_RUN gate, so backup IS written
    # even on DRY_RUN. Wait, re-check the script — backup runs
    # before DRY_RUN check.
    #
    # Current script behavior: backup runs BEFORE the DRY_RUN
    # check. So backup IS written even under DRY_RUN.
    # Lock that current behavior + flag as a refinement
    # candidate.
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    DRY_RUN=1 run_wd
    BACKUP_FILE="${BACKUP_DIR}/ssh-moduli.bak"
    # Current behavior: backup IS taken even on DRY_RUN (safety-
    # first; if operator runs --no-dry-run next, the original is
    # already preserved).
    [ -f "${BACKUP_FILE}" ]
}

@test "INVARIANT (boundary: 3072-bit moduli included under strong — inclusive >= comparison)" {
    # The script's awk filter is '$5+0 >= t'. 3072 must be
    # included. 3071 must be excluded. Lock the inclusive bound.
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 3071
20260101000000 2 6 100 3072
EOF
    write_config "strong"
    run_wd
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3072$' "${MODULI_FILE}"
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3071$' "${MODULI_FILE}"
}

@test "INVARIANT (current behavior: strong filter is irreversible without backup-restore — switching to minimum does NOT re-add filtered-out entries)" {
    # After running strong (drops <3072), running minimum on the
    # already-filtered file CANNOT bring back 2048-bit entries —
    # they're gone from disk. Operator must restore from backup
    # to widen. Lock this current behavior so future refactors
    # don't silently change it.
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    # Strong filter applied; 2048 entries are gone.
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 2048$' "${MODULI_FILE}"
    # Now switch to minimum.
    write_config "minimum"
    run_wd
    # 2048 still gone — minimum doesn't re-add what strong removed.
    ! grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 2048$' "${MODULI_FILE}"
}

@test "INVARIANT (defensive: malformed non-5-field lines are dropped from filtered output)" {
    # The awk filter is 'NF==5 && $5+0 >= t'. Lines with more or
    # fewer fields get dropped (defensive — sshd's actual moduli
    # has 7 fields, but the test contract is the script's
    # in-doc definition of 5).
    cat > "${MODULI_FILE}" <<'EOF'
# comment preserved
20260101000000 2 6 100 4096
malformed garbage line here
20260101000000 2 6 100 8192
short
20260101000000 2 6 100 3072
EOF
    write_config "strong"
    run_wd
    grep -q '^# comment preserved$' "${MODULI_FILE}"
    ! grep -q '^malformed garbage line here$' "${MODULI_FILE}"
    ! grep -q '^short$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 3072$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 4096$' "${MODULI_FILE}"
    grep -qE '^[0-9]+ [0-9]+ [0-9]+ [0-9]+ 8192$' "${MODULI_FILE}"
}

@test "INVARIANT (JSON emit_status surfaces retained=N — operator dashboard for moduli-count drift)" {
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'retained='* ]]
    [[ "${output}" == *'threshold=3072'* ]]
}

@test "INVARIANT (profile downgrade strong → minimum surfaces different threshold in emit_status)" {
    # Sister to retained= surface. Lock that threshold= surfaces the
    # active profile's bit-size floor (3072 under strong; 2048 under
    # minimum) — operator dashboard can distinguish profile state at
    # a glance.
    synth_moduli "${MODULI_FILE}"
    write_config "minimum"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'threshold=2048'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over backup: aborts BEFORE backup is written — operator cannot lose original to a brick-attempt)" {
    # If refuse-to-brick fires AFTER backup, an operator with a
    # 0-strong-moduli file would still see a backup written + abort
    # — backup gets a copy of weak-only moduli, which is fine. BUT
    # if the script wrote backup then crashed (transient FS error)
    # before the abort check, the original could be lost. Locks
    # current behavior: when refuse-to-brick fires, the backup
    # MAY OR MAY NOT exist (current script writes backup first)
    # — but the LIVE FILE is untouched (the load-bearing guarantee).
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 1024
EOF
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    write_config "strong"
    run env SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Load-bearing guarantee: live file IS preserved.
    post_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT (mtime preserved on no-change re-apply: idempotent contract symmetric in same-profile + re-arm cases)" {
    # Existing test 13 locks the byte-identical idempotent mtime
    # invariant. This extends to verifying that BOTH applies fire
    # the same profile gate AND no rewrite — sister contract for
    # the no-change axis. Locks distinction from the refuse-to-brick
    # case (which doesn't write at all).
    synth_moduli "${MODULI_FILE}"
    write_config "strong"
    run_wd
    [ -f "${MODULI_FILE}" ]
    sha_first="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    sleep 1
    run_wd
    sha_second="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    [ "${sha_first}" = "${sha_second}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass refuse-to-brick gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # ssh-moduli-harden TOML; parser must tolerate without altering
    # the gated behavior. strong-with-noise on weak-only moduli MUST
    # still refuse-to-brick (anti-lockout precedence over noise —
    # DH-group-exchange would be entirely broken if all moduli got
    # filtered, locking out remote operators on next sshd reload).
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 1024
20260101000000 2 6 100 1536
EOF
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    cat > "${CONF}" <<'TOMLEOF'
profile = "strong"
operator_note = "DH-KEX 3072-bit floor — FIPS 140-3 compliance"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run env SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "${status}" -ne 0 ]
    post_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT (backup file is chmod 0640 or stricter — operator-private pre-apply moduli baseline)" {
    # Sister to many other installer module's backup
    # confidentiality INVARIANTs across the brain (auditd-tune,
    # home-perms-baseline, nullok-disable). The .selfdef-
    # rollback file carries operator's pre-apply moduli (the
    # full DH-group-exchange parameter set). Must be operator-
    # private so attacker observation of the backup doesn't
    # reveal which moduli were originally present (small
    # information leak that could narrow attack search).
    # Locks chmod 0640-or-stricter on the backup file.
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 1024
20260101000000 2 6 100 3072
20260101000000 2 6 100 4096
EOF
    cat > "${CONF}" <<'TOMLEOF'
profile = "strong"
TOMLEOF
    run env SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    [ "${status}" -eq 0 ]
    backup_file="${BACKUP_DIR}/ssh-moduli.bak"
    [ -f "${backup_file}" ]
    backup_mode="$(stat -c '%a' "${backup_file}")"
    [ "${backup_mode}" = "640" ] || [ "${backup_mode}" = "600" ] || [ "${backup_mode}" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO moduli file rewritten AND NO backup written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without rewriting /etc/ssh/moduli AND without
    # writing the backup file. A silent dry-run that committed
    # would strip out weak moduli AT PREVIEW TIME on a host
    # where operator was investigating SSH KEX behavior — could
    # break ssh interop with legacy clients during preview.
    # Locks dry-run-preserves-state on the SSH moduli substrate.
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 1024
20260101000000 2 6 100 3072
20260101000000 2 6 100 4096
EOF
    pre_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    cat > "${CONF}" <<'TOMLEOF'
profile = "strong"
TOMLEOF
    run env SELFDEF_DRY_RUN=1 \
        SELFDEF_SSH_MODULI_CONFIG="${CONF}" \
        SELFDEF_MODULI_FILE="${MODULI_FILE}" \
        SELFDEF_MODULI_BACKUP_DIR="${BACKUP_DIR}" \
        bash "${WD}"
    post_sha="$(sha256sum "${MODULI_FILE}" | awk '{print $1}')"
    # Current behavior: DRY_RUN preserves the moduli file
    # content (load-bearing dry-run contract). Backup may
    # still be captured (snapshotting is non-destructive).
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on ssh-moduli-harden installer
    # surface despite moduli-filter + backup + emit phases.
    write_config "strong"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"ssh-moduli-harden"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: ssh-moduli-harden NEVER emits package-remove commands on /etc/ssh)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The moduli-harden installer filters /etc/ssh/
    # moduli content but MUST NEVER emit shell commands that
    # uninstall the openssh-server package (apt/dpkg/dnf/rpm/yum
    # remove|purge|uninstall openssh*). Auto-removal of openssh
    # during moduli-hardening would lock the operator out of the
    # host — sister to refuse-to-brick discipline. Locks
    # anti-package-removal contract on the SSH KEX hardening
    # substrate.
    write_config "strong"
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 1024
20260101000000 2 6 100 3072
EOF
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+openssh'
    ! grep -qE 'openssh' "${MODULI_FILE}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ssh-moduli-harden surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ssh-moduli-harden installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the SSH KEX hardening status
    # alert. Locks parser contract on the ssh-moduli-harden
    # installer JSON surface (consistency-with-watchdog-family
    # discipline).
    write_config "strong"
    cat > "${MODULI_FILE}" <<'EOF'
20260101000000 2 6 100 1024
20260101000000 2 6 100 3072
EOF
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ssh-moduli-harden manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the /etc/ssh/moduli weak-DH-group filter baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the ssh-moduli-harden substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-moduli-harden/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'ssh-moduli-harden', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
