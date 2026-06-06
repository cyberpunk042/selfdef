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
