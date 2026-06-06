#!/usr/bin/env bats
# L2 functional + capture-regression suite for ssh-authkeys-watchdog.
#
# ssh-authkeys-watchdog is the MITRE T1098.004 sentry — the single
# most common Linux persistence vector is dropping a public key into
# a user's authorized_keys for backdoored passwordless SSH access.
# This watchdog hashes the base64 key body (comment-independent) of
# every user's authorized_keys{,2} + the central authorized_keys.d
# into a baseline, then alerts on a NEW key.
#
# Severity:
#   ok    → no delta
#   warn  → a key REMOVED only (post-hoc cleanup)
#   alert → a key ADDED (the persistence signature)
#
# What this suite locks:
#   - INVENTORY-CAPTURE regression (existing) — `emit_keys` must
#     write records to `$current` not stdout; the 2026-05-27 bug
#     left the baseline empty and a new key was NEVER detected
#   - Synthetic-passwd fixture surfaces every user's authorized_keys
#     in the baseline with the user, file path, and 32-char sha256
#     prefix of the base64 body
#   - Comment-independent hashing: a key with the same body but
#     different comment hashes to the SAME fp → no_delta
#   - Central authorized_keys.d surface: a key dropped there is
#     captured under the `central:<basename>` synthetic user
#   - DELTA detect: ADDED key (drop-into-existing file) → alert
#   - DELTA detect: ADDED file (new user's first key) → alert
#   - DELTA detect: REMOVED key → warn (post-hoc cleanup; not alert)
#   - ENFORCE profile: addition → exit-1 (failure surface for systemd
#     unit alerting); removal → exit-0 (operator cleanup is OK)
#   - REPORT profile: any delta → exit-0 (log-only)
#
# Adds SELFDEF_AUTHKEYS_PASSWD_FILE + SELFDEF_AUTHKEYS_CENTRAL_DIR
# env-var overrides (added 2026-06-06) for L2 delta-testability.
# Live defaults unchanged.
#
# Run with: bats packaging/test/L2-ssh-authkeys-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd/ssh-authkeys-watchdog.sh"

# Two valid ED25519-shape fixture keys (base64 body differs).
KEY_ALICE='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlIceFiXTUREbody1ForUnitTest selfdef-l2-alice'
KEY_BOB='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoBfixturebody2forunittests0001 selfdef-l2-bob'
KEY_EVIL='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEv1Lfixturebody3attackerpersist1 selfdef-l2-evil'

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
    BASELINE="${TMP}/ssh-authkeys-baseline.tsv"
    PASSWD_FILE="${TMP}/passwd"
    HOMES_ROOT="${TMP}/homes"
    CENTRAL_DIR="${TMP}/authorized_keys.d"
    mkdir -p "${HOMES_ROOT}/alice/.ssh" "${HOMES_ROOT}/bob/.ssh" "${CENTRAL_DIR}"
    # Synthetic /etc/passwd pointing at our test homes.
    cat > "${PASSWD_FILE}" <<EOF
alice:x:1000:1000:Alice:${HOMES_ROOT}/alice:/bin/bash
bob:x:1001:1001:Bob:${HOMES_ROOT}/bob:/bin/bash
EOF
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_AUTHKEYS_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUTHKEYS_BASELINE="${BASELINE}" \
    SELFDEF_AUTHKEYS_PASSWD_FILE="${PASSWD_FILE}" \
    SELFDEF_AUTHKEYS_CENTRAL_DIR="${CENTRAL_DIR}" \
    bash "${WD}"
}

run_wd_rc() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_AUTHKEYS_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUTHKEYS_BASELINE="${BASELINE}" \
    SELFDEF_AUTHKEYS_PASSWD_FILE="${PASSWD_FILE}" \
    SELFDEF_AUTHKEYS_CENTRAL_DIR="${CENTRAL_DIR}" \
    bash "${WD}" >/dev/null 2>&1
    echo $?
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Helper: write each user's starting authorized_keys.
plant_baseline_keys() {
    printf '%s\n' "${KEY_ALICE}" > "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    printf '%s\n' "${KEY_BOB}" > "${HOMES_ROOT}/bob/.ssh/authorized_keys"
}

@test "first run captures the planted authorized keys into the baseline (capture-regression lock)" {
    plant_baseline_keys
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # Each record is <user>\t<file>\t<fp32> — at least one well-formed row.
    awk -F'\t' 'NF>=3{ok=1} END{exit ok?0:1}' "${BASELINE}"
    # Both users surface.
    grep -qP '^alice\t' "${BASELINE}"
    grep -qP '^bob\t' "${BASELINE}"
    cap | grep -qE '"baseline_count":[2-9]'
}

@test "baseline is chmod 0600 (confidentiality — SSH key fingerprints are sensitive)" {
    plant_baseline_keys
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (comment-independent hashing): same body + different comment → same fp → no_delta" {
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Rewrite alice's key with a DIFFERENT comment but the same body.
    cat > "${HOMES_ROOT}/alice/.ssh/authorized_keys" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlIceFiXTUREbody1ForUnitTest renamed-comment-doesnt-mask
EOF
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "central authorized_keys.d surface — a key in /etc/ssh/authorized_keys.d/ is captured under central:<basename>" {
    plant_baseline_keys
    printf '%s\n' "${KEY_BOB}" > "${CENTRAL_DIR}/operator-shared"
    run_wd
    grep -qP '^central:operator-shared\t' "${BASELINE}"
}

@test "DELTA detect — ADDED key (drop into EXISTING file) → alert / authorized_key_added (the canonical MITRE T1098.004 case)" {
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker appends a backdoor key to alice's existing file.
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"added":1'
}

@test "DELTA detect — ADDED file (first key for a user who had none) → alert / authorized_key_added" {
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker creates a new user's first authorized_keys.
    mkdir -p "${HOMES_ROOT}/alice/.ssh"
    cat > "${PASSWD_FILE}" <<EOF
alice:x:1000:1000:Alice:${HOMES_ROOT}/alice:/bin/bash
bob:x:1001:1001:Bob:${HOMES_ROOT}/bob:/bin/bash
evil:x:1002:1002:Evil:${HOMES_ROOT}/evil:/bin/bash
EOF
    mkdir -p "${HOMES_ROOT}/evil/.ssh"
    printf '%s\n' "${KEY_EVIL}" > "${HOMES_ROOT}/evil/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"authorized_key_added"'
}

@test "DELTA detect — REMOVED key → warn / authorized_key_removed (post-hoc cleanup, not alert)" {
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Operator removes bob's key.
    rm -f "${HOMES_ROOT}/bob/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"event":"authorized_key_removed"'
    cap | grep -q '"severity":"warn"'
}

@test "ENFORCE profile: ADDED key → exit-1 (failure surface for systemd unit alerting)" {
    plant_baseline_keys
    PROFILE=report run_wd
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "1" ]
}

@test "ENFORCE profile: REMOVED-only delta → exit-0 (operator cleanup is OK, no alert escalation)" {
    plant_baseline_keys
    PROFILE=report run_wd
    rm -f "${HOMES_ROOT}/bob/.ssh/authorized_keys"
    rc="$(PROFILE=enforce run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "REPORT profile: ADDED key → exit-0 (log-only — journald is the surface)" {
    plant_baseline_keys
    PROFILE=report run_wd
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    rc="$(PROFILE=report run_wd_rc)"
    [ "${rc}" = "0" ]
}

@test "INVARIANT (no auto-trust): ssh-authkeys-watchdog does NOT refresh the baseline on delta — every subsequent run re-reports the alert until operator updates the baseline" {
    # CONTRAST with group-integrity-watchdog (which DOES auto-refresh).
    # New SSH keys are NEVER routine; the alert must STAY visible.
    plant_baseline_keys
    PROFILE=report run_wd
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    PROFILE=report run_wd                                  # first delta run
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=report run_wd                                  # alert STAYS
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (added_sample carries user:file: with the SPECIFIC user for forensics)" {
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    # User name surfaces in the JSON sample (alice was the target).
    cap | grep -q 'alice'
}

@test "INVARIANT (authorized_keys2 surface — legacy filename ALSO captured): backward-compat axis" {
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker drops legacy authorized_keys2 file (old OpenSSH protocol).
    printf '%s\n' "${KEY_EVIL}" > "${HOMES_ROOT}/alice/.ssh/authorized_keys2"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (compound delta — 1 added AND 1 removed → alert; the added wins)" {
    # Realistic attacker rotation: add backdoor key + remove operator's
    # legitimate key. The added-key signature must escalate to alert
    # regardless of the simultaneous removal.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${HOMES_ROOT}/bob/.ssh/authorized_keys"
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (central directory: NEW central key dropped → alert)" {
    # Distinct from per-user authorized_keys: a key dropped in central
    # authorized_keys.d is also a persistence vector. Lock that the
    # central axis fires the same alert path.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s\n' "${KEY_EVIL}" > "${CENTRAL_DIR}/attacker-shared"
    run_wd
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    plant_baseline_keys
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ssh-authkeys -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (commented key NOT flagged: # prefix filtered from key inventory)" {
    # authorized_keys files use # as comment marker. Operator notes
    # about future keys must NOT surface as real keys.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a commented evil key.
    printf '# %s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    # Severity must NOT be alert (no real key added).
    ! cap | grep -q '"event":"authorized_key_added"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-key addition: 2 keys added to same authorized_keys → still single alert event)" {
    # When an attacker plants multiple keys at once, the alert
    # fires once (not per-key). Locks the consolidation.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add 2 distinct keys to alice's file.
    printf '%s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEv2Lfixturebody4attackerpersist2 evil2\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":2'
    # Single JSON record (SDD-062 contract preserved).
    main_count=$(cap | grep -cE '^-t selfdef-ssh-authkeys -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_AUTHKEYS_PROFILE)" {
    plant_baseline_keys
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (rsa-key algorithm axis: ssh-rsa key also surfaces as alert — algorithm-agnostic detection)" {
    # The watchdog must catch ALL SSH key algorithms, not just
    # ed25519. RSA + ECDSA + Ed25519 are all valid SSH key types
    # with same persistence semantics.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add an RSA key (different algorithm prefix).
    printf 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakeRSAkeyfortestpurposes attacker-rsa-key\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
}
