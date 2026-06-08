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

@test "INVARIANT (ecdsa-key algorithm axis: ecdsa-sha2-nistp256 key also surfaces as alert — algorithm-agnostic detection)" {
    # Sister to rsa-axis INVARIANT. ECDSA is a third common SSH
    # key algorithm. Lock it specifically so a regression that
    # whitelists only rsa+ed25519 would trip here.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBfakeECDSAkeybodyfortest attacker-ecdsa\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -q '"event":"authorized_key_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (forced-command-option NOT bypassing detection: command= prefix on the line still surfaces the key as added)" {
    # SSH options like 'command=...' or 'no-pty' prefix the actual
    # key. An attacker may use them to restrict the key's use OR
    # to hide the key behind option-noise hoping naive grep misses
    # it. Lock that the watchdog still extracts + tracks the key.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a key with command= prefix (restricted-shell exec).
    printf 'command="/usr/bin/restricted-shell",no-pty %s\n' "${KEY_EVIL}" >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (root-user authorized_keys gets baselined + monitored — highest-value account on the system)" {
    # If root has authorized_keys, the watchdog MUST track it like
    # any other user. Lock that the synthetic-passwd fixture
    # supports root's home and the inventory captures it.
    cat > "${PASSWD_FILE}" <<EOF
root:x:0:0:root:${HOMES_ROOT}/root:/bin/bash
alice:x:1000:1000:Alice:${HOMES_ROOT}/alice:/bin/bash
EOF
    mkdir -p "${HOMES_ROOT}/root/.ssh"
    printf '%s\n' "${KEY_BOB}" > "${HOMES_ROOT}/root/.ssh/authorized_keys"
    plant_baseline_keys
    run_wd
    grep -qP '^root\t' "${BASELINE}"
}

@test "INVARIANT (sk-ssh-ed25519 hardware-token key algorithm axis: also surfaces as alert — algorithm-agnostic detection includes FIDO2/security-key keys)" {
    # Sister to ssh-ed25519 + ecdsa-sha2-nistp256 algorithm axes
    # already locked. The sk-* algorithm family (sk-ssh-ed25519,
    # sk-ecdsa-sha2-nistp256) represents FIDO2/hardware-token-
    # backed SSH keys — a modern + increasingly common key type
    # that attackers may legitimately attempt to plant if they
    # can pivot to a system with a hardware key. The detection
    # MUST be algorithm-agnostic — sk-* keys MUST also surface
    # as alert when added to a user's authorized_keys.
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'sk-ssh-ed25519@openssh.com AAAAFHNrLXNzaC1lZDI1NTE5QHt= attacker-fido2\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — added_sample surfaces user:fingerprint for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a new
    # SSH key to an authorized_keys file, the user-name + key
    # fingerprint MUST surface in the JSON added_sample so
    # operator dashboard routes triage to the right user +
    # the specific fingerprint identifies WHICH key. Locks
    # operator-visibility on the SSH key-grant surface
    # (T1098.004 — Account Manipulation: SSH Authorized Keys).
    plant_baseline_keys
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEW== distinctive-attacker-key\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    # added_sample carries user:fingerprint — at minimum the
    # user name surfaces.
    cap | grep -qE '"added_sample":"[^"]*alice'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1098.004 SSH authorized_keys
    # surveillance.
    plant_baseline_keys
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ssh-authkeys surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ssh-authkeys-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1098.004 Account Manipulation: SSH
    # Authorized Keys alert. Locks parser contract on the SSH
    # key-grant detection surface.
    plant_baseline_keys
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok path
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEW== attacker\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: ssh-authkeys-watchdog NEVER deletes authorized_keys entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # ssh-authkeys-watchdog DETECTS T1098.004 Account
    # Manipulation: SSH Authorized Keys but MUST NEVER emit
    # sed/awk/rm commands to auto-clean the planted key. The
    # detected key may be operator-legitimate (operator added
    # a deploy key for a new automation account) — silent auto-
    # delete would destroy operator baseline state AND
    # forensic evidence chain. Auto-delete on authorized_keys
    # is also a denial-of-service primitive (attacker plants a
    # key, watchdog auto-deletes the WHOLE file). Surveillance,
    # never remediation. Locks anti-data-loss contract on the
    # ssh-authkeys surveillance substrate.
    plant_baseline_keys
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEW== attacker\n' >> "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    run_wd
    # All authorized_keys files MUST remain on disk with content
    # intact.
    [ -f "${HOMES_ROOT}/alice/.ssh/authorized_keys" ]
    grep -q 'attacker' "${HOMES_ROOT}/alice/.ssh/authorized_keys"
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'sed[[:space:]]+-i.*/d' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # ssh-authkeys-watchdog runs ON the timer's scheduled fire —
    # diffs every user's ~/.ssh/authorized_keys against baseline,
    # emits a verdict on new-key additions (persistence-vector
    # axis), then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the ssh-authkeys-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd/selfdef-ssh-authkeys.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ssh-authkeys-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # ssh-authkeys-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # ssh-authkeys-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'ssh-authkeys-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: ssh-authkeys-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. ssh-authkeys-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the ssh-authkeys-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (ssh-authkeys-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the ssh-authkeys-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-authkeys-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # ssh-authkeys-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # ssh-authkeys-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the ssh-authkeys-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-authkeys-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # ssh-authkeys-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-authkeys-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the ssh-authkeys-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-authkeys-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the ssh-authkeys-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the ssh-authkeys-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the ssh-authkeys-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the ssh-authkeys-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit declares OnBootSec= — boot-catchup-delay contract)" {
    # Sister to brain-wide systemd OnBootSec= INVARIANT
    # family. Watchdog .timer units MUST declare OnBootSec=
    # so the first watchdog fire is delayed until after boot
    # finishes settling. Locks the boot-catchup-delay
    # discipline on the ssh-authkeys-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnBootSec=' "${t}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the ssh-authkeys-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    [ -f "${script_dir}/ssh-authkeys-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (ssh-authkeys-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (ssh-authkeys-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script tag selfdef-ssh-authkeys matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-ssh-authkeys
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .timer file exists at canonical path modules/ssh-authkeys-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml exists at canonical path modules/ssh-authkeys-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (ssh-authkeys-watchdog systemd dir exists at modules/ssh-authkeys-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (ssh-authkeys-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-authkeys-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (ssh-authkeys-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (ssh-authkeys-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (ssh-authkeys-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"ssh-authkeys-watchdog"' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
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

@test "INVARIANT (ssh-authkeys-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (ssh-authkeys-watchdog module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-authkeys-watchdog/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}
