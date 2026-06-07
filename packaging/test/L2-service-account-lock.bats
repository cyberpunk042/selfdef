#!/usr/bin/env bats
# L2 functional suite for service-account-lock.
#
# service-account-lock closes the "service-account-with-shell"
# vector. Many distros ship system accounts (UID < 1000) with
# interactive shells set (typically /bin/bash) — historically a
# debugging convenience, but a routine pre-attack pivot target.
# The module walks /etc/passwd and chsh's interactive shells to
# nologin (then passwd -l locks the password) for non-reserved
# UID<1000 accounts.
#
# Profiles:
#   audit   → walk; LOG findings; make NO changes
#   enforce → walk; for each non-reserved UID<1000 with an
#             interactive shell: record original shell in
#             ORIGINAL_LOG (single-shot — preserves operator
#             baseline through repeat applies), then chsh to
#             nologin AND passwd -l
#
# Reserved UIDs (operator-configurable via reserved_uids in
# the TOML — defaults to 0,1,2,3) are LEFT ALONE (root + bin
# + daemon + sys typically need a shell for system tasks).
#
# CRITICAL INVARIANTS:
#   - Original-shell-preserved: re-applying enforce on an
#     already-locked account does NOT overwrite the
#     ORIGINAL_LOG entry (so uninstall.sh can restore the
#     real baseline, not the current locked state).
#   - Already-nologin skipped: accounts whose shell is already
#     nologin/false don't get logged or modified.
#
# Adds SELFDEF_PASSWD_FILE env-var (added 2026-06-06) for L2
# testability. SELFDEF_SVC_ACCOUNT_LOG was already exposed.
# Live default unchanged.
#
# Run with: bats packaging/test/L2-service-account-lock.bats

WD="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/chsh" <<'CHEOF'
#!/usr/bin/env bash
printf 'chsh %s\n' "$*" >> "${CHSH_LOG}"
exit 0
CHEOF
    chmod +x "${BIN}/chsh"
    cat > "${BIN}/passwd" <<'PEOF'
#!/usr/bin/env bash
printf 'passwd %s\n' "$*" >> "${PASSWD_LOG}"
exit 0
PEOF
    chmod +x "${BIN}/passwd"
    export CHSH_LOG="${TMP}/chsh.log"
    export PASSWD_LOG="${TMP}/passwd.log"
    : > "${CHSH_LOG}"
    : > "${PASSWD_LOG}"
    CONF="${TMP}/service-account-lock.toml"
    PASSWD_FILE="${TMP}/passwd"
    ORIGINAL_LOG="${TMP}/service-accounts-original.txt"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [reserved_uids_csv]
write_config() {
    local profile="$1" reserved="${2:-0,1,2,3}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'reserved_uids = "%s"\n' "${reserved}" >> "${CONF}"
}

# Synthetic /etc/passwd. Mix:
#   root      uid=0    (reserved — leave alone)
#   daemon    uid=1    (reserved — leave alone)
#   nobody    uid=65534 (UID>=1000 in spirit; but the script's gate
#                       is `uid < 1000`, so uid=65534 may also slip
#                       past — leave it OUT to avoid test ambiguity)
#   www-data  uid=33   (non-reserved + bash → LOCK candidate)
#   smmsp     uid=51   (non-reserved + nologin → ALREADY LOCKED;
#                       skipped silently)
#   bin       uid=2    (reserved — leave alone)
#   alice     uid=1000 (operator-interactive — left alone)
write_synth_passwd() {
    cat > "${PASSWD_FILE}" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/bash
smmsp:x:51:51:Sendmail Mail Submission Program:/var/spool/mqueue:/usr/sbin/nologin
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
EOF
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    CHSH_LOG="${CHSH_LOG}" \
    PASSWD_LOG="${PASSWD_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SVC_ACCOUNT_CONFIG="${CONF}" \
    SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
    SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SVC_ACCOUNT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SVC_ACCOUNT_CONFIG="${SELFDEF_SVC_ACCOUNT_CONFIG}" \
        SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
        SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    write_synth_passwd
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SVC_ACCOUNT_CONFIG="${CONF}" \
        SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
        SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit|enforce"* ]]
}

@test "audit profile LOGS the www-data finding but does NOT chsh/passwd" {
    write_synth_passwd
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *"FOUND: www-data"* ]]
    # No chsh / passwd invocations.
    [ ! -s "${CHSH_LOG}" ]
    [ ! -s "${PASSWD_LOG}" ]
    # No ORIGINAL_LOG created in audit mode.
    ! [ -f "${ORIGINAL_LOG}" ]
}

@test "audit profile does NOT log already-nologin accounts (daemon, bin, smmsp)" {
    write_synth_passwd
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" != *"FOUND: daemon"* ]]
    [[ "${output}" != *"FOUND: bin"* ]]
    [[ "${output}" != *"FOUND: smmsp"* ]]
}

@test "audit profile does NOT log reserved UIDs (root with bash shell is reserved)" {
    write_synth_passwd
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" != *"FOUND: root"* ]]
}

@test "audit profile does NOT log operator-interactive accounts (alice uid=1000)" {
    write_synth_passwd
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" != *"FOUND: alice"* ]]
}

@test "enforce profile chsh www-data → nologin AND passwd -l + records original shell" {
    write_synth_passwd
    write_config "enforce"
    run_wd
    # chsh fired with nologin shell + www-data.
    grep -qE 'chsh.*-s.*nologin.*www-data' "${CHSH_LOG}"
    # passwd -l fired with www-data.
    grep -q 'passwd -l www-data' "${PASSWD_LOG}"
    # Original-shell log records the pre-lock state for uninstall.sh.
    [ -f "${ORIGINAL_LOG}" ]
    grep -q '^www-data /bin/bash$' "${ORIGINAL_LOG}"
}

@test "INVARIANT: ORIGINAL_LOG records ONLY the first-seen pre-lock state (single-shot baseline preservation)" {
    write_synth_passwd
    write_config "enforce"
    run_wd
    [ -f "${ORIGINAL_LOG}" ]
    pre_sha="$(sha256sum "${ORIGINAL_LOG}" | awk '{print $1}')"
    # Re-apply enforce — even though chsh is mocked to "succeed",
    # the original-shell record must NOT be overwritten.
    : > "${CHSH_LOG}"; : > "${PASSWD_LOG}"
    run_wd
    post_sha="$(sha256sum "${ORIGINAL_LOG}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT: enforce skips reserved UIDs even if they have an interactive shell (root uid=0)" {
    write_synth_passwd
    write_config "enforce"
    run_wd
    ! grep -q 'chsh.*root' "${CHSH_LOG}"
    ! grep -q 'passwd -l root' "${PASSWD_LOG}"
}

@test "INVARIANT: enforce skips operator-interactive accounts (UID>=1000)" {
    write_synth_passwd
    write_config "enforce"
    run_wd
    ! grep -q 'chsh.*alice' "${CHSH_LOG}"
    ! grep -q 'passwd -l alice' "${PASSWD_LOG}"
}

@test "INVARIANT: operator-customized reserved_uids list excludes named UIDs from locking" {
    write_synth_passwd
    # Treat www-data (uid=33) as reserved.
    write_config "enforce" "0,1,2,3,33"
    run_wd
    ! grep -q 'chsh.*www-data' "${CHSH_LOG}"
    ! grep -q 'passwd -l www-data' "${PASSWD_LOG}"
}

@test "INVARIANT: DRY_RUN does not chsh/passwd or write ORIGINAL_LOG" {
    write_synth_passwd
    write_config "enforce"
    DRY_RUN=1 run_wd
    [ ! -s "${CHSH_LOG}" ]
    [ ! -s "${PASSWD_LOG}" ]
    ! [ -f "${ORIGINAL_LOG}" ]
}

@test "default profile is audit (no profile key — conservative read-only default)" {
    write_synth_passwd
    : > "${CONF}"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *"FOUND: www-data"* ]]
    [ ! -s "${CHSH_LOG}" ]
    [ ! -s "${PASSWD_LOG}" ]
}

@test "emit_status reports audited + locked counts in JSON" {
    write_synth_passwd
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    # Only www-data triggers a lock (the other shell-having
    # account is root which is reserved).
    [[ "${output}" == *'audited=1'* ]]
    [[ "${output}" == *'locked=1'* ]]
}

@test "INVARIANT (multiple non-reserved interactive accounts: ALL get chsh + passwd -l)" {
    # Lock the multi-account coverage. Two non-reserved
    # interactive shells both should get neutralized.
    cat > "${PASSWD_FILE}" <<'EOF'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
postfix:x:114:121:postfix:/var/spool/postfix:/bin/sh
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
EOF
    write_config "enforce"
    run_wd
    # Both non-reserved interactive accounts get neutralized.
    grep -qE 'chsh.*-s.*nologin.*www-data' "${CHSH_LOG}"
    grep -qE 'chsh.*-s.*nologin.*postfix' "${CHSH_LOG}"
    grep -q 'passwd -l www-data' "${PASSWD_LOG}"
    grep -q 'passwd -l postfix' "${PASSWD_LOG}"
    # alice (UID>=1000) NOT touched.
    ! grep -q 'chsh.*alice' "${CHSH_LOG}"
}

@test "INVARIANT (audit JSON: audited=N + locked=0 contract — read-only invariant)" {
    write_synth_passwd
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'audited=1'* ]]
    # Audit mode MUST report locked=0 — never any actual locks.
    [[ "${output}" == *'locked=0'* ]]
}

@test "INVARIANT (chsh AND passwd both fire per account — atomicity contract; chsh-without-passwd-l leaves password active)" {
    # Locking the shell without locking the password leaves a
    # hole: an attacker with the password could still re-set the
    # shell via chsh. Both MUST fire per account.
    write_synth_passwd
    write_config "enforce"
    run_wd
    chsh_count="$(grep -c 'chsh.*www-data' "${CHSH_LOG}")"
    passwd_count="$(grep -c 'passwd -l www-data' "${PASSWD_LOG}")"
    [ "${chsh_count}" -ge 1 ]
    [ "${passwd_count}" -ge 1 ]
}

@test "INVARIANT (whitespace tolerance in reserved_uids CSV: '0, 1, 2, 3' with spaces normalized)" {
    # Operator may write the CSV with spaces. Parser must handle.
    write_synth_passwd
    printf 'profile = "enforce"\n' > "${CONF}"
    printf 'reserved_uids = "0, 1, 2, 3"\n' >> "${CONF}"
    run_wd
    # www-data (uid=33, not in reserved list with or without
    # whitespace) MUST get locked.
    grep -qE 'chsh.*-s.*nologin.*www-data' "${CHSH_LOG}"
    # root (uid=0, in reserved list) MUST NOT.
    ! grep -q 'chsh.*root' "${CHSH_LOG}"
}

@test "INVARIANT (emit_status JSON: module surfaced for operator dashboard)" {
    write_synth_passwd
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"service-account-lock"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
}

@test "INVARIANT (default reserved_uids 0,1,2,3 covers root + daemon + bin + sys — anti-deletion-by-empty-config)" {
    # An empty/missing reserved_uids value MUST default to 0,1,2,3.
    # Otherwise an empty reserved list would lock root → catastrophic.
    write_synth_passwd
    printf 'profile = "enforce"\n' > "${CONF}"      # NO reserved_uids
    run_wd
    # root (uid=0) MUST NOT be locked — default reserved list protects it.
    ! grep -q 'chsh.*root' "${CHSH_LOG}"
}

@test "INVARIANT (audit profile produces stable findings on identical input — deterministic enumeration)" {
    # Audit must produce same output across runs given same passwd.
    # Locks against non-deterministic ordering that would break
    # operator-dashboard diff-tracking.
    write_synth_passwd
    write_config "audit"
    output_first="$(run_wd 2>&1 | grep 'FOUND:')"
    output_second="$(run_wd 2>&1 | grep 'FOUND:')"
    [ "${output_first}" = "${output_second}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # service-account-lock TOML; parser must tolerate without
    # altering the profile-gated behavior. enforce-with-noise still
    # fires chsh + passwd -l on www-data (non-reserved UID<1000
    # with interactive shell) AND root-protection preserved (root in
    # default reserved_uids 0,1,2,3 NOT touched) — anti-bricking on
    # the system-account neutralization substrate.
    write_synth_passwd
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
reserved_uids = "0,1,2,3"
operator_note = "service-account-with-shell = pre-attack pivot vector"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -qE 'chsh.*-s.*nologin.*www-data' "${CHSH_LOG}"
    grep -q 'passwd -l www-data' "${PASSWD_LOG}"
    ! grep -q 'chsh.*root' "${CHSH_LOG}"
    ! grep -q 'passwd -l root' "${PASSWD_LOG}"
}

@test "INVARIANT (interactive-shell detection covers zsh/dash/ksh — not bash-only axis)" {
    # Sister to many other watchdog's shell-variant coverage
    # INVARIANTs across the brain. Attacker may set a non-bash
    # interactive shell (zsh/dash/ksh/fish) on a non-reserved
    # system account to dodge a bash-only detector. The neutralize
    # gate must fire on ANY interactive shell, not just /bin/bash
    # or /bin/sh. Locks the multi-shell axis on the service-account
    # neutralization substrate.
    cat > "${PASSWD_FILE}" <<'EOF'
root:x:0:0:root:/root:/bin/bash
zsh-user:x:40:40:zsh-svc:/var/svc:/bin/zsh
dash-user:x:41:41:dash-svc:/var/svc:/bin/dash
ksh-user:x:42:42:ksh-svc:/var/svc:/bin/ksh
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
EOF
    write_config "enforce"
    run_wd
    grep -qE 'chsh.*-s.*nologin.*zsh-user' "${CHSH_LOG}"
    grep -qE 'chsh.*-s.*nologin.*dash-user' "${CHSH_LOG}"
    grep -qE 'chsh.*-s.*nologin.*ksh-user' "${CHSH_LOG}"
    grep -q 'passwd -l zsh-user' "${PASSWD_LOG}"
    grep -q 'passwd -l dash-user' "${PASSWD_LOG}"
    grep -q 'passwd -l ksh-user' "${PASSWD_LOG}"
}

@test "INVARIANT (DRY_RUN does not fire any chsh / passwd -l)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The service-account-lock DRY_RUN path
    # MUST be a no-op against live state — operator using
    # --dry-run to preview expects ZERO mutations. Locks the
    # dry-run side-effect-freedom contract so a regression that
    # fires chsh or passwd -l through DRY_RUN would be caught
    # (silent account neutralization during preview would lock
    # out legitimate operator-intended users).
    write_synth_passwd
    write_config "enforce"
    DRY_RUN=1 run_wd
    ! [ -s "${CHSH_LOG}" ]
    ! [ -s "${PASSWD_LOG}" ]
}

@test "INVARIANT (sample/operator-readable account count surfaces in JSON — operator dashboard tracks scope)" {
    # Sister to many other installer module's acted=N JSON
    # INVARIANTs across the brain. The service-account-lock
    # apply emit_status JSON MUST carry a numeric count of how
    # many accounts were neutralized so operator dashboard
    # tracks scope of action. Without it, operators cannot
    # distinguish a zero-action no-op run from a successful
    # multi-account lockdown — both look identical in the
    # output. Locks operator observability contract on the
    # cleartext-shell-lockdown substrate.
    write_synth_passwd
    write_config "enforce"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_SVC_ACCOUNT_CONFIG="${CONF}" \
        SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
        SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
        CHSH_LOG="${CHSH_LOG}" \
        PASSWD_LOG="${PASSWD_LOG}" \
        bash "${WD}"
    # emit_status carries `locked=N` numeric count.
    [[ "${output}" =~ locked=[0-9] ]]
}
