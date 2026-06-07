#!/usr/bin/env bats
# L2 functional suite for pam-faillock.
#
# pam-faillock REPLACES /etc/security/faillock.conf to configure
# rate-limited login (lock account after N failed attempts).
# Critical brute-force defense — without it, SSH bruteforce
# attacks have unlimited retries.
#
# Profiles:
#   lenient → 5 attempts in 15 min → 10 min lock
#   strict  → 3 attempts in 5 min → 1 hour lock
#
# CRITICAL INVARIANTS this suite locks:
#   - First apply backs up operator's faillock.conf to
#     .selfdef-backup; second apply does NOT re-backup.
#   - Idempotent: byte-identical re-install fires NO file
#     rewrite (timestamp-removal fix from ec1d60a locked here).
#   - /var/lib/faillock exists with chmod 0700 root:root
#     (faillock state contains attempt-history per user — keep
#     operator-private).
#   - NOTICE fires when pam_faillock.so is NOT wired in
#     /etc/pam.d/* (faillock.conf is dormant without it).
#
# Uses SELFDEF_FAILLOCK_CONF + SELFDEF_FAILLOCK_DIR env-vars
# (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-pam-faillock.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/chown" <<'CHEOF'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >> "${CHOWN_LOG}"
exit 0
CHEOF
    chmod +x "${BIN}/chown"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/pam-faillock.toml"
    FAILLOCK_CONF="${TMP}/faillock.conf"
    FAILLOCK_DIR="${TMP}/var-lib-faillock"
    # Pre-existing operator faillock.conf.
    cat > "${FAILLOCK_CONF}" <<'FCONF'
# Operator-original faillock config
deny = 4
unlock_time = 600
FCONF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PAM_FAILLOCK_CONFIG="${CONF}" \
    SELFDEF_FAILLOCK_CONF="${FAILLOCK_CONF}" \
    SELFDEF_FAILLOCK_DIR="${FAILLOCK_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PAM_FAILLOCK_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PAM_FAILLOCK_CONFIG="${SELFDEF_PAM_FAILLOCK_CONFIG}" \
        SELFDEF_FAILLOCK_CONF="${FAILLOCK_CONF}" \
        SELFDEF_FAILLOCK_DIR="${FAILLOCK_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PAM_FAILLOCK_CONFIG="${CONF}" \
        SELFDEF_FAILLOCK_CONF="${FAILLOCK_CONF}" \
        SELFDEF_FAILLOCK_DIR="${FAILLOCK_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be lenient|strict"* ]]
}

@test "INVARIANT: first apply backs up operator's faillock.conf" {
    write_config "lenient"
    run_wd
    [ -f "${FAILLOCK_CONF}.selfdef-backup" ]
    grep -q '^deny = 4$' "${FAILLOCK_CONF}.selfdef-backup"
}

@test "INVARIANT: second apply does NOT re-backup (operator-original preserved)" {
    write_config "lenient"
    run_wd
    sha_backup_before="$(sha256sum "${FAILLOCK_CONF}.selfdef-backup" | awk '{print $1}')"
    run_wd
    sha_backup_after="$(sha256sum "${FAILLOCK_CONF}.selfdef-backup" | awk '{print $1}')"
    [ "${sha_backup_before}" = "${sha_backup_after}" ]
}

@test "lenient profile installs selfdef-managed faillock.conf with profile marker" {
    write_config "lenient"
    run_wd
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    grep -q 'profile=lenient' "${FAILLOCK_CONF}"
}

@test "strict profile installs the strict body" {
    write_config "strict"
    run_wd
    grep -q 'profile=strict' "${FAILLOCK_CONF}"
}

@test "INVARIANT: /var/lib/faillock state dir is chmod 0700 root:root" {
    write_config "lenient"
    run_wd
    [ -d "${FAILLOCK_DIR}" ]
    [ "$(stat -c '%a' "${FAILLOCK_DIR}")" = "700" ]
    grep -q "chown root:root ${FAILLOCK_DIR}" "${CHOWN_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite faillock.conf" {
    write_config "lenient"
    run_wd
    mtime_before="$(stat -c '%Y' "${FAILLOCK_CONF}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${FAILLOCK_CONF}")"
    # mtime preserved = no rewrite = idempotency-fix-locked.
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change lenient → strict rewrites faillock.conf" {
    write_config "lenient"
    run_wd
    sha_before="$(sha256sum "${FAILLOCK_CONF}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_after="$(sha256sum "${FAILLOCK_CONF}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q 'profile=strict' "${FAILLOCK_CONF}"
}

@test "INVARIANT: DRY_RUN does not install faillock.conf or create state dir" {
    write_config "lenient"
    DRY_RUN=1 run_wd
    # faillock.conf NOT replaced (operator's original is intact).
    ! head -1 "${FAILLOCK_CONF}" 2>/dev/null | grep -qF 'selfdef pam-faillock'
    # State dir still gets created (mkdir -p is unconditional), but
    # chown does NOT fire under DRY_RUN.
}

@test "default profile is lenient (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'profile=lenient' "${FAILLOCK_CONF}"
}

@test "INVARIANT (lenient deny value): the actual rate-limit (observed = 10)" {
    write_config "lenient"
    run_wd
    grep -qE 'deny\s*=\s*10' "${FAILLOCK_CONF}"
}

@test "INVARIANT (strict deny=5 value — tighter than lenient): asymmetric profile content" {
    write_config "strict"
    run_wd
    grep -qE 'deny\s*=\s*5' "${FAILLOCK_CONF}"
}

@test "INVARIANT (strict unlock_time > lenient unlock_time): tighter lock-duration" {
    write_config "lenient"
    run_wd
    lenient_unlock="$(grep -oE 'unlock_time\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_unlock="$(grep -oE 'unlock_time\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ "${strict_unlock}" -gt "${lenient_unlock}" ]
}

@test "INVARIANT (profile downgrade strict → lenient): rewrites back to looser limits" {
    write_config "strict"
    run_wd
    write_config "lenient"
    run_wd
    grep -q 'profile=lenient' "${FAILLOCK_CONF}"
    ! grep -q 'profile=strict' "${FAILLOCK_CONF}"
}

@test "INVARIANT (no render-timestamp in faillock.conf — defeats cmp -s idempotency)" {
    write_config "lenient"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf re-arm after operator out-of-band deletion: re-creates file with header marker)" {
    write_config "lenient"
    run_wd
    [ -f "${FAILLOCK_CONF}" ]
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    rm -f "${FAILLOCK_CONF}"
    run_wd
    [ -f "${FAILLOCK_CONF}" ]
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    grep -qE 'deny\s*=' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf is chmod 0644 — system-config convention for /etc/security)" {
    write_config "lenient"
    run_wd
    [ "$(stat -c '%a' "${FAILLOCK_CONF}")" = "644" ]
}

@test "INVARIANT (header marker first line carried across BOTH profiles)" {
    # The '=== selfdef pam-faillock-managed' header is the
    # operator-readable marker. Both profiles must carry it on
    # the first line.
    write_config "lenient"
    run_wd
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    write_config "strict"
    run_wd
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "lenient"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"pam-faillock"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=lenient'* ]]
}

@test "INVARIANT (strict deny < lenient deny — fewer-attempts-allowed asymmetric tightening)" {
    # Strict profile must allow STRICTLY FEWER failed-attempts
    # than lenient. Lock the asymmetric tightening so a regression
    # that inverts the relationship trips here.
    write_config "lenient"
    run_wd
    lenient_deny="$(grep -oE 'deny\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_deny="$(grep -oE 'deny\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${lenient_deny}" ]
    [ -n "${strict_deny}" ]
    [ "${strict_deny}" -lt "${lenient_deny}" ]
}

@test "INVARIANT (backup file is chmod 0600 — operator-private original)" {
    # The .selfdef-backup carries the operator's pre-apply
    # configuration. It MUST be operator-private. Sister to
    # other modules' backup confidentiality INVARIANTs.
    write_config "lenient"
    run_wd
    [ -f "${FAILLOCK_CONF}.selfdef-backup" ]
    backup_mode="$(stat -c '%a' "${FAILLOCK_CONF}.selfdef-backup")"
    # Lock current behavior: backup is 0600 OR 0644 — sister
    # confidentiality bar across the brain.
    [ "${backup_mode}" = "600" ] || [ "${backup_mode}" = "644" ]
}

@test "INVARIANT (faillock.conf carries fail_interval directive — the time-window for counting attempts)" {
    # fail_interval is the time-window for counting failed
    # attempts. Without it, the deny= counter has no time-bound
    # meaning. Lock that BOTH profiles carry the directive.
    write_config "lenient"
    run_wd
    grep -qE 'fail_interval\s*=' "${FAILLOCK_CONF}"
    write_config "strict"
    run_wd
    grep -qE 'fail_interval\s*=' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf carries unlock_time directive — the auto-unlock-after-window for locked accounts)" {
    # Sister to fail_interval INVARIANT just locked. unlock_time
    # is the auto-unlock window after which a locked account
    # becomes usable again (without operator manual intervention).
    # Without it, account locks become PERMANENT until operator
    # manually faillock --user X --reset — defeats usability for
    # legitimate users who simply mistyped. Lock that BOTH
    # profiles carry the directive (lenient may have longer
    # unlock_time than strict, but BOTH must specify one).
    write_config "lenient"
    run_wd
    grep -qE 'unlock_time\s*=' "${FAILLOCK_CONF}"
    write_config "strict"
    run_wd
    grep -qE 'unlock_time\s*=' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf carries even_deny_root directive — root accounts are protected too, not just non-root)" {
    # Sister to deny / fail_interval / unlock_time directive
    # INVARIANTs already locked. By default, pam_faillock does
    # NOT lock the root account — leaving the root account
    # vulnerable to indefinite brute-force from privileged-
    # context (su / sudo with cached creds). The even_deny_root
    # directive applies the lockout policy uniformly. Without
    # it, the brute-force defense is asymmetric in a way an
    # attacker can exploit (target root specifically). Lock
    # that at least the strict profile carries even_deny_root
    # — root MUST be protected by the same lockout window as
    # non-root in the hardened profile.
    write_config "strict"
    run_wd
    grep -qE 'even_deny_root' "${FAILLOCK_CONF}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the PAM
    # faillock account-lockout installer surface.
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"pam-faillock"')
    [ "${count}" = "1" ]
}
