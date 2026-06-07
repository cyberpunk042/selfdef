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

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on service-account-lock installer
    # surface across multi-account audit.
    write_synth_passwd
    write_config "audit"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_SVC_ACCOUNT_CONFIG="${CONF}" \
        SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
        SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
        CHSH_LOG="${CHSH_LOG}" \
        PASSWD_LOG="${PASSWD_LOG}" \
        bash "${WD}"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"service-account-lock"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no userdel/no account deletion — chsh/passwd-l ONLY, never remove /etc/passwd lines)" {
    # Sister to brain-wide no-auto-uninstall + no-data-loss
    # discipline. The service-account-lock module NEUTRALIZES
    # service accounts (chsh → nologin, passwd -l) but MUST
    # NEVER emit shell commands that DELETE accounts from
    # /etc/passwd (userdel, deluser). Account-removal is
    # operator-only — silent userdel during lockdown would
    # break package-uninstall-restore paths AND remove
    # forensic evidence. T1531 Account Access Removal (when
    # weaponized) is exactly what the lockdown discipline
    # must NOT do — neutralize, never erase.
    write_synth_passwd
    write_config "enforce"
    SYSCALL_LOG="${TMP}/userdel.log"
    : > "${SYSCALL_LOG}"
    cat > "${BIN}/userdel" <<UDEOF
#!/usr/bin/env bash
printf 'userdel %s\n' "\$*" >> "${SYSCALL_LOG}"
exit 0
UDEOF
    chmod +x "${BIN}/userdel"
    cat > "${BIN}/deluser" <<DLEOF
#!/usr/bin/env bash
printf 'deluser %s\n' "\$*" >> "${SYSCALL_LOG}"
exit 0
DLEOF
    chmod +x "${BIN}/deluser"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_SVC_ACCOUNT_CONFIG="${CONF}" \
        SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
        SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
        CHSH_LOG="${CHSH_LOG}" \
        PASSWD_LOG="${PASSWD_LOG}" \
        bash "${WD}"
    # userdel/deluser MUST NEVER have fired.
    ! [ -s "${SYSCALL_LOG}" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on service-account-lock surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The service-account-lock installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the service-account neutralization
    # status alert. Locks parser contract on the service-
    # account-lock installer JSON surface (consistency-with-
    # watchdog-family discipline).
    write_synth_passwd
    write_config "enforce"
    output=$(run env PATH="${BIN}:${PATH}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_SVC_ACCOUNT_CONFIG="${CONF}" \
        SELFDEF_PASSWD_FILE="${PASSWD_FILE}" \
        SELFDEF_SVC_ACCOUNT_LOG="${ORIGINAL_LOG}" \
        CHSH_LOG="${CHSH_LOG}" \
        PASSWD_LOG="${PASSWD_LOG}" \
        bash "${WD}" 2>&1)
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. service-account-lock manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the system-account chsh/passwd-l hardening. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'service-account-lock', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: service-account-lock installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # service-account-lock writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the service-account-lock
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # service-account-lock install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the service-account-lock lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the service-account-lock requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the service-account-lock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the service-account-lock module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the service-account-lock module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the service-account-lock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for service-account-lock is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the service-account-lock install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (service-account-lock module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the service-account-lock requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (service-account-lock module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the service-account-lock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the service-account-lock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (service-account-lock module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the service-account-lock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (service-account-lock module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (service-account-lock module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (service-account-lock module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (service-account-lock module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (service-account-lock README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (service-account-lock install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (service-account-lock install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (service-account-lock install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (service-account-lock install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (service-account-lock install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (service-account-lock install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (service-account-lock install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (service-account-lock install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (service-account-lock install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (service-account-lock install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (service-account-lock install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (service-account-lock install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (service-account-lock module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (service-account-lock module.toml exists at canonical path modules/service-account-lock/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/service-account-lock/module.toml"
    [ -f "${mtoml}" ]
}
