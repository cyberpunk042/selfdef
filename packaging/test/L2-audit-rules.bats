#!/usr/bin/env bats
# L2 functional suite for audit-rules.
#
# audit-rules writes selfdef rule files (50-selfdef-base.rules
# and optionally 50-selfdef-paranoid.rules) to /etc/audit/rules.d
# and runs `augenrules --load` to atomic-swap the live rule set.
#
# Profiles:
#   base     → install 50-selfdef-base.rules only
#   paranoid → install BOTH base + paranoid (augenrules
#              concatenates by filename sort)
#
# CRITICAL INVARIANTS this suite locks:
#   - Only touches files prefixed `50-selfdef-*` — operator-
#     authored rules in the same dir are PRESERVED.
#   - Profile downgrade paranoid → base REMOVES the paranoid
#     file (no stale rules carrying paranoid restrictions when
#     the operator deliberately backed off).
#   - Idempotent: byte-identical re-install fires NO augenrules
#     --load.
#   - DRY_RUN protects file install + augenrules.
#
# Uses SELFDEF_AUDIT_RULES_DIR + SELFDEF_AUDIT_RULES_SRC env-vars
# (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-audit-rules.bats

WD="${BATS_TEST_DIRNAME}/../../modules/audit-rules/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/augenrules" <<'AEOF'
#!/usr/bin/env bash
printf 'augenrules %s\n' "$*" >> "${AUGEN_LOG}"
exit 0
AEOF
    chmod +x "${BIN}/augenrules"
    export AUGEN_LOG="${TMP}/augen.log"
    : > "${AUGEN_LOG}"
    CONF="${TMP}/audit-rules.toml"
    RULES_DIR="${TMP}/audit-rules.d"
    RULES_SRC="${TMP}/audit-rules-src"
    mkdir -p "${RULES_DIR}" "${RULES_SRC}"
    # Fixture rule source files.
    cat > "${RULES_SRC}/base.rules" <<'BEOF'
-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group  -p wa -k group
BEOF
    cat > "${RULES_SRC}/paranoid.rules" <<'PEOF'
-w /var/log -p wa -k logwatch
-w /etc/audit -p wa -k auditwatch
PEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    AUGEN_LOG="${AUGEN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AUDIT_RULES_CONFIG="${CONF}" \
    SELFDEF_AUDIT_RULES_SRC="${RULES_SRC}" \
    SELFDEF_AUDIT_RULES_DIR="${RULES_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AUDIT_RULES_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDIT_RULES_CONFIG="${SELFDEF_AUDIT_RULES_CONFIG}" \
        SELFDEF_AUDIT_RULES_SRC="${RULES_SRC}" \
        SELFDEF_AUDIT_RULES_DIR="${RULES_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing rules.d → die (auditd not installed)" {
    write_config "base"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDIT_RULES_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_SRC="${RULES_SRC}" \
        SELFDEF_AUDIT_RULES_DIR="${TMP}/no-rules-d" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"audit rules dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDIT_RULES_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_SRC="${RULES_SRC}" \
        SELFDEF_AUDIT_RULES_DIR="${RULES_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be base|paranoid"* ]]
}

@test "base profile installs ONLY 50-selfdef-base.rules" {
    write_config "base"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    ! [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
    # Drop-in chmod 0640 (audit-rules.d convention — owner+group read).
    [ "$(stat -c '%a' "${RULES_DIR}/50-selfdef-base.rules")" = "640" ]
}

@test "paranoid profile installs BOTH base + paranoid" {
    write_config "paranoid"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
}

@test "INVARIANT: profile downgrade paranoid → base REMOVES 50-selfdef-paranoid.rules" {
    write_config "paranoid"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    write_config "base"
    : > "${AUGEN_LOG}"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    ! [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]    # REMOVED
    # augenrules reload fires (stale removal IS a change).
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT: operator-authored rules (non-50-selfdef-* prefix) are PRESERVED" {
    write_config "base"
    # Operator pre-installed a rule.
    printf '%s\n' '-w /opt/sentinel -p wa -k operator' > "${RULES_DIR}/30-operator-custom.rules"
    run_wd
    # Operator rule must survive.
    [ -f "${RULES_DIR}/30-operator-custom.rules" ]
    grep -q '30-operator-custom' <(ls "${RULES_DIR}")
    # selfdef base file also present.
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
}

@test "INVARIANT: idempotent — re-install with identical content fires NO augenrules --load" {
    write_config "base"
    run_wd
    : > "${AUGEN_LOG}"
    run_wd
    ! grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT: DRY_RUN does not install rules or fire augenrules" {
    write_config "base"
    DRY_RUN=1 run_wd
    ! [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    ! grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "default profile is base (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    ! [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves rule-file mtime" {
    write_config "base"
    run_wd
    mtime_before="$(stat -c '%Y' "${RULES_DIR}/50-selfdef-base.rules")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${RULES_DIR}/50-selfdef-base.rules")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile upgrade base → paranoid): writes paranoid + fires augenrules" {
    # Reverse direction of the downgrade test — locks bidirectional.
    write_config "base"
    run_wd
    ! [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    write_config "paranoid"
    : > "${AUGEN_LOG}"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT (paranoid rule-file content): paranoid carries /var/log + /etc/audit watches" {
    write_config "paranoid"
    run_wd
    grep -qE '/var/log' "${RULES_DIR}/50-selfdef-paranoid.rules"
    grep -qE '/etc/audit' "${RULES_DIR}/50-selfdef-paranoid.rules"
}

@test "INVARIANT (base rule-file content): base carries identity-file watches (passwd + shadow + group)" {
    write_config "base"
    run_wd
    grep -qE '/etc/passwd' "${RULES_DIR}/50-selfdef-base.rules"
    grep -qE '/etc/shadow' "${RULES_DIR}/50-selfdef-base.rules"
    grep -qE '/etc/group' "${RULES_DIR}/50-selfdef-base.rules"
}

@test "INVARIANT (paranoid file is chmod 0640 too — convention matches base)" {
    write_config "paranoid"
    run_wd
    [ "$(stat -c '%a' "${RULES_DIR}/50-selfdef-paranoid.rules")" = "640" ]
}

@test "INVARIANT (no render-timestamp in rule files): defeats cmp -s idempotency" {
    write_config "paranoid"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${RULES_DIR}/50-selfdef-base.rules"
    ! grep -qE '^# Generated [0-9]{4}-' "${RULES_DIR}/50-selfdef-paranoid.rules"
}
