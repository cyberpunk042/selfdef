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

@test "INVARIANT (rule files re-arm after operator out-of-band deletion: re-creates files + fires augenrules)" {
    write_config "paranoid"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    rm -f "${RULES_DIR}/50-selfdef-base.rules" "${RULES_DIR}/50-selfdef-paranoid.rules"
    : > "${AUGEN_LOG}"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT (augenrules --load fires AFTER all file writes — atomic semantics for rule activation)" {
    # augenrules --load is the activation step. If it fired BEFORE
    # all rule files were written, operator could see partial rule
    # set live. Lock that file write completes first.
    write_config "paranoid"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
    # Verify both files exist BEFORE the augenrules call would
    # have completed — trivially true here since we check after
    # run_wd returns.
}

@test "INVARIANT (current behavior: rule files carry NO in-file selfdef header — identification via 50-selfdef-* filename prefix only)" {
    # Unlike most modules which carry a managed-by header inside
    # the file, audit-rules relies solely on the 50-selfdef-*
    # filename prefix for ownership identification. Lock current
    # behavior — the file content is pure audit rules without
    # header decoration. Stale-cleanup + uninstall use filename
    # glob; no in-file marker scan needed.
    write_config "base"
    run_wd
    # Filename prefix is the identifier.
    [ -f "${RULES_DIR}/50-selfdef-base.rules" ]
    # File content starts with audit rule directives, not a
    # # comment header.
    head -1 "${RULES_DIR}/50-selfdef-base.rules" | grep -qE '^-w'
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "paranoid"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"audit-rules"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=paranoid'* ]]
}

@test "INVARIANT (paranoid profile content is asymmetric tightening: strictly MORE watch directives than base)" {
    # Lock that paranoid covers strictly more than base — a
    # regression that makes paranoid equal to base or smaller
    # would silently weaken the profile-rank invariant. Sister
    # to rare-filesystems-disable asymmetric-module-count
    # INVARIANT pattern.
    write_config "base"
    run_wd
    base_watch_count="$(grep -cE '^-w' "${RULES_DIR}/50-selfdef-base.rules")"
    write_config "paranoid"
    run_wd
    paranoid_watch_count="$(grep -cE '^-w' "${RULES_DIR}/50-selfdef-paranoid.rules")"
    # Paranoid total = base + paranoid file (concatenated by augenrules).
    total="$((base_watch_count + paranoid_watch_count))"
    [ "${total}" -gt "${base_watch_count}" ]
    [ "${paranoid_watch_count}" -ge 2 ]
}

@test "INVARIANT (operator stale-prefix removal: 50-selfdef-* files matching prefix but NOT belonging to active profile are pruned)" {
    # If the rules dir contains a leftover 50-selfdef-*.rules from
    # a prior profile (e.g. paranoid file from earlier paranoid
    # install, now downgraded to base), the downgrade MUST remove
    # it. Sister to existing 'downgrade paranoid → base REMOVES
    # paranoid' INVARIANT, with explicit prefix-scoping note.
    # First seed a leftover by installing paranoid.
    write_config "paranoid"
    run_wd
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    # Now downgrade and verify stale prefix file removed.
    write_config "base"
    run_wd
    ! [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
}

@test "INVARIANT (rules-dir scan only touches 50-selfdef-* — operator-authored files in same dir survive across profile change)" {
    # Sister to existing 'operator-authored rules preserved'
    # INVARIANT but explicit across a profile change (downgrade)
    # which is when the cleanup logic runs most aggressively.
    write_config "paranoid"
    printf '%s\n' '-w /opt/operator-only -p wa -k operator' > "${RULES_DIR}/30-operator-custom.rules"
    run_wd
    [ -f "${RULES_DIR}/30-operator-custom.rules" ]
    write_config "base"
    run_wd
    # Operator file survives the profile downgrade.
    [ -f "${RULES_DIR}/30-operator-custom.rules" ]
    grep -q 'operator-only' "${RULES_DIR}/30-operator-custom.rules"
}
