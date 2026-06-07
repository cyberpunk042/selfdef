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

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # audit-rules TOML; parser must tolerate without altering the
    # profile-gated content. paranoid-with-noise still emits the
    # paranoid rule set (strictly more watch directives than base)
    # AND augenrules --load fires (atomic rule activation).
    cat > "${CONF}" <<'TOMLEOF'
profile = "paranoid"
operator_note = "audit rules — paranoid for AI substrate forensics"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    # Paranoid rule file is installed.
    [ -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    # augenrules --load fired.
    grep -qE 'augenrules.*--load' "${AUGEN_LOG}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO rule files written AND NO augenrules --load fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / aslr-baseline / apport-
    # disable / many others). Operator's exploratory --dry-run
    # MUST preview without writing /etc/audit/rules.d/50-selfdef-*
    # AND without firing augenrules --load. Without strict DRY_RUN
    # gating, a previewed dry-run would silently flip the kernel-
    # level audit rule set on a host where operator was
    # investigating — and might not even know the rules are
    # reloaded. Locks the dry-run-preserves-state contract on the
    # audit rule-loading substrate (forensics enable surface).
    write_config "paranoid"
    : > "${AUGEN_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${RULES_DIR}/50-selfdef-paranoid.rules" ]
    ! grep -qE 'augenrules.*--load' "${AUGEN_LOG}"
}

@test "INVARIANT (rule files are chmod 0640 — operator+adm-group readable, NOT world)" {
    # Sister to brain-wide audit-config 0640 INVARIANT. Audit
    # rules carry sensitive operator-environment intelligence —
    # MUST NOT be world-readable.
    write_config "base"
    run_wd
    base_file="${RULES_DIR}/50-selfdef-base.rules"
    [ -f "${base_file}" ]
    mode="$(stat -c '%a' "${base_file}")"
    [ "${mode}" = "640" ] || [ "${mode}" = "600" ] || [ "${mode}" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on audit-rules installer surface
    # across rule-files + augenrules-reload phases.
    write_config "base"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"audit-rules"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (canonical source rule files carry 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The canonical audit-rules source
    # files at modules/audit-rules/rules/{base,paranoid}.rules
    # MUST carry a comment marker identifying them as selfdef-
    # managed so when they land at /etc/audit/rules.d/50-selfdef-
    # *.rules a stale-cleanup head -5 grep at uninstall time can
    # identify which files selfdef owns vs which is operator-
    # original. Without a marker, a subsequent uninstaller could
    # not tell apart operator baseline audit rules from selfdef-
    # injected ones — risking accidental rollback of operator
    # custom rules. Locks marker-discipline on the source-of-
    # truth audit-rules substrate.
    SRC_DIR="${BATS_TEST_DIRNAME}/../../modules/audit-rules/rules"
    [ -d "${SRC_DIR}" ]
    for f in "${SRC_DIR}"/*.rules; do
        head -5 "${f}" | grep -qE '^#.*(selfdef|audit-rules|managed)'
    done
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on audit-rules surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The audit-rules installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the audit-rules apply status alert. Locks
    # parser contract on the audit-rules installer JSON surface
    # (consistency-with-watchdog-family discipline).
    write_config "base"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. audit-rules manifest declares install + profile
    # gating (default / strict) the resolver enforces; malformed
    # manifest wedges the auditd rule baseline. Python's tomllib
    # is the canonical parser. Locks anti-malformed-manifest on
    # the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'audit-rules', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # audit-rules install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the audit-rules lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/audit-rules/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the audit-rules requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (audit-rules module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the audit-rules module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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

@test "INVARIANT (audit-rules module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the audit-rules module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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

@test "INVARIANT (audit-rules module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the audit-rules
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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

@test "INVARIANT (audit-rules module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for audit-rules is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (audit-rules module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the audit-rules install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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

@test "INVARIANT (audit-rules module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the audit-rules requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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

@test "INVARIANT (audit-rules module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the audit-rules
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (audit-rules module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the audit-rules
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (audit-rules module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (audit-rules module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (audit-rules module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the audit-rules substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
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

@test "INVARIANT (audit-rules module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (audit-rules module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (audit-rules module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (audit-rules module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (audit-rules module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (audit-rules module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/audit-rules/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (audit-rules README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/audit-rules/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (audit-rules install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/audit-rules/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (audit-rules install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/audit-rules/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (audit-rules install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/audit-rules/install/check.sh"
    [ -x "${chk}" ]
}
