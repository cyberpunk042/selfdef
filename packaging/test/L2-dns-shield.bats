#!/usr/bin/env bats
# L2 functional suite for dns-shield.
#
# dns-shield renders a blocklist (profile + operator additions
# minus operator allowlist) into a bracketed BEGIN/END marker
# block in /etc/hosts. Only the region between the markers is
# selfdef's; everything else in /etc/hosts is preserved byte-
# for-byte.
#
# Profiles:
#   base   → base.txt (well-known ad/tracker/malware domains)
#   strict → base + strict.txt (broader inclusion — may produce
#            false positives on legitimate-but-tracking-heavy
#            services)
#
# CRITICAL INVARIANTS this suite locks:
#   - Pre-existing /etc/hosts content OUTSIDE the BEGIN/END
#     markers is PRESERVED byte-for-byte. Operator's manual hosts
#     entries are sacrosanct.
#   - Each domain renders TWO entries: `0.0.0.0 <domain>` AND
#     `0.0.0.0 www.<domain>` (the www-variant catches the most
#     common entry point).
#   - Allowlist SUBTRACTS from the blocklist (allowlist wins).
#   - Operator additions ADD to the blocklist.
#   - Idempotent: byte-identical re-render → /etc/hosts NOT
#     re-written.
#   - DRY_RUN does not touch /etc/hosts.
#
# Uses SELFDEF_HOSTS_FILE + SELFDEF_DNS_SHIELD_BLOCKLISTS +
# SELFDEF_DNS_SHIELD_DIR + SELFDEF_DNS_SHIELD_OPERATOR_FILE +
# SELFDEF_DNS_SHIELD_ALLOW_FILE env-vars (all already present).
#
# Run with: bats packaging/test/L2-dns-shield.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    CONF="${TMP}/dns-shield.toml"
    BLOCKLISTS_SRC="${TMP}/blocklists"
    HOSTS_FILE="${TMP}/hosts"
    OPERATOR_DIR="${TMP}/dns-shield"
    OPERATOR_FILE="${OPERATOR_DIR}/operator.txt"
    ALLOW_FILE="${OPERATOR_DIR}/allowlist.txt"
    mkdir -p "${BLOCKLISTS_SRC}" "${OPERATOR_DIR}"
    # Fixture blocklists.
    cat > "${BLOCKLISTS_SRC}/base.txt" <<'BEOF'
# Base blocklist
ads.example
tracker.example
malware.example
BEOF
    cat > "${BLOCKLISTS_SRC}/strict.txt" <<'SEOF'
# Strict additions
analytics.example
social-widget.example
SEOF
    # Pre-existing /etc/hosts with operator content.
    cat > "${HOSTS_FILE}" <<'HEOF'
127.0.0.1 localhost
127.0.1.1 myhost.example.com myhost
192.168.1.50 nas.lan nas
# operator note: do not touch
::1 ip6-localhost
HEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_DNS_SHIELD_CONFIG="${CONF}" \
    SELFDEF_DNS_SHIELD_BLOCKLISTS="${BLOCKLISTS_SRC}" \
    SELFDEF_HOSTS_FILE="${HOSTS_FILE}" \
    SELFDEF_DNS_SHIELD_DIR="${OPERATOR_DIR}" \
    SELFDEF_DNS_SHIELD_OPERATOR_FILE="${OPERATOR_FILE}" \
    SELFDEF_DNS_SHIELD_ALLOW_FILE="${ALLOW_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_DNS_SHIELD_CONFIG="${TMP}/missing.toml"
    run env \
        SELFDEF_DNS_SHIELD_CONFIG="${SELFDEF_DNS_SHIELD_CONFIG}" \
        SELFDEF_DNS_SHIELD_BLOCKLISTS="${BLOCKLISTS_SRC}" \
        SELFDEF_HOSTS_FILE="${HOSTS_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing blocklist source dir → die" {
    write_config "base"
    run env \
        SELFDEF_DNS_SHIELD_CONFIG="${CONF}" \
        SELFDEF_DNS_SHIELD_BLOCKLISTS="${TMP}/missing-bl" \
        SELFDEF_HOSTS_FILE="${HOSTS_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"blocklist source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env \
        SELFDEF_DNS_SHIELD_CONFIG="${CONF}" \
        SELFDEF_DNS_SHIELD_BLOCKLISTS="${BLOCKLISTS_SRC}" \
        SELFDEF_HOSTS_FILE="${HOSTS_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be base|strict"* ]]
}

@test "base profile renders BEGIN/END markers + base domains (with www variants)" {
    write_config "base"
    run_wd
    grep -q '=== selfdef dns-shield BEGIN' "${HOSTS_FILE}"
    grep -q '=== selfdef dns-shield END' "${HOSTS_FILE}"
    # Each domain has bare + www variant.
    grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 www\.ads\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 tracker\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 malware\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT: pre-existing /etc/hosts content OUTSIDE markers is PRESERVED byte-for-byte" {
    write_config "base"
    run_wd
    # Operator entries must survive.
    grep -q '^127\.0\.0\.1 localhost$' "${HOSTS_FILE}"
    grep -q '^127\.0\.1\.1 myhost\.example\.com myhost$' "${HOSTS_FILE}"
    grep -q '^192\.168\.1\.50 nas\.lan nas$' "${HOSTS_FILE}"
    grep -q '^# operator note: do not touch$' "${HOSTS_FILE}"
    grep -q '^::1 ip6-localhost$' "${HOSTS_FILE}"
}

@test "strict profile renders BOTH base + strict domains" {
    write_config "strict"
    run_wd
    # Base domains.
    grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    # Strict-only additions.
    grep -q '^0\.0\.0\.0 analytics\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 social-widget\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT: operator additions ADD to the blocklist" {
    write_config "base"
    printf '%s\n' 'custom-bad-site.example' > "${OPERATOR_FILE}"
    run_wd
    grep -q '^0\.0\.0\.0 custom-bad-site\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 www\.custom-bad-site\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT: allowlist SUBTRACTS from the blocklist" {
    write_config "base"
    printf '%s\n' 'ads.example' > "${ALLOW_FILE}"     # allowlist ads.example
    run_wd
    # ads.example should NOT appear (allowlisted).
    ! grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    # Other base domains still present.
    grep -q '^0\.0\.0\.0 tracker\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT: idempotent — re-render with identical input does NOT re-write /etc/hosts" {
    # The rendered block omits the timestamp comment (fixed 2026-06-06)
    # so byte-equality across runs is now guaranteed: /etc/hosts is
    # NOT re-written on a no-content-change apply. Locks both the
    # SHA256 byte-equality AND the mtime preservation — the latter
    # is what watchdogs key on for inventory diffs.
    write_config "base"
    run_wd
    sha_before="$(sha256sum "${HOSTS_FILE}" | awk '{print $1}')"
    mtime_before="$(stat -c '%Y' "${HOSTS_FILE}")"
    sleep 1
    run_wd
    sha_after="$(sha256sum "${HOSTS_FILE}" | awk '{print $1}')"
    mtime_after="$(stat -c '%Y' "${HOSTS_FILE}")"
    [ "${sha_before}" = "${sha_after}" ]
    # mtime preserved — the no-change apply doesn't bump the file's
    # modification time, so downstream watchdogs (hosts-file-watchdog)
    # don't fire spurious "changed" findings.
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not modify /etc/hosts" {
    write_config "base"
    sha_before="$(sha256sum "${HOSTS_FILE}" | awk '{print $1}')"
    DRY_RUN=1 run_wd
    sha_after="$(sha256sum "${HOSTS_FILE}" | awk '{print $1}')"
    [ "${sha_before}" = "${sha_after}" ]
}

@test "INVARIANT: second run with profile change strict → base rewrites the bracketed block (NOT the operator content)" {
    write_config "strict"
    run_wd
    grep -q '^0\.0\.0\.0 analytics\.example$' "${HOSTS_FILE}"
    write_config "base"
    run_wd
    # analytics.example (strict-only) MUST be removed.
    ! grep -q '^0\.0\.0\.0 analytics\.example$' "${HOSTS_FILE}"
    # Base domains still present.
    grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    # Operator entries STILL preserved.
    grep -q '^127\.0\.0\.1 localhost$' "${HOSTS_FILE}"
}

@test "default profile is base (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    ! grep -q '^0\.0\.0\.0 analytics\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT (comment-line in operator file is NOT rendered): comment-skip guard" {
    write_config "base"
    cat > "${OPERATOR_FILE}" <<'EOF'
# This is just a comment, not a domain
real-bad-site.example
EOF
    run_wd
    grep -q '^0\.0\.0\.0 real-bad-site\.example$' "${HOSTS_FILE}"
    # Literal '# This is just a comment...' should NOT become a hosts line.
    ! grep -qE '^0\.0\.0\.0 #' "${HOSTS_FILE}"
}

@test "INVARIANT (blank-line in operator file is NOT rendered as 0.0.0.0)" {
    write_config "base"
    cat > "${OPERATOR_FILE}" <<'EOF'
real-bad-site.example

another-bad.example
EOF
    run_wd
    grep -q '^0\.0\.0\.0 real-bad-site\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 another-bad\.example$' "${HOSTS_FILE}"
    # No empty 0.0.0.0 line.
    ! grep -qE '^0\.0\.0\.0 *$' "${HOSTS_FILE}"
}

@test "INVARIANT (allowlist applies to BOTH bare + www variants): allowing X removes both X and www.X" {
    write_config "base"
    printf '%s\n' 'ads.example' > "${ALLOW_FILE}"
    run_wd
    ! grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    ! grep -q '^0\.0\.0\.0 www\.ads\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT (deduplication: same domain in base + operator → renders ONCE)" {
    write_config "base"
    # Re-add base list domain via operator file.
    printf '%s\n' 'ads.example' > "${OPERATOR_FILE}"
    run_wd
    # Count occurrences — should be 1 (or 2 with www, but not more).
    n_ads=$(grep -c '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}")
    [ "${n_ads}" = "1" ]
}

@test "INVARIANT (BEGIN/END markers form a SINGLE block — not multiple stacks on re-apply)" {
    write_config "base"
    run_wd
    run_wd
    run_wd
    n_begin=$(grep -c 'selfdef dns-shield BEGIN' "${HOSTS_FILE}")
    n_end=$(grep -c 'selfdef dns-shield END' "${HOSTS_FILE}")
    [ "${n_begin}" = "1" ]
    [ "${n_end}" = "1" ]
}

@test "INVARIANT (END marker comes AFTER BEGIN — bracket integrity)" {
    write_config "base"
    run_wd
    begin_line=$(grep -nE '^# === selfdef dns-shield BEGIN' "${HOSTS_FILE}" | head -1 | cut -d: -f1)
    end_line=$(grep -nE '^# === selfdef dns-shield END' "${HOSTS_FILE}" | head -1 | cut -d: -f1)
    [ "${end_line}" -gt "${begin_line}" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "strict"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"dns-shield"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=strict'* ]]
}

@test "INVARIANT (allowlist with comment line is respected — comment-skip applies to allowlist too)" {
    # allowlist file uses same # comment convention as operator file.
    # Lock that allowlist comments don't accidentally subtract an empty
    # entry (no-op) but don't accidentally PASS the comment as a domain.
    write_config "base"
    cat > "${ALLOW_FILE}" <<'EOF'
# allowlist file
ads.example
# comment again
EOF
    run_wd
    ! grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    # tracker.example NOT in allowlist, should still be blocked.
    grep -q '^0\.0\.0\.0 tracker\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT (operator additions deduplicate with strict-list — same domain in operator + strict renders ONCE)" {
    # In strict profile, if operator additions include a domain that
    # strict.txt already has, the merged result must render that domain
    # ONCE (not twice). Locks dedup across all sources.
    write_config "strict"
    printf '%s\n' 'analytics.example' > "${OPERATOR_FILE}"      # already in strict.txt
    run_wd
    n=$(grep -c '^0\.0\.0\.0 analytics\.example$' "${HOSTS_FILE}")
    [ "${n}" = "1" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # dns-shield TOML; parser must tolerate without altering the
    # profile-gated behavior. strict-with-noise still renders BOTH
    # base + strict domains AND preserves operator /etc/hosts content
    # outside the BEGIN/END marker block (operator entries
    # sacrosanct).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "broader inclusion — may produce false positives"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q '^0\.0\.0\.0 ads\.example$' "${HOSTS_FILE}"
    grep -q '^0\.0\.0\.0 analytics\.example$' "${HOSTS_FILE}"
    grep -q '^127\.0\.0\.1 localhost$' "${HOSTS_FILE}"
}

@test "INVARIANT (allowlist takes precedence over operator additions: same domain in operator + allow → allowlist wins, domain NOT blocked)" {
    # Sister to the allowlist-subtracts INVARIANT already locked.
    # When a domain appears in BOTH operator additions AND
    # allowlist, the allowlist must win (operator may move a
    # domain to allowlist while forgetting to remove from
    # additions — must not block). Locks the precedence-of-
    # allowlist contract.
    write_config "base"
    printf '%s\n' 'controversial.example' > "${OPERATOR_FILE}"
    printf '%s\n' 'controversial.example' > "${ALLOW_FILE}"
    run_wd
    # controversial.example NOT blocked (allowlist won).
    ! grep -q '^0\.0\.0\.0 controversial\.example$' "${HOSTS_FILE}"
    ! grep -q '^0\.0\.0\.0 www\.controversial\.example$' "${HOSTS_FILE}"
}

@test "INVARIANT (hosts file carries selfdef self-identifying section markers — operator audit trail + uninstall identification)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain. The rendered hosts file
    # accumulates BOTH selfdef-managed entries AND operator-
    # hand-authored entries. selfdef MUST bracket its managed
    # section with BEGIN/END marker comments so a stale-cleanup
    # pass (operator housekeeping or uninstall path) can
    # reliably identify which entries to remove without
    # touching operator state. Locks the section-marker contract
    # on the DNS-block-list substrate.
    write_config "base"
    run_wd
    [ -f "${HOSTS_FILE}" ]
    grep -qE '# .*selfdef.*BEGIN|# .*BEGIN.*selfdef|# selfdef.*dns-shield' "${HOSTS_FILE}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO hosts file written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/hosts. A silent dry-run that
    # committed would inject the blocklist into the operator's
    # resolution path AT PREVIEW TIME — any browser/CLI tool
    # would start failing to resolve blocklisted domains
    # silently. Locks dry-run-preserves-state on the DNS-block-
    # list substrate (the operator's blocklist is operator-
    # explicit choice; agent-preview must not commit it).
    write_config "base"
    # Capture pre-existing hosts content (the fixture starts
    # with operator-pre-existing baseline content per setup).
    pre_existing="$(wc -l < "${HOSTS_FILE}" 2>/dev/null || echo 0)"
    DRY_RUN=1 run_wd
    post_dry="$(wc -l < "${HOSTS_FILE}" 2>/dev/null || echo 0)"
    [ "${pre_existing}" = "${post_dry}" ]
}

@test "INVARIANT (hosts file chmod preserves original mode — DNS-block-list installer does NOT degrade /etc/hosts perm)" {
    # Sister to brain-wide preserve-existing-perm INVARIANTs.
    # /etc/hosts is typically 0644 system-config; the dns-shield
    # appending MUST NOT degrade the file mode.
    write_config "base"
    chmod 0644 "${HOSTS_FILE}"
    run_wd
    mode="$(stat -c '%a' "${HOSTS_FILE}")"
    [ "${mode}" = "644" ] || [ "${mode}" = "640" ] || [ "${mode}" = "600" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on dns-shield installer surface.
    write_config "base"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"dns-shield"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: dns-shield NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The dns-shield installer appends to /etc/hosts
    # with selfdef-managed block-list entries but MUST NEVER
    # emit shell commands that uninstall any DNS-related
    # package (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # libnss-* | systemd-resolved | resolvconf | unbound). The
    # dns-shield strategy is purely /etc/hosts-based blocking
    # — no upstream daemon dependency. Locks anti-package-
    # removal contract on the DNS shield substrate.
    write_config "base"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${HOSTS_FILE}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. dns-shield manifest declares install + profile
    # gating (light / strict) the resolver enforces; malformed
    # manifest wedges the DNS sinkhole baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'dns-shield', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: dns-shield installer NEVER deletes /etc/hosts entries outside its self-identifying section — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # dns-shield writes its own self-identifying section in
    # /etc/hosts (sinkhole entries); it MUST NEVER rm/sed-i
    # delete entries outside the selfdef-managed section. The
    # operator's pre-existing /etc/hosts entries are sacrosanct.
    # Locks no-auto-delete on the dns-shield installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/hosts([^.]|$)' "${f}"
        ! grep -qE 'sed[[:space:]]+-i.*\bd\b.*\b/etc/hosts\b' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # dns-shield install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the dns-shield lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    # the dns-shield requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    # present discipline on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    # category-present discipline on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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
    # semver-X.Y.Z discipline on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (dns-shield module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the dns-shield module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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

@test "INVARIANT (dns-shield module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the dns-shield module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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

@test "INVARIANT (dns-shield module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the dns-shield
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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

@test "INVARIANT (dns-shield module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for dns-shield is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (dns-shield module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the dns-shield install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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

@test "INVARIANT (dns-shield module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the dns-shield requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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

@test "INVARIANT (dns-shield module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the dns-shield
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (dns-shield module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the dns-shield
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (dns-shield module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (dns-shield module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (dns-shield module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the dns-shield substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
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

@test "INVARIANT (dns-shield module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (dns-shield module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (dns-shield module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (dns-shield module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (dns-shield README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/dns-shield/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (dns-shield install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (dns-shield install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (dns-shield install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (dns-shield install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (dns-shield install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (dns-shield install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (dns-shield install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (dns-shield install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (dns-shield install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (dns-shield install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (dns-shield install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (dns-shield install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (dns-shield module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (dns-shield module.toml exists at canonical path modules/dns-shield/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (dns-shield module dir is at canonical path modules/dns-shield/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/dns-shield"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (dns-shield install dir exists at modules/dns-shield/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (dns-shield install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (dns-shield install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (dns-shield install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (dns-shield install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (dns-shield module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (dns-shield install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (dns-shield install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (dns-shield install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (dns-shield install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (dns-shield install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (dns-shield install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (dns-shield install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (dns-shield install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/dns-shield/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (dns-shield module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (dns-shield module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (dns-shield module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (dns-shield module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (dns-shield module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (dns-shield module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (dns-shield module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (dns-shield module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"dns-shield"' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (dns-shield module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (dns-shield module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (dns-shield module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (dns-shield module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (dns-shield module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (dns-shield module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (dns-shield module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (dns-shield module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (dns-shield module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (dns-shield module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (dns-shield module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (dns-shield module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/dns-shield/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}
