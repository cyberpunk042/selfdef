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
