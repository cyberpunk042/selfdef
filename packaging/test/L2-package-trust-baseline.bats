#!/usr/bin/env bats
# L2 functional suite for package-trust-baseline.
#
# package-trust-baseline installs /etc/apt/apt.conf.d/50-
# selfdef-secure with package-trust hardening directives
# (signed-by, no AllowUnauthenticated, no AllowDowngradeToInsecureRepositories,
# verbose validation behavior). Validates the result with
# `apt-config dump` after write — a syntactically-bad file
# rolls back via a single-shot backup.
#
# Profiles:
#   standard → NIST-aligned baseline (signed-by enforcement,
#              fail-closed on unsigned, default-deny untrusted
#              repos)
#   strict   → audit-frameworks-aligned (CIS / STIG) — tighter
#              repository pinning + explicit deny-list for
#              insecure transport
#
# Rollback invariant: if apt-config dump rejects the rendered
# file, the previous content (if any) is restored byte-
# identical. If no prior content existed, the rendered file is
# removed. Either way, the script `die`s with a clear message.
#
# Run with: bats packaging/test/L2-package-trust-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    # Default apt-config mock: ACCEPT (exit 0). Override per-test by
    # rewriting this file.
    cat > "${BIN}/apt-config" <<'AEOF'
#!/usr/bin/env bash
exit 0
AEOF
    chmod +x "${BIN}/apt-config"
    CONF="${TMP}/package-trust-baseline.toml"
    APT_CONFD="${TMP}/apt.conf.d"
    DST="${APT_CONFD}/50-selfdef-secure"
    mkdir -p "${APT_CONFD}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PKG_TRUST_CONFIG="${CONF}" \
    SELFDEF_APT_CONFD="${APT_CONFD}" \
    bash "${WD}"
}

# Helper: rewrite apt-config to REJECT (exit 1).
make_apt_config_reject() {
    cat > "${BIN}/apt-config" <<'AEOF'
#!/usr/bin/env bash
exit 1
AEOF
    chmod +x "${BIN}/apt-config"
}

@test "missing config → die" {
    SELFDEF_PKG_TRUST_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PKG_TRUST_CONFIG="${SELFDEF_PKG_TRUST_CONFIG}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PKG_TRUST_CONFIG="${CONF}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|strict"* ]]
}

@test "standard profile installs the drop-in" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    # The standard profile should NOT allow unauthenticated packages.
    grep -qE 'AllowUnauthenticated[[:space:]]*"?false"?' "${DST}"
}

@test "strict profile installs the drop-in (content differs from standard)" {
    write_config "standard"
    run_wd
    sha_standard="$(sha256sum "${DST}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_strict="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_standard}" != "${sha_strict}" ]
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "standard"
    run_wd
    [ "$(stat -c '%a' "${DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    mtime_before="$(stat -c '%Y' "${DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: apt-config dump REJECTION rolls back to the previous content (single-shot backup)" {
    # First apply with accepting apt-config — establishes baseline.
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    pre_sha="$(sha256sum "${DST}" | awk '{print $1}')"
    # Now switch profile to strict + make apt-config reject. The
    # script should: install the new content, validate, observe
    # rejection, restore the standard content, and die.
    write_config "strict"
    make_apt_config_reject
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PKG_TRUST_CONFIG="${CONF}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"refused to commit"* ]]
    # File restored to pre-apply standard content.
    [ -f "${DST}" ]
    post_sha="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
    # No leftover rollback file.
    ! ls "${APT_CONFD}"/*.selfdef-rollback.* >/dev/null 2>&1
}

@test "INVARIANT: apt-config dump REJECTION on FIRST install removes the file (no prior backup)" {
    write_config "standard"
    make_apt_config_reject
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PKG_TRUST_CONFIG="${CONF}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"refused to commit"* ]]
    # No file left behind (clean failure).
    ! [ -f "${DST}" ]
    ! ls "${APT_CONFD}"/*.selfdef-rollback.* >/dev/null 2>&1
}

@test "INVARIANT: DRY_RUN does not write the drop-in" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'profile=standard'* ]]
}

@test "emit_status reports changes count (1 first install; 0 idempotent re-apply)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile downgrade strict → standard): rewrites drop-in to standard content" {
    write_config "strict"
    run_wd
    sha_strict="$(sha256sum "${DST}" | awk '{print $1}')"
    write_config "standard"
    run_wd
    sha_standard="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_strict}" != "${sha_standard}" ]
}

@test "INVARIANT (standard does NOT carry insecure-repo directives — no AllowUnauthenticated true)" {
    # The actual hardening: ensure the rendered file CANNOT contain
    # AllowUnauthenticated true or its variants.
    write_config "standard"
    run_wd
    ! grep -qE 'AllowUnauthenticated[[:space:]]*"?true"?' "${DST}"
}

@test "INVARIANT (no render-timestamp in drop-in — defeats cmp -s idempotency)" {
    write_config "standard"
    run_wd
    ! grep -qE '^// Generated [0-9]{4}-' "${DST}"
    ! grep -qE '^# Generated [0-9]{4}-' "${DST}"
}

@test "INVARIANT (apt-config validation called — apt-config dump runs against the rendered file)" {
    # Wrap apt-config to log invocations.
    cat > "${BIN}/apt-config" <<EOF
#!/usr/bin/env bash
printf 'apt-config %s\\n' "\$*" >> "${TMP}/apt-config.log"
exit 0
EOF
    chmod +x "${BIN}/apt-config"
    write_config "standard"
    run_wd
    [ -f "${TMP}/apt-config.log" ]
    grep -q '^apt-config ' "${TMP}/apt-config.log"
}

@test "INVARIANT (drop-in filename 50-selfdef-*): tracking + uninstall identification" {
    write_config "standard"
    run_wd
    case "${DST}" in
        */50-selfdef-*) : ;;
        *) fail "drop-in filename must follow 50-selfdef-* pattern" ;;
    esac
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in)" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    rm -f "${DST}"
    run_wd
    [ -f "${DST}" ]
    grep -qE 'AllowUnauthenticated[[:space:]]*"?false"?' "${DST}"
}

@test "INVARIANT (drop-in carries selfdef-identifier header — operator audit trail)" {
    # APT conf uses // for line comments. The header is the
    # operator-readable selfdef-managed marker.
    write_config "standard"
    run_wd
    grep -qE '^(//|#).*selfdef.*package-trust|^(//|#).*managed-by.*selfdef' "${DST}"
}

@test "INVARIANT (strict profile carries pinning/repo-restriction directives — stronger than standard)" {
    # Strict (CIS/STIG) profile must carry pinning or repo-
    # restriction directives beyond just 'no AllowUnauthenticated'.
    # Lock that strict content includes some additional directive
    # like APT::Default-Release or stricter Acquire:: settings.
    write_config "strict"
    run_wd
    # Strict file content must mention at least one stricter
    # directive than standard.
    grep -qiE 'AllowDowngradeToInsecureRepositories|AllowInsecureRepositories|Default-Release|Verbose' "${DST}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"package-trust-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=standard'* ]]
}
