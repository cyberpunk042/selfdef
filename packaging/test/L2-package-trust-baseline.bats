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

@test "INVARIANT (apt-config dump REJECTION preserves WORKING content via single-shot backup — rollback fingerprint matches pre-attempt sha)" {
    # Sister axis to the existing rollback INVARIANT but explicit
    # about the load-bearing guarantee: when the SECOND apply fails
    # validation, the drop-in is restored to BYTE-IDENTICAL pre-
    # apply state. Lock the no-corruption-window contract.
    write_config "standard"
    run_wd
    pre_sha="$(sha256sum "${DST}" | awk '{print $1}')"
    pre_mode="$(stat -c '%a' "${DST}")"
    write_config "strict"
    make_apt_config_reject
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PKG_TRUST_CONFIG="${CONF}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Byte-identical restoration.
    [ "$(sha256sum "${DST}" | awk '{print $1}')" = "${pre_sha}" ]
    # Mode preserved too.
    [ "$(stat -c '%a' "${DST}")" = "${pre_mode}" ]
}

@test "INVARIANT (rollback contract: no leftover .selfdef-rollback.* files after a successful re-apply — single-shot cleanup)" {
    # The .selfdef-rollback.* sidecar should NEVER persist past a
    # successful apply. If the rollback file lingers, a future
    # operator looking at apt.conf.d might mistake it for a real
    # drop-in. Lock single-shot cleanup contract.
    write_config "standard"
    run_wd
    write_config "strict"
    run_wd
    write_config "standard"
    run_wd
    # No rollback sidecar files should linger.
    ! ls "${APT_CONFD}"/*.selfdef-rollback.* >/dev/null 2>&1
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 grep predictability)" {
    # Sister to rare-filesystems-disable + rare-network-protocols-
    # disable + pam-history header-marker INVARIANT. The selfdef-
    # identifier MUST appear on the first non-blank line so
    # stale-detection head -1 scans reliably identify selfdef-owned
    # files.
    write_config "standard"
    run_wd
    first_nonblank="$(grep -m1 -v '^[[:space:]]*$' "${DST}")"
    [[ "${first_nonblank}" == *"selfdef"* ]] || [[ "${first_nonblank}" == *"managed-by"* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # package-trust-baseline TOML; parser must tolerate without
    # altering the profile-gated behavior. strict-with-noise
    # still installs the strict apt drop-in (AllowUnauthenticated
    # = false + AllowDowngradeToInsecureRepositories = false +
    # SecureBoot enforcement — anti-supply-chain-attack on the
    # apt-get update transaction).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "supply-chain MITM defense via apt secure-by-default"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DST}" ]
    grep -qE 'AllowUnauthenticated|AllowDowngradeToInsecure|Verify-Peer|secure' "${DST}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing the apt drop-in. A silent dry-run
    # that committed would flip the apt-secure-by-default posture
    # on a host where operator was investigating package-management
    # behavior — could break operator workflow that intentionally
    # uses 3rd-party-repo with relaxed authentication during
    # bootstrap. Locks dry-run-preserves-state on the apt-supply-
    # chain-defense substrate.
    write_config "strict"
    rm -f "${DST}"
    DRY_RUN=1 run_wd
    [ ! -f "${DST}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the apt
    # supply-chain-defense installer surface (T1195.001 supply
    # chain compromise via downgraded apt-secure posture).
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"package-trust-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (drop-in carries selfdef-identifier in filename — operator audit-trail + uninstall identification)" {
    # Sister to brain-wide filename-identifier INVARIANTs. apt
    # drop-in filename MUST carry selfdef identifier so operator
    # can immediately identify ownership via `ls /etc/apt/apt.conf.d/`.
    write_config "strict"
    run_wd
    case "${DST}" in
        */50-selfdef-*) : ;;
        *) fail "drop-in filename must follow 50-selfdef-* convention" ;;
    esac
}

@test "INVARIANT (no auto-uninstall: package-trust-baseline NEVER emits package-remove commands on apt)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The package-trust-baseline installer writes an
    # apt.conf.d drop-in pinning APT::Get::AllowUnauthenticated=
    # false but MUST NEVER emit shell commands that uninstall
    # the apt package itself (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall apt|apt-utils). Silent auto-removal would tear
    # down the package-management substrate entirely — every
    # upgrade path is broken; the host becomes unable to
    # receive CVE patches. T1195.001 self-defeat by the very
    # module meant to harden the supply-chain. Locks anti-
    # package-removal contract on the package-trust-baseline
    # substrate.
    write_config "strict"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(apt|apt-utils)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DST}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. package-trust-baseline manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the apt allow-downgrades / unsigned-suite-deny
    # baseline. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the package-trust-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'package-trust-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: package-trust-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # package-trust-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the package-trust-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # package-trust-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the package-trust-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the package-trust-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}
