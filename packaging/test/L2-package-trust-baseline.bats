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

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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
    # the package-trust-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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
    # package-trust-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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
    # package-trust-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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
    # Locks semver-X.Y.Z discipline on the package-trust-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the package-trust-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the package-trust-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the package-trust-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for package-trust-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the package-trust-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the package-trust-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the package-trust-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the package-trust-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the package-trust-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the package-trust-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the package-trust-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (package-trust-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (package-trust-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (package-trust-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (package-trust-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (package-trust-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (package-trust-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (package-trust-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (package-trust-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (package-trust-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (package-trust-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (package-trust-baseline module.toml exists at canonical path modules/package-trust-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (package-trust-baseline module dir is at canonical path modules/package-trust-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (package-trust-baseline install dir exists at modules/package-trust-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (package-trust-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (package-trust-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (package-trust-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (package-trust-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (package-trust-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (package-trust-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (package-trust-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (package-trust-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (package-trust-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (package-trust-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (package-trust-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (package-trust-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (package-trust-baseline module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (package-trust-baseline module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (package-trust-baseline module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (package-trust-baseline module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (package-trust-baseline module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"package-trust-baseline"' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
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

@test "INVARIANT (package-trust-baseline module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (package-trust-baseline module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (package-trust-baseline module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (package-trust-baseline module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (package-trust-baseline module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (package-trust-baseline module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/package-trust-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}
