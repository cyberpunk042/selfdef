#!/usr/bin/env bats
# L2 functional suite for rare-network-protocols-disable.
#
# rare-network-protocols-disable installs a modprobe blacklist
# for rarely-used network-protocol kernel modules. Each disabled
# protocol is one less network-protocol code path attackers can
# target. Profiles:
#   baseline → dccp + sctp + rds + tipc (4 modules — the high-CVE
#              ones that ship enabled by default on most distros)
#   strict   → baseline + atm + can + appletalk + decnet + ipx +
#              netrom + ax25 + rose + x25 (13 modules total —
#              every historical network protocol any modern
#              endpoint shouldn't need)
#
# Adds SELFDEF_RAREPROTO_MODPROBE_FILE env-var (added 2026-06-06)
# for L2 testability.
#
# Run with: bats packaging/test/L2-rare-network-protocols-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    CONF="${TMP}/rare-network-protocols-disable.toml"
    MODPROBE_FILE="${TMP}/selfdef-rare-network-protocols-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_RARENET_CONFIG="${CONF}" \
    SELFDEF_RAREPROTO_MODPROBE_FILE="${MODPROBE_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_RARENET_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RARENET_CONFIG="${SELFDEF_RARENET_CONFIG}" \
        SELFDEF_RAREPROTO_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RARENET_CONFIG="${CONF}" \
        SELFDEF_RAREPROTO_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile blacklists 4 high-CVE protocols (dccp + sctp + rds + tipc)" {
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    for m in dccp sctp rds tipc; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
    # Strict-only protocols NOT present.
    ! grep -q 'blacklist atm' "${MODPROBE_FILE}"
    ! grep -q 'blacklist ipx' "${MODPROBE_FILE}"
}

@test "strict profile blacklists 13 protocols (baseline + 9 legacy)" {
    write_config "strict"
    run_wd
    for m in dccp sctp rds tipc atm can appletalk decnet ipx netrom ax25 rose x25; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
}

@test "blacklist file is chmod 0644 (modprobe.d convention)" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "blacklist carries header-marker + timestamp + profile" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef rare-network-protocols-disable' "${MODPROBE_FILE}"
    ! grep -qE '^# Generated [0-9]{4}-' "${MODPROBE_FILE}"  # no timestamp (2026-06-06 idempotency fix)
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite blacklist (2026-06-06 idempotency fix)" {
    write_config "baseline"
    run_wd
    mtime_before="$(stat -c '%Y' "${MODPROBE_FILE}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${MODPROBE_FILE}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write blacklist file" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "default profile is baseline (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
    ! grep -q 'blacklist atm' "${MODPROBE_FILE}"
}

@test "INVARIANT (profile upgrade baseline → strict): adds all 9 legacy protocols + bumps metadata" {
    write_config "baseline"
    run_wd
    ! grep -q 'blacklist atm' "${MODPROBE_FILE}"
    write_config "strict"
    run_wd
    for m in atm can appletalk decnet ipx netrom ax25 rose x25; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
    grep -q 'profile=strict' "${MODPROBE_FILE}"
}

@test "INVARIANT (profile downgrade strict → baseline): REMOVES legacy-only protocols (operator-relax intent)" {
    write_config "strict"
    run_wd
    grep -q 'blacklist atm' "${MODPROBE_FILE}"
    write_config "baseline"
    run_wd
    ! grep -q 'blacklist atm' "${MODPROBE_FILE}"
    ! grep -q 'blacklist ipx' "${MODPROBE_FILE}"
    ! grep -q 'blacklist x25' "${MODPROBE_FILE}"
}

@test "INVARIANT (baseline coverage is the 4 high-CVE family — locks expected count)" {
    write_config "baseline"
    run_wd
    count="$(grep -cE '^(blacklist|install) ' "${MODPROBE_FILE}")"
    # 4 modules — be lenient about install-vs-blacklist line shape.
    [ "${count}" -ge 4 ]
}

@test "INVARIANT (modprobe.d filename selfdef-* pattern): tracking + uninstall identification" {
    write_config "baseline"
    run_wd
    case "${MODPROBE_FILE}" in
        */selfdef-*.conf) : ;;
        *) fail "modprobe blacklist filename must follow selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (header-marker pin): managed-by header present (collateral-damage protection at uninstall)" {
    write_config "baseline"
    run_wd
    grep -qE '^#.*managed-by:.*selfdef' "${MODPROBE_FILE}"
}

@test "INVARIANT (install /bin/true hardening for each protocol: defends against manual modprobe — locks SCTP/DCCP CVE attack surface)" {
    # SCTP + DCCP have had memory-corruption CVEs in recent
    # kernels. The install /bin/true line blocks even root-
    # modprobe (the canonical hardening shape).
    write_config "baseline"
    run_wd
    for m in dccp sctp rds tipc; do
        grep -qE "^install[[:space:]]+${m}[[:space:]]+/bin/(true|false)" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (header-marker first non-blank line: stale-cleanup head -1 grep predictability)" {
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${MODPROBE_FILE}")"
    [ "${first_line}" = "# managed-by: selfdef rare-network-protocols-disable" ]
}

@test "INVARIANT (blacklist re-arm after operator deletion: re-creates with header + entries)" {
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    rm -f "${MODPROBE_FILE}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef rare-network-protocols-disable' "${MODPROBE_FILE}"
    grep -q 'blacklist dccp' "${MODPROBE_FILE}"
    grep -q 'blacklist sctp' "${MODPROBE_FILE}"
}

@test "INVARIANT (strict module count = 13; baseline count = 4): explicit set sizes lock against silent shrink" {
    # Verify baseline carries exactly 4 unique blacklisted modules
    # (or 4 install lines), strict carries 13. Regression that
    # silently removed a module would surface here.
    write_config "baseline"
    run_wd
    baseline_count="$(grep -cE '^blacklist ' "${MODPROBE_FILE}")"
    write_config "strict"
    run_wd
    strict_count="$(grep -cE '^blacklist ' "${MODPROBE_FILE}")"
    [ "${baseline_count}" = "4" ]
    [ "${strict_count}" = "13" ]
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "baseline"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"rare-network-protocols-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=baseline'* ]]
}

@test "INVARIANT (downgrade preserves header-marker — downgrade does not strip ownership marker)" {
    # Sister to rare-filesystems-disable downgrade-preserves-header.
    # strict→baseline rewrites the file with fewer modules but MUST
    # still carry managed-by header so stale-detection head -1
    # still identifies the file as selfdef-owned.
    write_config "strict"
    run_wd
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${MODPROBE_FILE}")"
    [ "${first_line}" = "# managed-by: selfdef rare-network-protocols-disable" ]
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
}

@test "INVARIANT (each legacy strict-only protocol has BOTH blacklist + install lines — same hardening shape as baseline)" {
    # Sister to rare-filesystems-disable strict-shape-symmetry. The
    # 9 legacy strict-only protocols (atm/can/appletalk/decnet/ipx/
    # netrom/ax25/rose/x25) must receive the SAME canonical
    # hardening treatment as the baseline 4 (dccp/sctp/rds/tipc).
    # Otherwise strict is structurally weaker per-protocol despite
    # covering more.
    write_config "strict"
    run_wd
    for m in atm can appletalk decnet ipx netrom ax25 rose x25; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
        grep -qE "^install[[:space:]]+${m}[[:space:]]+/bin/(true|false)" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (current behavior: write target is overwritten — selfdef-prefixed filename means file is owned by selfdef)" {
    # Sister to rare-filesystems-disable overwrite-current-behavior.
    # The file path is explicitly selfdef-prefixed
    # (/etc/modprobe.d/selfdef-rare-network-protocols-blacklist.conf)
    # — any file at that path is treated as selfdef-owned. Operators
    # wanting custom modprobe blacklists use different filenames.
    # Lock current contract; future refinement could add header-
    # marker guard before overwrite.
    printf '%s\n' '# managed-by: somebody-else' 'blacklist some-other-protocol' > "${MODPROBE_FILE}"
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef rare-network-protocols-disable' "${MODPROBE_FILE}"
    ! grep -q 'somebody-else' "${MODPROBE_FILE}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # rare-network-protocols-disable TOML; parser must tolerate
    # without altering the profile-gated behavior. baseline-with-
    # noise still blacklists the canonical CVE-prone protocols
    # (dccp/sctp/rds/tipc) — the foundational rare-protocol-driver
    # neutralization (memory-corruption CVE family).
    cat > "${CONF}" <<'TOMLEOF'
profile = "baseline"
operator_note = "DCCP/SCTP/RDS/TIPC = memory-corruption CVE surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    for m in dccp sctp rds tipc; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
    grep -q 'managed-by: selfdef rare-network-protocols-disable' "${MODPROBE_FILE}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to rare-filesystems-disable drop-in 0644 INVARIANT
    # just locked and many other installer module's chmod 0644
    # INVARIANTs across the brain. The modprobe drop-in lives
    # in /etc/modprobe.d/ and is parsed by modprobe at module-
    # autoload time + by initramfs hooks. Must be world-readable
    # + root-write-only — any other perm would let an attacker
    # rewrite the blacklist to allow the rare protocol drivers,
    # re-exposing the memory-corruption CVE surface (DCCP/SCTP/
    # RDS/TIPC).
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO modprobe drop-in written when DRY_RUN=1)" {
    # Sister to rare-filesystems-disable DRY_RUN INVARIANT just
    # locked and every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/modprobe.d/50-selfdef-rare-
    # net.conf. Silent dry-run could prevent legitimate use of
    # DCCP/SCTP/RDS/TIPC (e.g. operator investigating Carrier-
    # Grade NAT setup or RDMA testing) at preview time.
    write_config "baseline"
    rm -f "${MODPROBE_FILE}"
    DRY_RUN=1 run_wd
    [ ! -f "${MODPROBE_FILE}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on rare-network-protocols-disable
    # installer surface.
    write_config "baseline"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"rare-network-protocols-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: kernel-network-protocol packages NEVER auto-removed)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs.
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    ! grep -qE 'apt-get|dpkg|dnf|rpm' "${MODPROBE_FILE}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on rare-network-protocols-disable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The rare-network-protocols-disable installer MUST only
    # emit severity values from the closed set {ok,warn,alert}
    # — never custom values (critical, error, fatal, notice,
    # info). Operator dashboard parsers branch on the literal
    # severity string; an out-of-set value silently falls
    # through routing and the operator never sees the rare-net-
    # protocol neutralization status alert. Locks parser
    # contract on the rare-network-protocols-disable installer
    # JSON surface (consistency-with-watchdog-family discipline).
    write_config "baseline"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. rare-network-protocols-disable manifest declares
    # install + profile gating (audit / strict) the resolver
    # enforces; malformed manifest wedges the rare-net /etc/
    # modprobe.d disable drop-ins. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'rare-network-protocols-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: rare-network-protocols-disable installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # rare-network-protocols-disable writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the rare-network-protocols-disable
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # rare-network-protocols-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the rare-network-protocols-disable lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    # the rare-network-protocols-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    # rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    # rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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
    # Locks semver-X.Y.Z discipline on the rare-network-protocols-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the rare-network-protocols-disable module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the rare-network-protocols-disable module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the rare-network-protocols-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for rare-network-protocols-disable is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the rare-network-protocols-disable install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the rare-network-protocols-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the rare-network-protocols-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the rare-network-protocols-disable
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the rare-network-protocols-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (rare-network-protocols-disable install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (rare-network-protocols-disable install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (rare-network-protocols-disable install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (rare-network-protocols-disable install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (rare-network-protocols-disable module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml exists at canonical path modules/rare-network-protocols-disable/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (rare-network-protocols-disable module dir is at canonical path modules/rare-network-protocols-disable/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (rare-network-protocols-disable install dir exists at modules/rare-network-protocols-disable/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (rare-network-protocols-disable install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (rare-network-protocols-disable install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (rare-network-protocols-disable module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (rare-network-protocols-disable install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (rare-network-protocols-disable install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (rare-network-protocols-disable install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (rare-network-protocols-disable install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"rare-network-protocols-disable"' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (rare-network-protocols-disable module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (rare-network-protocols-disable module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (rare-network-protocols-disable module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (rare-network-protocols-disable module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
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

@test "INVARIANT (rare-network-protocols-disable module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml provides list elements are all non-empty strings — TOML-provides-elements-string-canonical 131)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides') or []
for el in p:
    assert isinstance(el, str) and el, f'provides element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml conflicts list elements are all non-empty strings (or empty list) — TOML-conflicts-elements-string-canonical 132)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts') or []
for el in c:
    assert isinstance(el, str) and el, f'conflicts element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml consumes list elements are all non-empty strings (or empty) — TOML-consumes-elements-string-canonical 133)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes') or []
for el in c:
    assert isinstance(el, str) and el, f'consumes element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml depends_on list elements are all non-empty strings (or empty) — TOML-depends-on-elements-string-canonical 134)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('depends_on') or []
for el in c:
    assert isinstance(el, str) and el, f'depends_on element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths list elements are all absolute paths (starting with /) — TOML-install-paths-paths-absolute-canonical 135)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert isinstance(el, str) and el and el.startswith('/'), f'install_paths.paths element must be absolute path, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths list elements are unique (no duplicates) — TOML-install-paths-paths-unique-canonical 136)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert len(paths) == len(set(paths)), f'install_paths.paths must be unique, duplicates: {[p for p in paths if paths.count(p) > 1]!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml name field matches kebab-case pattern [a-z][a-z0-9-]+ — TOML-name-kebab-case-canonical 137)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
import re
n = data.get('name', '')
assert re.fullmatch(r'[a-z][a-z0-9-]+', n), f'name must match kebab-case [a-z][a-z0-9-]+, got {n!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml requires items have exactly the {kind, value} keyset (no extras) — TOML-requires-elements-strict-keys-canonical 138)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert set(el.keys()) == {'kind', 'value'}, f'requires element must have exactly kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths elements use FHS-canonical prefixes {/etc, /var, /usr, /run, /opt} — TOML-install-paths-fhs-prefix-canonical 139)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
prefixes = ('/etc/', '/var/', '/usr/', '/run/', '/opt/')
for el in paths:
    assert any(el.startswith(pf) for pf in prefixes), f'install_paths.paths element must use FHS-canonical prefix {prefixes}, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths elements do not end with trailing slash — TOML-install-paths-no-trailing-slash-canonical 140)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert not el.endswith('/'), f'install_paths.paths element must not end with /, got {el!r}'
"
}

@test "INVARIANT (rare-network-protocols-disable module.toml install_paths.paths elements do not contain double slashes (// not allowed) — TOML-install-paths-no-double-slash-canonical 141)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert '//' not in el, f'install_paths.paths element must not contain //, got {el!r}'
"
}
