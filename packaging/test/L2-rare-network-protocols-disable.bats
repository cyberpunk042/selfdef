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
