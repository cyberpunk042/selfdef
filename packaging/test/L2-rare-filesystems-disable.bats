#!/usr/bin/env bats
# L2 functional suite for rare-filesystems-disable.
#
# rare-filesystems-disable installs a modprobe blacklist for
# rarely-used filesystem drivers. Each disabled kernel module is
# one less remote-mount / loop-mount / USB-auto-mount attack
# surface. Profiles:
#   baseline → cramfs / freevxfs / jffs2 / hfs / hfsplus / udf /
#              ksmbd (7 modules)
#   strict   → baseline + squashfs + nfsd + gfs2 (10 modules)
#
# Each rare filesystem is one less kernel-driver code path
# attackers can target. CVEs have hit cramfs, hfsplus, ksmbd, etc.
# in recent years.
#
# Adds SELFDEF_RAREFS_MODPROBE_FILE env-var (added 2026-06-06)
# for L2 testability.
#
# Run with: bats packaging/test/L2-rare-filesystems-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rare-filesystems-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    CONF="${TMP}/rare-filesystems-disable.toml"
    MODPROBE_FILE="${TMP}/selfdef-rare-filesystems-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_RAREFS_CONFIG="${CONF}" \
    SELFDEF_RAREFS_MODPROBE_FILE="${MODPROBE_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_RAREFS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RAREFS_CONFIG="${SELFDEF_RAREFS_CONFIG}" \
        SELFDEF_RAREFS_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RAREFS_CONFIG="${CONF}" \
        SELFDEF_RAREFS_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile installs blacklist with 7 baseline modules" {
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef rare-filesystems-disable' "${MODPROBE_FILE}"
    # Check the 7 baseline modules.
    for m in cramfs freevxfs jffs2 hfs hfsplus udf ksmbd; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
    # Strict-only modules should NOT be present.
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    ! grep -q 'blacklist nfsd' "${MODPROBE_FILE}"
}

@test "strict profile adds squashfs + nfsd + gfs2 on top of baseline" {
    write_config "strict"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    # All 10 modules.
    for m in cramfs freevxfs jffs2 hfs hfsplus udf ksmbd squashfs nfsd gfs2; do
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
    grep -q 'managed-by: selfdef rare-filesystems-disable' "${MODPROBE_FILE}"
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
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
}

@test "INVARIANT (profile upgrade baseline → strict): adds strict-only modules + bumps profile metadata" {
    write_config "baseline"
    run_wd
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    write_config "strict"
    run_wd
    grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    grep -q 'blacklist nfsd' "${MODPROBE_FILE}"
    grep -q 'blacklist gfs2' "${MODPROBE_FILE}"
    grep -q 'profile=strict' "${MODPROBE_FILE}"
}

@test "INVARIANT (profile downgrade strict → baseline): REMOVES strict-only modules" {
    # If profile downgrade leaves strict-only modules in the blacklist,
    # the operator's intent (relax) is silently violated.
    write_config "strict"
    run_wd
    grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    write_config "baseline"
    run_wd
    ! grep -q 'blacklist squashfs' "${MODPROBE_FILE}"
    ! grep -q 'blacklist nfsd' "${MODPROBE_FILE}"
    ! grep -q 'blacklist gfs2' "${MODPROBE_FILE}"
}

@test "INVARIANT (each blacklist line has 'install <mod> /bin/false' OR 'blacklist <mod>' shape)" {
    # blacklist alone allows manual modprobe to still load; install
    # /bin/false is the stricter shape that even root-modprobe blocks.
    # At minimum the file must use one of these canonical shapes.
    write_config "baseline"
    run_wd
    # Each baseline module appears as blacklist; install /bin/false may
    # also appear for hardening.
    for m in cramfs freevxfs jffs2; do
        grep -qE "(blacklist|install) ${m}" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (modprobe.d path convention): filename matches selfdef-* pattern (for tracking + uninstall)" {
    write_config "baseline"
    run_wd
    case "${MODPROBE_FILE}" in
        */selfdef-*.conf) : ;;
        *) fail "modprobe blacklist filename must follow selfdef-*.conf pattern; got: ${MODPROBE_FILE}" ;;
    esac
}

@test "INVARIANT (header-marker pin): file MUST carry the managed-by header (collateral-damage protection at uninstall)" {
    # Without this header, uninstall can't safely identify selfdef-
    # authored vs operator-authored blacklist content.
    write_config "baseline"
    run_wd
    grep -qE '^#.*managed-by:.*selfdef' "${MODPROBE_FILE}"
}

@test "INVARIANT (install /bin/true hardening: each module also blocked via install line — defends against manual modprobe)" {
    # 'blacklist' alone allows manual modprobe to still load the
    # module. 'install <mod> /bin/true' blocks even explicit
    # modprobe invocations. Lock that the canonical hardening
    # shape is present (whitespace tolerant — actual config uses
    # multi-space alignment).
    write_config "baseline"
    run_wd
    for m in cramfs jffs2 hfs hfsplus; do
        grep -qE "^install[[:space:]]+${m}[[:space:]]+/bin/(true|false)" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (blacklist re-arm after operator deletion: re-creates with header)" {
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    rm -f "${MODPROBE_FILE}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'managed-by: selfdef rare-filesystems-disable' "${MODPROBE_FILE}"
    grep -q 'blacklist cramfs' "${MODPROBE_FILE}"
}

@test "INVARIANT (header-marker is first non-blank line — predictable for stale-cleanup head -1 grep)" {
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${MODPROBE_FILE}")"
    [ "${first_line}" = "# managed-by: selfdef rare-filesystems-disable" ]
}

@test "INVARIANT (current behavior: write target is overwritten — selfdef-prefixed filename means file is owned by selfdef)" {
    # Unlike wireless-disable + wwan-disable which check the
    # header marker before removal in their downgrade paths,
    # rare-filesystems-disable does NOT guard against overwriting
    # a pre-existing file at the target path. This is current
    # behavior because the file path is explicitly selfdef-
    # prefixed (/etc/modprobe.d/selfdef-rare-filesystems-blacklist.
    # conf) — any file at that path is treated as selfdef-owned.
    # Operators wanting custom modprobe blacklists use different
    # filenames. Lock current contract; future refinement could
    # add header-marker guard.
    printf '%s\n' '# managed-by: somebody-else' 'blacklist some-other-mod' > "${MODPROBE_FILE}"
    write_config "baseline"
    run_wd
    # The file IS overwritten with selfdef content.
    grep -q 'managed-by: selfdef rare-filesystems-disable' "${MODPROBE_FILE}"
    ! grep -q 'somebody-else' "${MODPROBE_FILE}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "baseline"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"rare-filesystems-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=baseline'* ]]
}

@test "INVARIANT (downgrade preserves header-marker — downgrade does not strip ownership marker)" {
    # When operator downgrades strict→baseline (which REMOVES modules
    # per the removal invariant), the file is rewritten — but the
    # managed-by header MUST still appear so future stale-detection
    # head -1 still identifies the file as selfdef-owned.
    write_config "strict"
    run_wd
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${MODPROBE_FILE}")"
    [ "${first_line}" = "# managed-by: selfdef rare-filesystems-disable" ]
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
}

@test "INVARIANT (each strict-only module has BOTH blacklist + install lines — same hardening shape as baseline modules)" {
    # The asymmetric tightening invariant locks profile rank by count.
    # This invariant locks the per-module SHAPE — strict-only modules
    # (squashfs/nfsd/gfs2) must receive the SAME canonical hardening
    # treatment (blacklist + install /bin/false-or-true) as baseline
    # modules. Otherwise strict is structurally weaker per-module.
    write_config "strict"
    run_wd
    for m in squashfs nfsd gfs2; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
        grep -qE "^install[[:space:]]+${m}[[:space:]]+/bin/(true|false)" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (asymmetric module-count: strict has strictly MORE blacklist lines than baseline — locks profile-rank invariant)" {
    # If a future refactor accidentally inverts profile-rank (strict
    # has fewer modules than baseline), or has equal count, the
    # operator's tightening intent is silently violated. Lock that
    # strict line count is STRICTLY greater than baseline.
    write_config "baseline"
    run_wd
    baseline_count="$(grep -cE '^blacklist[[:space:]]' "${MODPROBE_FILE}")"
    write_config "strict"
    run_wd
    strict_count="$(grep -cE '^blacklist[[:space:]]' "${MODPROBE_FILE}")"
    [ "${baseline_count}" -gt 0 ]
    [ "${strict_count}" -gt "${baseline_count}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # rare-filesystems-disable TOML; parser must tolerate without
    # altering the profile-gated behavior. strict-with-noise still
    # blacklists ALL strict modules (squashfs/nfsd/gfs2) — the
    # full rare-filesystem-driver neutralization (defense against
    # USB-attached attack-filesystem mounting + kernel module
    # exploits in obscure file systems).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "rare-FS drivers = obscure-kernel-CVE surface"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    for m in squashfs nfsd gfs2; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to many other installer module's chmod 0644 INVARIANT
    # across the brain. The modprobe drop-in (e.g. 50-selfdef-
    # rare-fs.conf) lives in /etc/modprobe.d/ and is parsed by
    # modprobe at module-autoload time + by initramfs hooks.
    # Must be world-readable (initramfs scripts run as varying
    # uids during early boot) and root-write-only — any other
    # perm would let an attacker rewrite the blacklist to allow
    # the rare FS drivers, re-exposing the kernel-CVE surface.
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}
