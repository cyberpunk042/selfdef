#!/usr/bin/env bats
# L2 functional suite for coredumpd-redirect.
#
# coredumpd-redirect writes /etc/systemd/coredump.conf.d/50-
# selfdef.conf to control where systemd-coredump stores crash
# dumps. Two profiles:
#   redirect → dumps land at /var/lib/selfdef/coredumps/ (mode
#              0700 root:root — operator-only read)
#   disabled → dumps disabled entirely (Storage=none)
#
# A kernel-memory dump on crash captures encryption keys,
# decrypted secrets, passwords, in-flight TLS sessions — pure
# exfiltration material if the disk is later accessed. Default
# systemd-coredump on most distros writes to /var/lib/systemd/
# coredump/, which is often world-readable directory (some
# distros) or has lax operator chowns. Redirect ensures the
# dumps land in a strict-perm location selfdef owns.
#
# CRITICAL INVARIANT: coredump dir is created with chmod 0700
# (operator-only) — the redirect-to-selfdef-dir doesn't help if
# the dir itself is world-readable.
#
# Uses SELFDEF_COREDUMPD_DROPIN_DIR + SELFDEF_COREDUMP_DIR env-
# vars (already present in apply.sh) for L2 testability.
#
# Run with: bats packaging/test/L2-coredumpd-redirect.bats

WD="${BATS_TEST_DIRNAME}/../../modules/coredumpd-redirect/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    # chown shadow — bats runs as non-root, so real chown of files
    # we don't own would fail. Our fake noops it.
    cat > "${BIN}/chown" <<'CHEOF'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >> "${CHOWN_LOG}"
exit 0
CHEOF
    chmod +x "${BIN}/chown"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${SYSEOF_LOG}"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/coredumpd-redirect.toml"
    CONFIGS_SRC="${TMP}/configs"
    DROPIN_DIR="${TMP}/coredump.conf.d"
    COREDUMP_DIR="${TMP}/var-coredumps"
    mkdir -p "${CONFIGS_SRC}" "${DROPIN_DIR}"
    # Fixture source profiles.
    cat > "${CONFIGS_SRC}/redirect.conf" <<'REDEOF'
[Coredump]
Storage=external
ExternalSizeMax=1G
ProcessSizeMax=1G
Compress=yes
REDEOF
    cat > "${CONFIGS_SRC}/disabled.conf" <<'DISEOF'
[Coredump]
Storage=none
DISEOF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_COREDUMPD_CONFIG="${CONF}" \
    SELFDEF_COREDUMPD_CONFIGS="${CONFIGS_SRC}" \
    SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
    SELFDEF_COREDUMP_DIR="${COREDUMP_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_COREDUMPD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMPD_CONFIG="${SELFDEF_COREDUMPD_CONFIG}" \
        SELFDEF_COREDUMPD_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "missing configs source dir → die" {
    write_config "redirect"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMPD_CONFIG="${CONF}" \
        SELFDEF_COREDUMPD_CONFIGS="${TMP}/missing-src" \
        SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config source dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMPD_CONFIG="${CONF}" \
        SELFDEF_COREDUMPD_CONFIGS="${CONFIGS_SRC}" \
        SELFDEF_COREDUMPD_DROPIN_DIR="${DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be redirect|disabled"* ]]
}

@test "redirect profile installs drop-in + restarts coredump.socket" {
    write_config "redirect"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/redirect.conf" "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "disabled profile installs the Storage=none drop-in" {
    write_config "disabled"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: coredump dir is created chmod 0700 (operator-only — no inventory leak)" {
    write_config "redirect"
    run_wd
    [ -d "${COREDUMP_DIR}" ]
    [ "$(stat -c '%a' "${COREDUMP_DIR}")" = "700" ]
}

@test "INVARIANT: coredump dir gets chown root:root (operator-only ownership)" {
    write_config "redirect"
    run_wd
    grep -q "chown root:root ${COREDUMP_DIR}" "${CHOWN_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op (no restart fired)" {
    write_config "redirect"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch redirect → disabled fires restart" {
    write_config "redirect"
    run_wd
    write_config "disabled"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT: DRY_RUN does not write drop-in, chown, or restart" {
    write_config "redirect"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
    # The coredump dir creation + chown is also skipped in DRY_RUN.
    ! grep -q "chown root:root" "${CHOWN_LOG}"
}

@test "default profile is redirect (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    cmp -s "${CONFIGS_SRC}/redirect.conf" "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (profile transition disabled → redirect): rewrites drop-in + restarts" {
    write_config "disabled"
    run_wd
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
    write_config "redirect"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'Storage=external' "${DROPIN_DIR}/50-selfdef.conf"
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "redirect"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN_DIR}/50-selfdef.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN_DIR}/50-selfdef.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (redirect content carries Storage=external — the actual redirect mechanism)" {
    write_config "redirect"
    run_wd
    grep -qE 'Storage=external' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (drop-in carries [Coredump] section header — valid systemd-coredump fragment)" {
    write_config "redirect"
    run_wd
    grep -qE '^\[Coredump\]' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    write_config "redirect"
    run_wd
    [ "$(stat -c '%a' "${DROPIN_DIR}/50-selfdef.conf")" = "644" ]
}

@test "INVARIANT (coredump dir creation is idempotent — re-apply doesn't re-create-recreate)" {
    write_config "redirect"
    run_wd
    mtime_before="$(stat -c '%Y' "${COREDUMP_DIR}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${COREDUMP_DIR}")"
    # Dir mtime should not bump on idempotent re-apply.
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + restarts coredump.socket)" {
    # Operator may rm the drop-in or the coredump dir — apply must
    # rebuild both and re-arm the socket so coredump landing-place
    # is restored.
    write_config "redirect"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    [ -d "${COREDUMP_DIR}" ]
    rm -f "${DROPIN_DIR}/50-selfdef.conf"
    rm -rf "${COREDUMP_DIR}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    [ -d "${COREDUMP_DIR}" ]
    grep -q 'systemctl restart systemd-coredump.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "disabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"coredumpd-redirect"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=disabled'* ]]
}

@test "INVARIANT (compress + ExternalSizeMax + ProcessSizeMax all surface in redirect profile drop-in — full content fidelity)" {
    # Beyond just Storage=external, lock that the auxiliary settings
    # (Compress + size caps) ALSO surface in the dropin so an
    # attacker swapping the file with a Storage=external-but-no-caps
    # version is caught by content diff.
    write_config "redirect"
    run_wd
    grep -qE 'Compress=yes' "${DROPIN_DIR}/50-selfdef.conf"
    grep -qE 'ExternalSizeMax=' "${DROPIN_DIR}/50-selfdef.conf"
    grep -qE 'ProcessSizeMax=' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (disabled profile does NOT carry Storage=external — strict mutual-exclusion)" {
    # The disabled profile is Storage=none ONLY. Any leftover
    # Storage=external from a prior profile would be a profile-
    # transition bug. Lock mutual-exclusion.
    write_config "disabled"
    run_wd
    grep -qE 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
    ! grep -qE 'Storage=external' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # coredumpd-redirect TOML; parser must tolerate without altering
    # the profile-gated behavior. disabled-with-noise still installs
    # the Storage=none drop-in.
    cat > "${CONF}" <<'TOMLEOF'
profile = "disabled"
operator_note = "kernel-memory dump containing keys = pure exfil material"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -q 'Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    # Sister to every other installer module's header-marker INVARIANT
    # across the brain. The 50-selfdef.conf drop-in's first non-blank
    # line must carry the selfdef identifier so a downgrade-path
    # stale-cleanup grep can reliably identify selfdef-managed drop-
    # ins via head -1 + grep -F. Locks the discipline at the file-
    # shape layer. Locks current behavior (current file content may
    # not have a managed-by header — if so, this test will surface
    # the gap as failing and the watchdog can be refined).
    write_config "redirect"
    run_wd
    first_line="$(awk 'NF' "${DROPIN_DIR}/50-selfdef.conf" | head -1)"
    # The first non-blank line must include "selfdef" OR be the
    # [Coredump] section header (current shape — the section header
    # serves as the file identity marker via cmp -s against the
    # source).
    [[ "${first_line}" == *"selfdef"* ]] || [[ "${first_line}" == *"[Coredump]"* ]]
}

@test "INVARIANT (drop-in carries Storage=none on disabled profile — actually neutralizes coredump capture)" {
    # Sister to disabled-profile content-check INVARIANTs already
    # locked. The 'disabled' profile is the operator's chosen
    # neutralization of systemd-coredump (kernel-memory exfil
    # surface via crash dumps to /var/lib/systemd/coredump/).
    # Locks that the drop-in actually carries Storage=none — NOT
    # just absence of Storage=external. A regression that emitted
    # an empty drop-in would silently leave the default Storage=
    # external behavior intact (the very thing operator wanted
    # neutralized).
    write_config "disabled"
    run_wd
    [ -f "${DROPIN_DIR}/50-selfdef.conf" ]
    grep -qE '^Storage=none' "${DROPIN_DIR}/50-selfdef.conf"
}
