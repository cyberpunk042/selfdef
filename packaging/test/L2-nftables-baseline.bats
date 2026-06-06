#!/usr/bin/env bats
# L2 functional suite for nftables-baseline.
#
# nftables-baseline renders a default-deny inet ruleset to
# /etc/nftables.d/selfdef-baseline.nft, validates it with
# `nft -c -f` (parse check), enforces an SSH-allow anti-lockout
# invariant, backs up the current live ruleset (single-shot),
# then loads the new ruleset into the kernel.
#
# Profiles:
#   baseline → input default-drop except SSH + ICMP + loopback
#              + established; output default-accept; forward
#              default-drop
#   web      → baseline + extra TCP allow ports from operator's
#              allow_tcp = "80,443" toml field
#   locked   → baseline + OUTPUT default-drop (only established
#              + DNS/NTP/HTTPS egress). Refuse-to-brick gate
#              requires acknowledge_egress = true (parallel to
#              other refuse-to-brick guards in the fleet).
#
# CRITICAL INVARIANTS:
#   - Parse-check before commit: rendered ruleset MUST pass
#     `nft -c -f` BEFORE being written to /etc/nftables.d/
#     (anti-brick: an invalid ruleset that breaks `nft -f` would
#     lock the operator out + leave the host firewall-less)
#   - Anti-lockout: rendered ruleset MUST contain an explicit
#     SSH-port accept (belt-and-suspenders — the renderer always
#     emits one, but verify before going live)
#   - Refuse-to-brick: locked profile (OUTPUT default-drop)
#     refuses without acknowledge_egress=true (can break apt /
#     monitoring / package-managers)
#   - Idempotent: byte-identical re-apply does NOT rewrite the
#     dropin AND does NOT fire `nft delete` + `nft -f` reload
#     (2026-06-06 variant-B fix; the destructive reload is
#     gated on content-change)
#
# Run with: bats packaging/test/L2-nftables-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    # nft mock: configurable parse-check behavior + log all calls.
    cat > "${BIN}/nft" <<'NFTEOF'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >> "${NFT_LOG}"
# `nft -c -f <file>` is the parse check — honor NFT_PARSE_OK.
if [[ "$1" == "-c" && "$2" == "-f" ]]; then
    [[ "${NFT_PARSE_OK:-1}" == "1" ]] && exit 0 || exit 1
fi
# `nft -f <file>` is the live load — honor NFT_LOAD_OK.
if [[ "$1" == "-f" ]]; then
    [[ "${NFT_LOAD_OK:-1}" == "1" ]] && exit 0 || exit 1
fi
# `nft list ruleset` is for the backup — emit a placeholder.
if [[ "$1" == "list" && "$2" == "ruleset" ]]; then
    echo "# placeholder existing ruleset"
    exit 0
fi
# `nft delete table ...` for idempotent re-apply.
exit 0
NFTEOF
    chmod +x "${BIN}/nft"
    # ss mock for detect_ssh_ports (lib uses it to find SSH ports).
    cat > "${BIN}/ss" <<'SSEOF'
#!/usr/bin/env bash
# Emit a minimal ss listing showing sshd on :22.
exit 0
SSEOF
    chmod +x "${BIN}/ss"
    export NFT_LOG="${TMP}/nft.log"
    : > "${NFT_LOG}"
    CONF="${TMP}/nftables-baseline.toml"
    NFT_DROPIN_DIR="${TMP}/nftables.d"
    NFT_DROPIN="${NFT_DROPIN_DIR}/selfdef-baseline.nft"
    BACKUP_DIR="${TMP}/backup"
    BACKUP_FILE="${BACKUP_DIR}/nftables-live-ruleset.bak"
    mkdir -p "${NFT_DROPIN_DIR}" "${BACKUP_DIR}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [extra_lines]
write_config() {
    local profile="$1"
    shift
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    for line in "$@"; do
        printf '%s\n' "${line}" >> "${CONF}"
    done
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    NFT_LOG="${NFT_LOG}" \
    NFT_PARSE_OK="${NFT_PARSE_OK:-1}" \
    NFT_LOAD_OK="${NFT_LOAD_OK:-1}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_NFT_CONFIG="${CONF}" \
    SELFDEF_NFT_DROPIN_DIR="${NFT_DROPIN_DIR}" \
    SELFDEF_NFT_DROPIN="${NFT_DROPIN}" \
    SELFDEF_NFT_BACKUP_DIR="${BACKUP_DIR}" \
    SELFDEF_NFT_BACKUP_FILE="${BACKUP_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_NFT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NFT_CONFIG="${SELFDEF_NFT_CONFIG}" \
        SELFDEF_NFT_DROPIN_DIR="${NFT_DROPIN_DIR}" \
        SELFDEF_NFT_DROPIN="${NFT_DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NFT_CONFIG="${CONF}" \
        SELFDEF_NFT_DROPIN_DIR="${NFT_DROPIN_DIR}" \
        SELFDEF_NFT_DROPIN="${NFT_DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|web|locked"* ]]
}

@test "baseline profile renders the dropin with default-deny input + SSH accept + loopback accept" {
    write_config "baseline"
    run_wd
    [ -f "${NFT_DROPIN}" ]
    grep -q 'policy drop' "${NFT_DROPIN}"
    grep -q 'tcp dport { 22' "${NFT_DROPIN}"
    grep -q 'iifname "lo" accept' "${NFT_DROPIN}"
    grep -q 'managed-by: selfdef nftables-baseline' "${NFT_DROPIN}"
}

@test "web profile honors allow_tcp = \"80,443\" extra TCP allow ports" {
    write_config "web" 'allow_tcp = "80,443"'
    run_wd
    [ -f "${NFT_DROPIN}" ]
    grep -qE 'tcp dport \{.*22.*80.*443' "${NFT_DROPIN}"
}

@test "INVARIANT: locked profile without acknowledge_egress → die (refuse-to-brick for OUTPUT default-drop)" {
    write_config "locked"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NFT_CONFIG="${CONF}" \
        SELFDEF_NFT_DROPIN_DIR="${NFT_DROPIN_DIR}" \
        SELFDEF_NFT_DROPIN="${NFT_DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"acknowledge_egress"* ]]
    ! [ -f "${NFT_DROPIN}" ]
}

@test "INVARIANT: locked WITH acknowledge_egress renders OUTPUT policy=drop + minimal egress accepts" {
    write_config "locked" 'acknowledge_egress = true'
    run_wd
    [ -f "${NFT_DROPIN}" ]
    # OUTPUT chain default-drop.
    grep -qE 'hook output priority 0; policy drop' "${NFT_DROPIN}"
    # DNS + NTP + HTTPS egress accepts.
    grep -qE 'udp dport \{[^}]*53[^}]*123' "${NFT_DROPIN}"
    grep -qE 'tcp dport \{[^}]*53[^}]*443' "${NFT_DROPIN}"
}

@test "INVARIANT: parse-check failure (nft -c -f exits 1) aborts before any file is written" {
    write_config "baseline"
    NFT_PARSE_OK=0 run env PATH="${BIN}:${PATH}" \
        NFT_LOG="${NFT_LOG}" \
        NFT_PARSE_OK=0 \
        SELFDEF_NFT_CONFIG="${CONF}" \
        SELFDEF_NFT_DROPIN_DIR="${NFT_DROPIN_DIR}" \
        SELFDEF_NFT_DROPIN="${NFT_DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"failed 'nft -c' parse"* ]]
    # Live dropin file MUST not have been written.
    ! [ -f "${NFT_DROPIN}" ]
}

@test "first apply backs up the current live ruleset once (single-shot)" {
    write_config "baseline"
    run_wd
    [ -f "${BACKUP_FILE}" ]
    grep -q '# placeholder existing ruleset' "${BACKUP_FILE}"
}

@test "INVARIANT: backup-once — re-apply does NOT overwrite the existing backup" {
    write_config "baseline"
    run_wd
    [ -f "${BACKUP_FILE}" ]
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_FILE}")"
    sleep 1
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_FILE}")"
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
}

@test "first apply fires nft -f load to install the ruleset into the kernel" {
    write_config "baseline"
    run_wd
    grep -qE "nft -f ${NFT_DROPIN}" "${NFT_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite dropin OR fire nft delete+load (2026-06-06 variant-B fix)" {
    write_config "baseline"
    run_wd
    [ -f "${NFT_DROPIN}" ]
    dropin_mtime_before="$(stat -c '%Y' "${NFT_DROPIN}")"
    : > "${NFT_LOG}"
    sleep 1
    run_wd
    dropin_mtime_after="$(stat -c '%Y' "${NFT_DROPIN}")"
    [ "${dropin_mtime_before}" = "${dropin_mtime_after}" ]
    # Live destructive reload is gated on content-change.
    ! grep -q "nft delete table inet selfdef_filter" "${NFT_LOG}"
    ! grep -qE "nft -f ${NFT_DROPIN}" "${NFT_LOG}"
}

@test "INVARIANT: profile switch baseline → web REWRITES dropin AND fires nft delete + nft -f reload" {
    write_config "baseline"
    run_wd
    sha_before="$(sha256sum "${NFT_DROPIN}" | awk '{print $1}')"
    : > "${NFT_LOG}"
    write_config "web" 'allow_tcp = "8080"'
    run_wd
    sha_after="$(sha256sum "${NFT_DROPIN}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q "nft delete table inet selfdef_filter" "${NFT_LOG}"
    grep -qE "nft -f ${NFT_DROPIN}" "${NFT_LOG}"
}

@test "INVARIANT: no render-timestamp in nft dropin (defeats cmp -s)" {
    write_config "baseline"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${NFT_DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write the dropin or fire nft delete/load" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${NFT_DROPIN}" ]
    ! grep -q 'nft delete' "${NFT_LOG}"
    ! grep -qE "nft -f ${NFT_DROPIN}" "${NFT_LOG}"
}

@test "default profile is baseline (no profile key — conservative endpoint default)" {
    : > "${CONF}"
    run_wd
    [ -f "${NFT_DROPIN}" ]
    grep -q 'policy drop' "${NFT_DROPIN}"
}

@test "emit_status reports profile + ssh_ports + tcp_allow + egress in JSON" {
    write_config "baseline"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=baseline'* ]]
    [[ "${output}" == *'tcp_allow='* ]]
    [[ "${output}" == *'egress=accept'* ]]
}
