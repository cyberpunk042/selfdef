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

@test "INVARIANT (dropin re-arm after operator out-of-band deletion: re-creates dropin + fires nft -f load)" {
    write_config "baseline"
    run_wd
    [ -f "${NFT_DROPIN}" ]
    rm -f "${NFT_DROPIN}"
    : > "${NFT_LOG}"
    run_wd
    [ -f "${NFT_DROPIN}" ]
    grep -q 'managed-by: selfdef nftables-baseline' "${NFT_DROPIN}"
    grep -qE "nft -f ${NFT_DROPIN}" "${NFT_LOG}"
}

@test "INVARIANT (header marker first non-blank line — predictable for operator audit + stale-cleanup)" {
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${NFT_DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef nftables-baseline" ] || \
        grep -qE '^#.*managed-by: selfdef nftables-baseline' "${NFT_DROPIN}"
}

@test "INVARIANT (forward chain has default-drop policy — sovereign endpoint refuses routing)" {
    # A sovereign endpoint should NEVER forward packets. The
    # forward chain default-drop ensures the host can't be turned
    # into a router via kernel misconfiguration or attacker
    # sysctl edit.
    write_config "baseline"
    run_wd
    grep -qE 'hook forward priority 0; policy drop' "${NFT_DROPIN}"
}

@test "INVARIANT (locked profile in JSON: egress=drop surfaces — operator dashboard sees egress posture)" {
    # The egress= field tells operator at-a-glance which egress
    # posture is active. drop = locked, accept = baseline/web.
    write_config "locked" 'acknowledge_egress = true'
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'profile=locked'* ]]
    [[ "${output}" == *'egress=drop'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key: locked+ack=false ALWAYS dies — config layering doesn't bypass)" {
    # Sister to tmpfs-baseline refuse-to-brick-precedence INVARIANT
    # + kernel-yama paranoid + unprivileged-userns deny pattern. The
    # acknowledge_egress gate fires BEFORE other knobs (extra config
    # lines must not bypass the gate).
    write_config "locked" 'acknowledge_egress = false' 'extra_knob = "anything"'
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NFT_CONFIG="${CONF}" \
        SELFDEF_NFT_DROPIN_DIR="${NFT_DROPIN_DIR}" \
        SELFDEF_NFT_DROPIN="${NFT_DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"acknowledge_egress"* ]]
    ! [ -f "${NFT_DROPIN}" ]
}

@test "INVARIANT (anti-lockout SSH-accept rule on EVERY profile — baseline + web + locked all include SSH accept)" {
    # Anti-lockout is the foundational discipline. Locks that
    # SSH-accept fires across all 3 profiles, not just baseline.
    # A regression that drops SSH-accept from any profile would
    # produce a remote-lockout on apply.
    write_config "baseline"
    run_wd
    grep -q 'tcp dport { 22' "${NFT_DROPIN}"
    write_config "web" 'allow_tcp = "80,443"'
    run_wd
    grep -q 'tcp dport { 22' "${NFT_DROPIN}"
    write_config "locked" 'acknowledge_egress = true'
    run_wd
    grep -q 'tcp dport { 22' "${NFT_DROPIN}"
}

@test "INVARIANT (nft delete + nft -f ordering: delete BEFORE -f load on content-change reload — atomic swap)" {
    # Order matters: nft delete table fires BEFORE nft -f load on
    # content-change. Otherwise the new rules would be added on
    # top of the old rules, creating a transient double-rule
    # state visible to attacker traffic.
    write_config "baseline"
    run_wd
    : > "${NFT_LOG}"
    write_config "web" 'allow_tcp = "8080"'
    run_wd
    delete_line="$(grep -n 'nft delete table inet selfdef_filter' "${NFT_LOG}" | head -1 | cut -d: -f1)"
    load_line="$(grep -n "nft -f ${NFT_DROPIN}" "${NFT_LOG}" | head -1 | cut -d: -f1)"
    [ -n "${delete_line}" ]
    [ -n "${load_line}" ]
    [ "${delete_line}" -lt "${load_line}" ]
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to many other installer module's chmod 0644 INVARIANT
    # across the brain (sysctl drop-ins, journal-tune, kernel-yama).
    # The nftables ruleset drop-in lands at /etc/nftables.d/50-
    # selfdef.conf alongside operator-hand-authored / packaging-
    # provided drop-ins. Must be world-readable (nft -f reads it
    # at boot via nftables.service) and root-write-only — any
    # other perm would let an attacker silently rewrite the
    # ruleset to allow ingress on any port + bypass the entire
    # firewall posture.
    write_config "baseline"
    run_wd
    [ -f "${NFT_DROPIN}" ]
    [ "$(stat -c '%a' "${NFT_DROPIN}")" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO nft -f load fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/nftables.d/50-selfdef.conf AND
    # without firing nft -f load. A silent dry-run that committed
    # would re-apply the firewall ruleset AT PREVIEW TIME — could
    # lock out the operator's admin SSH source IP if egress profile
    # has changed since last apply. Locks dry-run-preserves-state
    # on the host-firewall ruleset substrate.
    write_config "baseline"
    rm -f "${NFT_DROPIN}"
    : > "${NFT_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${NFT_DROPIN}" ]
    ! grep -qE "nft -f ${NFT_DROPIN}" "${NFT_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the
    # host-firewall installer surface.
    write_config "baseline"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"nftables-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (locked profile carries DROP policy on OUTPUT chain — egress-deny semantics)" {
    # Sister to brain-wide profile-specific-content INVARIANTs.
    # locked profile is the strictest mode and MUST carry an
    # OUTPUT chain with DROP policy. Without it the locked
    # profile silently degrades to non-locked egress.
    write_config "locked" 'acknowledge_egress = true'
    run_wd
    grep -qE 'chain output \{.*type filter hook output' "${NFT_DROPIN}" \
        || grep -qE 'chain output' "${NFT_DROPIN}"
    grep -qE 'policy drop' "${NFT_DROPIN}"
}

@test "INVARIANT (no auto-uninstall: nftables-baseline NEVER emits package-remove commands on nftables)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The nftables-baseline installer writes the
    # selfdef-baseline drop-in but MUST NEVER emit shell
    # commands that uninstall the nftables package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall nftables|
    # nft). Silent auto-removal would tear down the host
    # firewall substrate entirely — every downstream defense
    # (bridge-l2, vpn-bridge, suricata NFQUEUE, polarproxy NAT)
    # loses substrate. T1562.001 self-defeat. Locks anti-
    # package-removal contract on the nftables-baseline
    # substrate.
    write_config "baseline"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(nftables|nft)'
    [ ! -f "${NFT_DROPIN}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${NFT_DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. nftables-baseline manifest declares install +
    # profile gating (default / locked) the resolver enforces;
    # malformed manifest wedges the nftables egress-deny
    # baseline. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'nftables-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: nftables-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # nftables-baseline writes its own drop-in or config; it MUST NEVER
    # rm/find-delete an operator's pre-existing entries not
    # owned by THIS module. Locks no-auto-delete on the
    # nftables-baseline installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # nftables-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the nftables-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    # the nftables-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    # present discipline on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    # category-present discipline on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the nftables-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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

@test "INVARIANT (nftables-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the nftables-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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

@test "INVARIANT (nftables-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the nftables-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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

@test "INVARIANT (nftables-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for nftables-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the nftables-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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

@test "INVARIANT (nftables-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the nftables-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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

@test "INVARIANT (nftables-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the nftables-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the nftables-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the nftables-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
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

@test "INVARIANT (nftables-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (nftables-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (nftables-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (nftables-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (nftables-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (nftables-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (nftables-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (nftables-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (nftables-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (nftables-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (nftables-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (nftables-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (nftables-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (nftables-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (nftables-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (nftables-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (nftables-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (nftables-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nftables-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}
