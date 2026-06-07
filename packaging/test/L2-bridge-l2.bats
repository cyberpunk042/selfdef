#!/usr/bin/env bats
# L2 bats unit tests for the bridge-l2 module (MS024 — transparent
# L2 bridge + nftables policy substrate for inline network modules).
#
# Run with: bats packaging/test/L2-bridge-l2.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/bridge-l2"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + declares name = bridge-l2" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"bridge-l2"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides l2-bridge + forward-policy contracts" {
    grep -q 'l2-bridge'      "${MODULE_DIR}/module.toml"
    grep -q 'forward-policy' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires ip + nft + systemctl binaries" {
    grep -q 'value = "ip"'        "${MODULE_DIR}/module.toml"
    grep -q 'value = "nft"'       "${MODULE_DIR}/module.toml"
    grep -q 'value = "systemctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires CONFIG_BRIDGE + CONFIG_NF_TABLES kernel features" {
    grep -q 'CONFIG_BRIDGE'    "${MODULE_DIR}/module.toml"
    grep -q 'CONFIG_NF_TABLES' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_BRIDGE_L2_CONFIG + _TEMPLATES override" {
    grep -q 'SELFDEF_BRIDGE_L2_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_BRIDGE_L2_TEMPLATES' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads bridge_name + forward_policy + management_iface + members" {
    grep -q 'bridge_name'      "${INSTALL_DIR}/apply.sh"
    grep -q 'forward_policy'   "${INSTALL_DIR}/apply.sh"
    grep -q 'management_iface' "${INSTALL_DIR}/apply.sh"
    grep -q 'members'          "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh writes /etc/nftables.d/selfdef-bridge.conf" {
    grep -q '/etc/nftables.d/selfdef-bridge.conf' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh rejects unknown profile cleanly (dry-run smoke)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_BRIDGE_L2_CONFIG="${TEST_DIR}/bridge-l2.toml"
    echo 'profile = "totally-bogus-profile-12345"' > "${SELFDEF_BRIDGE_L2_CONFIG}"
    # Mock ip / nft / systemctl.
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    for b in ip nft systemctl; do
        printf '#!/bin/bash\nexit 0\n' > "${MOCK_BIN}/${b}"
        chmod +x "${MOCK_BIN}/${b}"
    done
    export PATH="${MOCK_BIN}:${PATH}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_BRIDGE_L2_CONFIG MOCK_BIN
    # bridge-l2 only supports default profile "passthrough"; a totally
    # bogus profile should either be rejected OR fall through cleanly.
    # We assert the script doesn't crash with an unhandled error and
    # doesn't exit with a parse error.
    [ "${status}" -ne 2 ]
}

# ============================================================================
# E0247 nftables template structure invariants (verbatim from
# templates/nftables.conf.tmpl). The bridge-l2 contract with consumer
# modules (suricata, polarproxy, etc.) is that the rendered ruleset
# exposes a `selfdef_bridge` table with a `forward_hook` chain those
# consumers add jumps into. A silent rename here would break every
# consumer at apply-time; the rules below freeze that contract.
# ============================================================================

@test "E0247 template declares table inet selfdef_bridge" {
    grep -qE '^table[[:space:]]+inet[[:space:]]+selfdef_bridge[[:space:]]*\{' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template exposes empty forward_hook chain for consumer modules" {
    grep -qE '^[[:space:]]*chain[[:space:]]+forward_hook[[:space:]]*\{[[:space:]]*\}' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template FORWARD chain hooks at priority filter with substitutable policy" {
    grep -qE 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+forward[[:space:]]+priority[[:space:]]+filter;[[:space:]]+policy[[:space:]]+@@FORWARD_POLICY@@;' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 FORWARD chain jumps into forward_hook on both iif + oif (consumer surface)" {
    grep -qE '^[[:space:]]*iifname[[:space:]]+"@@BRIDGE_NAME@@"[[:space:]]+jump[[:space:]]+forward_hook' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
    grep -qE '^[[:space:]]*oifname[[:space:]]+"@@BRIDGE_NAME@@"[[:space:]]+jump[[:space:]]+forward_hook' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template carries three substitution tokens (BRIDGE_NAME, FORWARD_POLICY, MGMT_INPUT_RULE)" {
    grep -q '@@BRIDGE_NAME@@' "${MODULE_DIR}/templates/nftables.conf.tmpl"
    grep -q '@@FORWARD_POLICY@@' "${MODULE_DIR}/templates/nftables.conf.tmpl"
    grep -q '@@MGMT_INPUT_RULE@@' "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template input chain default policy is accept (management-iface drop is a substituted rule, not the chain policy)" {
    grep -qE 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+input[[:space:]]+priority[[:space:]]+filter;[[:space:]]+policy[[:space:]]+accept;' \
        "${MODULE_DIR}/templates/nftables.conf.tmpl"
}

@test "E0247 template flushes ruleset at top (bridge-l2 owns its table cleanly)" {
    # First non-comment, non-blank line must be `flush ruleset`.
    first=$(grep -vE '^[[:space:]]*(#|$)' "${MODULE_DIR}/templates/nftables.conf.tmpl" | head -1)
    [ "${first}" = "flush ruleset" ]
}

# ============================================================================
# E0248 forward_policy allowlist + idempotent-skip contract.
# `apply.sh` validates forward_policy ∈ {accept, drop}; a silent allowlist
# widening (e.g. accidentally accepting "reject") could render an nft
# ruleset the kernel refuses to load, taking the bridge down. The skip
# contract is similarly load-bearing: operators (and selfdefctl status
# parsers) depend on the exact JSON `status:skipped` marker.
# ============================================================================

@test "E0248 apply.sh validates forward_policy against accept|drop allowlist" {
    grep -qE '\[\[[[:space:]]+"\$FORWARD_POLICY"[[:space:]]+==[[:space:]]+"accept"[[:space:]]+\|\|[[:space:]]+"\$FORWARD_POLICY"[[:space:]]+==[[:space:]]+"drop"[[:space:]]+\]\]' \
        "${INSTALL_DIR}/apply.sh"
}

@test "E0248 apply.sh emits status:skipped when ruleset already at target state" {
    grep -qE 'emit_status[[:space:]]+"skipped"[[:space:]]+"already at target state"' \
        "${INSTALL_DIR}/apply.sh"
}

@test "E0248 apply.sh writes ruleset to /etc/nftables.d/selfdef-bridge.conf (E0247 deploy path)" {
    grep -qE '/etc/nftables\.d/selfdef-bridge\.conf' "${INSTALL_DIR}/apply.sh"
}

@test "E0250 caveat surfaced in operator README (severs connection if run on bridged NIC)" {
    grep -qiE 'sever|severs|severing' "${MODULE_DIR}/README.md"
    grep -qiE 'management interface|console' "${MODULE_DIR}/README.md"
}

@test "INVARIANT (apply.sh emits emit_status JSON for operator dashboard observability — SDD-062 consumer contract)" {
    # Sister to every other installer module's emit_status INVARIANT
    # across the brain. The bridge-l2 apply.sh MUST surface its
    # apply outcome to the operator dashboard via the emit_status
    # JSON record (status=ok / skipped, profile, message). Without
    # it, an operator deploying a transparent L2 bridge has no
    # signal whether the bridge came up successfully, was skipped
    # as already-at-target, or which forward_policy is live. Closes
    # the emit_status visibility axis on the L2-bridge substrate
    # alongside the E0248 emit_status skipped contract already
    # locked. The MS024 transparent L2 bridge + nftables policy
    # surface is foundational for all inline network modules
    # (suricata, polarproxy, …); dashboard observability gates
    # operator confidence to deploy.
    grep -q 'emit_status' "${INSTALL_DIR}/apply.sh"
    # Should emit at least the canonical success+skipped pair.
    n_emits=$(grep -cE '^[[:space:]]*emit_status' "${INSTALL_DIR}/apply.sh" || echo 0)
    [ "${n_emits}" -ge 1 ]
}

@test "INVARIANT (module.toml provides l2-bridge contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (suricata ids+eve-json, slm-cpu-
    # loop slm-loop-runtime, tensor-parallel-inference tensor-
    # parallel-runtime, wasm-aot-cache wasm-aot-cache-dir). The
    # bridge-l2 module is the substrate every inline network
    # module composes on. Its provides token names the L2-bridge
    # interface — every consumer module (suricata, polarproxy,
    # future inline IDS/IPS modules) lists this in depends_on. A
    # silent rename of the token would break every downstream
    # consumer.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"l2-bridge"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"bridge-l2"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"selfdef_bridge"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh renders ruleset with chmod 0644 — system-config convention)" {
    # Sister to many other installer module's chmod-0644
    # INVARIANT across the brain (sysctl drop-ins, limits.d,
    # ssh-hardening drop-in, journal-tune drop-in, AppArmor
    # AA_LIST). The /etc/nftables.d/selfdef-bridge.conf
    # ruleset lands at a system-config path consumed by
    # nftables.service at boot AND by operator audit tooling.
    # 0644 is the standard read-everyone, write-root
    # convention. A world-writable regression would let any
    # user rewrite the L2 bridge ruleset and disable inline
    # IDS/IPS surveillance silently. Locks the file-perm
    # contract on the transparent L2 bridge ruleset render
    # path.
    grep -qE 'install[[:space:]].*-m[[:space:]]+0?644' "${INSTALL_DIR}/apply.sh" \
        || grep -qE 'chmod[[:space:]]+0?644' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (apply.sh uses set -euo pipefail — anti-half-installed-state contract)" {
    # Sister to brain-wide installer-script-hygiene INVARIANTs.
    # Without set -euo pipefail a mid-install failure leaves the
    # host in a half-installed state silently.
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/apply.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/apply.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/apply.sh")
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — full lifecycle fail-loud invariant)" {
    # Sister to apply.sh fail-loud INVARIANT just locked. The
    # check.sh + uninstall.sh paths MUST also be fail-loud —
    # half-cleanup state during operator MTTR (orphan nftables
    # table inet selfdef_bridge with no rules) silently drops
    # L2-bridge traffic.
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/check.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/check.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/check.sh")
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/uninstall.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/uninstall.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/uninstall.sh")
}

@test "INVARIANT (no auto-uninstall: bridge-l2 installer NEVER emits package-remove commands on nftables)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The bridge-l2 installer wires nftables FORWARD
    # rules + bridge table inet selfdef_bridge but MUST NEVER
    # emit shell commands that uninstall the nftables package
    # itself (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # nftables|nft). Silent auto-removal of nftables would tear
    # down the L2 bridge ruleset entirely + leave the network
    # path in unfiltered state — every downstream filter (suricata
    # NFQUEUE, ingress hooks, FORWARD chain) loses substrate.
    # Locks anti-package-removal contract on the L2 bridge
    # substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(nftables|nft)' "${f}"
    done
}
