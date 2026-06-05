#!/usr/bin/env bats
# L2 bats unit tests for the suricata module (MS023 sister — Inline
# IDS via Suricata, NFQUEUE or AF_PACKET copy-mode). Depends on
# bridge-l2 (MS024).
#
# Run with: bats packaging/test/L2-suricata.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/suricata"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + name = suricata" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"suricata"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on bridge-l2 (MS024 substrate)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"bridge-l2"' "${MODULE_DIR}/module.toml"
}

@test "module.toml profile default = host-ids" {
    grep -qE 'default[[:space:]]*=[[:space:]]*"host-ids"' "${MODULE_DIR}/module.toml"
}

@test "install scripts exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail + DRY_RUN aware" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_SURICATA_CONFIG + _TEMPLATES override" {
    grep -q 'SELFDEF_SURICATA_CONFIG'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_SURICATA_TEMPLATES' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads mode + queue_num config keys (NFQUEUE)" {
    grep -q 'mode'      "${INSTALL_DIR}/apply.sh"
    grep -q 'queue_num' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh handles both NFQUEUE + AF_PACKET copy-modes" {
    grep -q 'nfqueue'    "${INSTALL_DIR}/apply.sh"
    grep -qE 'af.packet|AF_PACKET' "${INSTALL_DIR}/apply.sh"
}

# ============================================================================
# Cross-module consumer contract — suricata's nfqueue template adds a jump
# INTO bridge-l2's `inet selfdef_bridge` table → `forward_hook` chain.
# E0245 verbatim: "the owning module does not know about its consumers".
# That makes a silent rename of either the table or the chain a CROSS-MODULE
# silent break that only surfaces at apply-time on a real host. These
# assertions freeze the consumer-side of bridge-l2's E0247 contract.
# ============================================================================

@test "nfqueue rule targets bridge-l2's selfdef_bridge table (E0245 consumer contract)" {
    grep -qE 'inet[[:space:]]+selfdef_bridge' \
        "${MODULE_DIR}/templates/nfqueue.rule.tmpl"
}

@test "nfqueue rule jumps into bridge-l2's forward_hook chain (E0247 consumer surface)" {
    grep -qE 'add[[:space:]]+rule[[:space:]]+inet[[:space:]]+selfdef_bridge[[:space:]]+forward_hook' \
        "${MODULE_DIR}/templates/nfqueue.rule.tmpl"
}

@test "nfqueue rule uses queue ... bypass (suricata-down fail-open is intentional)" {
    grep -qE 'queue[[:space:]]+num[[:space:]]+@@QUEUE_NUM@@[[:space:]]+bypass' \
        "${MODULE_DIR}/templates/nfqueue.rule.tmpl"
}

@test "nfqueue rule carries @@QUEUE_NUM@@ substitution token" {
    grep -q '@@QUEUE_NUM@@' "${MODULE_DIR}/templates/nfqueue.rule.tmpl"
}

@test "nfqueue rule carries selfdef-suricata comment (operator nft list rule audit)" {
    grep -q 'comment "selfdef-suricata"' "${MODULE_DIR}/templates/nfqueue.rule.tmpl"
}
