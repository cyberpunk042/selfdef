#!/usr/bin/env bats
# L2 bats unit tests for the motd-doctrine module — login banner
# (/etc/issue + /etc/issue.net + /etc/motd) + selfdef-presence dynamic
# motd. The four templates here drive the operator-visible login surface
# every authorized user sees on every shell session — drift in the
# advertised selfdefctl verbs, the legal-warning citation, or the
# MODULES_DIR contract means operators see broken or wrong information
# at every login. The four shipped templates are:
#   - templates/issue.txt        — /etc/issue (local-console authorized-use)
#   - templates/issue.net.txt    — /etc/issue.net (network-login banner)
#   - templates/motd.txt         — /etc/motd (minimal profile static board)
#   - templates/50-selfdef-presence — verbose-profile dynamic motd script
#
# Run with: bats packaging/test/L2-motd-doctrine.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine"
INSTALL_DIR="${MODULE_DIR}/install"
TEMPLATES_DIR="${MODULE_DIR}/templates"

# ============================================================================
# Manifest contract — module identity + provides + install paths
# ============================================================================

@test "module.toml exists + declares name = motd-doctrine" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"motd-doctrine"' "${MODULE_DIR}/module.toml"
}

@test "module.toml declares category = hardening (login banner is a hardening surface)" {
    grep -qE '^category[[:space:]]*=[[:space:]]*"hardening"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides login-banner contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[[[:space:]]*"login-banner"[[:space:]]*\]' "${MODULE_DIR}/module.toml"
}

@test "module.toml declares both minimal + verbose profiles" {
    grep -qE 'available[[:space:]]*=[[:space:]]*\[[[:space:]]*"minimal"[[:space:]]*,[[:space:]]*"verbose"[[:space:]]*\]' "${MODULE_DIR}/module.toml"
    grep -qE 'default[[:space:]]*=[[:space:]]*"minimal"' "${MODULE_DIR}/module.toml"
}

@test "module.toml install_paths lists all five host-touched paths (MS011 Z-8 / SDD-026)" {
    grep -q '/etc/issue' "${MODULE_DIR}/module.toml"
    grep -q '/etc/issue.net' "${MODULE_DIR}/module.toml"
    grep -q '/etc/motd' "${MODULE_DIR}/module.toml"
    grep -q '/etc/update-motd.d/50-selfdef-presence' "${MODULE_DIR}/module.toml"
    grep -q '/etc/selfdef/modules/motd-doctrine.toml' "${MODULE_DIR}/module.toml"
}

# ============================================================================
# Install scripts — standard module-contract surface
# ============================================================================

@test "install/apply.sh + check.sh + uninstall.sh all present + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail (fail-loud invariant)" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

# ============================================================================
# Four template files — the operator-visible login surface contract.
# These templates carry the legal-warning text (issue.txt / issue.net.txt
# — CFAA citation required for jurisdiction), the selfdef-presence
# advertisement (motd.txt — selfdefctl verbs), and the dynamic motd
# (50-selfdef-presence — MODULES_DIR contract).
# ============================================================================

@test "all four templates present (issue + issue.net + motd + 50-selfdef-presence)" {
    [ -f "${TEMPLATES_DIR}/issue.txt" ]
    [ -f "${TEMPLATES_DIR}/issue.net.txt" ]
    [ -f "${TEMPLATES_DIR}/motd.txt" ]
    [ -f "${TEMPLATES_DIR}/50-selfdef-presence" ]
}

@test "issue.txt carries CFAA + 18 U.S.C. § 1030 citation (jurisdictional invariant)" {
    grep -q 'CFAA' "${TEMPLATES_DIR}/issue.txt"
    grep -qE '18 U\.S\.C\.[[:space:]]+§[[:space:]]+1030' "${TEMPLATES_DIR}/issue.txt"
}

@test "issue.txt declares AUTHORIZED USE ONLY header" {
    grep -qE 'AUTHORIZED[[:space:]]+USE[[:space:]]+ONLY' "${TEMPLATES_DIR}/issue.txt"
}

@test "issue.txt cites selfdef repo URL (operator can verify the IPS upstream)" {
    # URL is line-wrapped in the banner for terminal width; match the
    # two halves on their respective lines rather than as a contiguous
    # string.
    grep -q 'github.com/cyberpunk042' "${TEMPLATES_DIR}/issue.txt"
    grep -qE '^selfdef\)' "${TEMPLATES_DIR}/issue.txt"
}

@test "issue.net.txt is shipped (network-login banner — distinct from local /etc/issue)" {
    [ -s "${TEMPLATES_DIR}/issue.net.txt" ]
}

@test "motd.txt advertises the operator-pull selfdefctl verbs (operator UX contract)" {
    # The five verbs the motd advertises are the operator's pull-surface
    # entry points; a silent rename of any of them strands operators on
    # broken instructions at every login.
    grep -q 'selfdefctl modules list' "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdefctl alerts'       "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdefctl health'       "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdefctl dashboards'   "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdefctl ssh-wrap install' "${TEMPLATES_DIR}/motd.txt"
}

@test "motd.txt cites the per-watchdog journal tags (operator log-spelunking contract)" {
    grep -q 'selfdef-aide'      "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdef-rkhunter'  "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdef-clamav'    "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdef-lynis'     "${TEMPLATES_DIR}/motd.txt"
    grep -q 'selfdef-time-skew' "${TEMPLATES_DIR}/motd.txt"
}

@test "50-selfdef-presence is an executable bash script (pam-motd composes /etc/motd via numbered scripts)" {
    head -1 "${TEMPLATES_DIR}/50-selfdef-presence" | grep -qE '^#!/usr/bin/env bash|^#!/bin/bash'
}

@test "50-selfdef-presence honors SELFDEF_MODULES_DIR override with /etc/selfdef/modules default" {
    grep -qE 'SELFDEF_MODULES_DIR:?-?/etc/selfdef/modules' "${TEMPLATES_DIR}/50-selfdef-presence"
}

@test "50-selfdef-presence places itself in the 50- prefix range (mid-sequence pam-motd composition)" {
    # The script's name + comment block document its insertion point
    # in pam-motd's numbered composition (00-header -> 10-help-text ->
    # 50-selfdef-presence -> 90-updates-available). Renaming away from
    # the 50- prefix would break that composition.
    grep -qE '50-selfdef-presence' "${TEMPLATES_DIR}/50-selfdef-presence"
    grep -qE '50-prefix|50.*prefix' "${TEMPLATES_DIR}/50-selfdef-presence"
}

@test "INVARIANT (issue.txt cites monitoring + recording — CFAA banner notice axis)" {
    # CFAA-compliant banner standard requires: (1) AUTHORIZED USE ONLY,
    # (2) monitoring/recording notice, (3) statutory citation. Items 1 + 3
    # are locked in existing tests; lock item 2 here (monitoring notice).
    # Refinement opportunity: explicit no-expectation-of-privacy clause
    # is not yet present — tracked separately, does not block this suite.
    grep -qE 'monitor|monitoring|monitored|recorded' "${TEMPLATES_DIR}/issue.txt"
}

@test "INVARIANT (issue.net.txt distinct from issue.txt — distinct content for network-vs-local banner discipline)" {
    # /etc/issue and /etc/issue.net SHOULD have distinct content because
    # they serve distinct attack contexts: /etc/issue covers physical-
    # console access; /etc/issue.net covers remote ssh/telnet. They MAY
    # share legal text but should not be byte-identical (otherwise the
    # network-banner discipline collapses to local-banner).
    ! cmp -s "${TEMPLATES_DIR}/issue.txt" "${TEMPLATES_DIR}/issue.net.txt"
}

@test "INVARIANT (apply.sh installs all 4 templates to correct paths — install_paths fidelity)" {
    # The apply.sh script MUST install each template to its declared path.
    # Locks the install_paths manifest <-> apply.sh consistency.
    grep -q '/etc/issue' "${INSTALL_DIR}/apply.sh"
    grep -q '/etc/issue.net' "${INSTALL_DIR}/apply.sh"
    grep -q '/etc/motd' "${INSTALL_DIR}/apply.sh"
    grep -q '/etc/update-motd.d' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (50-selfdef-presence script handles missing MODULES_DIR gracefully — defensive contract)" {
    # If /etc/selfdef/modules doesn't exist (selfdef partially installed
    # or test environment), the dynamic motd MUST NOT crash. Lock that
    # the script carries some form of existence-check.
    grep -qE '\[ -d|test -d|\[\[ -d|if.*-d' "${TEMPLATES_DIR}/50-selfdef-presence"
}
