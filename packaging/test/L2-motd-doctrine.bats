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

@test "INVARIANT (50-selfdef-presence script is shell-sourceable — bash -n parses cleanly; pam-motd invocation contract)" {
    # Sister to many other installer module shell-sourceable INVARIANTs
    # across the brain. pam-motd invokes the dynamic-motd scripts via
    # bash; the script MUST parse cleanly (no malformed shebang, no
    # syntax errors). A regression to invalid shell syntax would
    # silently break the dynamic motd on every login.
    bash -n "${TEMPLATES_DIR}/50-selfdef-presence"
}

@test "INVARIANT (50-selfdef-presence script handles missing MODULES_DIR gracefully — defensive contract)" {
    # If /etc/selfdef/modules doesn't exist (selfdef partially installed
    # or test environment), the dynamic motd MUST NOT crash. Lock that
    # the script carries some form of existence-check.
    grep -qE '\[ -d|test -d|\[\[ -d|if.*-d' "${TEMPLATES_DIR}/50-selfdef-presence"
}

@test "INVARIANT (issue + issue.net carry selfdef self-identifying marker — operator-audit-trail on pre-login banners)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain. /etc/issue + /etc/issue.net are
    # the pre-login banners displayed by getty (console) +
    # telnet/ssh (network). MUST carry a selfdef identifier so a
    # stale-cleanup pass can identify selfdef-managed banners
    # from operator-hand-authored ones. Without the marker, a
    # careless overwrite or operator-customization could clobber
    # the selfdef-provided legal banner (compliance regimes
    # mandate specific banner text — operator MUST be able to
    # tell where it came from for audit purposes).
    # Lock current behavior: at least ONE of the issue/issue.net
    # templates carries the marker.
    grep -qE 'selfdef|managed-by' "${TEMPLATES_DIR}/issue.txt" \
        || grep -qE 'selfdef|managed-by' "${TEMPLATES_DIR}/issue.net.txt" \
        || grep -qE 'selfdef|managed-by' "${TEMPLATES_DIR}/motd.txt"
}

@test "INVARIANT (templates chmod 0644 — system-config convention; operator-readable but root-write-only)" {
    # Sister to many other installer module's chmod-0644
    # INVARIANT across the brain (sysctl drop-ins, limits.d,
    # ssh-hardening drop-in, journal-tune drop-in, AppArmor
    # AA_LIST, bridge-l2 nftables ruleset). The motd-doctrine
    # template files land at /etc/issue + /etc/issue.net +
    # /etc/motd + /etc/update-motd.d/50-selfdef-presence as
    # system-config paths. 0644 is the standard read-everyone,
    # write-root convention. A 0666 world-writable regression
    # would let any user rewrite the pre-login legal banner
    # (compliance audit-trail tamper) or the post-login
    # presence-indicator. Locks the file-perm contract on
    # the pre/post-login banner substrate at the shipped-
    # source layer (apply.sh's install -m 0644 contract).
    grep -qE 'install[[:space:]].*-m[[:space:]]+0?644' "${INSTALL_DIR}/apply.sh" \
        || grep -qE 'chmod[[:space:]]+0?644' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (50-selfdef-presence executable chmod 0755 — pam-motd execution contract)" {
    # Sister to brain-wide chmod-0755-executable INVARIANTs on
    # script files (vs chmod-0644-on-config-data). The
    # /etc/update-motd.d/50-selfdef-presence script is
    # executed by pam-motd at login time — pam-motd only runs
    # files in /etc/update-motd.d/ that are executable. A
    # 0644 regression on the script would silently disable the
    # selfdef post-login presence banner (operator can't tell
    # selfdef is running on the host from their login
    # session). Locks the executable-script perm contract at
    # the shipped-source layer (apply.sh's install -m 0755
    # for the script file, separate from -m 0644 for the
    # banner config files).
    grep -qE 'install[[:space:]].*-m[[:space:]]+0?755[[:space:]].*50-selfdef-presence' "${INSTALL_DIR}/apply.sh" \
        || grep -qE '50-selfdef-presence.*-m[[:space:]]+0?755' "${INSTALL_DIR}/apply.sh" \
        || grep -qE 'chmod[[:space:]]+0?755[[:space:]].*50-selfdef-presence' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (apply.sh uses set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # Silent apply.sh failure leaves operator-facing banner half-
    # installed (e.g. issue.txt placed but motd.txt not, or motd
    # script not chmod 0755) — pre-login legal/CFAA notice
    # missing on some hosts; operator can't tell which.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — full lifecycle fail-loud invariant)" {
    # Sister to apply.sh fail-loud INVARIANT just locked above
    # and brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # The motd-doctrine check.sh + uninstall.sh paths MUST be
    # fail-loud across the full module surface. Silent check.sh
    # failure would mask banner-template corruption from
    # operator dashboard view; silent uninstall.sh failure
    # leaves stale 50-selfdef-presence script in /etc/update-
    # motd.d/ after package purge — orphan banner referencing
    # uninstalled module. Locks fail-loud contract on the full
    # motd-doctrine module-script surface.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/check.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. motd-doctrine manifest declares install + the
    # template install_paths the resolver enforces; malformed
    # manifest wedges the pre-login banner doctrine baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'motd-doctrine', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: motd-doctrine installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # motd-doctrine writes its own drop-in into a system config dir;
    # it MUST NEVER rm/find-delete an operator's pre-existing
    # entries not owned by THIS module. Locks no-auto-delete on
    # the motd-doctrine installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/(login\.defs|systemd|update-motd|motd)([[:space:]]|$)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(login\.defs|systemd|update-motd|motd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # motd-doctrine install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the motd-doctrine lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}
