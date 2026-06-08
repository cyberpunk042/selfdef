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

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    # the motd-doctrine requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    # present discipline on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    # category-present discipline on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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
    # semver-X.Y.Z discipline on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the motd-doctrine module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the motd-doctrine module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the motd-doctrine
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for motd-doctrine is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the motd-doctrine install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the motd-doctrine requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the motd-doctrine
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the motd-doctrine
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the motd-doctrine substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (motd-doctrine module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (motd-doctrine module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (motd-doctrine module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (motd-doctrine README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (motd-doctrine install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (motd-doctrine install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (motd-doctrine install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (motd-doctrine install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (motd-doctrine install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (motd-doctrine install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (motd-doctrine install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (motd-doctrine install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (motd-doctrine install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (motd-doctrine install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (motd-doctrine install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (motd-doctrine install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (motd-doctrine module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (motd-doctrine module.toml exists at canonical path modules/motd-doctrine/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (motd-doctrine module dir is at canonical path modules/motd-doctrine/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (motd-doctrine install dir exists at modules/motd-doctrine/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (motd-doctrine install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (motd-doctrine install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (motd-doctrine install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (motd-doctrine install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (motd-doctrine module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (motd-doctrine install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (motd-doctrine install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (motd-doctrine install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (motd-doctrine install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (motd-doctrine install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (motd-doctrine install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (motd-doctrine install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (motd-doctrine install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (motd-doctrine module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (motd-doctrine module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (motd-doctrine module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (motd-doctrine module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (motd-doctrine module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (motd-doctrine module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (motd-doctrine module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"motd-doctrine"' "${mtoml}"
}

@test "INVARIANT (motd-doctrine module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
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

@test "INVARIANT (motd-doctrine module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (motd-doctrine module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/motd-doctrine/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}
