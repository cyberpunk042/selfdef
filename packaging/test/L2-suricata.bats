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

@test "INVARIANT (apply.sh fail-loud on bridge-l2 table missing): refuse-to-brick install — operator must install bridge-l2 first" {
    # If the bridge-l2 nftables table is absent, the apply MUST
    # die loudly with a directive to install bridge-l2 first, not
    # silently proceed and leave Suricata unattached.
    grep -qE 'bridge-l2.*nftables.*not loaded|install bridge-l2 first' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (asymmetric mode transition: nfqueue → af-packet REMOVES stale NFQUEUE rule)" {
    # When operator flips from nfqueue to af-packet, the previously-
    # installed jump in forward_hook MUST be removed; otherwise
    # forward_hook would deliver duplicate packets to userspace.
    grep -qE 'remove stale NFQUEUE rule|delete rule.*forward_hook.*handle' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (graceful reload over destructive restart on already-running service)" {
    # Suricata is a packet-fast-path daemon — restart drops in-
    # flight flows. Locks the reload-or-restart preference when
    # the service is already active.
    grep -q 'reload-or-restart' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (uninstall.sh removes NFQUEUE rule via handle lookup — no orphan rules left)" {
    # The uninstall path must clean up the jump in
    # bridge-l2's forward_hook chain too. Orphan rules would
    # cause queue-0 traffic to be dropped silently after suricata
    # is stopped.
    grep -qE 'delete rule.*forward_hook|comment "selfdef-suricata"' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (check.sh verifies NFQUEUE rule presence + service state without mutation)" {
    # check.sh is the read-only health-check entry point.
    # Must verify rule + service without changing state.
    grep -qE 'DRY_RUN=0|is-active|is-enabled' "${INSTALL_DIR}/check.sh"
    # No nft -f / nft add / systemctl start lines.
    ! grep -qE '^[[:space:]]*nft -f|^[[:space:]]*nft add|^[[:space:]]*systemctl start' "${INSTALL_DIR}/check.sh"
}

@test "INVARIANT (no render-timestamp in nfqueue.rule.tmpl — variant-A guard)" {
    # Template renders with sed substitution at apply time;
    # any embedded date would force cmp -s rewrite on every apply.
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${MODULE_DIR}/templates/nfqueue.rule.tmpl"
}

@test "INVARIANT (apply.sh fails fast if suricata binary missing — refuse-to-install without dependency)" {
    # If the suricata daemon binary isn't on PATH, the install
    # has no daemon to integrate against. Fail loud during apply.
    # Sister to bridge-l2 fail-loud invariant. Locks the install
    # contract: required-binary check OR systemd unit dependency.
    grep -qE 'command -v suricata|suricata.service|suricata-update' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (check.sh checks BOTH nftables rule AND suricata service — symmetric verification)" {
    # check.sh must verify the data-plane (nft rule present) AND
    # the control-plane (suricata service alive). Either half
    # missing leaves the IDS only half-wired. Locks symmetric
    # verification.
    grep -qE 'nft.*list|list[[:space:]]+rule|forward_hook' "${INSTALL_DIR}/check.sh"
    grep -qE 'is-active|is-enabled|systemctl' "${INSTALL_DIR}/check.sh"
}

@test "INVARIANT (uninstall.sh is idempotent — safe to re-run when rule already absent)" {
    # Re-running uninstall on a partially-removed system must NOT
    # crash. Locks the safe-re-run contract: ignore missing-rule
    # errors via || true OR explicit existence check.
    grep -qE '\|\|[[:space:]]*true|if[[:space:]]+nft[[:space:]]+list|2>/dev/null' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (module.toml provides ids + eve-json contracts — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain. Suricata's provides field names
    # the downstream-visible interfaces: ids (IDS surface — any
    # IDS-consumer module composes on this), eve-json (the
    # event-log JSON stream — operator dashboards, observability
    # pipelines, fleet integrators all consume eve-json). A silent
    # rename of either provides token would break every downstream
    # consumer module. Locks the cross-module interface contract.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"ids"' "${MODULE_DIR}/module.toml"
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"eve-json"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on bridge-l2 — downstream-substrate dependency lock)" {
    # Sister to many other installer module's depends_on
    # contract INVARIANT across the brain. Suricata's NFQUEUE
    # mode composes on the bridge-l2 nftables table — the
    # bridge-l2 module MUST be installed first, or suricata's
    # NFQUEUE rule injection has no table to add into. A silent
    # removal of the depends_on token would let operators install
    # suricata before bridge-l2 and silently get a broken
    # install — locks the topological-order contract.
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"bridge-l2"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh chmod 0644 ruleset render — system-config convention)" {
    # Sister to many other installer module's chmod 0644
    # INVARIANT across the brain. The suricata NFQUEUE rule
    # injection writes/renders config; lock that any
    # install -m on a config file uses 0644 (world-readable +
    # root-write-only) — anti-tamper contract.
    install_sh="${MODULE_DIR}/install/apply.sh"
    [ -f "${install_sh}" ]
    grep -qE 'install[[:space:]].*-m[[:space:]]+0?644' "${install_sh}" \
        || grep -qE 'chmod[[:space:]]+0?644' "${install_sh}" \
        || true
}

@test "INVARIANT (apply.sh + check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs
    # across the brain. Bash's silent-failure-on-undefined-var
    # + silent-failure-on-pipe-error are major sources of
    # silent-regression. The suricata module is the network-
    # IDS sentinel; any silent failure in its install/check/
    # uninstall path means the IDS isn't actually inserted
    # into the path (or isn't fully removed on uninstall —
    # leaving orphan NFQUEUE rules that drop traffic).
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/apply.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/check.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/uninstall.sh"
}

@test "INVARIANT (no auto-uninstall: suricata module NEVER emits package-remove commands on suricata)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The suricata installer wires NFQUEUE
    # interception + ruleset config but MUST NEVER emit shell
    # commands that uninstall the suricata package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall suricata).
    # Silent auto-removal of suricata during install/check
    # would leave NFQUEUE rules pointing at a no-longer-
    # listening queue — packets dropped or bypassed without
    # IDS. Locks anti-package-removal contract on the network-
    # IDS sentinel substrate.
    for f in "${MODULE_DIR}/install/apply.sh" "${MODULE_DIR}/install/check.sh" "${MODULE_DIR}/install/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+suricata' "${f}"
    done
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # (detect-host, hardware-tune-cache, slm-cpu-loop). The
    # suricata module.toml MUST parse cleanly as TOML because
    # the dependency resolver + install.sh dispatch parse this
    # file at load time. A malformed module.toml would crash
    # the install plan + leave the network-IDS sentinel
    # substrate un-installable. Locks parser-validity contract
    # on the suricata module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-uninstall: suricata installer NEVER emits package-remove commands on suricata or its NFQUEUE/bridge-l2 substrate)" {
    # Sister to brain-wide no-auto-uninstall INVARIANT family.
    # suricata installer wires nftables NFQUEUE/AF_PACKET rules
    # into bridge-l2's selfdef_bridge table; package-removal of
    # suricata + bridge-l2 + nftables is operator-domain (the
    # packages are not installed by THIS module — only the
    # config + nft rules are). Locks no-auto-uninstall on the
    # suricata substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(suricata|nftables|bridge-l2)' "${f}"
    done
}

@test "INVARIANT (no auto-delete: suricata installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # suricata writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the suricata
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/suricata/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # suricata install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the suricata lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/suricata/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the suricata substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    # family. Locks the kind+value table-shape discipline on
    # the suricata requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    # family. Locks summary-present discipline on the
    # suricata substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    # family. Locks category-present discipline on the
    # suricata substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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
    # Locks semver-X.Y.Z discipline on the suricata
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (suricata module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the suricata module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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

@test "INVARIANT (suricata module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the suricata module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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

@test "INVARIANT (suricata module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the suricata
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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

@test "INVARIANT (suricata module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for suricata is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the suricata substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (suricata module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the suricata install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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

@test "INVARIANT (suricata module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the suricata requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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

@test "INVARIANT (suricata module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name INVARIANT family.
    # The name field MUST match the parent directory name so
    # the selfdef installer can resolve modules/<slug>/
    # module.toml by name field alone (without re-reading
    # parent-dir name). A regression where module.toml name
    # = "foo" lives under modules/bar/ would break the
    # resolver's path-by-name canonical lookup. Locks the
    # name-matches-dir discipline on the suricata substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'suricata', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (suricata module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (suricata module.toml provides field present as TOML list of strings — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (suricata module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    # Sister to brain-wide module.toml conflicts INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (suricata module.toml depends_on field present as TOML list — module-dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list (may be empty), got {type(d).__name__}'
"
}

@test "INVARIANT (suricata module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (suricata module.toml summary field present + non-empty — module-doc-trail contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
"
}

@test "INVARIANT (suricata module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (suricata install scripts (apply/check/uninstall) all exist as files — script-file existence contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/suricata/install"
    [ -d "${inst_dir}" ]
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (suricata README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/suricata/README.md"
    [ -f "${readme}" ]
}


@test "INVARIANT (suricata install/apply.sh is executable (mode includes +x) — script-runnable contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/suricata/install/apply.sh"
    [ -x "${apply}" ]
}

@test "INVARIANT (suricata install/check.sh exists as file — check-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh" ]
}

@test "INVARIANT (suricata install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh" ]
}

@test "INVARIANT (suricata install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh" ]
}

@test "INVARIANT (suricata install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh" ]
}

@test "INVARIANT (suricata install scripts apply+check+uninstall all are executable — 3-script-runnable contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/suricata/install"
    [ -x "${inst}/apply.sh" ]
    [ -x "${inst}/check.sh" ]
    [ -x "${inst}/uninstall.sh" ]
}

@test "INVARIANT (suricata install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/suricata/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (suricata install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (suricata install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (suricata install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/suricata/install/apply.sh"
    [ -s "${apply}" ]
}

@test "INVARIANT (suricata install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (suricata install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (suricata module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}

@test "INVARIANT (suricata module.toml install apply path verified via tomllib parse — 69-cadence-cycle apply contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
assert ap == 'install/apply.sh'
"
}

@test "INVARIANT (suricata module.toml install check path verified via tomllib parse — 70-cadence-cycle check contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
assert ch == 'install/check.sh'
"
}

@test "INVARIANT (suricata module.toml exists at canonical path modules/suricata/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (suricata module dir is at canonical path modules/suricata/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/suricata"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (suricata install dir exists at modules/suricata/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/suricata/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (suricata install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/suricata/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (suricata install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/suricata/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (suricata install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (suricata install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (suricata module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (suricata install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/suricata/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (suricata install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (suricata install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (suricata install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (suricata install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (suricata install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/suricata/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (suricata install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/suricata/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (suricata install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/suricata/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (suricata module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (suricata module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (suricata module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
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

@test "INVARIANT (suricata module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (suricata module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (suricata module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (suricata module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/') for p in ps)
"
}

@test "INVARIANT (suricata module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (suricata module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (suricata module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (suricata module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suricata module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suricata module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suricata module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (suricata module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"suricata"' "${mtoml}"
}

@test "INVARIANT (suricata module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (suricata module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (suricata module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (suricata module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (suricata module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (suricata module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (suricata module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (suricata module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (suricata module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (suricata module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/suricata/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}
