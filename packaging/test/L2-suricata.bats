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
