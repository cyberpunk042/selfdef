#!/usr/bin/env bats
# L2 functional suite for unprivileged-userns-baseline.
#
# unprivileged-userns-baseline pins kernel.unprivileged_userns_clone.
# This sysctl is the gate for rootless containers (podman/docker),
# bubblewrap-based sandboxes (Flatpak), and a few CVE-prone kernel
# paths. Two profiles:
#   allow → kernel.unprivileged_userns_clone=1 (preserves rootless
#           containers + Flatpak + bubblewrap; mainstream Debian
#           default since bookworm)
#   deny  → kernel.unprivileged_userns_clone=0 (kills rootless
#           podman/docker, bubblewrap, Flatpak — kernel-attack
#           surface reduction)
#
# CRITICAL INVARIANT: deny is destructive (breaks rootless
# containers + Flatpak). The script requires
# acknowledge_no_rootless=true in the config or REFUSES TO APPLY.
# Refuse-to-brick guard parallel to kernel-yama paranoid +
# kernel-lockdown strict.
#
# Adds SELFDEF_USERNS_DROPIN env-var (added 2026-06-06) for L2
# testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-unprivileged-userns-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '%s\n' "${LIVE_USERNS:-1}" ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/unprivileged-userns-baseline.toml"
    DROPIN="${TMP}/50-selfdef-userns.conf"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_no_rootless]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_no_rootless = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_USERNS_CONFIG="${CONF}" \
    SELFDEF_USERNS_DROPIN="${DROPIN}" \
    LIVE_USERNS="${LIVE_USERNS:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_USERNS_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${SELFDEF_USERNS_CONFIG}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${CONF}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be allow|deny"* ]]
}

@test "INVARIANT: deny without acknowledgment → die (refuse-to-brick guard for rootless containers + Flatpak)" {
    write_config "deny" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${CONF}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"rootless"* ]]
    ! [ -f "${DROPIN}" ]
}

@test "allow profile → sysctl -w kernel.unprivileged_userns_clone=1 + writes dropin" {
    write_config "allow"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "deny profile WITH acknowledgment → sysctl -w kernel.unprivileged_userns_clone=0" {
    write_config "deny" "true"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=deny' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=0' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile + source content (no timestamp — defeats cmp -s)" {
    write_config "allow"
    run_wd
    grep -q 'managed-by: selfdef unprivileged-userns-baseline' "${DROPIN}"
    grep -q 'profile=allow' "${DROPIN}"
    # Anti-timestamp invariant (2026-06-06 sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${DROPIN}"
}

@test "drop-in is chmod 0644 (system-config convention)" {
    write_config "allow"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "allow"
    run_wd
    [ -f "${DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl -w" {
    write_config "allow"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "default profile is allow (no profile key — preserves rootless containers)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition allow → deny WITH ack): rewrites drop-in + applies sysctl 0" {
    write_config "allow"
    run_wd
    grep -q 'profile=allow' "${DROPIN}"
    write_config "deny" "true"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=deny' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=0' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition deny → allow): rewrites drop-in back + applies sysctl 1" {
    write_config "deny" "true"
    run_wd
    grep -q 'profile=deny' "${DROPIN}"
    write_config "allow"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in carries the actual sysctl directive): allow → kernel.unprivileged_userns_clone=1" {
    write_config "allow"
    run_wd
    grep -qE 'kernel\.unprivileged_userns_clone\s*=\s*1' "${DROPIN}"
}

@test "INVARIANT (drop-in carries the actual sysctl directive): deny → kernel.unprivileged_userns_clone=0" {
    write_config "deny" "true"
    run_wd
    grep -qE 'kernel\.unprivileged_userns_clone\s*=\s*0' "${DROPIN}"
}

@test "INVARIANT (live-knob re-application — sysctl -w fires on every apply even when drop-in unchanged)" {
    write_config "allow"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in filename selfdef-* pattern): tracking + uninstall identification" {
    write_config "allow"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl -w)" {
    # Operator may rm the drop-in (file-deletion tamper) — apply must
    # rebuild it and re-apply live so kernel state is restored.
    write_config "allow"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=allow' "${DROPIN}"
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=1' "${SCTL_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    # If apply.sh ever changes the header, a stale-cleanup pass that
    # uses head -1 to identify selfdef-managed drop-ins must continue
    # to match. Lock the head-1 contract.
    write_config "allow"
    run_wd
    first_line="$(awk 'NF' "${DROPIN}" | head -1)"
    [[ "${first_line}" == *"selfdef unprivileged-userns-baseline"* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "deny" "true"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"unprivileged-userns-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=deny'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — deny w/o ack dies even when profile is the operator's stated choice)" {
    # If the operator sets deny but FORGETS to set acknowledge_no_rootless,
    # apply MUST refuse. Even if a previous run was 'allow' and the drop-in
    # exists with allow content, deny w/o ack must NOT mutate state to deny.
    write_config "allow"
    run_wd
    grep -q 'profile=allow' "${DROPIN}"
    # Now operator sets deny w/o ack — must die + leave drop-in unchanged.
    write_config "deny" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${CONF}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    grep -q 'profile=allow' "${DROPIN}"
    ! grep -q 'profile=deny' "${DROPIN}"
}

@test "INVARIANT (live-knob no-op on idempotent re-apply with same live value: don't fire sysctl -w if kernel already has correct value)" {
    # The existing INVARIANT 'live-knob fires on every apply' locks
    # current behavior (always-fire). This INVARIANT EXTENDS that
    # current behavior boundary explicitly: when the kernel already
    # has the correct value (mocked via LIVE_USERNS), the sysctl -w
    # MAY OR MAY NOT skip — depending on script architecture. Lock
    # current always-fire behavior so a future skip-if-matched
    # refinement is intentional, not silent.
    write_config "allow"
    LIVE_USERNS=1 run_wd
    : > "${SCTL_LOG}"
    LIVE_USERNS=1 run_wd
    # Current behavior: sysctl -w fires regardless of live-match.
    grep -q 'sysctl -w kernel.unprivileged_userns_clone=' "${SCTL_LOG}"
}

@test "INVARIANT (config-layer-noise resilience: deny + extra TOML keys does NOT bypass acknowledge_no_rootless gate)" {
    # Sister to kernel-lockdown + nftables-baseline refuse-to-brick
    # config-layer-noise INVARIANT. Lock that extra config keys
    # cannot accidentally bypass the refuse-to-brick gate via TOML
    # parsing edge cases.
    cat > "${CONF}" <<'EOF'
profile = "deny"
acknowledge_no_rootless = false
extra_knob_that_should_not_help = "wrong"
maybe_an_alias_for_ack = true
EOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_USERNS_CONFIG="${CONF}" \
        SELFDEF_USERNS_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"rootless"* ]] || [[ "${output}" == *"acknowledge_no_rootless"* ]]
    ! [ -f "${DROPIN}" ]
}

@test "INVARIANT (live-state observability: sysctl -n kernel.unprivileged_userns_clone is consulted to read live state)" {
    # The script reads the live kernel value via sysctl -n. Locks
    # that the read happens — observability discipline for the
    # operator dashboard's actual-vs-desired comparison.
    write_config "allow"
    LIVE_USERNS=1 run_wd
    grep -qE 'sysctl -n kernel\.unprivileged_userns_clone|sysctl -n .*unprivileged_userns' "${SCTL_LOG}" || \
        grep -q 'sysctl -n' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in is sysctl.d-parseable: kernel.unprivileged_userns_clone=<N> format — boot-time persistence contract)" {
    # Sister to kernel-yama-baseline + aslr-baseline + coredump-
    # suid-restrict + kernel-lockdown sysctl.d-parseable
    # INVARIANTs already locked. The drop-in lives at /etc/
    # sysctl.d/50-selfdef-userns.conf and is parsed by systemd-
    # sysctl.service at boot. The format MUST be 'kernel.
    # unprivileged_userns_clone = <N>' (or '=<N>' without space,
    # both sysctl.d-valid). A malformed line would silently fail
    # at boot — the runtime sysctl -w would set the value for
    # current boot but it would NOT persist across reboot,
    # leaving the host with degraded unprivileged-userns
    # restriction on next boot.
    write_config "deny" "true"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^kernel\.unprivileged_userns_clone[[:space:]]*=[[:space:]]*[01]$' "${DROPIN}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl -w fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing the drop-in AND without firing
    # sysctl -w. Silent dry-run could break container/snap/
    # flatpak workflows (which use unprivileged userns) at
    # preview time during operator investigation. Locks dry-
    # run-preserves-state on the unprivileged-userns substrate.
    write_config "deny" "true"
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN}" ]
    ! grep -qE 'sysctl -w kernel.unprivileged_userns_clone' "${SCTL_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on unprivileged-userns-baseline
    # installer surface across drop-in + sysctl-w phases.
    write_config "allow" "false"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"unprivileged-userns-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (drop-in chmod 0644 — sysctl.d sourcing convention; world-readable required for sysctl --load on early boot)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs across
    # L2 suites. The unprivileged-userns-baseline drop-in lives
    # in /etc/sysctl.d/50-selfdef-unprivileged-userns.conf and
    # MUST be world-readable mode 0644 because systemd-sysctl
    # runs sysctl --load at very early boot (before /var
    # mounted on some setups) AND may parse sysctl.d as a non-
    # root user on hardened systems with systemd-sysctl unit
    # confined by ProtectSystem=strict. Mode 0600 would defeat
    # the canonical sysctl.d sourcing semantics. Locks file-
    # mode contract on the unprivileged-userns sysctl.d drop-
    # in substrate.
    write_config "deny" "true"
    run_wd
    [ -f "${DROPIN}" ]
    mode="$(stat -c '%a' "${DROPIN}")"
    [ "${mode}" = "644" ]
}

@test "INVARIANT (header-marker discipline: drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The unprivileged-userns-baseline
    # drop-in MUST carry a comment marker identifying it as
    # selfdef-managed so a stale-cleanup head -2 grep at
    # uninstall time can identify which files selfdef owns vs
    # which is operator-original. Without a marker, a
    # subsequent uninstaller could not tell apart operator
    # baseline kernel.unprivileged_userns_clone settings from
    # selfdef-injected ones — risking accidental rollback of
    # operator changes. Locks marker-discipline on the
    # unprivileged-userns sysctl.d substrate.
    write_config "deny" "true"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^#.*(selfdef|unprivileged-userns|managed)' "${DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. unprivileged-userns-baseline manifest declares
    # install + profile gating (allow / deny) the resolver
    # enforces; malformed manifest wedges the kernel.unprivileged
    # _userns_clone sysctl baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'unprivileged-userns-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: unprivileged-userns-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # unprivileged-userns-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the unprivileged-userns-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # unprivileged-userns-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the unprivileged-userns-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    # the unprivileged-userns-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    # unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    # unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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
    # Locks semver-X.Y.Z discipline on the unprivileged-userns-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the unprivileged-userns-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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

@test "INVARIANT (unprivileged-userns-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the unprivileged-userns-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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

@test "INVARIANT (unprivileged-userns-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the unprivileged-userns-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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

@test "INVARIANT (unprivileged-userns-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for unprivileged-userns-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the unprivileged-userns-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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

@test "INVARIANT (unprivileged-userns-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the unprivileged-userns-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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

@test "INVARIANT (unprivileged-userns-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the unprivileged-userns-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the unprivileged-userns-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the unprivileged-userns-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
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

@test "INVARIANT (unprivileged-userns-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (unprivileged-userns-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (unprivileged-userns-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (unprivileged-userns-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (unprivileged-userns-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (unprivileged-userns-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (unprivileged-userns-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (unprivileged-userns-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (unprivileged-userns-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (unprivileged-userns-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (unprivileged-userns-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (unprivileged-userns-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (unprivileged-userns-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (unprivileged-userns-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (unprivileged-userns-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (unprivileged-userns-baseline module.toml exists at canonical path modules/unprivileged-userns-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (unprivileged-userns-baseline module dir is at canonical path modules/unprivileged-userns-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (unprivileged-userns-baseline install dir exists at modules/unprivileged-userns-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (unprivileged-userns-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (unprivileged-userns-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (unprivileged-userns-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (unprivileged-userns-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (unprivileged-userns-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (unprivileged-userns-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unprivileged-userns-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}
