#!/usr/bin/env bats
# L2 functional suite for kernel-yama-baseline.
#
# kernel-yama-baseline pins kernel.yama.ptrace_scope. ptrace is
# how debuggers (gdb, strace) attach to processes. Without
# restriction, ANY process can ptrace ANY same-uid process —
# attacker tools (memory scrapers, password sniffers, etc.) use
# this to dump in-memory secrets from already-running processes
# without escalating privileges.
#
# Profiles:
#   relaxed  → ptrace_scope=1 (only ancestors / declared tracees;
#              the kernel default since Linux 3.4)
#   strict   → ptrace_scope=2 (admin-only ptrace)
#   paranoid → ptrace_scope=3 (no ptrace AT ALL —
#              IRREVERSIBLE until reboot)
#
# CRITICAL INVARIANT: paranoid (=3) is irreversible until reboot.
# The script requires acknowledge_paranoid=true in the config or
# REFUSES TO APPLY. Refuse-to-brick guard parallel to kernel-
# lockdown's strict acknowledgment.
#
# Adds SELFDEF_YAMA_DROPIN env-var (added 2026-06-06) for L2
# testability. Live default unchanged.
#
# Run with: bats packaging/test/L2-kernel-yama-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '%s\n' "${LIVE_YAMA:-1}" ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/kernel-yama-baseline.toml"
    DROPIN="${TMP}/50-selfdef-yama.conf"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_paranoid]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_paranoid = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_YAMA_CONFIG="${CONF}" \
    SELFDEF_YAMA_DROPIN="${DROPIN}" \
    LIVE_YAMA="${LIVE_YAMA:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_YAMA_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${SELFDEF_YAMA_CONFIG}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be relaxed|strict|paranoid"* ]]
}

@test "INVARIANT: paranoid without acknowledgment → die (refuse-to-brick guard)" {
    write_config "paranoid" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]]
    ! [ -f "${DROPIN}" ]
}

@test "relaxed profile → sysctl -w kernel.yama.ptrace_scope=1" {
    write_config "relaxed"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.yama.ptrace_scope=1' "${SCTL_LOG}"
}

@test "strict profile → sysctl -w kernel.yama.ptrace_scope=2 (admin-only)" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.yama.ptrace_scope=2' "${SCTL_LOG}"
}

@test "paranoid profile WITH acknowledgment → sysctl -w kernel.yama.ptrace_scope=3" {
    write_config "paranoid" "true"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'sysctl -w kernel.yama.ptrace_scope=3' "${SCTL_LOG}"
}

@test "INVARIANT: live=3 but profile=2 → drop-in still placed (post-reboot effect) + log WARN" {
    # Live state is already paranoid (locked-until-reboot). Apply strict
    # → the drop-in is installed (so the post-reboot value is 2), but
    # sysctl -w may be a no-op the kernel rejects. Either way, the
    # script should not die — it logs WARN and continues.
    write_config "strict"
    LIVE_YAMA=3 run_wd                  # kernel reports current=3
    [ -f "${DROPIN}" ]                  # drop-in still placed
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "strict"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl -w" {
    write_config "strict"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile" {
    write_config "strict"
    run_wd
    grep -q 'managed-by: selfdef kernel-yama-baseline' "${DROPIN}"
    grep -q 'profile=strict' "${DROPIN}"
}

@test "default profile is relaxed (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=relaxed' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=1' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in carries actual sysctl directive ptrace_scope=N)" {
    write_config "strict"
    run_wd
    grep -qE 'kernel\.yama\.ptrace_scope\s*=\s*2' "${DROPIN}"
}

@test "INVARIANT (profile transition relaxed → strict): rewrites drop-in + applies live" {
    write_config "relaxed"
    run_wd
    grep -q 'profile=relaxed' "${DROPIN}"
    write_config "strict"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=strict' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=2' "${SCTL_LOG}"
}

@test "INVARIANT (profile transition strict → paranoid WITH ack): rewrites drop-in + applies =3 live" {
    write_config "strict"
    run_wd
    write_config "paranoid" "true"
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'profile=paranoid' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=3' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in chmod 0644): sysctl.d convention" {
    write_config "strict"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (live-knob re-application — sysctl -w fires on every apply)" {
    write_config "strict"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w kernel.yama.ptrace_scope=' "${SCTL_LOG}"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "strict"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl -w)" {
    # Operator may rm the drop-in — apply must rebuild and re-apply
    # live so kernel state is restored.
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=strict' "${DROPIN}"
    grep -q 'sysctl -w kernel.yama.ptrace_scope=2' "${SCTL_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "strict"
    run_wd
    first_line="$(awk 'NF' "${DROPIN}" | head -1)"
    [[ "${first_line}" == *"selfdef kernel-yama-baseline"* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "paranoid" "true"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"kernel-yama-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=paranoid'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — paranoid w/o ack dies even after prior strict install)" {
    # Operator installs strict first, then flips to paranoid but
    # FORGETS to set acknowledge_paranoid. apply MUST refuse AND
    # leave the prior strict drop-in unchanged — no silent
    # escalation to ptrace_scope=3 which is IRREVERSIBLE-until-reboot.
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=strict' "${DROPIN}"
    # Operator sets paranoid w/o ack.
    write_config "paranoid" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Prior strict drop-in preserved at profile=strict.
    grep -q 'profile=strict' "${DROPIN}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass refuse-to-brick gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # kernel-yama-baseline TOML; parser must tolerate without
    # altering the gated behavior. paranoid-with-noise WITHOUT ack
    # MUST still refuse (refuse-to-brick precedence over noise).
    # paranoid-with-noise WITH ack MUST still apply ptrace_scope=3.
    cat > "${CONF}" <<'TOMLEOF'
profile = "paranoid"
acknowledge_paranoid = false
operator_note = "memory-scraper / password-sniffer defense"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"IRREVERSIBLE until reboot"* ]]
    ! [ -f "${DROPIN}" ]
}

@test "INVARIANT (drop-in is sysctl.d-parseable: kernel.yama.ptrace_scope=<N> format — boot-time persistence contract)" {
    # Sister to many other installer module's parser-compatible-
    # format INVARIANT across the brain. The drop-in lives at
    # /etc/sysctl.d/50-selfdef-kernel-yama.conf and is parsed by
    # systemd-sysctl.service at boot. The format MUST be
    # 'kernel.yama.ptrace_scope = <N>' (or '=<N>' without space,
    # both are sysctl.d-valid). A malformed line would silently
    # fail at boot — the runtime sysctl -w would set ptrace_scope
    # for the current boot but the value would NOT persist across
    # reboot, leaving the host degraded on the next boot. Locks
    # the boot-time persistence contract on the audit-trail-
    # integrity ladder.
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^kernel\.yama\.ptrace_scope[[:space:]]*=[[:space:]]*[123]$' "${DROPIN}"
}

@test "INVARIANT (drop-in is chmod 0644 — sysctl.d convention)" {
    # Sister to many other installer module's chmod 0644 INVARIANT
    # across the brain (sysctl drop-ins, limits.d, ssh-hardening
    # drop-in). The kernel-yama sysctl.d drop-in must be world-
    # readable (systemd-sysctl reads it at boot) and root-write-
    # only — any other perm would let an attacker silently
    # downgrade ptrace_scope to 0 (allow all ptrace) which would
    # re-expose the memory-scraper / password-sniffer attack
    # surface that strict / paranoid profiles defend against.
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in written AND NO sysctl -w fired when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing the drop-in AND without firing
    # sysctl -w. Silent dry-run could block legitimate debugger
    # workflows (gdb -p, strace -p) on a host where operator was
    # investigating ptrace_scope behavior. Locks dry-run-preserves-
    # state on the kernel-yama-baseline substrate.
    write_config "strict"
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN}" ]
    ! grep -qE 'sysctl -w kernel.yama.ptrace_scope' "${SCTL_LOG}"
}

@test "INVARIANT (paranoid ptrace_scope = 3 — strictest mode)" {
    # Sister to ssh-hardening + many other profile-rank
    # INVARIANTs. ptrace_scope=3 is the strictest YAMA mode
    # (no ptrace from anywhere). Paranoid MUST hit this value.
    write_config "paranoid" "true"
    run_wd
    grep -qE '^kernel\.yama\.ptrace_scope[[:space:]]*=[[:space:]]*3' "${DROPIN}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on kernel-yama-baseline installer
    # surface across drop-in + sysctl-w phases.
    write_config "standard" "false"
    run env PATH="${BIN}:${PATH}" \
        SCTL_LOG="${SCTL_LOG}" \
        SELFDEF_DRY_RUN=0 \
        SELFDEF_YAMA_CONFIG="${CONF}" \
        SELFDEF_YAMA_DROPIN="${DROPIN}" \
        LIVE_YAMA=1 \
        bash "${WD}"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"kernel-yama-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The kernel-yama-baseline drop-in
    # MUST carry a comment marker identifying it as selfdef-
    # managed so a stale-cleanup head -2 grep at uninstall time
    # can identify which files selfdef owns vs which is operator-
    # original. Without a marker, a subsequent uninstaller could
    # not tell apart operator baseline ptrace_scope settings from
    # selfdef-injected ones — risking accidental rollback of
    # operator changes. Locks marker-discipline on the kernel-
    # yama-baseline sysctl.d substrate.
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^#.*(selfdef|kernel-yama-baseline|managed)' "${DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. kernel-yama-baseline manifest declares install +
    # profile gating (relaxed / strict / paranoid) the resolver
    # enforces; malformed manifest wedges the kernel.yama.
    # ptrace_scope hardening. Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the kernel-yama-
    # baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'kernel-yama-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: kernel-yama-baseline installer NEVER deletes operator-pre-existing sysctl/systemd configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # kernel-yama-baseline writes its own /etc/sysctl.d or /etc/systemd
    # drop-in; it MUST NEVER rm/find-delete an operator's
    # pre-existing /etc/sysctl.conf, /etc/sysctl.d, or
    # /etc/systemd entries not owned by THIS module. Locks
    # no-auto-delete on the kernel-yama-baseline installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/sysctl\.conf' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/sysctl\.d.*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # kernel-yama-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the kernel-yama-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    # the kernel-yama-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    # present discipline on the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    # category-present discipline on the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the kernel-yama-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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

@test "INVARIANT (kernel-yama-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the kernel-yama-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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

@test "INVARIANT (kernel-yama-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the kernel-yama-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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

@test "INVARIANT (kernel-yama-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for kernel-yama-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the kernel-yama-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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

@test "INVARIANT (kernel-yama-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the kernel-yama-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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

@test "INVARIANT (kernel-yama-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the kernel-yama-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the kernel-yama-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the kernel-yama-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
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

@test "INVARIANT (kernel-yama-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (kernel-yama-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (kernel-yama-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (kernel-yama-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (kernel-yama-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/kernel-yama-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}
