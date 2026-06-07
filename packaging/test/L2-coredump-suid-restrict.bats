#!/usr/bin/env bats
# L2 functional suite for coredump-suid-restrict.
#
# coredump-suid-restrict blocks setuid-binary core dumps. By
# default, a setuid binary that crashes does NOT dump core
# (fs.suid_dumpable=0) — and that's because the dump contains
# the binary's effective-uid memory contents, including any
# secrets the setuid program loaded. Some misconfigured systems
# enable fs.suid_dumpable=1 or =2 for debugging; this module
# pins it back to 0.
#
# Profiles:
#   suid-only → fs.suid_dumpable=0 only (lets normal-user processes
#               still dump cores)
#   all-off   → suid-dumpable=0 PLUS /etc/security/limits.d/* with
#               `* hard core 0` (disables ALL coredumps, PAM
#               evaluated on next login)
#
# CRITICAL INVARIANT: profile downgrade all-off → suid-only
# REMOVES the limits.d file (no stale file from prior profile).
# Without this, the user could "downgrade" the profile but still
# have the all-off PAM restriction active — defeating the
# downgrade intent.
#
# Adds 2 env-var overrides for L2 testability. Live default
# unchanged.
#
# Run with: bats packaging/test/L2-coredump-suid-restrict.bats

WD="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '0\n' ;;
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/coredump-suid-restrict.toml"
    SYSCTL_DROPIN="${TMP}/50-selfdef-suid-dumpable.conf"
    LIMITS_DROPIN="${TMP}/50-selfdef-coredump.conf"
    LIMITS_D="$(dirname "${LIMITS_DROPIN}")"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_COREDUMP_SUID_CONFIG="${CONF}" \
    SELFDEF_COREDUMP_SUID_SYSCTL_DROPIN="${SYSCTL_DROPIN}" \
    SELFDEF_COREDUMP_SUID_LIMITS_DROPIN="${LIMITS_DROPIN}" \
    SELFDEF_LIMITS_D="${LIMITS_D}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_COREDUMP_SUID_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMP_SUID_CONFIG="${SELFDEF_COREDUMP_SUID_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_COREDUMP_SUID_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be suid-only|all-off"* ]]
}

@test "suid-only profile installs sysctl drop-in + sysctl -w fs.suid_dumpable=0" {
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
    # No limits.d file from suid-only profile.
    ! [ -f "${LIMITS_DROPIN}" ]
}

@test "all-off profile installs BOTH sysctl + limits.d drop-ins" {
    write_config "all-off"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
}

@test "INVARIANT: profile downgrade all-off → suid-only REMOVES stale limits.d file" {
    write_config "all-off"
    run_wd
    [ -f "${LIMITS_DROPIN}" ]
    # Downgrade.
    write_config "suid-only"
    run_wd
    ! [ -f "${LIMITS_DROPIN}" ]               # MUST be removed
    [ -f "${SYSCTL_DROPIN}" ]                 # sysctl drop-in retained
}

@test "INVARIANT: stale limits.d files NOT owned by selfdef are left alone" {
    write_config "suid-only"
    # Pre-existing limits.d file with someone else's header.
    printf '# managed-by: someone-else\n* hard core 0\n' > "${LIMITS_DROPIN}"
    run_wd
    # File still present — selfdef won't touch what it didn't create.
    [ -f "${LIMITS_DROPIN}" ]
    grep -q 'someone-else' "${LIMITS_DROPIN}"
}

@test "INVARIANT: DRY_RUN does not write either drop-in or fire sysctl" {
    write_config "all-off"
    DRY_RUN=1 run_wd
    ! [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile (no timestamp — defeats cmp -s)" {
    write_config "suid-only"
    run_wd
    grep -q 'managed-by: selfdef coredump-suid-restrict' "${SYSCTL_DROPIN}"
    grep -q 'profile=suid-only' "${SYSCTL_DROPIN}"
    # Anti-timestamp invariant (2026-06-06 idempotency sweep).
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${SYSCTL_DROPIN}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "suid-only"
    run_wd
    mtime_before="$(stat -c '%Y' "${SYSCTL_DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${SYSCTL_DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "default profile is suid-only (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (profile upgrade suid-only → all-off): ADDS limits.d drop-in (reverse of test-104)" {
    write_config "suid-only"
    run_wd
    ! [ -f "${LIMITS_DROPIN}" ]
    write_config "all-off"
    run_wd
    [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (sysctl drop-in carries fs.suid_dumpable=0 directive — the actual restriction)" {
    write_config "suid-only"
    run_wd
    grep -qE '^fs\.suid_dumpable\s*=\s*0' "${SYSCTL_DROPIN}"
}

@test "INVARIANT (all-off limits.d carries '* hard core 0' — PAM-evaluated restriction)" {
    write_config "all-off"
    run_wd
    grep -qE 'hard\s+core\s+0' "${LIMITS_DROPIN}"
}

@test "INVARIANT (sysctl drop-in chmod 0644 — sysctl.d convention)" {
    write_config "suid-only"
    run_wd
    [ "$(stat -c '%a' "${SYSCTL_DROPIN}")" = "644" ]
}

@test "INVARIANT (all-off limits.d drop-in chmod 0644 — security/limits.d convention)" {
    write_config "all-off"
    run_wd
    [ "$(stat -c '%a' "${LIMITS_DROPIN}")" = "644" ]
}

@test "INVARIANT (no render-timestamp in limits.d drop-in — defeats cmp -s on PAM file too)" {
    # The variant-A guard for the secondary drop-in. The sysctl drop-in
    # is covered above; the PAM-evaluated limits.d drop-in also lives
    # under the same cmp -s gate and must not carry a render-timestamp.
    write_config "all-off"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${LIMITS_DROPIN}"
}

@test "INVARIANT (sysctl -w fires on every apply): the LIVE kernel knob must be set even when drop-in unchanged" {
    # If the sysctl drop-in is already on disk byte-identical, the
    # disk-write skips (mtime test) — BUT the LIVE kernel parameter
    # might still be wrong (operator could have done `sysctl -w
    # fs.suid_dumpable=1`). The script must still re-apply the LIVE
    # knob even on idempotent-disk path.
    write_config "suid-only"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    # Even with disk unchanged, sysctl -w fires for the live-knob.
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates sysctl drop-in + fires sysctl -w)" {
    # Operator may rm the sysctl drop-in — apply must rebuild
    # and re-apply live so kernel state is restored.
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    rm -f "${SYSCTL_DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    grep -q 'sysctl -w fs.suid_dumpable=0' "${SCTL_LOG}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion all-off: re-creates BOTH drop-ins)" {
    # all-off has 2 drop-ins (sysctl + limits.d). Both must be
    # re-armed on deletion.
    write_config "all-off"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
    rm -f "${SYSCTL_DROPIN}" "${LIMITS_DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "suid-only"
    run_wd
    first_line="$(awk 'NF' "${SYSCTL_DROPIN}" | head -1)"
    [[ "${first_line}" == *"selfdef coredump-suid-restrict"* ]]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "all-off"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"coredump-suid-restrict"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=all-off'* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # TOML; parser must tolerate without altering the profile-gated
    # behavior. all-off-with-noise still installs BOTH sysctl +
    # limits.d drop-ins.
    cat > "${CONF}" <<'TOMLEOF'
profile = "all-off"
operator_note = "all-off — disable ALL coredumps"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (asymmetric profile content: suid-only does NOT install limits.d — limits is all-off-only)" {
    # Sister to many other installer module's asymmetric-profile
    # INVARIANT across the brain (ssh-hardening AllowGroups,
    # selinux-baseline autorelabel, tmpfs-baseline /tmp-only). The
    # suid-only profile narrows to the suid-only-coredump axis (the
    # priv-elevated-process leak vector); the all-off profile widens
    # to ALL coredumps via the limits.d PAM-evaluated hard core 0
    # directive. If suid-only silently installed limits.d, it would
    # over-reach (operator's debugging of non-suid processes would
    # break unexpectedly). Locks the boundary: suid-only sysctl-
    # only, all-off both.
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    ! [ -f "${LIMITS_DROPIN}" ]
}

@test "INVARIANT (sysctl drop-in is sysctl.d-parseable: fs.suid_dumpable=0 format — boot-time persistence contract)" {
    # Sister to kernel-yama-baseline + aslr-baseline sysctl.d-
    # parseable INVARIANTs already locked. The drop-in lives at
    # /etc/sysctl.d/50-selfdef-coredump-suid.conf and is parsed
    # by systemd-sysctl.service at boot. The format MUST be
    # 'fs.suid_dumpable = 0' (or '=0' without space, both
    # sysctl.d-valid). A malformed line would silently fail at
    # boot — the runtime sysctl -w would set the value for
    # current boot but it would NOT persist across reboot,
    # leaving the host with degraded suid-coredump-restriction
    # on next boot.
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    grep -qE '^fs\.suid_dumpable[[:space:]]*=[[:space:]]*0$' "${SYSCTL_DROPIN}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl -w fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/sysctl.d/50-selfdef-coredump-
    # suid.conf AND without firing sysctl -w fs.suid_dumpable=0.
    # A silent dry-run that committed would flip the live kernel
    # knob on a host where operator was investigating coredump
    # behavior (suid-binary debugging). Locks the dry-run-
    # preserves-state contract on the coredump-suid-restriction
    # substrate.
    write_config "suid-only"
    rm -f "${SYSCTL_DROPIN}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${SYSCTL_DROPIN}" ]
    ! grep -q 'sysctl -w fs.suid_dumpable' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    write_config "suid-only"
    run_wd
    [ -f "${SYSCTL_DROPIN}" ]
    [ "$(stat -c '%a' "${SYSCTL_DROPIN}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on coredump-suid-restrict
    # installer surface across sysctl + limits.d phases.
    write_config "suid-only"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"coredump-suid-restrict"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: coredump-suid-restrict NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The coredump-suid-restrict installer writes a
    # sysctl drop-in to lock fs.suid_dumpable=0 + an optional
    # limits.d drop-in but MUST NEVER emit shell commands that
    # uninstall kernel-related packages or systemd-coredump
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall systemd-
    # coredump|libpam-modules). Auto-removal would be
    # categorically wrong: catastrophic at the substrate level.
    # Locks anti-package-removal contract on the suid-coredump
    # restriction substrate.
    write_config "suid-only"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${SYSCTL_DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. coredump-suid-restrict installs sysctl + limits.d
    # drop-ins gated by profile (suid-only / all-off); a
    # malformed module.toml would break the dependency-resolver
    # at install-time + leave the suid-dumpable hardening
    # wedged. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the coredump-suid-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'coredump-suid-restrict', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: coredump-suid-restrict installer NEVER deletes operator-pre-existing sysctl/limits configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # coredump-suid-restrict writes its own sysctl drop-in +
    # limits.d drop-in; it MUST NEVER rm/find-delete an
    # operator's pre-existing /etc/sysctl.conf or
    # /etc/security/limits.conf or limits.d entries not owned
    # by THIS module. Locks no-auto-delete on the coredump-
    # suid-restrict installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/sysctl\.conf' "${f}"
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/security/limits\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl|security/limits)\.d.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # coredump-suid-restrict install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the coredump-suid-restrict lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    # the coredump-suid-restrict requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    # present discipline on the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    # category-present discipline on the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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
    # semver-X.Y.Z discipline on the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the coredump-suid-restrict module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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

@test "INVARIANT (coredump-suid-restrict module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the coredump-suid-restrict module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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

@test "INVARIANT (coredump-suid-restrict module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the coredump-suid-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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

@test "INVARIANT (coredump-suid-restrict module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for coredump-suid-restrict is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the coredump-suid-restrict install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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

@test "INVARIANT (coredump-suid-restrict module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the coredump-suid-restrict requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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

@test "INVARIANT (coredump-suid-restrict module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the coredump-suid-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the coredump-suid-restrict
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the coredump-suid-restrict substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
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

@test "INVARIANT (coredump-suid-restrict module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (coredump-suid-restrict module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (coredump-suid-restrict README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (coredump-suid-restrict install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (coredump-suid-restrict install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (coredump-suid-restrict install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (coredump-suid-restrict install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/coredump-suid-restrict/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}
