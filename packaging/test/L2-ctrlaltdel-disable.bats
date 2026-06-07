#!/usr/bin/env bats
# L2 functional suite for ctrlaltdel-disable.
#
# ctrlaltdel-disable blocks the Ctrl+Alt+Del reboot vector. Two
# profiles:
#   mask         → systemctl mask ctrl-alt-del.target (the unit
#                  systemd maps the chord to; masking blocks ALL
#                  presses)
#   burst-guard  → write logind drop-in with CtrlAltDelBurstAction=
#                  none (allows single press = normal reboot but
#                  blocks the 7-press-in-2s emergency hard-reset)
#
# Physical Ctrl+Alt+Del is the universal "fast-path-to-reboot"
# vector. An attacker with physical access (or a janitor with a
# USB Rubber Ducky) can use it to bypass an interactive session
# lock + initiate reboot to a malicious USB / network boot. Mask
# closes the door entirely.
#
# Uses SELFDEF_LOGIND_DROPIN_DIR env-var override (already present
# in the script) for L2 testability without writing to the real
# /etc/systemd/logind.conf.d.
#
# Run with: bats packaging/test/L2-ctrlaltdel-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/ctrlaltdel-disable.toml"
    LOGIND_DIR="${TMP}/logind.conf.d"
    LOGIND_DROPIN="${LOGIND_DIR}/50-selfdef-cad.conf"
    # Both SELFDEF_LOGIND_DROPIN_DIR (for mkdir -p) and
    # SELFDEF_LOGIND_DROPIN (for the write target) are now
    # overridable — the lib.sh override was added 2026-06-06 so the
    # burst-guard idempotency invariant can be exercised in tests.
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_CAD_CONFIG="${CONF}" \
    SELFDEF_LOGIND_DROPIN_DIR="${LOGIND_DIR}" \
    SELFDEF_LOGIND_DROPIN="${LOGIND_DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_CAD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CAD_CONFIG="${SELFDEF_CAD_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_CAD_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|burst-guard"* ]]
}

@test "mask profile → systemctl mask ctrl-alt-del.target" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + mask profile → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 + burst-guard profile → no file written, no systemctl reload" {
    write_config "burst-guard"
    DRY_RUN=1 run_wd
    # The dropin file MUST NOT exist after DRY_RUN.
    ! [ -f /etc/systemd/logind.conf.d/50-selfdef-cad.conf ]
    # systemctl reload also doesn't fire.
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "mask profile is idempotent on second run" {
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "INVARIANT: burst-guard idempotent — re-install does NOT rewrite logind drop-in OR fire logind reload (2026-06-06 idempotency fix)" {
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${LOGIND_DROPIN}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${LOGIND_DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    # Reload-side-effect gated on content-change.
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT: no render-timestamp in logind drop-in (defeats cmp -s)" {
    write_config "burst-guard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${LOGIND_DROPIN}"
}

@test "INVARIANT (burst-guard profile content): logind drop-in carries CtrlAltDelBurstAction=none" {
    write_config "burst-guard"
    run_wd
    grep -qE '^CtrlAltDelBurstAction=none' "${LOGIND_DROPIN}"
}

@test "INVARIANT (burst-guard profile installs drop-in + fires logind reload first time)" {
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (profile change mask → burst-guard): writes drop-in + reloads logind on transition" {
    write_config "mask"
    run_wd
    write_config "burst-guard"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (logind drop-in perms): drop-in is chmod 0644 (system-config convention for /etc/systemd/logind.conf.d)" {
    write_config "burst-guard"
    run_wd
    [ "$(stat -c '%a' "${LOGIND_DROPIN}")" = "644" ]
}

@test "INVARIANT (logind drop-in carries [Login] section header): valid logind.conf.d fragment shape" {
    write_config "burst-guard"
    run_wd
    grep -qE '^\[Login\]' "${LOGIND_DROPIN}"
}

@test "INVARIANT (mask profile does NOT write logind drop-in — the two profiles are mutually-exclusive mechanisms)" {
    # mask blocks ALL Ctrl+Alt+Del presses via target masking;
    # burst-guard allows single press + blocks 7-press burst via
    # logind drop-in. These are different mechanisms, never
    # composed. Lock that mask doesn't accidentally write the
    # drop-in too.
    write_config "mask"
    run_wd
    ! [ -f "${LOGIND_DROPIN}" ]
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (logind drop-in carries managed-by header marker — operator audit trail)" {
    # Header marker enables stale-cleanup head -1 grep for
    # ownership identification. Operator audit trail too —
    # 'who put this drop-in here'.
    write_config "burst-guard"
    run_wd
    grep -qE '^#.*selfdef.*ctrlaltdel|^#.*managed-by.*selfdef' "${LOGIND_DROPIN}"
}

@test "INVARIANT (burst-guard re-arm after operator deletion: re-creates drop-in + fires logind reload)" {
    # Operator deletes the drop-in out-of-band. Next apply re-
    # creates with intact content + fires logind reload to apply
    # live.
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    rm -f "${LOGIND_DROPIN}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -qE '^CtrlAltDelBurstAction=none' "${LOGIND_DROPIN}"
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"ctrlaltdel-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (downgrade mask → burst-guard does NOT auto-unmask ctrl-alt-del.target — operator-explicit unmask required)" {
    # Once masked, downgrade to burst-guard does NOT auto-unmask
    # the target. The unmask requires explicit operator action.
    # Mask is sticky like avahi-disable's mask profile.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "burst-guard"
    run_wd
    # burst-guard fires logind reload + writes drop-in, but does NOT unmask.
    grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline)" {
    write_config "burst-guard"
    run_wd
    first_line="$(awk 'NF' "${LOGIND_DROPIN}" | head -1)"
    [[ "${first_line}" == *"selfdef"* || "${first_line}" == *"managed-by"* ]]
}

@test "INVARIANT (burst-guard does NOT silently escalate to mask — profile is the operator's stated choice)" {
    # If operator chose burst-guard (allows single press = legitimate
    # reboot), the apply MUST NOT silently escalate to mask. burst-
    # guard is intentionally permissive; mask is the stricter option
    # operator must explicitly choose.
    write_config "burst-guard"
    run_wd
    [ -f "${LOGIND_DROPIN}" ]
    grep -qE '^CtrlAltDelBurstAction=none' "${LOGIND_DROPIN}"
    # systemctl mask MUST NOT have fired.
    ! grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # ctrlaltdel-disable TOML; parser must tolerate without altering
    # the profile-gated behavior. mask-with-noise still fires
    # systemctl mask ctrl-alt-del.target without writing the burst-
    # guard logind drop-in (mutual-exclusion preserved).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "ctrl+alt+del = janitor-with-rubber-ducky reboot vector"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
    ! [ -f "${LOGIND_DROPIN}" ]
}

@test "INVARIANT (mask profile does NOT fire logind reload — mutual-exclusion contract)" {
    # Sister to mask-vs-burst-guard mutual-exclusion INVARIANT
    # already locked. The mask profile fires systemctl mask on
    # ctrl-alt-del.target — that's the SOLE mechanism. burst-guard
    # writes a logind drop-in + fires logind reload. The two paths
    # are mutually exclusive. Locks that mask does NOT fire the
    # logind reload (would be a redundant + potentially confusing
    # systemctl call that operator inspection might mis-attribute
    # to burst-guard activation).
    write_config "mask"
    run_wd
    grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
    ! grep -q 'systemctl kill -s HUP systemd-logind' "${SYSEOF_LOG}"
    ! grep -q 'systemctl reload systemd-logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (burst-guard profile does NOT mask ctrl-alt-del.target — mutual-exclusion contract)" {
    # Sister to the mask-no-logind INVARIANT above (the inverse
    # half of the mutual-exclusion contract). The burst-guard
    # profile is the SOFTER neutralization (logind drop-in tunes
    # the burst rate to 0); it must NOT additionally fire mask on
    # ctrl-alt-del.target — that would be the mask profile's
    # mechanism. Locks the asymmetric profile-content boundary so
    # operator inspection can reliably tell which profile is
    # live just from the systemctl audit trail.
    write_config "burst-guard"
    run_wd
    ! grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO systemctl mask/reload fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without firing systemctl mask ctrl-alt-del.target
    # AND without reloading systemd-logind. A silent dry-run
    # that committed would flip reboot-trigger behavior on a
    # host under investigation (data-center hosts with KVM access
    # need ctrl-alt-del functional for emergency reboot). Locks
    # dry-run-preserves-state on the reboot-trigger-burst-guard
    # substrate.
    write_config "burst-guard"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    ! grep -q 'systemctl mask ctrl-alt-del.target' "${SYSEOF_LOG}"
    ! grep -qE 'systemctl (reload|kill).*logind' "${SYSEOF_LOG}"
}

@test "INVARIANT (no auto-uninstall: ctrl-alt-del.target package NEVER auto-removed)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs.
    write_config "mask"
    run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on ctrlaltdel-disable installer
    # surface.
    write_config "mask"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"ctrlaltdel-disable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ctrlaltdel-disable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ctrlaltdel-disable installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the ctrl-alt-del neutralization
    # status alert. Locks parser contract on the ctrlaltdel-
    # disable installer JSON surface (consistency-with-
    # watchdog-family discipline).
    write_config "mask"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ctrlaltdel-disable manifest declares install +
    # profile gating the resolver enforces at install-time; a
    # malformed manifest would break the resolver + leave the
    # ctrl-alt-del mask/burst-guard hardening wedged. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the ctrlaltdel-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'ctrlaltdel-disable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: ctrlaltdel-disable installer NEVER deletes operator-pre-existing logind configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # ctrlaltdel-disable writes its own /etc/systemd/logind.conf.d/
    # drop-in (burst-guard profile) AND/OR masks ctrl-alt-del.target;
    # it MUST NEVER rm/find-delete an operator's pre-existing
    # /etc/systemd/logind.conf or logind.conf.d entries not owned
    # by THIS module. Locks no-auto-delete on the ctrlaltdel-
    # disable installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/systemd/logind\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/systemd/logind.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # ctrlaltdel-disable install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the ctrlaltdel-disable lifecycle
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/install"
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
    # the depends_on field of the ctrlaltdel-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
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
    # ctrlaltdel-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
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
    # the ctrlaltdel-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
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
    # the ctrlaltdel-disable requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
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
    # present discipline on the ctrlaltdel-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
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
    # category-present discipline on the ctrlaltdel-disable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ctrlaltdel-disable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}
