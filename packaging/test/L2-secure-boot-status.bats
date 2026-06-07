#!/usr/bin/env bats
# L2 functional suite for secure-boot-status.
#
# secure-boot-status runs a periodic check that UEFI Secure
# Boot is enabled. The detector ships as a libexec script +
# systemd service + timer, profile-selected by a 50-profile.conf
# drop-in (Environment=SELFDEF_SECURE_BOOT_PROFILE=...).
#
# Profiles:
#   monitor → log finding; exit 0 regardless
#   require → exit non-zero if SecureBoot is not enabled (the
#             service's failure surface lets operator alerting
#             hooks pick it up)
#
# Same install pattern as mta-loopback-detect — install_one()
# helper does cmp -s, the daemon-reload + enable --now are
# gated on `changes > 0` (no-op apply is fully side-effect-free).
#
# Run with: bats packaging/test/L2-secure-boot-status.bats

WD="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/install/apply.sh"

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
    CONF="${TMP}/secure-boot-status.toml"
    LIBEXEC_DIR="${TMP}/libexec/selfdef"
    SYSTEMD_DIR="${TMP}/systemd"
    DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-secure-boot-status.service.d"
    DROPIN_PROFILE="${DROPIN_DIR_SVC}/50-profile.conf"
    SCRIPT_DST="${LIBEXEC_DIR}/secure-boot-status.sh"
    SVC_DST="${SYSTEMD_DIR}/selfdef-secure-boot-status.service"
    TIMER_DST="${SYSTEMD_DIR}/selfdef-secure-boot-status.timer"
    mkdir -p "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SECURE_BOOT_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SECURE_BOOT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SECURE_BOOT_CONFIG="${SELFDEF_SECURE_BOOT_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SECURE_BOOT_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be monitor|require"* ]]
}

@test "monitor profile installs the libexec script + service + timer + profile dropin" {
    write_config "monitor"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ -f "${SVC_DST}" ]
    [ -f "${TIMER_DST}" ]
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=monitor$' "${DROPIN_PROFILE}"
}

@test "require profile installs the artifact set with require profile env" {
    write_config "require"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=require$' "${DROPIN_PROFILE}"
}

@test "libexec script is chmod 0755 (executable for the systemd unit)" {
    write_config "monitor"
    run_wd
    [ "$(stat -c '%a' "${SCRIPT_DST}")" = "755" ]
}

@test "service + timer + dropin are chmod 0644 (system-config convention)" {
    write_config "monitor"
    run_wd
    [ "$(stat -c '%a' "${SVC_DST}")" = "644" ]
    [ "$(stat -c '%a' "${TIMER_DST}")" = "644" ]
    [ "$(stat -c '%a' "${DROPIN_PROFILE}")" = "644" ]
}

@test "first apply fires daemon-reload + enables the timer" {
    write_config "monitor"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-secure-boot-status.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite artifacts OR fire systemctl" {
    write_config "monitor"
    run_wd
    script_mtime_before="$(stat -c '%Y' "${SCRIPT_DST}")"
    svc_mtime_before="$(stat -c '%Y' "${SVC_DST}")"
    timer_mtime_before="$(stat -c '%Y' "${TIMER_DST}")"
    dropin_mtime_before="$(stat -c '%Y' "${DROPIN_PROFILE}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    script_mtime_after="$(stat -c '%Y' "${SCRIPT_DST}")"
    svc_mtime_after="$(stat -c '%Y' "${SVC_DST}")"
    timer_mtime_after="$(stat -c '%Y' "${TIMER_DST}")"
    dropin_mtime_after="$(stat -c '%Y' "${DROPIN_PROFILE}")"
    [ "${script_mtime_before}" = "${script_mtime_after}" ]
    [ "${svc_mtime_before}" = "${svc_mtime_after}" ]
    [ "${timer_mtime_before}" = "${timer_mtime_after}" ]
    [ "${dropin_mtime_before}" = "${dropin_mtime_after}" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch monitor → require REWRITES profile dropin AND fires daemon-reload + enable" {
    write_config "monitor"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "require"
    run_wd
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=require$' "${DROPIN_PROFILE}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-secure-boot-status.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write any artifact or fire systemctl" {
    write_config "monitor"
    DRY_RUN=1 run_wd
    ! [ -f "${SCRIPT_DST}" ]
    ! [ -f "${SVC_DST}" ]
    ! [ -f "${TIMER_DST}" ]
    ! [ -f "${DROPIN_PROFILE}" ]
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is monitor (no profile key — conservative log-only default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=monitor$' "${DROPIN_PROFILE}"
}

@test "emit_status reports changes count (4 first install; 0 idempotent)" {
    write_config "monitor"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=4'* ]]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile downgrade require → monitor): rewrites drop-in back + fires daemon-reload" {
    write_config "require"
    run_wd
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=require$' "${DROPIN_PROFILE}"
    : > "${SYSEOF_LOG}"
    write_config "monitor"
    run_wd
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=monitor$' "${DROPIN_PROFILE}"
    ! grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=require$' "${DROPIN_PROFILE}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (libexec script probes mokutil or efivars for SecureBoot state)" {
    # The detector must actually check Secure Boot state via mokutil
    # --sb-state OR /sys/firmware/efi/efivars/SecureBoot-*.
    write_config "monitor"
    run_wd
    grep -qE 'mokutil|efivars|SecureBoot' "${SCRIPT_DST}"
}

@test "INVARIANT (service unit references libexec script — wiring is correct)" {
    write_config "monitor"
    run_wd
    grep -qE '^ExecStart=' "${SVC_DST}"
    grep -q 'secure-boot-status' "${SVC_DST}"
}

@test "INVARIANT (timer unit carries OnCalendar / OnBootSec / OnUnitActiveSec — actually fires periodically)" {
    write_config "monitor"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${TIMER_DST}"
}

@test "INVARIANT (no render-timestamp in ANY of the 4 installed files): variant-A guard fleet-wide" {
    write_config "monitor"
    run_wd
    for f in "${SCRIPT_DST}" "${SVC_DST}" "${TIMER_DST}" "${DROPIN_PROFILE}"; do
        ! grep -qE '^# Generated [0-9]{4}-' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files + fires daemon-reload)" {
    # Operator may rm one of the installed files — apply must rebuild
    # and re-arm the timer so SecureBoot surveillance is restored.
    write_config "monitor"
    run_wd
    [ -f "${TIMER_DST}" ]
    rm -f "${SCRIPT_DST}" "${SVC_DST}" "${TIMER_DST}" "${DROPIN_PROFILE}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ -f "${SVC_DST}" ]
    [ -f "${TIMER_DST}" ]
    [ -f "${DROPIN_PROFILE}" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "require"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"secure-boot-status"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=require'* ]]
}

@test "INVARIANT (require profile non-zero-exit semantics in libexec: PROFILE check translates SecureBoot=disabled to systemd-failure)" {
    # The require profile is the lever that turns missing SecureBoot
    # into a systemd service failure. Lock that the libexec script
    # contains profile-aware exit logic (exits non-zero when require
    # profile + SecureBoot disabled).
    write_config "require"
    run_wd
    grep -qE 'PROFILE|SELFDEF_SECURE_BOOT_PROFILE|require' "${SCRIPT_DST}"
    grep -qE 'exit\s+[1-9]|return\s+[1-9]' "${SCRIPT_DST}"
}

@test "INVARIANT (timer + service carry 'selfdef' identifier in Description/Documentation — operator-audit-trail)" {
    write_config "monitor"
    run_wd
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef' "${TIMER_DST}"
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef' "${SVC_DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # secure-boot-status TOML; parser must tolerate without altering
    # the profile-gated behavior. require-with-noise still writes the
    # SELFDEF_SECURE_BOOT_PROFILE=require drop-in (escalates missing
    # SecureBoot from log-only to systemd-failure-recorded — the
    # operator-dashboard signal that powers boot-chain-integrity
    # surveillance).
    cat > "${CONF}" <<'TOMLEOF'
profile = "require"
operator_note = "SecureBoot off = boot-chain integrity broken — alert"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=require$' "${DROPIN_PROFILE}"
    ! grep -q '^Environment=SELFDEF_SECURE_BOOT_PROFILE=monitor$' "${DROPIN_PROFILE}"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # Sister to many other installer module's shell-sourceable
    # INVARIANT across the brain. The libexec script runs from
    # systemd ExecStart. bash -n must parse cleanly. A syntax
    # regression would silently break the surveillance every boot.
    write_config "monitor"
    run_wd
    bash -n "${SCRIPT_DST}"
}

@test "INVARIANT (timer unit carries OnUnitActiveSec — recurrent re-armed cadence beyond OnBootSec one-shot)" {
    # Sister to doctor-timer + entropy-baseline OnUnitActiveSec
    # INVARIANTs already locked. A one-shot timer that fires
    # only on OnBootSec would let a long-uptime host run for
    # weeks without secure-boot status check. The selfdef-
    # secure-boot.timer MUST carry OnUnitActiveSec=<period> so
    # the secure-boot surveillance runs recurrently across long
    # uptimes — defends against attacker subverting secure-boot
    # state between boots (e.g. via UEFI firmware exploit that
    # changes SetupMode mid-uptime).
    write_config "monitor"
    run_wd
    grep -qE '^OnUnitActiveSec=' "${TIMER_DST}"
}

@test "INVARIANT (timer unit carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to doctor-timer + entropy-baseline + mta-loopback-
    # detect Persistent=true INVARIANTs. Without it, host
    # offline for 24+ hours misses every secure-boot probe in
    # that window. With Persistent=true, systemd fires immediately
    # on boot if interval has elapsed since last successful fire.
    # Locks missed-fire-catch-up contract on secure-boot
    # surveillance substrate.
    write_config "monitor"
    run_wd
    grep -qE '^Persistent=true' "${TIMER_DST}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on secure-boot-status installer
    # surface across the 4 installed artifacts (script + service
    # + timer + drop-in).
    write_config "monitor"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"secure-boot-status"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (libexec script is chmod 0755 — executable contract for ExecStart)" {
    # Sister to brain-wide chmod 0755 INVARIANTs for service-
    # executable files. The systemd service ExecStart= MUST
    # invoke an executable script; chmod 0644 would silently
    # break the timer.
    write_config "monitor"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ "$(stat -c '%a' "${SCRIPT_DST}")" = "755" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes (entropy-baseline, swap-
    # encryption-detect, doctor-timer, bootloader-password-
    # detect, mta-loopback-detect). The secure-boot-status probe
    # runs ON the timer's scheduled fire — executes ONCE, reads
    # SecureBoot/SetupMode EFI vars, emits a verdict, then
    # exits. Type=simple would leave systemd thinking the probe
    # is a long-running daemon, breaking timer's OnSuccess /
    # OnUnitActiveSec semantics. Locks oneshot-probe contract
    # on the secure-boot-status substrate.
    write_config "monitor"
    run_wd
    grep -qE '^Type=oneshot' "${SVC_DST}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. secure-boot-status manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the Secure Boot status probe. Python's tomllib is
    # the canonical parser. Locks anti-malformed-manifest on
    # the secure-boot-status substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'secure-boot-status', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: secure-boot-status installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # secure-boot-status writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the secure-boot-status
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # secure-boot-status install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the secure-boot-status lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the secure-boot-status substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    # the secure-boot-status requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    # secure-boot-status substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    # secure-boot-status substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
    # Locks semver-X.Y.Z discipline on the secure-boot-status
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (secure-boot-status module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the secure-boot-status module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/secure-boot-status/module.toml"
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
