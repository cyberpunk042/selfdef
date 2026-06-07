#!/usr/bin/env bats
# L2 functional suite for tmpfs-baseline.
#
# tmpfs-baseline hardens /tmp + /var/tmp mount options.
#
# Profiles:
#   noexec → install tmp.mount.d/50-selfdef.conf +
#            var-tmp.mount.d/50-selfdef.conf drop-ins adding
#            noexec,nosuid,nodev. /tmp's backing store is
#            unchanged.
#   tmpfs  → noexec drop-ins + REPLACE tmp.mount with a tmpfs-
#            backed version (RAM-backed; 25% RAM size cap by
#            default). Gated by acknowledge_tmpfs=true
#            (refuse-to-brick parallel to kernel-yama paranoid
#            + unprivileged-userns deny).
#
# Profile downgrade tmpfs → noexec restores the OS-shipped
# tmp.mount from the backup (or removes the selfdef tmp.mount
# if no backup exists, leaving systemd's built-in tmp.mount
# default to take over).
#
# Run with: bats packaging/test/L2-tmpfs-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/apply.sh"

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
    CONF="${TMP}/tmpfs-baseline.toml"
    SYSTEMD_DIR="${TMP}/systemd"
    TMP_DROPIN="${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf"
    VARTMP_DROPIN="${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf"
    TMP_MOUNT="${SYSTEMD_DIR}/tmp.mount"
    TMP_MOUNT_BACKUP="${TMP_MOUNT}.selfdef-backup"
    mkdir -p "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_tmpfs]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_tmpfs = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_TMPFS_BASELINE_CONFIG="${CONF}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_TMPFS_BASELINE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_TMPFS_BASELINE_CONFIG="${SELFDEF_TMPFS_BASELINE_CONFIG}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_TMPFS_BASELINE_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be noexec|tmpfs"* ]]
}

@test "INVARIANT: tmpfs without acknowledgment → die (refuse-to-brick guard for /tmp size cap)" {
    write_config "tmpfs" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_TMPFS_BASELINE_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"acknowledge_tmpfs"* ]]
    [[ "${output}" == *"25% RAM"* ]]
    ! [ -f "${TMP_DROPIN}" ]
    ! [ -f "${VARTMP_DROPIN}" ]
    ! [ -f "${TMP_MOUNT}" ]
}

@test "noexec profile installs both noexec drop-ins (tmp + var-tmp) AND does NOT touch tmp.mount" {
    write_config "noexec"
    run_wd
    [ -f "${TMP_DROPIN}" ]
    [ -f "${VARTMP_DROPIN}" ]
    grep -qE 'noexec' "${TMP_DROPIN}"
    grep -qE 'nosuid' "${TMP_DROPIN}"
    grep -qE 'nodev' "${TMP_DROPIN}"
    ! [ -f "${TMP_MOUNT}" ]
}

@test "tmpfs profile WITH acknowledgment installs noexec drop-ins AND REPLACES tmp.mount" {
    write_config "tmpfs" "true"
    run_wd
    [ -f "${TMP_DROPIN}" ]
    [ -f "${VARTMP_DROPIN}" ]
    [ -f "${TMP_MOUNT}" ]
    # tmpfs tmp.mount declares tmpfs as Type.
    grep -qE '^Type=tmpfs' "${TMP_MOUNT}"
}

@test "drop-ins are chmod 0644 (system-config convention)" {
    write_config "noexec"
    run_wd
    [ "$(stat -c '%a' "${TMP_DROPIN}")" = "644" ]
    [ "$(stat -c '%a' "${VARTMP_DROPIN}")" = "644" ]
}

@test "first apply fires systemctl daemon-reload" {
    write_config "noexec"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-ins OR fire systemctl" {
    write_config "noexec"
    run_wd
    tmp_dropin_mtime_before="$(stat -c '%Y' "${TMP_DROPIN}")"
    vartmp_dropin_mtime_before="$(stat -c '%Y' "${VARTMP_DROPIN}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    tmp_dropin_mtime_after="$(stat -c '%Y' "${TMP_DROPIN}")"
    vartmp_dropin_mtime_after="$(stat -c '%Y' "${VARTMP_DROPIN}")"
    [ "${tmp_dropin_mtime_before}" = "${tmp_dropin_mtime_after}" ]
    [ "${vartmp_dropin_mtime_before}" = "${vartmp_dropin_mtime_after}" ]
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT: tmpfs profile backs up pre-existing tmp.mount once (preserve OS-shipped state)" {
    # Simulate operator's OS-shipped tmp.mount.
    cat > "${TMP_MOUNT}" <<'EOF'
# OS-shipped tmp.mount (Debian default)
[Mount]
What=overlay
Where=/tmp
EOF
    pre_sha="$(sha256sum "${TMP_MOUNT}" | awk '{print $1}')"
    write_config "tmpfs" "true"
    run_wd
    [ -f "${TMP_MOUNT_BACKUP}" ]
    backup_sha="$(sha256sum "${TMP_MOUNT_BACKUP}" | awk '{print $1}')"
    [ "${pre_sha}" = "${backup_sha}" ]
    # Live file IS replaced (selfdef tmpfs tmp.mount).
    grep -qE '^Type=tmpfs' "${TMP_MOUNT}"
}

@test "INVARIANT: backup-once — re-applying tmpfs does NOT overwrite the existing backup" {
    cat > "${TMP_MOUNT}" <<'EOF'
[Mount]
What=overlay
EOF
    write_config "tmpfs" "true"
    run_wd
    [ -f "${TMP_MOUNT_BACKUP}" ]
    backup_mtime_before="$(stat -c '%Y' "${TMP_MOUNT_BACKUP}")"
    sleep 1
    run_wd
    backup_mtime_after="$(stat -c '%Y' "${TMP_MOUNT_BACKUP}")"
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
}

@test "INVARIANT: profile downgrade tmpfs → noexec restores the OS-shipped tmp.mount from backup" {
    cat > "${TMP_MOUNT}" <<'EOF'
# OS-shipped overlay-backed
[Mount]
What=overlay
Where=/tmp
EOF
    pre_sha="$(sha256sum "${TMP_MOUNT}" | awk '{print $1}')"
    write_config "tmpfs" "true"
    run_wd
    # Now the live file is selfdef-tmpfs and backup holds the OS original.
    [ -f "${TMP_MOUNT_BACKUP}" ]
    # Downgrade.
    write_config "noexec"
    run_wd
    # Backup is gone (was moved back to live).
    ! [ -f "${TMP_MOUNT_BACKUP}" ]
    # Live tmp.mount matches the pre-apply OS-shipped content.
    post_sha="$(sha256sum "${TMP_MOUNT}" | awk '{print $1}')"
    [ "${pre_sha}" = "${post_sha}" ]
}

@test "INVARIANT: profile downgrade tmpfs → noexec with NO backup removes the selfdef tmp.mount" {
    # No pre-existing tmp.mount (systemd's built-in handles /tmp).
    write_config "tmpfs" "true"
    run_wd
    [ -f "${TMP_MOUNT}" ]
    grep -qE '^Type=tmpfs' "${TMP_MOUNT}"
    ! [ -f "${TMP_MOUNT_BACKUP}" ]
    # Downgrade.
    write_config "noexec"
    run_wd
    # selfdef tmp.mount removed (no backup to restore).
    ! [ -f "${TMP_MOUNT}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-ins, tmp.mount, or fire systemctl" {
    write_config "noexec"
    DRY_RUN=1 run_wd
    ! [ -f "${TMP_DROPIN}" ]
    ! [ -f "${VARTMP_DROPIN}" ]
    ! [ -f "${TMP_MOUNT}" ]
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is noexec (no profile key — conservative no-tmpfs-flip default)" {
    : > "${CONF}"
    run_wd
    [ -f "${TMP_DROPIN}" ]
    [ -f "${VARTMP_DROPIN}" ]
    ! [ -f "${TMP_MOUNT}" ]
}

@test "emit_status reports changes count + reboot notice" {
    write_config "noexec"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=2'* ]]
    [[ "${output}" == *'reboot or manual remount'* ]]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (tmpfs tmp.mount carries size cap directive — defaults to 25% RAM per refuse-to-brick contract)" {
    # The whole point of the acknowledge_tmpfs gate is that /tmp
    # gets RAM-backed with a size cap. Lock that the tmp.mount
    # actually carries the size= or Size= directive.
    write_config "tmpfs" "true"
    run_wd
    [ -f "${TMP_MOUNT}" ]
    grep -qE '(size=|Options=.*size=)' "${TMP_MOUNT}"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates noexec drop-ins)" {
    write_config "noexec"
    run_wd
    [ -f "${TMP_DROPIN}" ]
    rm -f "${TMP_DROPIN}" "${VARTMP_DROPIN}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${TMP_DROPIN}" ]
    [ -f "${VARTMP_DROPIN}" ]
    grep -qE 'noexec' "${TMP_DROPIN}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-ins carry selfdef-identifier header — operator audit trail + uninstall identification)" {
    write_config "noexec"
    run_wd
    # Look for managed-by or selfdef header marker.
    grep -qE '^#.*selfdef|^#.*managed-by' "${TMP_DROPIN}"
    grep -qE '^#.*selfdef|^#.*managed-by' "${VARTMP_DROPIN}"
}

@test "INVARIANT (profile upgrade noexec → tmpfs with ack: creates tmp.mount + fires reload)" {
    # The reverse direction of downgrade tests. Both transitions
    # must work — locks the bidirectional contract.
    write_config "noexec"
    run_wd
    ! [ -f "${TMP_MOUNT}" ]
    : > "${SYSEOF_LOG}"
    write_config "tmpfs" "true"
    run_wd
    [ -f "${TMP_MOUNT}" ]
    grep -qE '^Type=tmpfs' "${TMP_MOUNT}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (refuse-to-brick precedence over profile-key: tmpfs+ack=false ALWAYS dies regardless of other knobs)" {
    # Sister to kernel-yama paranoid + unprivileged-userns deny
    # refuse-to-brick architectural pattern. Lock that the
    # acknowledge_tmpfs gate fires BEFORE any other knob (even if
    # config carries extra options that COULD bypass other checks,
    # this gate fires first).
    cat > "${CONF}" <<'EOF'
profile = "tmpfs"
acknowledge_tmpfs = false
# any number of other knobs here must not change the outcome
extra_knob = "anything"
EOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_TMPFS_BASELINE_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"acknowledge_tmpfs"* ]]
    ! [ -f "${TMP_MOUNT}" ]
}

@test "INVARIANT (drop-in noexec+nosuid+nodev triple coverage: every hardening flag explicitly present)" {
    # Both /tmp and /var/tmp drop-ins must carry ALL THREE
    # hardening options. Missing any one leaves a residual surface
    # (e.g. missing nosuid lets setuid binaries in /tmp still
    # escalate; missing nodev lets device-special files persist
    # there; missing noexec lets binaries execute).
    write_config "noexec"
    run_wd
    for f in "${TMP_DROPIN}" "${VARTMP_DROPIN}"; do
        grep -qE 'noexec' "${f}"
        grep -qE 'nosuid' "${f}"
        grep -qE 'nodev' "${f}"
    done
}

@test "INVARIANT (var-tmp drop-in is mount-options-only — never a Type=tmpfs replacement on /var/tmp)" {
    # /var/tmp must survive reboot per POSIX (sister to /tmp which
    # explicitly does NOT). The tmpfs profile must NEVER convert
    # /var/tmp to tmpfs — only /tmp. Locks the architectural
    # boundary: var-tmp.mount.d/50-selfdef.conf is options-only,
    # NEVER a full var-tmp.mount replacement.
    write_config "tmpfs" "true"
    run_wd
    [ -f "${VARTMP_DROPIN}" ]
    # var-tmp drop-in must NOT declare Type=tmpfs (would break
    # reboot persistence of /var/tmp).
    ! grep -qE '^Type=tmpfs' "${VARTMP_DROPIN}"
    # Locks that no full var-tmp.mount replacement file appears.
    ! [ -f "${SYSTEMD_DIR}/var-tmp.mount" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass refuse-to-brick gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # tmpfs-baseline TOML; parser must tolerate without altering
    # the gated behavior. tmpfs-with-noise WITHOUT ack MUST still
    # refuse-to-brick (unbootable-system precedence over noise —
    # no silent escalation to /tmp=tmpfs flip via parser tolerance
    # which would lose every file under /tmp at next reboot).
    cat > "${CONF}" <<'TOMLEOF'
profile = "tmpfs"
acknowledge_tmpfs = false
operator_note = "tmpfs-on-/tmp = volatile-by-reboot — operator MUST ack"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_TMPFS_BASELINE_CONFIG="${CONF}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"acknowledge_tmpfs"* ]]
    ! [ -f "${SYSTEMD_DIR}/tmp.mount" ]
}

@test "INVARIANT (DRY_RUN does not write drop-ins or tmp.mount)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The tmpfs-baseline DRY_RUN path MUST be
    # a no-op against the live filesystem — operator using
    # --dry-run to preview expects ZERO mutations. Locks the
    # dry-run side-effect-freedom contract so a regression that
    # writes drop-ins or tmp.mount through DRY_RUN would be
    # caught (silent flip to tmpfs-on-/tmp during preview would
    # lose every file under /tmp at next reboot).
    write_config "noexec"
    DRY_RUN=1 run_wd
    ! [ -f "${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf" ]
    ! [ -f "${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf" ]
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs. The systemd
    # mount drop-ins are world-readable so systemd at boot can
    # consume them, and root-write-only to prevent silent
    # tampering of /tmp / /var/tmp mount semantics.
    write_config "noexec"
    run_wd
    drop_in="${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf"
    [ -f "${drop_in}" ] || drop_in="${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf"
    if [ -f "${drop_in}" ]; then
        mode="$(stat -c '%a' "${drop_in}")"
        [ "${mode}" = "644" ] || [ "${mode}" = "640" ] || [ "${mode}" = "600" ]
    fi
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on tmpfs-baseline installer
    # surface across multi-drop-in (tmp + var-tmp) phases.
    write_config "noexec"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"tmpfs-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The tmpfs-baseline drop-in
    # under /etc/systemd/system/tmp.mount.d/50-selfdef.conf MUST
    # carry a comment marker identifying it as selfdef-managed
    # (managed-by / source / generator pointer) so a stale-
    # cleanup head -2 grep at uninstall time can identify which
    # files selfdef owns vs which is operator-original. Without
    # a marker, a subsequent uninstaller could not tell apart
    # operator baseline mount options from selfdef-injected
    # noexec/nosuid/nodev — risking accidental rollback of
    # operator changes. Locks marker-discipline on the tmpfs-
    # baseline mount-options substrate.
    write_config "noexec"
    run_wd
    drop_in="${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf"
    [ -f "${drop_in}" ] || drop_in="${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf"
    [ -f "${drop_in}" ]
    # First non-blank line should carry a header marker identifying
    # selfdef OR tmpfs-baseline OR managed-by.
    grep -qE '^#.*(selfdef|tmpfs-baseline|managed)' "${drop_in}"
}

@test "INVARIANT (no auto-uninstall: tmpfs-baseline NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The tmpfs-baseline installer writes a tmp.mount/
    # var-tmp.mount drop-in pinning noexec/nosuid/nodev but MUST
    # NEVER emit shell commands that uninstall systemd or other
    # mount-related packages (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall systemd|util-linux|mount). Auto-removal would
    # be catastrophic at the init system level — host becomes
    # unbootable. Locks anti-package-removal contract on the
    # tmpfs-baseline substrate.
    write_config "noexec"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(systemd|util-linux|mount)'
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. tmpfs-baseline manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the /tmp tmpfs mount-options baseline (nosuid,nodev,noexec).
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'tmpfs-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: tmpfs-baseline installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # tmpfs-baseline writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the tmpfs-baseline
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # tmpfs-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the tmpfs-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    # the tmpfs-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    # tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    # tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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
    # Locks semver-X.Y.Z discipline on the tmpfs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the tmpfs-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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

@test "INVARIANT (tmpfs-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the tmpfs-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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

@test "INVARIANT (tmpfs-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the tmpfs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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

@test "INVARIANT (tmpfs-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for tmpfs-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the tmpfs-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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

@test "INVARIANT (tmpfs-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the tmpfs-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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

@test "INVARIANT (tmpfs-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the tmpfs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the tmpfs-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the tmpfs-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
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

@test "INVARIANT (tmpfs-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (tmpfs-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (tmpfs-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (tmpfs-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (tmpfs-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (tmpfs-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (tmpfs-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (tmpfs-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (tmpfs-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (tmpfs-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (tmpfs-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (tmpfs-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (tmpfs-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (tmpfs-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (tmpfs-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tmpfs-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}
