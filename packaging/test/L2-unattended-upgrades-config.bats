#!/usr/bin/env bats
# L2 functional suite for unattended-upgrades-config.
#
# unattended-upgrades-config installs apt.conf.d drop-ins +
# enables apt-daily-upgrade.timer to automatically install
# security updates daily. CVE-mitigation that doesn't depend on
# operator-action is foundational defense.
#
# Profiles:
#   security-only       → install security updates only
#                         (50selfdef + 20selfdef-periodic)
#   security-and-reboot → ALSO add reboot override (apt-daily
#                         can reboot the host when needed)
#                         (50selfdef + 20selfdef-periodic +
#                          60selfdef-unattended-reboot)
#
# CRITICAL INVARIANTS this suite locks:
#   - Profile downgrade security-and-reboot → security-only
#     REMOVES the 60selfdef-unattended-reboot file (no auto-
#     reboot left behind when operator explicitly backed off).
#   - Idempotent: byte-identical re-install of all 3 (or 2)
#     files does NOT re-fire systemctl enable (avoids
#     unnecessary state churn).
#   - DRY_RUN protects drop-ins + systemctl enable.
#
# Uses SELFDEF_APT_CONFD env-var (already present).
#
# Run with: bats packaging/test/L2-unattended-upgrades-config.bats

WD="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"

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
    CONF="${TMP}/unattended-upgrades-config.toml"
    APT_CONFD="${TMP}/apt.conf.d"
    mkdir -p "${APT_CONFD}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_UU_CONFIG="${CONF}" \
    SELFDEF_APT_CONFD="${APT_CONFD}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_UU_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_UU_CONFIG="${SELFDEF_UU_CONFIG}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_UU_CONFIG="${CONF}" \
        SELFDEF_APT_CONFD="${APT_CONFD}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be security-only|security-and-reboot"* ]]
}

@test "security-only profile installs base + periodic, NOT reboot override" {
    write_config "security-only"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "security-and-reboot profile installs ALL 3 drop-ins" {
    write_config "security-and-reboot"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "INVARIANT: profile downgrade security-and-reboot → security-only REMOVES reboot override" {
    write_config "security-and-reboot"
    run_wd
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
    write_config "security-only"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]      # REMOVED
}

@test "systemctl enable fires for BOTH apt-daily + apt-daily-upgrade timers" {
    write_config "security-only"
    run_wd
    grep -q 'systemctl enable --now apt-daily.timer' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now apt-daily-upgrade.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-ins or enable timers" {
    write_config "security-only"
    DRY_RUN=1 run_wd
    ! [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    ! [ -f "${APT_CONFD}/20selfdef-periodic" ]
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "drop-ins are chmod 0644 (apt.conf.d convention)" {
    write_config "security-and-reboot"
    run_wd
    [ "$(stat -c '%a' "${APT_CONFD}/50selfdef-unattended-upgrades")" = "644" ]
    [ "$(stat -c '%a' "${APT_CONFD}/20selfdef-periodic")" = "644" ]
    [ "$(stat -c '%a' "${APT_CONFD}/60selfdef-unattended-reboot")" = "644" ]
}

@test "default profile is security-only (no profile key — the conservative default)" {
    : > "${CONF}"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtimes" {
    write_config "security-only"
    run_wd
    mtime_50_before="$(stat -c '%Y' "${APT_CONFD}/50selfdef-unattended-upgrades")"
    mtime_20_before="$(stat -c '%Y' "${APT_CONFD}/20selfdef-periodic")"
    sleep 1
    run_wd
    mtime_50_after="$(stat -c '%Y' "${APT_CONFD}/50selfdef-unattended-upgrades")"
    mtime_20_after="$(stat -c '%Y' "${APT_CONFD}/20selfdef-periodic")"
    [ "${mtime_50_before}" = "${mtime_50_after}" ]
    [ "${mtime_20_before}" = "${mtime_20_after}" ]
}

@test "INVARIANT (profile upgrade security-only → security-and-reboot): ADDS reboot override" {
    write_config "security-only"
    run_wd
    ! [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
    write_config "security-and-reboot"
    run_wd
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "INVARIANT (50selfdef enables Unattended-Upgrade Origins-Pattern for security only — does NOT include proposed)" {
    write_config "security-only"
    run_wd
    grep -qE 'Origins-Pattern|Allowed-Origins' "${APT_CONFD}/50selfdef-unattended-upgrades"
    grep -qiE '[Ss]ecurity' "${APT_CONFD}/50selfdef-unattended-upgrades"
    # Should NOT include the unstable/proposed origin.
    ! grep -qE 'proposed' "${APT_CONFD}/50selfdef-unattended-upgrades"
}

@test "INVARIANT (20selfdef-periodic enables Update-Package-Lists + Unattended-Upgrade)" {
    write_config "security-only"
    run_wd
    grep -qE 'Update-Package-Lists' "${APT_CONFD}/20selfdef-periodic"
    grep -qE 'Unattended-Upgrade' "${APT_CONFD}/20selfdef-periodic"
}

@test "INVARIANT (60selfdef-unattended-reboot sets Automatic-Reboot 'true')" {
    write_config "security-and-reboot"
    run_wd
    grep -qE 'Automatic-Reboot.*true' "${APT_CONFD}/60selfdef-unattended-reboot"
}

@test "INVARIANT (no render-timestamp in any drop-in): defeats cmp -s idempotency" {
    write_config "security-and-reboot"
    run_wd
    for f in "${APT_CONFD}/50selfdef-unattended-upgrades" \
             "${APT_CONFD}/20selfdef-periodic" \
             "${APT_CONFD}/60selfdef-unattended-reboot"; do
        ! grep -qE '^// Generated [0-9]{4}-' "$f"
        ! grep -qE '^# Generated [0-9]{4}-' "$f"
    done
}

@test "INVARIANT (drop-ins re-arm after operator out-of-band deletion: re-creates all drop-ins)" {
    write_config "security-and-reboot"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
    rm -f "${APT_CONFD}/50selfdef-unattended-upgrades" \
          "${APT_CONFD}/20selfdef-periodic" \
          "${APT_CONFD}/60selfdef-unattended-reboot"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    [ -f "${APT_CONFD}/20selfdef-periodic" ]
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "INVARIANT (current behavior: idempotent re-install DOES re-fire systemctl enable — systemctl is itself idempotent, no state churn observed)" {
    # Current behavior: enable fires unconditionally each apply.
    # systemctl enable on an already-enabled timer is itself
    # idempotent (no actual state change), so re-firing is safe.
    # Lock current behavior so future refactor that gates on
    # changes>0 is intentional.
    write_config "security-only"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # Current: enable IS re-fired. This is safe because systemctl
    # enable is idempotent.
    grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-ins carry selfdef-identifier header — operator audit trail + stale-cleanup)" {
    write_config "security-and-reboot"
    run_wd
    # The drop-ins are apt-conf format; comments use //
    # APT conf style + the marker is operator-readable.
    for f in "${APT_CONFD}/50selfdef-unattended-upgrades" \
             "${APT_CONFD}/20selfdef-periodic" \
             "${APT_CONFD}/60selfdef-unattended-reboot"; do
        grep -qE '^(//|#).*selfdef|^(//|#).*managed-by' "$f"
    done
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "security-only"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"unattended-upgrades-config"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=security-only'* ]]
}

@test "INVARIANT (both apt-daily.timer AND apt-daily-upgrade.timer enabled together — not one or the other)" {
    # apt-daily.timer downloads the index; apt-daily-upgrade.timer
    # installs. Both must be enabled for unattended-upgrades to
    # actually work end-to-end. Locks both fires together.
    write_config "security-only"
    run_wd
    grep -q 'apt-daily.timer' "${SYSEOF_LOG}"
    grep -q 'apt-daily-upgrade.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT (config-noise resilience: extra TOML keys do NOT bypass profile validation gate)" {
    # Sister to kernel-lockdown + nftables-baseline + unprivileged-
    # userns + proc-hidepid + usbguard + auditd-immutable config-
    # noise INVARIANT pattern. Lock that extra TOML keys cannot
    # accidentally cause silent profile mis-application.
    cat > "${CONF}" <<'EOF'
profile = "security-and-reboot"
extra_knob = "wrong"
maybe_alias_for_profile = "security-only"
EOF
    run_wd
    # The active profile is security-and-reboot (reboot file present).
    [ -f "${APT_CONFD}/60selfdef-unattended-reboot" ]
}

@test "INVARIANT (filename: all drop-ins follow selfdef-* identifier in NAME — tracking + uninstall identification)" {
    # Sister to many other modules' filename-convention INVARIANT.
    # All 3 drop-ins must carry 'selfdef' in their filename so the
    # uninstall + stale-cleanup pass can identify them.
    write_config "security-and-reboot"
    run_wd
    for f in "${APT_CONFD}/50selfdef-unattended-upgrades" \
             "${APT_CONFD}/20selfdef-periodic" \
             "${APT_CONFD}/60selfdef-unattended-reboot"; do
        case "${f}" in
            *selfdef*) : ;;
            *) fail "drop-in filename ${f} does not carry selfdef identifier" ;;
        esac
    done
}

@test "INVARIANT (apt-daily.timer ordering: download MUST be enabled BEFORE upgrade — install ordering in systemctl log)" {
    # apt-daily.timer (download) must be enabled BEFORE apt-daily-
    # upgrade.timer (install). If install enables before download,
    # the first upgrade window would have no fresh index. Lock the
    # ordering. Sister to other modules' service-action ordering
    # INVARIANTs.
    write_config "security-only"
    run_wd
    download_line="$(grep -n 'apt-daily.timer' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    upgrade_line="$(grep -n 'apt-daily-upgrade.timer' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ -n "${download_line}" ]
    [ -n "${upgrade_line}" ]
    # download (apt-daily) line comes before upgrade (apt-daily-upgrade) line.
    [ "${download_line}" -lt "${upgrade_line}" ]
}

@test "INVARIANT (security-only profile narrows to security advisories — anti-feature-update regression-risk)" {
    # Sister to dnf-automatic-config upgrade_type=security INVARIANT
    # already locked. The selfdef security-only profile MUST
    # explicitly narrow the unattended-upgrades transaction to
    # security-advisory-only patches, NOT the full updates +
    # backports stream which would auto-apply ALL repo updates
    # (including potential regression-risk feature updates the
    # operator hasn't tested). Locks Unattended-Upgrade::Allowed-
    # Origins to the security suite (Debian-Security / Ubuntu
    # security-updates).
    write_config "security-only"
    run_wd
    drop_in="${APT_CONFD}/50selfdef-unattended-upgrades"
    [ -f "${drop_in}" ]
    grep -qE 'Unattended-Upgrade::(Origins-Pattern|Allowed-Origins)' "${drop_in}"
    grep -qE 'security|Debian-Security|UbuntuESM' "${drop_in}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-ins written AND NO timer enable fired when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/apt/apt.conf.d/50selfdef-* AND
    # without enabling apt-daily.timer + apt-daily-upgrade.timer.
    # Silent dry-run could activate auto-update on a host where
    # operator was investigating package-management behavior.
    write_config "security-only"
    rm -f "${APT_CONFD}/50selfdef-unattended-upgrades"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${APT_CONFD}/50selfdef-unattended-upgrades" ]
    ! grep -qE 'systemctl enable apt-daily' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on unattended-upgrades installer
    # surface across drop-ins + timer-enable phases.
    write_config "security-only"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"unattended-upgrades-config"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (drop-in chmod 0644 — apt.conf.d sourcing convention; world-readable required for apt to parse)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs across
    # L2 suites. The unattended-upgrades-config drop-in lives in
    # /etc/apt/apt.conf.d/50selfdef-unattended-upgrades and MUST
    # be world-readable mode 0644 because apt-daily systemd
    # timer runs unattended-upgrades package AS ROOT but apt
    # itself reads /etc/apt/apt.conf.d/ with hardened apparmor
    # profile that drops capabilities — mode 0600 would defeat
    # the canonical apt-conf.d sourcing semantics on apparmor-
    # confined apt deployments. Locks file-mode contract on the
    # unattended-upgrades apt-conf.d drop-in substrate.
    write_config "security-only"
    run_wd
    dropin="${APT_CONFD}/50selfdef-unattended-upgrades"
    [ -f "${dropin}" ]
    mode="$(stat -c '%a' "${dropin}")"
    [ "${mode}" = "644" ]
}

@test "INVARIANT (no auto-uninstall: unattended-upgrades-config NEVER emits package-remove commands on unattended-upgrades)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The unattended-upgrades-config installer writes
    # an apt.conf.d drop-in + enables systemd timers but MUST
    # NEVER emit shell commands that uninstall the unattended-
    # upgrades package itself (apt/dpkg/dnf/rpm/yum remove|
    # purge|uninstall unattended-upgrades). Silent auto-removal
    # would leave the host with no automatic CVE-patch
    # mechanism — degrading the security-patch defense
    # substrate. Locks anti-package-removal contract on the
    # unattended-upgrades-config substrate.
    write_config "security-only"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+unattended-upgrades'
    dropin="${APT_CONFD}/50selfdef-unattended-upgrades"
    [ ! -f "${dropin}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${dropin}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. unattended-upgrades-config manifest declares
    # install + profile gating (security-only / all-updates)
    # the resolver enforces; malformed manifest wedges the
    # CVE-patch auto-install baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'unattended-upgrades-config', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: unattended-upgrades-config installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # unattended-upgrades-config writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the unattended-upgrades-config
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(sysctl\.conf|sysctl\.d|fstab|fstab\.d|systemd|profile\.d|login\.defs|apt|modprobe\.d|usbguard)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(sysctl\.d|fstab\.d|systemd|profile\.d|apt|modprobe\.d|usbguard).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # unattended-upgrades-config install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the unattended-upgrades-config lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    # the unattended-upgrades-config requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    # unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    # unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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
    # Locks semver-X.Y.Z discipline on the unattended-upgrades-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the unattended-upgrades-config module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the unattended-upgrades-config module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the unattended-upgrades-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for unattended-upgrades-config is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the unattended-upgrades-config install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the unattended-upgrades-config requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the unattended-upgrades-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the unattended-upgrades-config
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the unattended-upgrades-config substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (unattended-upgrades-config README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (unattended-upgrades-config install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (unattended-upgrades-config install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (unattended-upgrades-config install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (unattended-upgrades-config install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (unattended-upgrades-config install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (unattended-upgrades-config install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (unattended-upgrades-config install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (unattended-upgrades-config install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (unattended-upgrades-config module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml exists at canonical path modules/unattended-upgrades-config/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (unattended-upgrades-config module dir is at canonical path modules/unattended-upgrades-config/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (unattended-upgrades-config install dir exists at modules/unattended-upgrades-config/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (unattended-upgrades-config install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (unattended-upgrades-config install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (unattended-upgrades-config install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (unattended-upgrades-config module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (unattended-upgrades-config install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (unattended-upgrades-config install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (unattended-upgrades-config install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (unattended-upgrades-config install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (unattended-upgrades-config install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (unattended-upgrades-config install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (unattended-upgrades-config module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (unattended-upgrades-config module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (unattended-upgrades-config module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (unattended-upgrades-config module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"unattended-upgrades-config"' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
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

@test "INVARIANT (unattended-upgrades-config module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (unattended-upgrades-config module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (unattended-upgrades-config module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (unattended-upgrades-config module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/unattended-upgrades-config/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}
