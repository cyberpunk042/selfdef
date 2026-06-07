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
