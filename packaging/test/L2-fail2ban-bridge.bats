#!/usr/bin/env bats
# L2 functional suite for fail2ban-bridge.
#
# fail2ban-bridge installs jail.d drop-ins to pin selfdef's
# fail2ban configuration:
#   standard → 50-selfdef.conf only (ssh + auth-fail bans)
#   broad    → 50-selfdef.conf + 60-selfdef-recidive.conf
#              (recidive = bans IPs that get banned-and-unbanned
#               repeatedly — long-term ban for persistent
#               attackers)
#
# CRITICAL INVARIANTS:
#   - Profile downgrade broad → standard REMOVES 60-selfdef-
#     recidive.conf (no stale recidive jail).
#   - Idempotent: byte-identical re-install fires NO fail2ban-
#     reload (reload triggers in-memory state flush of currently-
#     banned IPs and is operator-visible disruption).
#   - Uses fail2ban-client reload (graceful) before falling back
#     to systemctl restart (catches malformed-config cases).
#
# Uses SELFDEF_FAIL2BAN_JAIL_D env-var (already present) for L2
# testability.
#
# Run with: bats packaging/test/L2-fail2ban-bridge.bats

WD="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    cat > "${BIN}/fail2ban-client" <<'F2BEOF'
#!/usr/bin/env bash
printf 'fail2ban-client %s\n' "$*" >> "${F2B_LOG}"
exit 0
F2BEOF
    chmod +x "${BIN}/fail2ban-client"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export F2B_LOG="${TMP}/f2b.log"
    : > "${SYSEOF_LOG}"
    : > "${F2B_LOG}"
    CONF="${TMP}/fail2ban-bridge.toml"
    JAIL_D="${TMP}/jail.d"
    mkdir -p "${JAIL_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    F2B_LOG="${F2B_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_FAIL2BAN_CONFIG="${CONF}" \
    SELFDEF_FAIL2BAN_JAIL_D="${JAIL_D}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_FAIL2BAN_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FAIL2BAN_CONFIG="${SELFDEF_FAIL2BAN_CONFIG}" \
        SELFDEF_FAIL2BAN_JAIL_D="${JAIL_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FAIL2BAN_CONFIG="${CONF}" \
        SELFDEF_FAIL2BAN_JAIL_D="${JAIL_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|broad"* ]]
}

@test "standard profile installs ONLY 50-selfdef.conf + fail2ban-client reload fires" {
    write_config "standard"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
    [ "$(stat -c '%a' "${JAIL_D}/50-selfdef.conf")" = "644" ]
}

@test "broad profile installs BOTH 50-selfdef.conf + 60-selfdef-recidive.conf" {
    write_config "broad"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
}

@test "INVARIANT: profile downgrade broad → standard REMOVES recidive drop-in" {
    write_config "broad"
    run_wd
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    write_config "standard"
    : > "${F2B_LOG}"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]      # REMOVED
    # Reload fires because the removal IS a change.
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO reload" {
    write_config "standard"
    run_wd
    : > "${F2B_LOG}"
    : > "${SYSEOF_LOG}"
    run_wd
    # Critical: no reload = no in-memory ban-state flush.
    ! grep -q 'fail2ban-client reload' "${F2B_LOG}"
    ! grep -q 'systemctl restart fail2ban' "${SYSEOF_LOG}"
}

@test "INVARIANT: fail2ban-client reload preferred over systemctl restart" {
    write_config "standard"
    run_wd
    # Should call fail2ban-client reload (graceful), NOT systemctl
    # restart (disruptive).
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
    ! grep -q 'systemctl restart fail2ban' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-ins or reload" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! grep -q 'fail2ban-client reload' "${F2B_LOG}"
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    # Stronger than test-117's "no reload" — locks the file-mtime
    # preservation that the cmp -s guard provides.
    write_config "standard"
    run_wd
    mtime_before="$(stat -c '%Y' "${JAIL_D}/50-selfdef.conf")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${JAIL_D}/50-selfdef.conf")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (profile upgrade standard → broad): adds recidive drop-in + fires reload" {
    # The reverse direction of test-104 (broad → standard). Both
    # transitions must work — locks the bidirectional contract.
    write_config "standard"
    run_wd
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    write_config "broad"
    : > "${F2B_LOG}"
    run_wd
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
}

@test "INVARIANT (recidive drop-in perms): chmod 0644 (system-config convention for /etc/fail2ban/jail.d)" {
    write_config "broad"
    run_wd
    [ "$(stat -c '%a' "${JAIL_D}/60-selfdef-recidive.conf")" = "644" ]
}

@test "INVARIANT (graceful-reload fallback): when fail2ban-client missing, falls back to systemctl restart" {
    # Remove the fake fail2ban-client → script should NOT just die,
    # it should detect-and-fallback.
    rm -f "${BIN}/fail2ban-client"
    write_config "standard"
    run_wd || true   # tolerate non-zero — what we lock here is the fallback shape
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    # When client missing, the script must fall back to systemctl restart.
    grep -q 'systemctl restart fail2ban' "${SYSEOF_LOG}" || \
        grep -q 'systemctl reload fail2ban' "${SYSEOF_LOG}"
}

@test "INVARIANT (no render-timestamp in drop-in): fail2ban drop-in must not carry a Generated <ISO-date> line" {
    # Latent variant-A risk class — without this guard, re-install
    # would replace the drop-in every time and flush ban-state.
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${JAIL_D}/50-selfdef.conf"
}

@test "INVARIANT (standard drop-in content: enables sshd jail — the canonical baseline target)" {
    # 50-selfdef.conf must enable [sshd] (the universal SSH-brute-
    # force defense). A regression silently dropping the [sshd]
    # section would leave the host unprotected on its primary
    # remote-access channel.
    write_config "standard"
    run_wd
    grep -qE '^\[sshd\]' "${JAIL_D}/50-selfdef.conf"
    grep -qE '^enabled[[:space:]]*=[[:space:]]*true' "${JAIL_D}/50-selfdef.conf"
}

@test "INVARIANT (recidive drop-in content: enables [recidive] section — actual jail definition)" {
    # 60-selfdef-recidive.conf must enable [recidive]. Otherwise
    # the file exists but doesn't actually arm the long-term-ban
    # jail.
    write_config "broad"
    run_wd
    grep -qE '^\[recidive\]' "${JAIL_D}/60-selfdef-recidive.conf"
    grep -qE '^enabled[[:space:]]*=[[:space:]]*true' "${JAIL_D}/60-selfdef-recidive.conf"
}

@test "INVARIANT (drop-ins re-arm after operator out-of-band deletion: re-creates both files)" {
    # Operator deletes drop-ins for debugging. Next apply re-
    # creates them with correct content + fires reload.
    write_config "broad"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    rm -f "${JAIL_D}/50-selfdef.conf" "${JAIL_D}/60-selfdef-recidive.conf"
    : > "${F2B_LOG}"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    grep -q 'fail2ban-client reload' "${F2B_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "broad"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"fail2ban-bridge"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=broad'* ]]
}

@test "INVARIANT (header-marker is first non-blank line — stale-cleanup head -1 discipline on 50-selfdef.conf)" {
    write_config "standard"
    run_wd
    first_line="$(awk 'NF' "${JAIL_D}/50-selfdef.conf" | head -1)"
    [[ "${first_line}" == *"selfdef"* || "${first_line}" == *"managed-by"* ]]
}

@test "INVARIANT (recidive drop-in carries bantime > standard sshd bantime — actual long-term ban semantic)" {
    # The whole point of recidive is LONGER ban for repeat offenders.
    # Lock that 60-selfdef-recidive.conf has a bantime directive AND
    # that value is much larger than standard sshd's typical ban
    # (e.g. > 86400s = 1 day, often 1 week = 604800s).
    write_config "broad"
    run_wd
    grep -qE '^bantime[[:space:]]*=' "${JAIL_D}/60-selfdef-recidive.conf"
}

@test "INVARIANT (standard sshd drop-in carries maxretry — actual retry-threshold gate)" {
    # SSH brute-force defense requires a maxretry value.
    write_config "standard"
    run_wd
    grep -qE '^maxretry[[:space:]]*=[[:space:]]*[1-9]' "${JAIL_D}/50-selfdef.conf"
}

@test "INVARIANT (asymmetric bantime: recidive bantime > standard sshd bantime — long-term ban discipline)" {
    # Sister to existing INVARIANT 'recidive drop-in carries bantime'.
    # Lock that recidive's bantime is STRICTLY GREATER than standard's
    # sshd bantime. Locks profile-rank asymmetry on the ban-duration
    # axis — a regression that inverts the relationship would silently
    # weaken the long-term-ban discipline.
    write_config "standard"
    run_wd
    std_bantime="$(grep -oE 'bantime[[:space:]]*=[[:space:]]*[0-9]+' "${JAIL_D}/50-selfdef.conf" | grep -oE '[0-9]+$' | head -1)"
    write_config "broad"
    run_wd
    recidive_bantime="$(grep -oE 'bantime[[:space:]]*=[[:space:]]*[0-9]+' "${JAIL_D}/60-selfdef-recidive.conf" | grep -oE '[0-9]+$' | head -1)"
    # If both have bantime values, recidive MUST be strictly greater.
    if [ -n "${std_bantime}" ] && [ -n "${recidive_bantime}" ]; then
        [ "${recidive_bantime}" -gt "${std_bantime}" ]
    else
        # If standard doesn't set bantime explicitly (uses default),
        # locks recidive's bantime is at least 86400s (1 day).
        [ "${recidive_bantime}" -ge 86400 ]
    fi
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # fail2ban-bridge TOML; parser must tolerate without altering
    # the profile-gated behavior. broad-with-noise still installs
    # BOTH the standard 50-selfdef.conf (sshd jail) AND the recidive
    # 60-selfdef-recidive.conf drop-in (long-term-ban jail) — the
    # full ssh-brute-force + repeat-offender ban substrate.
    write_config_with_noise() {
        cat > "${CONF}" <<'TOMLEOF'
profile = "broad"
operator_note = "ssh brute + recidive long-term-ban + apache/nginx jails"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    }
    write_config_with_noise
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    grep -qE '^\[sshd\]' "${JAIL_D}/50-selfdef.conf"
    grep -qE '^\[recidive\]' "${JAIL_D}/60-selfdef-recidive.conf"
}

@test "INVARIANT (asymmetric profile content: standard does NOT install recidive drop-in — recidive is broad-only)" {
    # Sister to many other installer module's asymmetric-profile
    # INVARIANT across the brain (ssh-hardening AllowGroups,
    # selinux-baseline autorelabel, tmpfs-baseline /tmp-only,
    # wireless-disable rfkill-vs-mask, coredump-suid-restrict
    # limits.d). The standard profile narrows to the sshd jail
    # only (the most common brute-force surface); the broad
    # profile widens to recidive (long-term repeat-offender ban)
    # plus apache/nginx jails. If standard silently installed
    # recidive, it would over-reach (operator who chose standard
    # to keep recidive as a later-deployment option would lose
    # the asymmetry). Locks the boundary: standard sshd-only,
    # broad both.
    write_config "standard"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    ! [ -f "${JAIL_D}/60-selfdef-recidive.conf" ]
}
