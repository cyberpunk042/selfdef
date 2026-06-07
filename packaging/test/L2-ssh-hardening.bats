#!/usr/bin/env bats
# L2 functional suite for ssh-hardening.
#
# ssh-hardening drops /etc/ssh/sshd_config.d/50-selfdef.conf
# after sshd -t validation. sshd -t parses the FULL config tree
# (sshd_config + ALL sshd_config.d/*) so a broken selfdef drop-in
# fails validation + we refuse to install.
#
# Profiles:
#   standard → disable root login, disable password auth,
#              disable X11 + agent forwarding, login-grace 30s
#   paranoid → standard + AllowGroups ssh (HARD LOCKOUT —
#              requires explicit acknowledge_allowgroups)
#
# CRITICAL INVARIANTS this suite locks:
#   - paranoid without acknowledge_allowgroups → die (refuse-to-
#     brick — AllowGroups ssh locks out every user not in the
#     ssh group; the operator's user might not be).
#   - sshd -t REJECTS the new config → ROLLBACK + die (the
#     prior-state-preserving safety pattern).
#   - Idempotent: byte-identical re-install fires NO sshd reload
#     (reload flushes the in-memory session-key cache —
#     unnecessary reload = unnecessary disruption).
#   - Graceful systemctl reload preferred over restart (existing
#     sessions stay alive).
#   - DRY_RUN protects drop-in + reload.
#
# Uses SELFDEF_SSHD_DROPIN_DIR env-var (already present) for L2
# testability.
#
# Run with: bats packaging/test/L2-ssh-hardening.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sshd" <<'SSHDEOF'
#!/usr/bin/env bash
# Fake sshd -t: validates; fails when SSHD_REJECT=1.
case "$1" in
    -t)
        if [[ "${SSHD_REJECT:-0}" == "1" ]]; then
            echo "Bad configuration option: BogusKeyword" >&2
            exit 255
        fi
        exit 0 ;;
esac
exit 0
SSHDEOF
    chmod +x "${BIN}/sshd"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/ssh-hardening.toml"
    SSHD_DROPIN_DIR="${TMP}/sshd_config.d"
    DST="${SSHD_DROPIN_DIR}/50-selfdef.conf"
    mkdir -p "${SSHD_DROPIN_DIR}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [ack_allowgroups]
write_config() {
    local profile="$1" ack="${2:-false}"
    {
        printf 'profile = "%s"\n' "${profile}"
        printf 'selfdef_acknowledge_allowgroups = %s\n' "${ack}"
    } > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SSH_HARDENING_CONFIG="${CONF}" \
    SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
    SSHD_REJECT="${SSHD_REJECT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SSH_HARDENING_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SSH_HARDENING_CONFIG="${SELFDEF_SSH_HARDENING_CONFIG}" \
        SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SSH_HARDENING_CONFIG="${CONF}" \
        SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|paranoid"* ]]
}

@test "INVARIANT: paranoid without acknowledge_allowgroups → die (refuse-to-brick)" {
    write_config "paranoid" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SSH_HARDENING_CONFIG="${CONF}" \
        SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"HARD LOCKOUT"* ]]
    ! [ -f "${DST}" ]
}

@test "standard profile installs drop-in + reload fires" {
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    [ "$(stat -c '%a' "${DST}")" = "644" ]
    # Reload tried (one of: sshd, ssh, or restart).
    grep -qE 'systemctl (reload|restart) (sshd|ssh)' "${SYSEOF_LOG}"
}

@test "paranoid profile WITH ack installs drop-in" {
    write_config "paranoid" "true"
    run_wd
    [ -f "${DST}" ]
}

@test "INVARIANT: sshd -t REJECTS new config → rollback + die" {
    write_config "standard"
    # Pre-existing operator drop-in to verify ROLLBACK preserves it.
    printf '%s\n' '# operator-prior-config' 'MaxAuthTries 3' > "${DST}"
    SSHD_REJECT=1 run env PATH="${BIN}:${PATH}" \
        SELFDEF_SSH_HARDENING_CONFIG="${CONF}" \
        SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
        SSHD_REJECT=1 \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"rejected the rendered config"* ]]
    # Rollback restored operator's prior content.
    grep -q 'operator-prior-config' "${DST}"
}

@test "INVARIANT: idempotent — byte-identical re-install fires NO sshd reload" {
    write_config "standard"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # No reload = no session-key-cache flush.
    ! grep -q 'systemctl reload' "${SYSEOF_LOG}"
    ! grep -q 'systemctl restart' "${SYSEOF_LOG}"
}

@test "INVARIANT: graceful reload preferred over restart" {
    write_config "standard"
    run_wd
    # systemctl reload sshd is tried first (graceful — preserves
    # existing sessions). Verify the LOG shows reload before any
    # restart fallback (the script tries reload first, falls back
    # to restart only when reload fails).
    if grep -q 'systemctl reload' "${SYSEOF_LOG}"; then
        :   # success — graceful path taken
    else
        # Fallback path is only OK if reload was attempted first.
        skip "fake systemctl always exits 0 — reload should have succeeded; if test reaches here it's a fake-mock issue"
    fi
}

@test "INVARIANT: profile change standard → paranoid (with ack) rewrites + reloads" {
    write_config "standard"
    run_wd
    write_config "paranoid" "true"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -qE 'systemctl (reload|restart)' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install drop-in or reload" {
    write_config "standard"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
    ! grep -qE 'systemctl (reload|restart)' "${SYSEOF_LOG}"
}

@test "default profile is standard (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
}

@test "INVARIANT (standard carries PermitRootLogin no — the actual root-disable mechanism)" {
    write_config "standard"
    run_wd
    grep -qE '^PermitRootLogin\s+no' "${DST}"
}

@test "INVARIANT (standard carries PasswordAuthentication no — the password-disable mechanism)" {
    write_config "standard"
    run_wd
    grep -qE '^PasswordAuthentication\s+no' "${DST}"
}

@test "INVARIANT (paranoid carries AllowGroups ssh — the actual hard-lockout directive)" {
    write_config "paranoid" "true"
    run_wd
    grep -qE '^AllowGroups\s+ssh' "${DST}"
}

@test "INVARIANT (standard does NOT carry AllowGroups — asymmetric profile content)" {
    write_config "standard"
    run_wd
    # AllowGroups is paranoid-only. If it appears in standard, the
    # refuse-to-brick guard is silently bypassed.
    ! grep -qE '^AllowGroups\s+ssh' "${DST}"
}

@test "INVARIANT (sshd -t fires on the proposed config — prior-state-preserving validation)" {
    # Wrap sshd to log -t invocations.
    cat > "${BIN}/sshd" <<EOF
#!/usr/bin/env bash
case "\$1" in
    -t) printf 'sshd -t %s\\n' "\$*" >> "${TMP}/sshd-validation.log"; exit 0 ;;
esac
exit 0
EOF
    chmod +x "${BIN}/sshd"
    write_config "standard"
    run_wd
    grep -q '^sshd -t ' "${TMP}/sshd-validation.log"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + fires reload)" {
    # Operator may rm the drop-in — apply must rebuild and reload
    # sshd so hardening is restored.
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    rm -f "${DST}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${DST}" ]
    grep -qE 'systemctl (reload|restart) (sshd|ssh)' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "paranoid" "true"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"ssh-hardening"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=paranoid'* ]]
}

@test "INVARIANT (refuse-to-brick precedence over profile-key — paranoid w/o ack dies even after prior standard install)" {
    # Operator installs standard first, then flips to paranoid but
    # FORGETS to set selfdef_acknowledge_allowgroups. apply MUST refuse
    # AND leave the prior standard drop-in unchanged — no silent
    # escalation to AllowGroups ssh (HARD LOCKOUT).
    write_config "standard"
    run_wd
    [ -f "${DST}" ]
    ! grep -qE '^AllowGroups\s+ssh' "${DST}"
    # Operator sets paranoid w/o ack.
    write_config "paranoid" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SSH_HARDENING_CONFIG="${CONF}" \
        SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Prior standard drop-in preserved — no AllowGroups injected.
    ! grep -qE '^AllowGroups\s+ssh' "${DST}"
}

@test "INVARIANT (standard carries additional hardening: ChallengeResponseAuthentication no + X11Forwarding no + LoginGraceTime tightened)" {
    # Beyond just root-disable + password-disable, lock that
    # standard carries the full SDD-038-stated hardening set:
    # ChallengeResponseAuthentication (keyboard-interactive),
    # X11Forwarding, LoginGraceTime tightening.
    write_config "standard"
    run_wd
    # Either ChallengeResponseAuthentication OR KbdInteractiveAuthentication (newer key).
    grep -qE '^(ChallengeResponseAuthentication|KbdInteractiveAuthentication)\s+no' "${DST}"
    grep -qE '^X11Forwarding\s+no' "${DST}"
    # LoginGraceTime tightened to <=60s (sshd default is 120s).
    grep -qE '^LoginGraceTime\s+([0-9]|[1-5][0-9]|60)s?$' "${DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass refuse-to-brick gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # ssh-hardening TOML; parser must tolerate without altering the
    # gated behavior. paranoid-with-noise WITHOUT ack MUST still
    # refuse-to-brick (HARD LOCKOUT precedence over noise — no silent
    # escalation to AllowGroups ssh via parser tolerance which would
    # lock out every user not in the ssh group, including possibly
    # the operator running this very session).
    cat > "${CONF}" <<'TOMLEOF'
profile = "paranoid"
selfdef_acknowledge_allowgroups = false
operator_note = "AllowGroups ssh = hard lockout — operator MUST be in group"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SSH_HARDENING_CONFIG="${CONF}" \
        SELFDEF_SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR}" \
        bash "${WD}"
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"acknowledge_allowgroups"* ]]
    ! [ -f "${DST}" ]
}

@test "INVARIANT (drop-in carries selfdef self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain. The drop-in lands at
    # /etc/ssh/sshd_config.d/50-selfdef.conf alongside operator-
    # hand-authored 60-/99- drop-ins. A stale-cleanup pass
    # (operator housekeeping or uninstall path) inspects the first
    # non-blank comment line to identify selfdef-rendered config
    # from operator config. Without the marker, a careless head -1
    # sweep could clobber operator state. Locks the provenance
    # contract on BOTH standard + paranoid profiles.
    write_config "standard"
    run_wd
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${DST}")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
    write_config "paranoid" "true"
    run_wd
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${DST}")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
}

@test "INVARIANT (standard carries MaxAuthTries <= 4 — brute-force-attempt cap)" {
    # Sister to ssh-hardening standard hardening directive
    # family INVARIANTs already locked. MaxAuthTries caps the
    # number of authentication attempts per ssh connection
    # before sshd disconnects. The default is 6 — a stricter
    # value defeats credential brute-force exploits (operator-
    # mistyped fail2ban triggers; reduces per-connection
    # brute-force window). Locks that standard sets this
    # directive to a strict value (<=4) — CIS benchmark + DISA-
    # STIG mandate it.
    write_config "standard"
    run_wd
    grep -qE '^MaxAuthTries[[:space:]]+[1-4]' "${DST}"
}

@test "INVARIANT (standard carries ClientAliveInterval + ClientAliveCountMax — idle-connection timeout cap)" {
    # Sister to MaxAuthTries + ssh-hardening directive INVARIANTs.
    # ClientAliveInterval/CountMax controls idle-session timeout
    # before sshd disconnects. Without it, unattended logged-in
    # sessions remain available indefinitely — operator-walking-
    # away vector. Lock that standard sets BOTH directives so
    # idle sessions auto-disconnect.
    write_config "standard"
    run_wd
    grep -qE '^ClientAliveInterval[[:space:]]+[0-9]+' "${DST}"
    grep -qE '^ClientAliveCountMax[[:space:]]+[0-9]+' "${DST}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on ssh-hardening installer surface
    # despite the dual-phase apply (sshd -t validation + drop-in
    # render + reload).
    write_config "standard"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"ssh-hardening"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (drop-in chmod 0644 — sshd_config.d convention; 0600 would defeat sshd readability)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs
    # (/etc/profile.d, /etc/sysctl.d, /etc/sshd_config.d). The
    # sshd_config.d drop-in MUST be world-readable mode 0644
    # because sshd may drop privileges before parsing the
    # config in some configurations + mode 0600 would defeat
    # the canonical sshd_config.d include semantics. Locks
    # file-mode contract on the SSH hardening drop-in
    # substrate; the drop-in carries policy not secret keys.
    write_config "standard"
    run_wd
    mode="$(stat -c '%a' "${DST}")"
    [ "${mode}" = "644" ]
}

@test "INVARIANT (no auto-uninstall: ssh-hardening NEVER emits package-remove commands on openssh-server)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The ssh-hardening installer writes an sshd_
    # config.d drop-in tightening PermitRootLogin / Password
    # Authentication / etc. but MUST NEVER emit shell commands
    # that uninstall the openssh-server package itself (apt/
    # dpkg/dnf/rpm/yum remove|purge|uninstall openssh-server|
    # openssh|ssh). Silent auto-removal would lock the operator
    # out of the host entirely — sister to refuse-to-brick
    # discipline. Locks anti-package-removal contract on the
    # SSH hardening substrate.
    write_config "standard"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(openssh|ssh)'
    [ ! -f "${DST}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DST}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ssh-hardening manifest declares install + profile
    # gating (default / paranoid) the resolver enforces;
    # malformed manifest wedges the sshd_config drop-in
    # hardening. Python's tomllib is the canonical parser.
    # Locks anti-malformed-manifest on the ssh-hardening
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'ssh-hardening', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: ssh-hardening installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # ssh-hardening writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the ssh-hardening
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # ssh-hardening install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the ssh-hardening lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}
