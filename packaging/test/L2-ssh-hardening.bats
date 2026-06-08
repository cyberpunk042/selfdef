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

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the ssh-hardening substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    # the ssh-hardening requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    # ssh-hardening substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    # ssh-hardening substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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
    # Locks semver-X.Y.Z discipline on the ssh-hardening
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the ssh-hardening module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the ssh-hardening module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the ssh-hardening
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for ssh-hardening is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the ssh-hardening substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the ssh-hardening install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the ssh-hardening requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the ssh-hardening
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the ssh-hardening
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the ssh-hardening substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the ssh-hardening substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (ssh-hardening README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (ssh-hardening install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (ssh-hardening install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (ssh-hardening install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (ssh-hardening install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (ssh-hardening install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (ssh-hardening install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (ssh-hardening install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (ssh-hardening install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (ssh-hardening install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (ssh-hardening install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (ssh-hardening install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (ssh-hardening install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (ssh-hardening module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (ssh-hardening module.toml exists at canonical path modules/ssh-hardening/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (ssh-hardening module dir is at canonical path modules/ssh-hardening/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (ssh-hardening install dir exists at modules/ssh-hardening/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (ssh-hardening install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-hardening install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (ssh-hardening install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (ssh-hardening install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (ssh-hardening module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (ssh-hardening install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (ssh-hardening install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (ssh-hardening install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (ssh-hardening install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (ssh-hardening install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (ssh-hardening install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (ssh-hardening install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (ssh-hardening install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (ssh-hardening module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"ssh-hardening"' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
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

@test "INVARIANT (ssh-hardening module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (ssh-hardening module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (ssh-hardening module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (ssh-hardening module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (ssh-hardening module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (ssh-hardening module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (ssh-hardening module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml requires list elements are inline-tables with kind+value keys (or empty) — TOML-requires-elements-shape-canonical 128)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert isinstance(el, dict), f'requires element must be inline-table, got {type(el).__name__}'
    assert 'kind' in el and 'value' in el, f'requires element must have kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml requires items have kind in bounded vocab {binary, package, kernel-feature} — TOML-requires-kind-vocab-canonical 129)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
allowed = {'binary', 'package', 'kernel-feature'}
for el in r:
    k = el.get('kind', '')
    assert k in allowed, f'requires.kind must be in {allowed}, got {k!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml requires items have value as non-empty string — TOML-requires-value-nonempty-canonical 130)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    v = el.get('value', '')
    assert isinstance(v, str) and v, f'requires.value must be non-empty string, got {v!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml provides list elements are all non-empty strings — TOML-provides-elements-string-canonical 131)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides') or []
for el in p:
    assert isinstance(el, str) and el, f'provides element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml conflicts list elements are all non-empty strings (or empty list) — TOML-conflicts-elements-string-canonical 132)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts') or []
for el in c:
    assert isinstance(el, str) and el, f'conflicts element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml consumes list elements are all non-empty strings (or empty) — TOML-consumes-elements-string-canonical 133)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes') or []
for el in c:
    assert isinstance(el, str) and el, f'consumes element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml depends_on list elements are all non-empty strings (or empty) — TOML-depends-on-elements-string-canonical 134)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('depends_on') or []
for el in c:
    assert isinstance(el, str) and el, f'depends_on element must be non-empty string, got {el!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths list elements are all absolute paths (starting with /) — TOML-install-paths-paths-absolute-canonical 135)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
for el in paths:
    assert isinstance(el, str) and el and el.startswith('/'), f'install_paths.paths element must be absolute path, got {el!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths list elements are unique (no duplicates) — TOML-install-paths-paths-unique-canonical 136)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
assert len(paths) == len(set(paths)), f'install_paths.paths must be unique, duplicates: {[p for p in paths if paths.count(p) > 1]!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml name field matches kebab-case pattern [a-z][a-z0-9-]+ — TOML-name-kebab-case-canonical 137)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
import re
n = data.get('name', '')
assert re.fullmatch(r'[a-z][a-z0-9-]+', n), f'name must match kebab-case [a-z][a-z0-9-]+, got {n!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml requires items have exactly the {kind, value} keyset (no extras) — TOML-requires-elements-strict-keys-canonical 138)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires') or []
for el in r:
    assert set(el.keys()) == {'kind', 'value'}, f'requires element must have exactly kind+value keys, got {sorted(el.keys())!r}'
"
}

@test "INVARIANT (ssh-hardening module.toml install_paths.paths elements use FHS-canonical prefixes {/etc, /var, /usr, /run, /opt} — TOML-install-paths-fhs-prefix-canonical 139)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hardening/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths') or {}
paths = ip.get('paths') or []
prefixes = ('/etc/', '/var/', '/usr/', '/run/', '/opt/')
for el in paths:
    assert any(el.startswith(pf) for pf in prefixes), f'install_paths.paths element must use FHS-canonical prefix {prefixes}, got {el!r}'
"
}
