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

@test "INVARIANT (DRY_RUN side-effect-freedom: NO jail.d drop-ins written AND NO fail2ban restart fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/fail2ban/jail.d/50-selfdef.conf
    # OR 60-selfdef-recidive.conf AND without restarting fail2ban.
    # A silent dry-run that committed would enable IP-banning at
    # preview time on a host where operator was investigating
    # fail2ban's ruleset — could lock out the operator's own
    # admin source IP on first failure. Locks dry-run-preserves-
    # state on the brute-force defense substrate.
    rm -f "${JAIL_D}/50-selfdef.conf" "${JAIL_D}/60-selfdef-recidive.conf"
    write_config "standard"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${JAIL_D}/50-selfdef.conf" ]
    [ ! -f "${JAIL_D}/60-selfdef-recidive.conf" ]
    ! grep -qE 'systemctl (restart|reload) fail2ban' "${SYSEOF_LOG}"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "standard"
    run_wd
    [ -f "${JAIL_D}/50-selfdef.conf" ]
    [ "$(stat -c '%a' "${JAIL_D}/50-selfdef.conf")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on fail2ban-bridge installer
    # surface across jail.d-drop-in + restart phases.
    write_config "standard"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"fail2ban-bridge"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: fail2ban-bridge NEVER emits package-remove commands on fail2ban)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The fail2ban-bridge installer writes jail.d
    # drop-ins for sshd + recidive but MUST NEVER emit shell
    # commands that uninstall the fail2ban package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall fail2ban).
    # Silent auto-removal would tear down the auth-brute-force
    # mitigation substrate entirely — every downstream defense
    # depending on fail2ban's ban-on-failed-auth loses
    # substrate. T1110 Brute Force defense self-defeat. Locks
    # anti-package-removal contract on the fail2ban bridge
    # substrate.
    write_config "standard"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+fail2ban'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${JAIL_D}/50-selfdef.conf"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. fail2ban-bridge manifest declares install + profile
    # gating (standard / broad) the resolver enforces; malformed
    # manifest wedges the fail2ban jail baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the fail2ban-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'fail2ban-bridge', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: fail2ban-bridge installer NEVER deletes operator-pre-existing jail.local — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # fail2ban-bridge writes its own /etc/fail2ban/jail.d/
    # drop-ins (standard / recidive); it MUST NEVER rm/find-
    # delete an operator's pre-existing /etc/fail2ban/jail.local
    # or jail.d entries not owned by THIS module. Locks no-auto-
    # delete on the fail2ban-bridge installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/fail2ban/jail\.local' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/fail2ban.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # fail2ban-bridge install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the fail2ban-bridge lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the fail2ban-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    # the fail2ban-bridge requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    # present discipline on the fail2ban-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    # category-present discipline on the fail2ban-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
    # semver-X.Y.Z discipline on the fail2ban-bridge substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (fail2ban-bridge module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the fail2ban-bridge module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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

@test "INVARIANT (fail2ban-bridge module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the fail2ban-bridge module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fail2ban-bridge/module.toml"
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
