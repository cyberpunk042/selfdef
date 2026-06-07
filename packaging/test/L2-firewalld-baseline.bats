#!/usr/bin/env bats
# L2 functional suite for firewalld-baseline.
#
# firewalld-baseline creates a permanent 'selfdef' zone with
# target=DROP (or %%REJECT%%), adds ssh + operator-named
# services/ports, then sets it as the default zone. Anti-lockout
# pattern parallel to nftables-baseline: ssh is added to the
# zone BEFORE it becomes default.
#
# Profiles:
#   baseline → target=DROP (silently drop unmatched) + ssh-allow
#   web      → target=DROP + ssh-allow + operator-allow_services
#              + operator-allow_ports (typically http, https)
#   block    → target=%%REJECT%% (icmp reject instead of silent
#              drop — operator visibility of denied attempts)
#
# Behavior on hosts without firewalld (typical Debian default,
# nftables-only): die early with redirect message to
# nftables-baseline. The conflicts=["nftables-baseline"]
# manifest field steers operators to the right module per distro.
#
# Adds SELFDEF_FIREWALLD_BACKUP_DIR + SELFDEF_FIREWALLD_BACKUP_FILE
# + SELFDEF_FIREWALLD_ZONE env-var overrides (added 2026-06-06)
# for L2 testability. Live defaults unchanged.
#
# Run with: bats packaging/test/L2-firewalld-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/firewalld-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/firewall-cmd" <<'FCEOF'
#!/usr/bin/env bash
printf 'firewall-cmd %s\n' "$*" >> "${FW_LOG}"
case "$*" in
    "--state")
        [[ "${FW_RUNNING:-1}" == "1" ]] && exit 0 || exit 252 ;;
    "--get-default-zone")
        printf '%s\n' "${PRIOR_DEFAULT_ZONE:-public}" ;;
    "--permanent --get-zones")
        # Pretend stack of zones already-present.
        printf '%s\n' "${PRE_EXISTING_ZONES:-public block drop trusted}" ;;
esac
exit 0
FCEOF
    chmod +x "${BIN}/firewall-cmd"
    export FW_LOG="${TMP}/firewall-cmd.log"
    : > "${FW_LOG}"
    CONF="${TMP}/firewalld-baseline.toml"
    BACKUP_DIR="${TMP}/backup"
    BACKUP_FILE="${BACKUP_DIR}/firewalld-default-zone.bak"
    mkdir -p "${BACKUP_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    local profile="$1"
    shift
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    for line in "$@"; do
        printf '%s\n' "${line}" >> "${CONF}"
    done
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    FW_LOG="${FW_LOG}" \
    FW_RUNNING="${FW_RUNNING:-1}" \
    PRIOR_DEFAULT_ZONE="${PRIOR_DEFAULT_ZONE:-public}" \
    PRE_EXISTING_ZONES="${PRE_EXISTING_ZONES:-public block drop trusted}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_FIREWALLD_CONFIG="${CONF}" \
    SELFDEF_FIREWALLD_BACKUP_DIR="${BACKUP_DIR}" \
    SELFDEF_FIREWALLD_BACKUP_FILE="${BACKUP_FILE}" \
    bash "${WD}"
}

# Helper: remove firewall-cmd binary to simulate non-firewalld host.
remove_firewall_cmd() {
    rm -f "${BIN}/firewall-cmd"
}

@test "missing config → die" {
    SELFDEF_FIREWALLD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FIREWALLD_CONFIG="${SELFDEF_FIREWALLD_CONFIG}" \
        SELFDEF_FIREWALLD_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_FIREWALLD_BACKUP_FILE="${BACKUP_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FIREWALLD_CONFIG="${CONF}" \
        SELFDEF_FIREWALLD_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_FIREWALLD_BACKUP_FILE="${BACKUP_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|web|block"* ]]
}

@test "non-firewalld host (firewall-cmd missing) → die with redirect to nftables-baseline" {
    remove_firewall_cmd
    write_config "baseline"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FIREWALLD_CONFIG="${CONF}" \
        SELFDEF_FIREWALLD_BACKUP_DIR="${BACKUP_DIR}" \
        SELFDEF_FIREWALLD_BACKUP_FILE="${BACKUP_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"firewall-cmd"* ]]
    [[ "${output}" == *"unavailable"* ]]
    [[ "${output}" == *"nftables-baseline"* ]]
}

@test "baseline profile creates zone + sets target DROP + adds ssh + sets default + reloads" {
    write_config "baseline"
    run_wd
    grep -q '\-\-permanent --new-zone=selfdef' "${FW_LOG}"
    grep -q '\-\-permanent --zone=selfdef --set-target=DROP' "${FW_LOG}"
    grep -q '\-\-permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
    grep -q '\-\-set-default-zone=selfdef' "${FW_LOG}"
    grep -q '\-\-reload' "${FW_LOG}"
}

@test "block profile sets target=%%REJECT%% (visible-deny variant)" {
    write_config "block"
    run_wd
    grep -q '\-\-permanent --zone=selfdef --set-target=%%REJECT%%' "${FW_LOG}"
}

@test "web profile honors allow_services + allow_ports operator config" {
    write_config "web" 'allow_services = "http,https"' 'allow_ports = "8080/tcp,8443/tcp"'
    run_wd
    grep -q '\-\-permanent --zone=selfdef --add-service=http' "${FW_LOG}"
    grep -q '\-\-permanent --zone=selfdef --add-service=https' "${FW_LOG}"
    grep -q '\-\-permanent --zone=selfdef --add-port=8080/tcp' "${FW_LOG}"
    grep -q '\-\-permanent --zone=selfdef --add-port=8443/tcp' "${FW_LOG}"
}

@test "INVARIANT: ssh is added to the zone BEFORE it becomes default (anti-lockout)" {
    write_config "baseline"
    run_wd
    # Extract line numbers for the ssh-add and the set-default-zone events.
    ssh_line="$(grep -nF -e '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}" | head -1 | cut -d: -f1)"
    default_line="$(grep -nF -e '--set-default-zone=selfdef' "${FW_LOG}" | head -1 | cut -d: -f1)"
    [ -n "${ssh_line}" ]
    [ -n "${default_line}" ]
    [ "${ssh_line}" -lt "${default_line}" ]
}

@test "INVARIANT: zone-already-exists path skips --new-zone (idempotent zone creation)" {
    # Pre-existing zone list INCLUDES 'selfdef'.
    write_config "baseline"
    PRE_EXISTING_ZONES="public block drop trusted selfdef" run_wd
    ! grep -q '\-\-permanent --new-zone=selfdef' "${FW_LOG}"
    # But the set-target + add-service + set-default still fire (idempotent re-apply).
    grep -q '\-\-permanent --zone=selfdef --set-target=DROP' "${FW_LOG}"
    grep -q '\-\-set-default-zone=selfdef' "${FW_LOG}"
}

@test "INVARIANT: backup captures the prior default zone once on first apply" {
    write_config "baseline"
    PRIOR_DEFAULT_ZONE=public run_wd
    [ -f "${BACKUP_FILE}" ]
    grep -q '^public$' "${BACKUP_FILE}"
    # Backup is operator-private.
    [ "$(stat -c '%a' "${BACKUP_FILE}")" = "600" ]
}

@test "INVARIANT: backup-once — re-apply does NOT overwrite the captured prior default zone" {
    write_config "baseline"
    PRIOR_DEFAULT_ZONE=public run_wd
    [ -f "${BACKUP_FILE}" ]
    # Re-apply with a DIFFERENT reported default — the backup must NOT track it
    # (we want the ORIGINAL distro state preserved, not the now-selfdef-zone state).
    backup_mtime_before="$(stat -c '%Y' "${BACKUP_FILE}")"
    sleep 1
    PRIOR_DEFAULT_ZONE=selfdef run_wd
    backup_mtime_after="$(stat -c '%Y' "${BACKUP_FILE}")"
    [ "${backup_mtime_before}" = "${backup_mtime_after}" ]
    grep -q '^public$' "${BACKUP_FILE}"
}

@test "INVARIANT: firewalld-not-running → continue with permanent config + WARN" {
    write_config "baseline"
    output="$(FW_RUNNING=0 run_wd 2>&1)"
    [[ "${output}" == *"WARN"* && "${output}" == *"firewalld is not running"* ]]
    # Permanent config still fires.
    grep -q '\-\-permanent --new-zone=selfdef' "${FW_LOG}"
}

@test "INVARIANT: DRY_RUN does not fire any firewall-cmd write" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    # Read-only invocations (--state, --get-default-zone) MAY have fired but
    # NO mutating invocations (--new-zone, --set-target, --add-service,
    # --set-default-zone, --reload).
    ! grep -q '\-\-permanent --new-zone' "${FW_LOG}"
    ! grep -q '\-\-permanent.*--set-target' "${FW_LOG}"
    ! grep -q '\-\-permanent.*--add-service' "${FW_LOG}"
    ! grep -q '\-\-set-default-zone' "${FW_LOG}"
    ! grep -q '\-\-reload' "${FW_LOG}"
}

@test "default profile is baseline (no profile key — conservative DROP default)" {
    : > "${CONF}"
    run_wd
    grep -q '\-\-permanent --zone=selfdef --set-target=DROP' "${FW_LOG}"
}

@test "emit_status reports profile + zone + target in JSON" {
    write_config "baseline"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=baseline'* ]]
    [[ "${output}" == *'zone=selfdef'* ]]
    [[ "${output}" == *'target=DROP'* ]]
    [[ "${output}" == *'ssh always allowed'* ]]
}

@test "INVARIANT (ssh always allowed across all 3 profiles: baseline + web + block — anti-lockout floor)" {
    # Lock that ssh is added unconditionally to the zone regardless
    # of profile. A regression where web-profile only adds operator-
    # allow-list (no ssh fallback) would lock remote operators out.
    for prof in baseline web block; do
        : > "${FW_LOG}"
        write_config "${prof}"
        run_wd
        grep -q -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
    done
}

@test "INVARIANT (--reload fires LAST: AFTER all --permanent writes — atomic activation, not partial state)" {
    # firewall-cmd --permanent writes go to disk; --reload promotes
    # them to runtime. If --reload fired BEFORE the writes finished,
    # operator could see partial state (zone exists but lacks ssh).
    # Lock the ordering.
    write_config "baseline"
    run_wd
    reload_line="$(grep -n -- '--reload' "${FW_LOG}" | tail -1 | cut -d: -f1)"
    addssh_line="$(grep -n -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}" | tail -1 | cut -d: -f1)"
    setdefault_line="$(grep -n -- '--set-default-zone=selfdef' "${FW_LOG}" | tail -1 | cut -d: -f1)"
    settarget_line="$(grep -n -- '--permanent --zone=selfdef --set-target=DROP' "${FW_LOG}" | tail -1 | cut -d: -f1)"
    [ -n "${reload_line}" ]
    [ "${reload_line}" -gt "${addssh_line}" ]
    [ "${reload_line}" -gt "${settarget_line}" ]
    [ "${reload_line}" -gt "${setdefault_line}" ]
}

@test "INVARIANT (whitespace tolerance in allow_services CSV: 'http , https' is normalized to http + https)" {
    # Operator may write the CSV with spaces around commas. Lock
    # that the parser strips whitespace + treats them as 2 distinct
    # services.
    write_config "web" 'allow_services = "http , https"'
    run_wd
    grep -q -- '--permanent --zone=selfdef --add-service=http' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-service=https' "${FW_LOG}"
    # No literal "http " with trailing space.
    ! grep -qE -- '--add-service=http $' "${FW_LOG}"
}

@test "INVARIANT (empty allow_services value: no extra --add-service calls beyond ssh — defensive empty handling)" {
    # An empty CSV must not produce an "--add-service=" invocation
    # (would fail at firewall-cmd level + leave zone in undefined
    # state). Only ssh added.
    write_config "web" 'allow_services = ""'
    run_wd
    # No empty --add-service= invocation.
    ! grep -qE -- '--add-service=[[:space:]]*$' "${FW_LOG}"
    # ssh still added.
    grep -q -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
}

@test "INVARIANT (emit_status JSON: module + status + profile surfaced for operator dashboard)" {
    write_config "block"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"firewalld-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=block'* ]]
}

@test "INVARIANT (re-arm after operator zone deletion: re-creates zone idempotently)" {
    # If the operator out-of-band removes the selfdef zone (e.g. via
    # firewall-cmd --permanent --delete-zone=selfdef), the next apply
    # MUST re-create it. Simulated here by toggling PRE_EXISTING_ZONES
    # back to not-include-selfdef on second apply.
    write_config "baseline"
    PRE_EXISTING_ZONES="public block drop trusted selfdef" run_wd
    # Now operator-delete: selfdef no longer in zone list.
    : > "${FW_LOG}"
    PRE_EXISTING_ZONES="public block drop trusted" run_wd
    grep -q -- '--permanent --new-zone=selfdef' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
}

@test "INVARIANT (block profile preserves ssh-allow + adds REJECT target — visible-deny does NOT lock out remote ops)" {
    # block profile uses REJECT instead of DROP (operator visibility of
    # denied attempts via icmp), but ssh MUST still be added so remote
    # ops aren't locked out by the visible-deny variant.
    write_config "block"
    run_wd
    grep -q -- '--permanent --zone=selfdef --set-target=%%REJECT%%' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
    # ssh ordering still BEFORE set-default (anti-lockout).
    ssh_line="$(grep -nF -e '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}" | head -1 | cut -d: -f1)"
    default_line="$(grep -nF -e '--set-default-zone=selfdef' "${FW_LOG}" | head -1 | cut -d: -f1)"
    [ "${ssh_line}" -lt "${default_line}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # firewalld-baseline TOML; parser must tolerate without altering
    # the profile-gated behavior. web-with-noise still honors
    # allow_services + allow_ports AND ssh-anti-lockout still fires.
    cat > "${CONF}" <<'TOMLEOF'
profile = "web"
allow_services = "http,https"
allow_ports = "8080/tcp"
operator_note = "ingress-edge — http + https + admin alt-port"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-service=http' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-service=https' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-port=8080/tcp' "${FW_LOG}"
}

@test "INVARIANT (zone name 'selfdef' is the uninstall identification marker — anti-orphan-zone contract)" {
    # Sister to many other installer module's self-identifying-
    # artifact INVARIANTs across the brain. The created zone MUST
    # be named 'selfdef' (not a randomly-generated zone name).
    # uninstall.sh identifies our zone via that exact name and
    # rolls it back; a generated name would orphan the zone on
    # uninstall (operator's firewalld would carry a permanent
    # zone of unknown provenance, no rollback path). Locks the
    # naming contract on the operator-audit-trail axis.
    write_config "baseline"
    run_wd
    # Every relevant firewall-cmd invocation uses --zone=selfdef,
    # never a random/dynamic zone name.
    grep -qE -- '--permanent.*--new-zone=selfdef|--new-zone selfdef' "${FW_LOG}"
    grep -q -- '--permanent --zone=selfdef --add-service=ssh' "${FW_LOG}"
    grep -q -- '--set-default-zone=selfdef' "${FW_LOG}"
}

@test "INVARIANT (DRY_RUN does not fire any firewall-cmd permanent rule changes or set-default-zone)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The firewalld-baseline DRY_RUN path MUST
    # be a no-op against the live firewalld state — operator
    # using --dry-run to preview-without-applying expects ZERO
    # mutations. Locks the dry-run side-effect-freedom contract
    # so a regression that fires --permanent through DRY_RUN
    # would be caught (sister to existing dry-run INVARIANT
    # already locked: this extends to the --set-default-zone
    # mutation specifically, which would re-route ALL traffic).
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! grep -q -- '--permanent --new-zone' "${FW_LOG}"
    ! grep -q -- '--permanent --zone=selfdef --add-service' "${FW_LOG}"
    ! grep -q -- '--set-default-zone=selfdef' "${FW_LOG}"
}

@test "INVARIANT (block profile carries REJECT (not DROP) target — visible-deny ICMP/TCP-RST semantic)" {
    # Sister to block-profile preserves ssh-allow INVARIANT
    # already locked. block profile's target is REJECT (not
    # DROP) — semantic difference: REJECT sends ICMP/TCP-RST
    # back to the source so connection attempts fail fast
    # client-side (visible deny); DROP silently discards
    # packets (invisible deny — appears as connection
    # timeout). Operator's choice for block was REJECT
    # specifically — visible-deny is debuggable + doesn't
    # waste client retry-budget. A silent regression to DROP
    # would change behavior with no operator signal. Locks
    # the REJECT-not-DROP semantic on the block-profile
    # surface. Sister to brain-wide asymmetric profile-
    # content INVARIANTs.
    write_config "block"
    run_wd
    grep -q -- '--permanent --zone=selfdef --set-target=REJECT' "${FW_LOG}" \
        || grep -q -- '--permanent --zone=selfdef --set-target=%%REJECT%%' "${FW_LOG}" \
        || grep -q -- 'set-target=REJECT' "${FW_LOG}"
}

@test "INVARIANT (firewall-cmd --reload fires after rule additions — semantic activation)" {
    # Sister to brain-wide reload-after-config INVARIANTs.
    # firewalld permanent rules don't activate until --reload.
    # Without it the baseline rules sit dormant.
    write_config "baseline"
    run_wd
    grep -qE 'firewall-cmd.*--reload' "${FW_LOG}"
}
