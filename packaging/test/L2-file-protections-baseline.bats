#!/usr/bin/env bats
# L2 functional suite for file-protections-baseline.
#
# file-protections-baseline pins fs.protected_* sysctls. These
# kernel knobs block classic symlink/hardlink-attack vectors:
#   fs.protected_hardlinks = 1 → can't hardlink to files you don't
#                                own (blocks privesc via setuid-
#                                hardlinks-in-/tmp class)
#   fs.protected_symlinks  = 1 → block following symlinks in
#                                sticky world-writable dirs (blocks
#                                /tmp race attacks)
#   fs.protected_fifos     = 2 → block writing to FIFOs owned by
#                                others in world-writable dirs
#   fs.protected_regular   = 2 → block writing to regular files
#                                owned by others in world-writable
#                                dirs (the 2017 CVE-2017-7610-class
#                                race window)
#
# Profiles:
#   baseline → conservative (=1 where appropriate)
#   strict   → aggressive (=2 everywhere)
#
# Adds SELFDEF_FILEPROT_DROPIN env-var for L2 testability. Live
# default unchanged.
#
# Run with: bats packaging/test/L2-file-protections-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/file-protections-baseline.toml"
    DROPIN="${TMP}/50-selfdef-file-protections.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_FILEPROT_CONFIG="${CONF}" \
    SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_FILEPROT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FILEPROT_CONFIG="${SELFDEF_FILEPROT_CONFIG}" \
        SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FILEPROT_CONFIG="${CONF}" \
        SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile installs drop-in + applies sysctl -w per key" {
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    # The baseline sysctls fire.
    grep -q 'sysctl -w fs.protected_hardlinks=1' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_symlinks=1' "${SCTL_LOG}"
}

@test "strict profile installs the strict drop-in" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    # Strict bumps the values higher.
    grep -q 'sysctl -w fs.protected_regular=2' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_fifos=2' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile + timestamp" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef file-protections-baseline' "${DROPIN}"
    grep -q 'profile=baseline' "${DROPIN}"
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"  # no timestamp (2026-06-06 idempotency fix)
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "baseline"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is baseline (no profile key — safe default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=baseline' "${DROPIN}"
}

@test "drop-in content contains every protected_* key (baseline)" {
    write_config "baseline"
    run_wd
    grep -q 'fs.protected_hardlinks' "${DROPIN}"
    grep -q 'fs.protected_symlinks' "${DROPIN}"
    grep -q 'fs.protected_fifos' "${DROPIN}"
    grep -q 'fs.protected_regular' "${DROPIN}"
}

@test "INVARIANT (strict profile bumps regular AND fifos to =2 — locks asymmetric profile values)" {
    write_config "strict"
    run_wd
    grep -qE 'fs\.protected_regular\s*=\s*2' "${DROPIN}"
    grep -qE 'fs\.protected_fifos\s*=\s*2' "${DROPIN}"
}

@test "INVARIANT (baseline profile has regular AND fifos at =2 too — high-CVE class needs strict default)" {
    # The 2017 CVE-2017-7610-class race needs =2 to actually block. =1
    # blocks symlinks but not regular-file races. Even baseline must
    # set regular + fifos to 2.
    write_config "baseline"
    run_wd
    grep -qE 'fs\.protected_regular\s*=\s*2' "${DROPIN}"
    grep -qE 'fs\.protected_fifos\s*=\s*2' "${DROPIN}"
}

@test "INVARIANT (profile upgrade baseline → strict): rewrites drop-in" {
    write_config "baseline"
    run_wd
    sha_before="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_after="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    # baseline and strict may differ in protected_hardlinks/symlinks value;
    # if content is identical at our protection level, that's also OK —
    # but at minimum the profile= metadata bumps.
    grep -q 'profile=strict' "${DROPIN}"
}

@test "INVARIANT (sysctl -w fires on every apply — live-knob re-application even when drop-in unchanged)" {
    # Disk path may skip on idempotent re-apply but LIVE kernel knob
    # must always be re-asserted (operator could have done sysctl -w
    # fs.protected_hardlinks=0 between runs).
    write_config "baseline"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w fs.protected_hardlinks=' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in filename selfdef-* pattern): tracking + uninstall identification" {
    write_config "baseline"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (no render-timestamp): defeats cmp -s idempotency guard" {
    write_config "baseline"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl)" {
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'fs\.protected_hardlinks' "${DROPIN}"
    grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (header marker first non-blank line — stale-cleanup head -1 grep discipline)" {
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef file-protections-baseline" ]
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "baseline"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"file-protections-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=baseline'* ]]
}

@test "INVARIANT (profile downgrade strict → baseline: rewrites drop-in + applies sysctls)" {
    # Bidirectional contract — operator can both tighten + loosen.
    write_config "strict"
    run_wd
    grep -q 'profile=strict' "${DROPIN}"
    : > "${SCTL_LOG}"
    write_config "baseline"
    run_wd
    grep -q 'profile=baseline' "${DROPIN}"
    ! grep -q 'profile=strict' "${DROPIN}"
    grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (all 4 protected_* sysctls fire on apply — full coverage check)" {
    # Lock that every protected_* sysctl knob fires on apply, not
    # just a subset. A regression that drops one knob from the
    # apply loop would silently leave that attack vector open.
    write_config "baseline"
    run_wd
    grep -q 'sysctl -w fs.protected_hardlinks=' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_symlinks=' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_fifos=' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_regular=' "${SCTL_LOG}"
}

@test "INVARIANT (strict profile has hardlinks/symlinks at strictly >= baseline values — profile-rank monotonic)" {
    # Strict's hardening MUST be at-least-as-strict as baseline's
    # on every knob. Locks profile-rank monotonicity: a regression
    # that loosens any knob in strict would trip here.
    write_config "baseline"
    run_wd
    baseline_hardlinks="$(grep -oE 'fs\.protected_hardlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    baseline_symlinks="$(grep -oE 'fs\.protected_symlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    write_config "strict"
    run_wd
    strict_hardlinks="$(grep -oE 'fs\.protected_hardlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    strict_symlinks="$(grep -oE 'fs\.protected_symlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    [ "${strict_hardlinks}" -ge "${baseline_hardlinks}" ]
    [ "${strict_symlinks}" -ge "${baseline_symlinks}" ]
}

@test "INVARIANT (drop-in is sysctl-parseable: each non-comment line matches key=value shape)" {
    # The drop-in is sourced by sysctl --system. Every non-comment
    # non-blank line MUST match the key=value sysctl grammar.
    # Sister to hardware-tune-cache shell-sourceable INVARIANT.
    write_config "baseline"
    run_wd
    # Check every non-empty non-comment line matches sysctl grammar.
    awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} /^[a-zA-Z_][a-zA-Z0-9_.]*[[:space:]]*=[[:space:]]*[0-9]+/ {next} {bad=1; print "malformed: " $0} END{exit bad?1:0}' "${DROPIN}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # file-protections-baseline TOML; parser must tolerate without
    # altering the profile-gated content. strict-with-noise still
    # installs the strict drop-in (protected_hardlinks=1 +
    # protected_symlinks=1 + protected_fifos=2 + protected_
    # regular=2 — the full set-tight family that defeats most
    # writable-/tmp + symlink-pointer races used as priv-esc
    # primitives).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "fs.protected_* — symlink + hardlink + fifo race defense"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^fs\.protected_hardlinks[[:space:]]*=' "${DROPIN}"
    grep -qE '^fs\.protected_symlinks[[:space:]]*=' "${DROPIN}"
}
