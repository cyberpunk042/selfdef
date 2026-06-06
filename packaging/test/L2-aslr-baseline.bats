#!/usr/bin/env bats
# L2 functional suite for aslr-baseline.
#
# aslr-baseline writes /etc/sysctl.d/50-selfdef-aslr.conf with
# kernel.randomize_va_space=2 (full ASLR — stack, mmap, brk, vdso
# all randomized) AND applies it live via `sysctl -w`. Full ASLR
# is foundational defense against memory-corruption exploits that
# rely on predictable addresses (ROP gadgets, libc base, heap
# layouts).
#
# Default Linux kernels usually ship with randomize_va_space=2
# already (the secure default), but operators / distros can flip
# it via boot args, init scripts, or kdump-induced kernel
# regressions. This baseline pins it.
#
# Only one profile: full. Refuses to apply with any other value
# (defensive — don't let a typo silently downgrade ASLR).
#
# Uses SELFDEF_ASLR_DROPIN env-var (added 2026-06-06) to point at
# a fixture path instead of the live /etc/sysctl.d.
#
# Run with: bats packaging/test/L2-aslr-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '2\n' ;;             # report current value
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/aslr-baseline.toml"
    DROPIN="${TMP}/50-selfdef-aslr.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ASLR_CONFIG="${CONF}" \
    SELFDEF_ASLR_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ASLR_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${SELFDEF_ASLR_CONFIG}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "INVARIANT: any non-full profile → die (refuse to silently downgrade ASLR)" {
    write_config "partial"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${CONF}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be full"* ]]
    # No drop-in written, no sysctl fired.
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "full profile writes drop-in + applies live via sysctl -w" {
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    # Drop-in carries the header marker + the randomize_va_space line.
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -q 'kernel.randomize_va_space' "${DROPIN}"
    # sysctl -w fired live.
    grep -q 'sysctl -w kernel.randomize_va_space=2' "${SCTL_LOG}"
}

@test "drop-in content includes header marker + profile (no render-timestamp, 2026-06-06 idempotency fix)" {
    write_config "full"
    run_wd
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -q 'profile=full' "${DROPIN}"
    # CRITICAL: NO render-timestamp — including it would defeat the
    # cmp -s idempotency check (per dns-shield/proc-hidepid fix
    # lineage, 2026-06-06).
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 fix)" {
    write_config "full"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "full"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644 (world-readable system-config convention for /etc/sysctl.d)" {
    write_config "full"
    run_wd
    perms="$(stat -c '%a' "${DROPIN}")"
    [ "${perms}" = "644" ]
}

@test "default profile is full (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'kernel.randomize_va_space' "${DROPIN}"
}

@test "second run is idempotent — drop-in still present, sysctl -w fires again (sysctl is itself idempotent)" {
    write_config "full"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    # sysctl -w fires every run — that's by design (the wrapper applies
    # the value live regardless of file change). The drop-in is what
    # carries persistence across reboot.
    grep -q 'sysctl -w kernel.randomize_va_space=2' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in target value is 2): the drop-in pins randomize_va_space=2, not 0 or 1" {
    # Locks the specific value 2 (full ASLR) — a regression that
    # mistakenly wrote =1 (partial ASLR) or =0 (no ASLR) would
    # defeat the module's purpose.
    write_config "full"
    run_wd
    grep -qE 'kernel\.randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
}

@test "INVARIANT (live sysctl -w applies value 2): the live invocation also pins 2" {
    write_config "full"
    run_wd
    grep -qE 'sysctl -w kernel\.randomize_va_space=2' "${SCTL_LOG}"
    # Locks that no other value reaches sysctl -w.
    ! grep -qE 'sysctl -w kernel\.randomize_va_space=[01]' "${SCTL_LOG}"
}

@test "INVARIANT (config rejection): a config with profile = \"\" (empty) → die" {
    write_config ""
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${CONF}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    # Empty profile may either default to full (rolled up to default)
    # or die — either way, no silent downgrade.
    if [ "$status" -eq 0 ]; then
        # Default to full is acceptable.
        grep -q 'kernel.randomize_va_space' "${DROPIN}"
        grep -qE 'randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
    else
        # Die is acceptable.
        [[ "${output}" == *"profile must be full"* ]]
    fi
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "full"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"aslr-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=full'* ]]
}

@test "INVARIANT (re-apply with DRY_RUN switches): apply real, then DRY_RUN — drop-in persists but second invocation fires nothing" {
    # Composition: real apply leaves drop-in + first sysctl call;
    # a follow-on DRY_RUN must not modify or fire anything new.
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    : > "${SCTL_LOG}"
    sleep 1
    DRY_RUN=1 run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — predictable for stale-cleanup head -1 grep)" {
    # The downgrade-path stale-cleanup uses head -1 + grep -F.
    # The header MUST be the first line — not buried — or stale
    # detection misses + leaves selfdef-owned files orphaned.
    write_config "full"
    run_wd
    first_line="$(head -1 "${DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef aslr-baseline" ]
}

@test "INVARIANT (re-arm after operator deletion: re-creates drop-in with header marker)" {
    # Operator deletes the drop-in out-of-band. Next apply re-
    # creates it cleanly with header-marker intact.
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -qE 'kernel\.randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
}

@test "INVARIANT (live= field in emit_status JSON — operator dashboard sees current kernel value)" {
    # The emit_status message body carries live=N where N is the
    # current sysctl -n value. Critical for operator dashboard
    # to detect drift between persistence (drop-in) and runtime
    # (live kernel state).
    write_config "full"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'live='* ]]
}

@test "INVARIANT (drop-in carries 'profile=full' marker — uninstall hook can identify which profile was active)" {
    # The 'profile=full' second-line marker is the audit-trail
    # for which profile was applied. Even though aslr-baseline
    # has only one profile, future expansion (e.g., paranoid
    # profile) requires the marker for diff routing.
    write_config "full"
    run_wd
    grep -qE '^# profile=full$' "${DROPIN}"
}

@test "INVARIANT (sysctl is invoked via -w flag for live application — NOT -p path)" {
    # Two acceptable mechanisms: sysctl -w key=val (write live)
    # vs sysctl -p /etc/sysctl.d/file (load entire file). Current
    # contract uses -w for surgical single-key application —
    # locks the choice so future refactor doesn't accidentally
    # switch to -p (which would also reload other unrelated
    # sysctl drop-ins; side-effect on other modules).
    write_config "full"
    run_wd
    grep -qE 'sysctl -w' "${SCTL_LOG}"
    ! grep -qE 'sysctl -p' "${SCTL_LOG}"
}
