#!/usr/bin/env bats
# L2 guard locking the SDD-061 D-6 single-source-of-truth invariant across
# EVERY watchdog scan script. After D-6, no watchdog carries its own copy
# of the injection-pattern set or the writable-location policy — they all
# consume the shared module-lib helpers. This guard fails if a new (or
# reverted) watchdog re-introduces an inline copy, so the "one-line edit in
# module-lib propagates everywhere" property cannot silently rot.
#
# Run with: bats packaging/test/L2-watchdog-dedup-guard.bats

SCRIPTS_GLOB="${BATS_TEST_DIRNAME}/../../modules/*-watchdog/systemd/*.sh"

scan_scripts() { compgen -G "${SCRIPTS_GLOB}"; }

@test "watchdog scan scripts exist (sanity)" {
    n="$(scan_scripts | grep -c .)"
    [ "${n}" -ge 40 ]
}

@test "no watchdog scan script carries an inline PATTERNS=( array" {
    bad=()
    for f in $(scan_scripts); do
        if grep -q 'PATTERNS=(' "$f"; then bad+=("$(basename "$f")"); fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'inline PATTERNS=( in: %s\n' "${bad[*]}" >&2
        printf 'use: mapfile -t PATTERNS < <(selfdef_injection_patterns)\n' >&2
        return 1
    fi
}

@test "no watchdog scan script carries the raw writable-path regex" {
    # The trailing-slash writable-root regex is module-lib's
    # selfdef_is_writable_path; modules must call the helper, not inline it.
    # (musl-ld-path legitimately keeps a distinct exact-match `...home)$`
    # form, which this pattern does not match.)
    bad=()
    for f in $(scan_scripts); do
        if grep -qE '=~ \^/\(tmp\|var/tmp\|dev/shm\|home\)/' "$f"; then
            bad+=("$(basename "$f")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'raw writable regex in: %s\n' "${bad[*]}" >&2
        printf 'use: selfdef_is_writable_path "$x"\n' >&2
        return 1
    fi
}

@test "every scan script using a shared helper also sources module-lib (fail-loud)" {
    bad=()
    for f in $(scan_scripts); do
        if grep -qE 'selfdef_injection_patterns|selfdef_is_writable_path' "$f"; then
            grep -q 'SELFDEF_MODULE_LIB' "$f" || bad+=("$(basename "$f")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'uses a shared helper but does not source module-lib: %s\n' "${bad[*]}" >&2
        return 1
    fi
}

@test "scripts that source module-lib emit a module_lib_missing fail-loud finding" {
    bad=()
    for f in $(scan_scripts); do
        if grep -q 'SELFDEF_MODULE_LIB' "$f"; then
            grep -q 'module_lib_missing' "$f" || bad+=("$(basename "$f")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'sources module-lib but no module_lib_missing fail-loud path: %s\n' "${bad[*]}" >&2
        return 1
    fi
}
