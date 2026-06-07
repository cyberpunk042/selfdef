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
        if grep -qE 'selfdef_injection_patterns|selfdef_is_writable_path|selfdef_is_writable_dir' "$f"; then
            grep -q 'SELFDEF_MODULE_LIB' "$f" || bad+=("$(basename "$f")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'uses a shared helper but does not source module-lib: %s\n' "${bad[*]}" >&2
        return 1
    fi
}

@test "no watchdog scan script carries an inline case-statement writable-root policy (SDD-063)" {
    # After the SDD-063 consolidation the attacker-writable-root enumeration
    # (/tmp/* | /var/tmp/* | /dev/shm/* | ...) lives only in module-lib's
    # selfdef_is_writable_dir / _path. A scan script that re-inlines it has
    # forked the policy. coredump-pattern-watchdog is the one DELIBERATE
    # exception: its policy is intentionally narrower (the world-writable
    # tmpfs roots only, excluding /home) so it keeps its own check.
    bad=()
    for f in $(scan_scripts); do
        case "$(basename "$f")" in
            coredump-pattern-watchdog.sh) continue ;;
        esac
        # non-comment line enumerating writable tmpfs roots as globs
        if grep -nE '/(tmp|var/tmp|dev/shm)/\*' "$f" \
            | grep -qvE '^[0-9]+:[[:space:]]*#'; then
            bad+=("$(basename "$f")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'inline case-statement writable policy in: %s\n' "${bad[*]}" >&2
        printf 'use: selfdef_is_writable_dir "$x"  (or _path for file paths)\n' >&2
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

@test "every consolidated watchdog has a same-named L2 functional-severity suite" {
    # A watchdog that consumes the shared module-lib helpers emits the
    # injection / writable-location alert tier that the SDD-062 Sigma rule
    # routes to the pager. Each one MUST own an L2 suite locking its
    # ok/warn/alert tiers + the module_lib_missing fail-loud, so a severity
    # regression cannot land silently. This closes the gap that 65/65
    # consolidated watchdogs were backfilled to satisfy (2026-05-27).
    bad=()
    for f in $(scan_scripts); do
        grep -q 'SELFDEF_MODULE_LIB' "$f" || continue
        mod="$(basename "$(dirname "$(dirname "$f")")")"   # modules/<mod>/systemd/<x>.sh
        suite="${BATS_TEST_DIRNAME}/L2-${mod}.bats"
        [ -f "${suite}" ] || bad+=("${mod}")
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'consolidated watchdog with no L2-<mod>.bats suite: %s\n' "${bad[*]}" >&2
        printf 'add packaging/test/L2-<mod>.bats covering ok/warn/alert + module_lib_missing.\n' >&2
        return 1
    fi
}

@test "every *-watchdog module has an L2-<mod>.bats functional suite (full-fleet coverage lock)" {
    # The SDD-063-consolidated check above only covers watchdogs that
    # source module-lib (the post-2026-05-27 fleet). 13 pre-SDD-063
    # watchdogs (audit-config, coredump-pattern, crontab-allow,
    # dns-resolver, hidden-process, kernel-cmdline, kernel-module,
    # listening-ports, logfile-integrity, mount-options, nfs-mount,
    # pci-device, ssh-hostkey, time-skew) carry their own bespoke
    # classification logic that ALSO emits severity findings — but
    # was not gated by the SDD-063 filter. The 2026-06-06 backfill
    # closed the coverage gap (every watchdog now has L2 functional
    # coverage; verified empirically at commit acfea98).
    #
    # This invariant LOCKS the backfill: any new *-watchdog module
    # shipped without a same-named L2-<mod>.bats suite will land
    # red here. Structural — emitter idiom is irrelevant. The
    # 105-watchdog fleet is the floor.
    bad=()
    for wd_dir in "${BATS_TEST_DIRNAME}/../../modules"/*-watchdog; do
        [ -d "${wd_dir}" ] || continue
        mod="$(basename "${wd_dir}")"
        suite="${BATS_TEST_DIRNAME}/L2-${mod}.bats"
        [ -f "${suite}" ] || bad+=("${mod}")
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'watchdog module without an L2 functional suite: %s\n' "${bad[*]}" >&2
        printf 'FIX: add packaging/test/L2-<mod>.bats covering ok/warn/alert\n' >&2
        printf '     tiers + JSON schema + enforce-exit. See L2-dns-resolver-\n' >&2
        printf '     watchdog.bats (canonical comm-delta) or L2-hidden-process-\n' >&2
        printf '     watchdog.bats (set-difference variant) as templates.\n' >&2
        return 1
    fi
}

@test "every scan script has at most one MAIN logger tag (SDD-062 single-record contract for downstream Sigma routing)" {
    # Each scan run emits ONE main JSON record (the SDD-062 downstream
    # consumer routes by tag). A script may also emit a -detail companion
    # for verbose follow-up; that's OK. What's NOT OK is >1 distinct
    # MAIN tag (a tag without -detail or -sample suffix) — Sigma consumer
    # would not route deterministically.
    bad=()
    for f in $(scan_scripts); do
        # Distinct MAIN tag names (excluding -detail / -sample variants).
        main_tags="$(grep -oE 'logger -t selfdef-[a-z0-9-]+' "$f" \
            | sort -u \
            | grep -vE -- '-(detail|sample|verbose)$' \
            | wc -l)"
        if [ "${main_tags}" -gt 1 ]; then
            bad+=("$(basename "$f"):${main_tags}-distinct-main-tags")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'scan script uses >1 distinct MAIN logger tag: %s\n' "${bad[*]}" >&2
        printf 'FIX: each scan script emits ONE main tag selfdef-<module>.\n' >&2
        printf '     -detail / -sample / -verbose suffix variants are OK.\n' >&2
        return 1
    fi
}

@test "every scan script that has profile semantics carries report+enforce profile dispatcher" {
    # The standard fail-loud / enforce-exit-non-zero contract requires
    # the script to branch on profile. Without this, the L2 enforce-
    # profile tests (and operator-set SELFDEF_*_PROFILE=enforce) would
    # silently no-op.
    bad=()
    for f in $(scan_scripts); do
        grep -q 'SELFDEF_MODULE_LIB' "$f" || continue
        grep -qE 'PROFILE' "$f" || continue
        # if it talks about PROFILE at all, it must distinguish enforce.
        grep -qE 'enforce' "$f" || bad+=("$(basename "$f"):missing-enforce-branch")
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'scan script references PROFILE but no enforce branch: %s\n' "${bad[*]}" >&2
        return 1
    fi
}

@test "module-lib-sourcing watchdogs gate the lib version, and dir-helper users require v4" {
    # SDD-061 D-6 / SDD-063: a watchdog that sources module-lib must refuse to
    # run against a too-old lib (the version gate `SELFDEF_MODULE_LIB_VERSION
    # -lt N → module_lib_outdated + exit`). A watchdog that calls the v4
    # `selfdef_is_writable_dir` helper but gates < 4 could source a v3 lib that
    # lacks that function → an unbound-function runtime error / silent policy
    # divergence. Lock both: (a) every sourcing watchdog has a version gate;
    # (b) dir-helper users gate >= 4.
    ungated=() ; dir_lowgate=()
    for f in $(scan_scripts); do
        grep -q 'SELFDEF_MODULE_LIB' "$f" || continue
        grep -qE 'SELFDEF_MODULE_LIB_VERSION.*-lt' "$f" || { ungated+=("$(basename "$f")"); continue; }
        if grep -q 'selfdef_is_writable_dir' "$f"; then
            req="$(grep -oE 'SELFDEF_MODULE_LIB_VERSION:-0\}" -lt [0-9]+' "$f" | grep -oE '[0-9]+$' | head -1)"
            [ "${req:-0}" -ge 4 ] || dir_lowgate+=("$(basename "$f"):gates-${req:-none}")
        fi
    done
    if [ "${#ungated[@]}" -gt 0 ] || [ "${#dir_lowgate[@]}" -gt 0 ]; then
        [ "${#ungated[@]}" -gt 0 ]    && printf 'sources module-lib but has no version gate: %s\n' "${ungated[*]}" >&2
        [ "${#dir_lowgate[@]}" -gt 0 ] && printf 'uses selfdef_is_writable_dir (v4) but gates < 4: %s\n' "${dir_lowgate[*]}" >&2
        printf 'FIX: gate `[[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt <N> ]] && module_lib_outdated; exit` (N=4 for dir-helper users).\n' >&2
        return 1
    fi
}

@test "INVARIANT (shellcheck shebang invariant — every watchdog scan script declares #!/usr/bin/env bash header)" {
    # Sister to the inventory-capture + routing-blind + baseline-leak +
    # module-lib-fail-loud + version-gate structural invariants already
    # locked. Locks: every watchdog scan script MUST declare a portable
    # `#!/usr/bin/env bash` shebang (not /bin/bash hardcoded path, not
    # /bin/sh which lacks bashisms the watchdogs rely on like
    # [[ ... ]], arrays, mapfile, and not missing entirely which would
    # require systemd's ExecStart to spell out the interpreter and
    # breaks manual `bash <script>` invocation discovery). A scan
    # script that drops the shebang silently breaks the systemd-unit
    # ExecStart=/path/script.sh contract — the unit fails to start
    # and the watchdog never runs, a silent surveillance gap. Locks
    # the structural shebang discipline across the fleet.
    bad=()
    for f in $(scan_scripts); do
        first_line="$(head -1 "$f")"
        if [[ "${first_line}" != "#!/usr/bin/env bash" ]]; then
            bad+=("$(basename "$f"):$(printf '%s' "${first_line}" | head -c 32)")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'watchdog scan script with non-canonical shebang: %s\n' "${bad[*]}" >&2
        printf 'FIX: first line MUST be exactly `#!/usr/bin/env bash`\n' >&2
        printf '     — portable across distros + supports the bashisms\n' >&2
        printf '     watchdogs rely on ([[ ]], arrays, mapfile, $current).\n' >&2
        return 1
    fi
}
