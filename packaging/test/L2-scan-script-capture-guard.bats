#!/usr/bin/env bats
# L2 guards against watchdog silent-failure classes (2026-05-27).
#
# Two ways a watchdog can look healthy while detecting/routing nothing:
#
# 1. INVENTORY-CAPTURE bug: a baseline/delta scan builds TSV records
#    (`printf '<kind>\t...'`) into a `mktemp` temp file, then diffs it with
#    `comm`. If a record printf misses its `>> "$<tmpfile>"` redirect, the
#    record goes to stdout, the temp file stays empty, every diff is a no-op,
#    and the watchdog silently detects NOTHING. This exact bug disabled three
#    critical watchdogs (self-integrity, account, pam-config) before it was
#    caught.
#
# 2. ROUTING-BLIND tag: SDD-062 routes a finding to a Detection Finding only
#    if its journald SyslogIdentifier starts with `selfdef-`. A watchdog that
#    emits `"severity":"alert"` under a non-`selfdef-` `logger -t` tag would
#    never route — a silent detection gap.
#
# Run with: bats packaging/test/L2-scan-script-capture-guard.bats

SCRIPTS_GLOB="${BATS_TEST_DIRNAME}/../../modules/*/systemd/*.sh"

scan_scripts() { compgen -G "${SCRIPTS_GLOB}"; }

@test "scan scripts exist (sanity)" {
    n="$(scan_scripts | grep -c .)"
    [ "${n}" -ge 40 ]
}

@test "every scan script that emits a severity finding tags it selfdef-* (SDD-062 routing)" {
    bad=()
    for f in $(scan_scripts); do
        # Only scripts that emit a structured severity finding route via SDD-062.
        grep -qE '"severity":"' "$f" || continue
        # Primary (non -detail) logger tags this script writes under.
        tags="$(grep -oE 'logger -t [a-zA-Z0-9_-]+' "$f" | awk '{print $3}' | grep -v -- '-detail$' | sort -u)"
        for t in ${tags}; do
            case "$t" in
                selfdef-*) : ;;
                *) bad+=("$(basename "$f"):${t}") ;;
            esac
        done
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'finding-emitting scan script with a non-selfdef- logger tag: %s\n' "${bad[*]}" >&2
        printf 'FIX: tag findings `logger -t selfdef-<name>` — the SDD-062 rule keys on the\n' >&2
        printf '     selfdef- SyslogIdentifier prefix; a non-prefixed tag never routes.\n' >&2
        return 1
    fi
}

@test "every comm-delta scan script redirects its inventory records into the diff temp file" {
    bad=()
    for f in $(scan_scripts); do
        # Only the scripts that build an inventory + diff it with comm.
        grep -qE 'comm -23|comm -13' "$f" || continue
        # The temp file the inventory must land in (first `X="$(mktemp)"`).
        tvar="$(grep -oE '^[a-z_]+="\$\(mktemp\)"' "$f" | head -1 | sed -E 's/=.*//')"
        [ -z "${tvar}" ] && continue
        # Record-building printfs: `printf '<kind>\t...`. These are the TSV
        # inventory lines (the JSON-emit printf starts with `{`, and the
        # human-readable detail lines go through `logger -t ...-detail`, so
        # neither matches this shape). Each MUST redirect to the temp file
        # on the same line (the established repo idiom).
        offenders="$(grep -nE "printf '[a-z0-9_]+\\\\t" "$f" \
            | grep -vE ">>? \"\\\$\{?(${tvar}|current|tmp)" \
            | grep -vE 'logger|-detail' || true)"
        if [ -n "${offenders}" ]; then
            bad+=("$(basename "$f")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'inventory printf not redirected to the diff temp file in: %s\n' "${bad[*]}" >&2
        printf 'FIX: append `>> "$<tmpvar>"` to each `printf "<kind>\\t..."` that builds the\n' >&2
        printf '     inventory. Without it the records go to stdout, the temp file is empty,\n' >&2
        printf '     and the watchdog silently detects nothing (the 2026-05-27\n' >&2
        printf '     self-integrity / account / pam-config bug class).\n' >&2
        return 1
    fi
}
