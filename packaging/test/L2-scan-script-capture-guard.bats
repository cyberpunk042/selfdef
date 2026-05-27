#!/usr/bin/env bats
# L2 guard against the inventory-capture bug class (2026-05-27).
#
# A baseline/delta scan script builds an inventory of TSV records
# (`printf '<kind>\t...'`) into a `mktemp` temp file, then diffs that temp
# file against the stored baseline with `comm`. If a record `printf` is
# missing its `>> "$<tmpfile>"` redirect, the record goes to STDOUT instead,
# the temp file stays empty, every diff is a no-op, and the watchdog silently
# detects NOTHING — while still emitting a healthy-looking baseline_initial /
# intact / no_delta event. This exact bug silently disabled three critical
# watchdogs (selfdef-self-integrity, account, pam-config) before it was
# caught. This guard fails if any comm-delta scan script has a record-building
# printf that does not redirect into the temp file it diffs.
#
# Run with: bats packaging/test/L2-scan-script-capture-guard.bats

SCRIPTS_GLOB="${BATS_TEST_DIRNAME}/../../modules/*/systemd/*.sh"

scan_scripts() { compgen -G "${SCRIPTS_GLOB}"; }

@test "scan scripts exist (sanity)" {
    n="$(scan_scripts | grep -c .)"
    [ "${n}" -ge 40 ]
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
