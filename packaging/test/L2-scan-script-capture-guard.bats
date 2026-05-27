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
# Plus a confidentiality invariant:
#
# 3. BASELINE LEAK: a watchdog's learned baseline records sensitive inventory
#    (the setuid-binary set, the account/sudo roster, PAM module hashes, …).
#    A baseline written world-readable leaks that inventory to any local user.
#    Every watchdog that creates a baseline/manifest MUST `chmod 0600` it.
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

@test "every comm-delta scan script populates its diff temp file with the inventory" {
    # Invariant (robust to BOTH established capture idioms):
    #   a watchdog that builds TSV records (`printf '...\t...\n'`) and diffs
    #   them with `comm` MUST land those records in the `$current` temp file
    #   via at least one populate-redirect — either
    #     (a) inline   `printf '...\t...\n' ... >> "$current"`              or
    #     (b) a block   `done > "$current"` / `done | sort -u > "$current"`
    #         / `} > "$current"`.
    #   Both forms contain the literal token `> "$current"` (>> for the
    #   inline form). If NEITHER appears, the records go to stdout, `$current`
    #   stays empty, every `comm` diff is a no-op, and the watchdog silently
    #   detects NOTHING.
    #
    # The earlier version of this guard keyed on `printf '<literal-kind>\t`
    # and so MISSED the five watchdogs that build records with a variable
    # first field (`printf '%s\t...`): cron-job, ssh-authkeys, sudoers,
    # systemd-unit, group-integrity — all five had the silent-no-op bug
    # (fixed 2026-05-27). This presence-of-populate-redirect form catches the
    # whole class regardless of the record-printf's first field, and does NOT
    # false-positive on the legitimate `done > "$current"` block idiom (it
    # contains the same `> "$current"` token).
    #
    # `${current}.sorted` (the read-modify-write dedup target) and the
    # `-o "$current"` in-place re-sort do NOT count as populate-redirects:
    # the former writes a *different* path, the latter has no `>`/`>>`.
    bad=()
    for f in $(scan_scripts); do
        grep -qE 'comm -23|comm -13' "$f" || continue
        # Builds TSV records? (format has a literal \t and ends \n; the
        # JSON-emit printf has no \t, the inline `printf '%s\t'` search-key
        # has no trailing \n, so neither matches.)
        grep -qE "printf '[^']*\\\\t[^']*\\\\n'" "$f" || continue
        # Must populate $current at least once.
        grep -qE '>>? *"\$current"' "$f" || bad+=("$(basename "$f")")
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'comm-delta watchdog builds records but never populates $current: %s\n' "${bad[*]}" >&2
        printf 'FIX: populate the temp file — append `>> "$current"` to each record\n' >&2
        printf '     `printf "...\\t...\\n"`, or redirect the collection block with\n' >&2
        printf '     `done > "$current"`. Without it the records go to stdout, $current\n' >&2
        printf '     is empty, and the watchdog silently detects nothing (the 2026-05-27\n' >&2
        printf '     self-integrity / account / pam-config / cron-job / ssh-authkeys /\n' >&2
        printf '     sudoers / systemd-unit / group-integrity bug class).\n' >&2
        return 1
    fi
}

@test "every watchdog that creates a baseline/manifest chmod 0600s it (no inventory leak)" {
    bad=()
    for f in $(scan_scripts); do
        # Creates a baseline by snapshotting the current inventory into it.
        grep -qE 'cp "\$current" "\$\{?(BASELINE|MANIFEST)' "$f" || continue
        # Must lock it to 0600 (owner-only) — the inventory is sensitive.
        grep -qE 'chmod 0?600 "\$\{?(BASELINE|MANIFEST)' "$f" || bad+=("$(basename "$f")")
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'creates a baseline without chmod 0600 (inventory leak): %s\n' "${bad[*]}" >&2
        printf 'FIX: `chmod 0600 "$BASELINE"` right after `cp "$current" "$BASELINE"`.\n' >&2
        return 1
    fi
}
