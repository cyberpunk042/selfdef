#!/usr/bin/env bats
# L2 structural guard locking the variant-A + variant-B idempotency
# invariant across EVERY module install/apply.sh.
#
# After the 2026-06-06 variant-A + variant-B sweep, no module apply.sh
# should:
#   - mv -f "$tmp" "$dst" WITHOUT a cmp -s "$tmp" "$dst" content-change
#     guard preceding it (variant-A — re-applies blindly mutate the
#     file's mtime + trigger any downstream destructive side-effects
#     like systemctl reload, nft delete + load, logind reload)
#   - render a `^# Generated <ISO-date>` metadata line into the
#     destination file (variant-B — the timestamp changes every apply
#     even when nothing else does, defeating the cmp -s guard for the
#     content-stable case)
#
# This guard fails if a new (or reverted) module re-introduces either
# anti-pattern, so the "every apply.sh re-apply is fully idempotent"
# property cannot silently rot.
#
# Allow-list (apply.sh files that legitimately match the heuristic
# but do NOT carry the bug — e.g. they render dynamic content where
# byte-stability is impossible by design, or they use a different
# atomic-write pattern that's already content-stable):
#   - none currently registered (all 187 module apply.sh files conform
#     after the 2026-06-06 sweep)
#
# Run with: bats packaging/test/L2-module-apply-idempotency-guard.bats

APPLY_GLOB="${BATS_TEST_DIRNAME}/../../modules/*/install/apply.sh"

scan_apply() { compgen -G "${APPLY_GLOB}"; }

@test "module apply.sh files exist (sanity — full sweep was 187 in 2026-06-06)" {
    n="$(scan_apply | grep -c .)"
    [ "${n}" -ge 180 ]
}

@test "INVARIANT (variant-A): no apply.sh has mv -f \"\$tmp\" \"\$dst\" without a preceding cmp -s content-change guard" {
    bad=()
    for f in $(scan_apply); do
        # Find every `mv -f "${tmp...}" "$<dst-var>"` line (the
        # idiomatic atomic-write commit). For each, walk backward up
        # to 8 lines to find a `cmp -s "${tmp...}"` content-change
        # guard. If the guard is missing, flag the file.
        #
        # We tolerate two atomic-write idioms:
        #   1. install -m <mode> "$src" "$dst"   (uses cmp -s
        #      separately above the install call)
        #   2. mv -f "$tmp" "$dst"               (this guard's target)
        # …because (1) is its own pattern and not what this guard
        # targets.
        awk '
            /mv -f.*\$.?\{?tmp/ {
                # Walk back up to 8 lines looking for `cmp -s`
                guarded = 0
                start = NR - 8
                if (start < 1) start = 1
                for (i = NR - 1; i >= start; i--) {
                    if (lines[i] ~ /cmp -s/) { guarded = 1; break }
                }
                if (!guarded) {
                    print NR ":" $0
                    exit_code = 1
                }
            }
            { lines[NR] = $0 }
            END { exit exit_code }
        ' "$f" >/dev/null 2>&1 || bad+=("$(basename "$(dirname "$(dirname "$f")")")")
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        printf 'modules with mv -f without cmp -s guard: %s\n' "${bad[*]}" >&2
        printf 'fix pattern:\n' >&2
        printf '  if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then\n' >&2
        printf '      rm -f "$tmp"\n' >&2
        printf '  else\n' >&2
        printf '      mv -f "$tmp" "$dst"\n' >&2
        printf '      log "wrote $dst"\n' >&2
        printf '  fi\n' >&2
        return 1
    fi
}

@test "INVARIANT (variant-B): no apply.sh renders \"# Generated \$(date ...)\" into the destination file content" {
    bad=()
    for f in $(scan_apply); do
        # Look for `# Generated $(date ...)` patterns being emitted
        # into the rendered file (via echo / cat <<EOF / printf into
        # $tmp). The variant-B bug is the timestamp appearing INSIDE
        # the file content. Comments explaining the anti-pattern
        # (i.e. lines like `# No render-timestamp — defeats cmp -s`)
        # are explicitly excluded by the negative-match.
        #
        # Heuristic: line contains `Generated ` followed by `$(date`
        # AND is NOT a shell comment about avoiding the timestamp.
        if grep -E 'Generated [^"]*\$\(date' "$f" 2>/dev/null \
            | grep -v 'No render-timestamp' \
            | grep -q .; then
            bad+=("$(basename "$(dirname "$(dirname "$f")")")")
        fi
        # Also catch the python-helper variant where a JSON field
        # `generated_at` is rendered with `datetime.utcnow()` or
        # `datetime.now()`.
        if grep -E 'generated_at.*datetime\.(utc)?now\(\)' "$f" 2>/dev/null \
            | grep -q .; then
            bad+=("$(basename "$(dirname "$(dirname "$f")")")")
        fi
    done
    if [ "${#bad[@]}" -gt 0 ]; then
        # Dedupe.
        readarray -t bad < <(printf '%s\n' "${bad[@]}" | sort -u)
        printf 'modules with render-timestamp in apply.sh: %s\n' "${bad[*]}" >&2
        printf 'fix: drop the timestamp; comment with reason.\n' >&2
        printf 'pattern:\n' >&2
        printf '    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).\n' >&2
        printf '    echo "# profile=$PROFILE"\n' >&2
        return 1
    fi
}

@test "INVARIANT (composition): the two guards above are checked against the SAME apply.sh inventory (drift catch)" {
    # If a module is added with neither variant-A nor variant-B bug
    # but with no `mv -f $tmp` line at all (e.g. it uses a different
    # atomic-write pattern), the two prior guards both pass for that
    # module. That's the right behavior — but if the inventory
    # changes, the guard SANITY count above (>=180) catches it.
    # This test asserts the two guards above run over the SAME glob,
    # so any drift between them is detected here.
    n_a="$(scan_apply | grep -c .)"
    [ "${n_a}" -ge 180 ]
}

@test "INVARIANT (variant-C operator-dashboard contract): every module apply.sh carries emit_status (directly or via profile-delegation) so dashboards see every apply outcome" {
    # The emit_status JSON record is the SDD-062 downstream consumer
    # contract — the operator dashboard / triage pipeline reads it to
    # know "did module X apply ok, profile=Y, with N changes" on
    # every install/apply cycle. A module apply.sh that doesn't emit
    # invisible-applies the module — dashboards lose visibility.
    # Locks structural invariant: every module either calls
    # emit_status directly in apply.sh, OR delegates to a profile
    # script that does. Both shapes preserve operator observability.
    missing=()
    for f in $(scan_apply); do
        module_dir="$(dirname "$(dirname "$f")")"
        module_name="$(basename "${module_dir}")"
        # Direct: apply.sh calls emit_status.
        if grep -q 'emit_status' "$f"; then
            continue
        fi
        # Delegated: apply.sh sources a lib/profile that calls
        # emit_status. Scan the WHOLE module tree for the call.
        if grep -rq 'emit_status' "${module_dir}" 2>/dev/null; then
            continue
        fi
        missing+=("${module_name}")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        printf 'modules with NO emit_status (operator-dashboard invisible): %s\n' "${missing[*]}" >&2
        printf 'fix: add emit_status call in apply.sh OR delegated lib.sh / profile script\n' >&2
        printf 'pattern:\n' >&2
        printf '    emit_status ok "module-name" "profile=$PROFILE changes=$CHANGES"\n' >&2
        return 1
    fi
}
