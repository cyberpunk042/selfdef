#!/usr/bin/env bats
# L2 functional + capture-regression suite for group-integrity-watchdog.
#
# group-integrity-watchdog inventories group membership two ways — the
# comma-member lists in /etc/group, and each user's PRIMARY group from
# /etc/passwd — into a baseline, then alerts on a new privileged-group member
# / membership change. It reads /etc/group + /etc/passwd directly (no
# input-source knob), so what this suite locks is the inventory-CAPTURE
# regression: the scan must actually write its records into the baseline it
# diffs — the 2026-05-27 bug where BOTH membership `printf`s went to stdout
# instead of `$current`, leaving the baseline empty and every diff a no-op.
#
# Run with: bats packaging/test/L2-group-integrity-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/group-integrity-watchdog/systemd/group-integrity-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/group-integrity-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_GROUPINT_PROFILE="${PROFILE:-report}" \
    SELFDEF_GROUPINT_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# /etc/passwd + /etc/group are world-readable and always populated; the
# primary-gid pass alone emits a record per user, so the inventory is
# reliably non-empty. Guard only against the (pathological) unreadable case.
have_account_db() { [ -r /etc/group ] && [ -r /etc/passwd ]; }

@test "first run captures the group-membership inventory into the baseline (non-empty)" {
    have_account_db || skip "/etc/group or /etc/passwd unreadable on this host"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # records are <group>\t<member> — at least one well-formed TSV row.
    awk -F'\t' 'NF>=2{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "unchanged group membership on second run -> ok / no_delta" {
    have_account_db || skip "/etc/group or /etc/passwd unreadable on this host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
