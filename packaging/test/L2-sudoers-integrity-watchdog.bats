#!/usr/bin/env bats
# L2 functional + capture-regression suite for sudoers-integrity-watchdog.
#
# sudoers-integrity-watchdog inventories the GRANT lines of /etc/sudoers and
# /etc/sudoers.d/* (dropping comments, blanks, and Defaults — sudo-tune owns
# tunables) into a baseline, then alerts on a new/dangerous grant. It reads
# those paths directly (no input-source knob), so what this suite locks is the
# inventory-CAPTURE regression: the scan must actually write its records into
# the baseline it diffs — the 2026-05-27 bug where `emit_rules`'s `printf`
# went to stdout instead of `$current`, leaving the baseline empty and every
# diff a no-op.
#
# Run with: bats packaging/test/L2-sudoers-integrity-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudoers-integrity-watchdog/systemd/sudoers-integrity-watchdog.sh"

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
    BASELINE="${TMP}/sudoers-integrity-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SUDOERS_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDOERS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# /etc/sudoers ships a `root ALL=(ALL:ALL) ALL` + `%sudo`/`%admin` grant on
# every sudo-enabled host, so the inventory is reliably non-empty there. Gate
# the data-dependent asserts on a readable sudoers with at least one grant.
have_sudo_grants() {
    [ -r /etc/sudoers ] && grep -qE '^[^#].*=' /etc/sudoers 2>/dev/null
}

@test "first run captures the sudoers grants into the baseline (non-empty)" {
    have_sudo_grants || skip "no readable sudoers grants on this host"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # records are <file>\t<rule> — at least one well-formed TSV row.
    awk -F'\t' 'NF>=2{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "the baseline is reported with a non-zero count (records reached \$current)" {
    have_sudo_grants || skip "no readable sudoers grants on this host"
    run_wd
    cap | grep -qE '"baseline_count":[1-9][0-9]*'
}

@test "unchanged sudoers on second run -> ok / no_delta" {
    have_sudo_grants || skip "no readable sudoers grants on this host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
