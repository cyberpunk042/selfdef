#!/usr/bin/env bats
# L2 functional + capture-regression suite for systemd-unit-watchdog.
#
# systemd-unit-watchdog inventories every enabled service/socket unit file
# (hashing its FragmentPath so a changed ExecStart is caught; transient units
# are name-only) into a baseline, then alerts on a unit added/changed. It
# queries systemctl directly (no input-source knob), so what this suite locks
# is the inventory-CAPTURE regression: the scan must actually write its records
# into the baseline it diffs — the 2026-05-27 bug where the record `printf`s
# went to stdout instead of `$current`, leaving the baseline empty and every
# diff a no-op.
#
# Run with: bats packaging/test/L2-systemd-unit-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/systemd-unit-watchdog/systemd/systemd-unit-watchdog.sh"

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
    BASELINE="${TMP}/systemd-units-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SYSDUNIT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SYSDUNIT_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Needs a live systemd with at least one enabled service/socket. Containers
# without systemd (or hosts with none enabled) have nothing to inventory, so
# gate the data-dependent asserts on that.
have_enabled_units() {
    command -v systemctl >/dev/null 2>&1 || return 1
    [ -n "$(systemctl list-unit-files --type=service,socket --state=enabled --no-legend 2>/dev/null | awk 'NF{print; exit}')" ]
}

@test "first run captures the enabled-unit inventory into the baseline (non-empty)" {
    have_enabled_units || skip "no live systemd / no enabled units on this host"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # records are <unit>\tenabled\t<hash|transient> — at least one TSV row.
    awk -F'\t' 'NF>=3{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "the baseline is reported with a non-zero count (records reached \$current)" {
    have_enabled_units || skip "no live systemd / no enabled units on this host"
    run_wd
    cap | grep -qE '"baseline_count":[1-9][0-9]*'
}

@test "unchanged units on second run -> ok / no_delta" {
    have_enabled_units || skip "no live systemd / no enabled units on this host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
