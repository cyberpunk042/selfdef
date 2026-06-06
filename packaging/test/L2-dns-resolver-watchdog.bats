#!/usr/bin/env bats
# L2 functional + capture-regression suite for dns-resolver-watchdog.
#
# dns-resolver-watchdog inventories the active DNS resolver configuration
# (nameservers + search domains from /etc/resolv.conf, systemd-resolved
# upstreams from resolvectl, and /etc/hosts override count) into a baseline,
# then alerts on a delta. The 2026-06-06 silent-no-op bug: the three emitter
# blocks (awk on resolv.conf, the resolvectl pipeline, the /etc/hosts
# printf) all went to stdout, and `{ sort -u > "${current}.sorted"; } <
# "$current"` then read an empty `$current` — leaving cur_count=0 and every
# diff a no-op. Same class as the 2026-05-27 cron-job-watchdog fix.
#
# Fix wrapped the three emit blocks in `{ ... } | sort -u > "$current"`. The
# /etc/hosts emitter is unconditional (every host has /etc/hosts), so the
# capture is deterministic without skip gating.
#
# Run with: bats packaging/test/L2-dns-resolver-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dns-resolver-watchdog/systemd/dns-resolver-watchdog.sh"

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
    BASELINE="${TMP}/dns-resolver-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DNSRES_PROFILE="${PROFILE:-report}" \
    SELFDEF_DNSRES_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures the resolver inventory into the baseline (non-empty)" {
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
    [ -s "${BASELINE}" ]                                  # capture regression lock
    # records are <class>\t<value> — at least one well-formed TSV row.
    awk -F'\t' 'NF>=2{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "the baseline is reported with a non-zero count (records reached \$current)" {
    run_wd
    # baseline_count:0 was the exact symptom of the stdout-leak bug.
    cap | grep -qE '"baseline_count":[1-9][0-9]*'
}

@test "the baseline includes the hosts_overrides record (the unconditional emit)" {
    run_wd
    grep -q '^hosts_overrides	' "${BASELINE}"
}

@test "unchanged resolver state on second run -> ok / no_delta" {
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}
