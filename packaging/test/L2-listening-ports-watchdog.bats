#!/usr/bin/env bats
# L2 functional suite for listening-ports-watchdog.
#
# listening-ports-watchdog snapshots the listening TCP+UDP set
# (`ss -Hnlt` + `ss -Hnlu`) and emits per-class events for added
# / removed listeners on the next run. A NEW listening port is one
# of the highest-signal indicators of a backdoor or reverse-shell
# listener — the watchdog routes 1..2 new listeners to warn / new_
# listener and 3+ to alert / mass_new_listeners.
#
# This is a canonical comm-delta watchdog (`current=$(mktemp)` +
# `cp "$current" "$BASELINE"` + chmod 0600). The L2-scan-script-
# capture guard's strengthened structural invariant (commit
# efee460) auto-enforces the populate-redirect; this suite locks
# the runtime detection behavior the static gate can't reach:
# severity-tier routing, JSON schema, removed-only doesn't alert.
#
# Test fixtures shadow `ss` on PATH with a deterministic listen-set
# so the baseline + delta paths fire reproducibly.
#
# Run with: bats packaging/test/L2-listening-ports-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd/listening-ports-watchdog.sh"

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
    BASELINE="${TMP}/listening-ports-baseline.tsv"
}

teardown() { rm -rf "${TMP}"; }

# mk_ss <tcp-lines-multiline> <udp-lines-multiline>
# Each line is the awk-shape "$4" value (Local Address:Port).
mk_ss() {
    local tcp="$1" udp="$2"
    cat > "${BIN}/ss" <<SSEOF
#!/usr/bin/env bash
# Fake ss for L2-listening-ports-watchdog tests.
# Args we honor: -Hnlt / -Hnlu / -Hnltp / -Hnlup.
flags="\$*"
case "\${flags}" in
    *-Hnlt[!p]*|*-Hnlt) printf '%s\n' '${tcp}' ;;
    *-Hnlu[!p]*|*-Hnlu) printf '%s\n' '${udp}' ;;
    *-Hnltp*)           printf '%s\n' '${tcp}' | awk '{print "LISTEN 0 4096 " \$1 " 0.0.0.0:* users:((\"fake\",pid=1,fd=3))"}' ;;
    *-Hnlup*)           printf '%s\n' '${udp}' | awk '{print "UNCONN 0 0 " \$1 " 0.0.0.0:* users:((\"fake\",pid=1,fd=3))"}' ;;
    *) ;;
esac
SSEOF
    chmod +x "${BIN}/ss"
}

# real ss output has the local-address column at $4; the watchdog uses
# `awk '{print "tcp\t" $4}'`. To make $4 the addr:port, the fake stdout
# needs 4 columns. Use a minimal 4-col line.
mk_ss_lines() {
    # caller passes addr:port values, comma-separated. We emit one
    # 4-col line per address so awk's $4 picks the port.
    local list="$1"
    local out=""
    IFS=',' read -ra arr <<< "${list}"
    for a in "${arr[@]}"; do
        out="${out}LISTEN 0 4096 ${a}"$'\n'
    done
    printf '%s' "${out}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_LISTENPORTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_LISTENPORTS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run creates the baseline TSV + chmod 0600" {
    tcp="$(mk_ss_lines '0.0.0.0:22,127.0.0.1:631')"
    udp="$(mk_ss_lines '0.0.0.0:5353')"
    mk_ss "${tcp}" "${udp}"
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"baseline_count":3'                      # 2 tcp + 1 udp
    awk -F'\t' 'NF==2{ok=1} END{exit ok?0:1}' "${BASELINE}"  # well-formed TSV
}

@test "unchanged listen-set on second run → ok / no_delta" {
    tcp="$(mk_ss_lines '0.0.0.0:22,127.0.0.1:631')"
    udp="$(mk_ss_lines '0.0.0.0:5353')"
    mk_ss "${tcp}" "${udp}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"added":0'
    cap | grep -qE '"removed":0'
}

@test "1 new listener → warn / new_listener" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    udp=""
    mk_ss "${tcp}" "${udp}"
    run_wd                              # baseline = {tcp 22}
    # Add one new TCP listener — second run shows 1 added.
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444')"
    mk_ss "${tcp}" "${udp}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"new_listener"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":1'
}

@test "3+ new listeners → alert / mass_new_listeners (backdoor signature)" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd                              # baseline = {tcp 22}
    # Add 3 new listeners — second run should escalate severity to alert.
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444,0.0.0.0:5555,0.0.0.0:6666')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_new_listeners"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
}

@test "REMOVED listener (operator cleanup) does not alert" {
    tcp="$(mk_ss_lines '0.0.0.0:22,127.0.0.1:631')"
    mk_ss "${tcp}" ""
    run_wd                              # baseline = {22, 631}
    # Remove the 631 listener — operator cleanup; must not alert.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # No new listeners → severity stays ok regardless of removed count.
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"no_delta"'
    cap | grep -qE '"removed":1'
}

@test "the emitted JSON carries every promised schema field" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd                              # baseline
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # delta-shape JSON
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-listening-ports"'
    printf '%s' "${line}" | grep -qE '"baseline_count":[0-9]+'
    printf '%s' "${line}" | grep -qE '"current_count":[0-9]+'
    printf '%s' "${line}" | grep -qE '"added":[0-9]+'
    printf '%s' "${line}" | grep -qE '"removed":[0-9]+'
    printf '%s' "${line}" | grep -q '"added_sample":'
    printf '%s' "${line}" | grep -q '"removed_sample":'
}

@test "enforce profile + 1 new listener → exit 1" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd                              # baseline
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    PATH="${BIN}:${PATH}" \
        SELFDEF_LISTENPORTS_PROFILE=enforce \
        SELFDEF_LISTENPORTS_BASELINE="${BASELINE}" \
        bash "${WD}" && fail "enforce + 1 added listener should exit non-zero"
    cap | grep -q '"event":"new_listener"'
}
