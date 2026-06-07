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

@test "boundary: 2 new listeners → warn (1..2 INCLUSIVE on the high end)" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444,0.0.0.0:5555')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"new_listener"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":2'
}

@test "INVARIANT (UDP detection): new UDP listener is detected (not just TCP)" {
    # Locks that the script captures BOTH protocols. A regression
    # that drops the UDP scan would let an attacker run a reverse
    # DNS / SOCKS / UDP-tunnel listener undetected.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    udp="$(mk_ss_lines '0.0.0.0:5353')"
    mk_ss "${tcp}" "${udp}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"warn"'                   # 1 added → warn
    cap | grep -q '5353'                                # surfaces in sample
}

@test "added_sample surfaces specific port:addr pairs (operator triage)" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '4444'                                # the added port surfaces
}

@test "removed_sample surfaces specific port:addr pairs (operator-cleanup visibility)" {
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:9999')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '9999'                                # the removed port surfaces
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-listening-ports -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): listening-ports-watchdog does NOT refresh the baseline on delta — alert STAYS until operator updates" {
    # CONTRAST against the auto-trust family. New listeners are
    # NEVER routine; the alert must STAY visible until operator
    # review. Joins ssh-authkeys, pam-config, sudoers-integrity,
    # account, cron-job, systemd-unit, dns-resolver, file-
    # capabilities, suid-sgid in the no-auto-trust group.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"new_listener"'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (TCP+UDP combined adds: 2 TCP + 1 UDP added = 3 total → alert mass_new_listeners)" {
    # The mass-new-listeners trigger counts ACROSS both protocols.
    # Locks that an attacker can't stay under the mass-add threshold
    # by splitting adds across protocols (2 TCP + 1 UDP = 3, alert).
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444,0.0.0.0:5555')"
    udp="$(mk_ss_lines '0.0.0.0:6666')"
    mk_ss "${tcp}" "${udp}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_new_listeners"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
}

@test "INVARIANT (IPv6 listener detected — '[::]:port' format surfaces in delta)" {
    # ss without explicit family flag emits both v4 + v6 listeners.
    # IPv6 listeners use [::]:port shape — must surface in delta
    # so attackers can't hide a reverse listener on v6.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,[::]:8080')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -q '8080'
}

@test "INVARIANT (simultaneous add+remove same scan: BOTH axes surface in JSON; severity routes by ADD count alone)" {
    # Operator removes a deprecated listener while attacker adds a
    # backdoor in the same window. Both deltas must surface in JSON
    # (added + removed counts both > 0), and severity must route
    # by ADD count alone (removed listeners don't suppress alert).
    tcp="$(mk_ss_lines '0.0.0.0:22,127.0.0.1:631')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"added":1'
    cap | grep -qE '"removed":1'
    cap | grep -q '"severity":"warn"'                   # add wins ladder
}

@test "INVARIANT (baseline TSV format: <proto>\\t<addr:port> per line — protocol-tagged for diff replay)" {
    # The baseline must carry protocol per entry (tcp\t / udp\t)
    # so downstream selfdef-relisten + diff replay can disambiguate
    # a tcp:8080 listener from a udp:8080 listener — same port
    # number, different protocols.
    tcp="$(mk_ss_lines '0.0.0.0:22,127.0.0.1:631')"
    udp="$(mk_ss_lines '0.0.0.0:5353')"
    mk_ss "${tcp}" "${udp}"
    run_wd
    [ -s "${BASELINE}" ]
    grep -qP '^tcp\t' "${BASELINE}"
    grep -qP '^udp\t' "${BASELINE}"
    # All lines have exactly 1 TAB (2 fields).
    awk -F'\t' '{if(NF!=2) bad=1} END{exit bad?1:0}' "${BASELINE}"
}

@test "INVARIANT (same-port different-proto: 0.0.0.0:53/tcp and 0.0.0.0:53/udp are tracked as 2 distinct listeners)" {
    # DNS listeners (port 53) commonly run on BOTH tcp + udp.
    # Same port-number but different proto must be tracked as
    # 2 distinct baseline entries — losing the protocol distinction
    # would let an attacker swap tcp:80 for udp:80 silently.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    # Add DNS on both protos. Now total: tcp{22,53} udp{53} = 3 listeners
    # of which 2 are new (tcp:53 + udp:53) — should warn.
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:53')"
    udp="$(mk_ss_lines '0.0.0.0:53')"
    mk_ss "${tcp}" "${udp}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":2'                          # 2 distinct entries
}

@test "INVARIANT (sample cap at 8: more than 8 added listeners surface in sample[] truncated, count NOT truncated)" {
    # Operator dashboard JSON budget: sample = first 8 listeners.
    # The 'added' count must reflect the TRUE count.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    # Now add 12 new listeners — true count surfaces, sample truncated.
    new_list='0.0.0.0:22,0.0.0.0:1001,0.0.0.0:1002,0.0.0.0:1003,0.0.0.0:1004,0.0.0.0:1005,0.0.0.0:1006,0.0.0.0:1007,0.0.0.0:1008,0.0.0.0:1009,0.0.0.0:1010,0.0.0.0:1011,0.0.0.0:1012'
    tcp="$(mk_ss_lines "${new_list}")"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"added":1[0-9]'                       # 12+ adds
    cap | grep -q '"event":"mass_new_listeners"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (port:address compound: same port, different bind-address — 127.0.0.1:631 vs 0.0.0.0:631 are 2 distinct listeners)" {
    # Bind-address matters for the attacker model — 127.0.0.1:631
    # is loopback-only; 0.0.0.0:631 is wildcard (potentially-internet-
    # facing). A listener flipping from 127.0.0.1:631 to 0.0.0.0:631
    # MUST surface as a delta (remove old + add new), not as no-delta.
    tcp="$(mk_ss_lines '0.0.0.0:22,127.0.0.1:631')"
    mk_ss "${tcp}" ""
    run_wd
    # Flip 127.0.0.1:631 → 0.0.0.0:631 (exposure-surface change).
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:631')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"added":1'
    cap | grep -qE '"removed":1'
}

@test "INVARIANT (high-port-range 4444+ backdoor signature: classic reverse-shell port surfaces in alert)" {
    # The classic metasploit / reverse-shell default port is 4444.
    # Sister attacker ports: 1337, 31337, 6666, 9999. Lock that the
    # watchdog surfaces these specifically — the value of the
    # added_sample field is operator-triage gold.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:31337')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '31337'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (3-add boundary lock: exactly 3 adds → alert mass_new_listeners; 2 → warn new_listener)" {
    # The mass threshold is 3 (inclusive). Sister to the existing
    # 1+2 warn tests and 3+ alert test — this case specifically
    # locks the 3-vs-2 boundary so a regression that bumps to 4+
    # would trip here.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    # Exactly 3 added.
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444,0.0.0.0:5555,0.0.0.0:6666')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_new_listeners"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_LISTENPORTS_PROFILE — operator-dashboard distinguishes report from enforce)" {
    # Sister to many other watchdog profile-echo INVARIANTs across
    # the brain. Downstream operator dashboard / triage pipeline
    # must see the profile value the watchdog ran under (report vs
    # enforce) so it can distinguish advisory findings from gate-
    # failing findings. The latter would have aborted the unit on
    # alert; the former just logged. Closes the profile-surfacing
    # axis on the listening-ports surveillance surface.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (DELTA detect — ADDED listener on distinctive 4444 port surfaces in JSON sample for operator-triage routing)" {
    # Sister to the high-port-range 4444+ backdoor signature
    # INVARIANT and many other watchdog DELTA-detect sample-
    # naming INVARIANTs across the brain. When a listener appears
    # on a distinctive port (4444 = canonical metasploit/msfconsole
    # default), the port number MUST surface in the JSON sample
    # so operator dashboard routes triage to the right port
    # (T1571 — Non-Standard Port; T1095 — Non-Application Layer
    # Protocol; meterpreter default reverse-tcp port).
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444')"
    mk_ss "${tcp}" ""
    run_wd
    cap | grep -q '4444'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. The selfdef-listening-ports
    # logger tag must fire EXACTLY ONCE per scan regardless of
    # how many new listeners surface (mass-add scenario, multi-
    # proto combo, distinctive-port + benign-listener combo).
    # Multi-line output would break the SDD-062 downstream JSON-
    # line consumer (Sigma correlator). Locks the consolidation
    # discipline on the network-port surveillance surface (T1571
    # — Non-Standard Port). Operator dashboard sees one alert
    # with N listeners in sample, not N separate alerts.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    tcp="$(mk_ss_lines '0.0.0.0:22,0.0.0.0:4444,0.0.0.0:5555,0.0.0.0:6666')"
    mk_ss "${tcp}" ""
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-listening-ports -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (UDP listener add — protocol-agnostic detection coverage)" {
    # Sister to brain-wide TCP listener INVARIANTs. UDP listeners
    # have same operator-visibility need as TCP — covert C2
    # channels often use UDP (DNS tunnels, custom protocols).
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    udp="$(mk_ss_lines '0.0.0.0:53535')"
    mk_ss "${tcp}" "${udp}"
    run_wd
    cap | grep -qE '53535|"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1571 non-standard-port listener
    # surveillance.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on listening-ports surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The listening-ports-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1571 non-standard-port listener
    # surveillance alert. Locks parser contract on the listening-
    # ports inventory delta detection surface.
    tcp="$(mk_ss_lines '0.0.0.0:22')"
    mk_ss "${tcp}" ""
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    tcp2="$(mk_ss_lines '0.0.0.0:22' '0.0.0.0:4444')"
    mk_ss "${tcp2}" ""
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # listening-ports-watchdog runs ON the timer's scheduled
    # fire — diffs ss -tlnp output against baseline, emits a
    # verdict on new-listener deltas, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the listening-ports-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd/selfdef-listening-ports.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. listening-ports-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # listening-ports-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # listening-ports-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'listening-ports-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: listening-ports-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. listening-ports-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the listening-ports-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (listening-ports-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the listening-ports-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (listening-ports-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # listening-ports-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (listening-ports-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # listening-ports-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (listening-ports-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the listening-ports-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (listening-ports-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # listening-ports-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (listening-ports-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the listening-ports-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (listening-ports-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the listening-ports-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (listening-ports-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # listening-ports-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (listening-ports-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the listening-ports-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (listening-ports-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the listening-ports-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (listening-ports-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the listening-ports-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/listening-ports-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}
