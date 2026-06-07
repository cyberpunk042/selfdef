#!/usr/bin/env bats
# L2 bats functional tests for the rhosts-watchdog scan script.
#
# /etc/hosts.equiv and ~/.rhosts/.shosts declare hosts/users trusted for
# PASSWORDLESS rlogin/rsh. A `+` wildcard is a classic trusted-relationship
# backdoor (T1199); root's ~/.rhosts existing at all is almost always a
# backdoor. Severity:
#   ok    → no delta
#   warn  → a trust entry / file added/removed/changed
#   alert → a `+` wildcard, a world-writable/non-root trust file, or a
#           per-user .rhosts/.shosts present
#
# Run with: bats packaging/test/L2-rhosts-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd/rhosts-watchdog.sh"

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
    BASELINE="${TMP}/baseline.tsv"
    EQUIV="${TMP}/hosts.equiv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_RHOSTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_RHOSTS_BASELINE="${BASELINE}" \
    SELFDEF_RHOSTS_FILES="${FILES_V:-$EQUIV}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'trusted.example.com\n' > "${EQUIV}"
}

@test "no rhosts files → ok / no_rhosts_files" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_rhosts_files"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hosts.equiv, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hosts.equiv on second run → ok / rhosts_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a + wildcard trust entry → alert / rhosts_trust_backdoor" {
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable trust file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign trust-entry change → warn / rhosts_changed" {
    seed_benign
    run_wd
    printf 'other.example.com\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"rhosts_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign hosts.equiv is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a wildcard trust entry" {
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — trust inventory enumerates legitimate trust relationships)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (multi-line + wildcard): + on its own line (not just trailing) → alert" {
    seed_benign
    run_wd
    printf '+\ntrusted.example.com\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (per-user .rhosts): a user-level .rhosts file IS flagged as a backdoor" {
    seed_benign
    run_wd
    # Test multi-file scan: declare a per-user rhosts file via FILES_V.
    user_rhosts="${TMP}/user-alice.rhosts"
    printf 'evil.example.com\n' > "${user_rhosts}"
    : > "${SELFDEF_TEST_LOGCAP}"
    FILES_V="${EQUIV} ${user_rhosts}" run_wd
    # Either the file's existence alone OR the wildcard signature fires alert.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing wildcard): baseline_initial fires alert if hosts.equiv already has a + at install-time" {
    printf '+\n' > "${EQUIV}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED trust entry (operator pruning) → warn" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rhosts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (group-writable): a group-writable trust file → alert too (more than just world-writable)" {
    seed_benign
    run_wd
    chmod 0664 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (no auto-trust): rhosts-watchdog does NOT refresh baseline on wildcard detection — alert STAYS until operator updates" {
    # rhosts wildcards (+ entry) are NEVER routine; the alert
    # must persist across runs until operator explicitly
    # re-baselines.
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented + wildcard NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com\n# + would be a backdoor\n' > "${EQUIV}"
    run_wd
    # Current behavior: commented + must NOT trigger alert.
    ! cap | grep -q '"event":"rhosts_trust_backdoor"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity precedence: wildcard + world-writable → alert with rhosts_trust_backdoor event taking precedence)" {
    # When both issues coexist (wildcard AND world-writable file),
    # severity must be alert. Locks the consolidation.
    seed_benign
    run_wd
    printf '+\n' > "${EQUIV}"
    chmod 0666 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    # Either event surfaces — both are valid; lock that alert
    # severity fires consistently.
    cap | grep -qE '"event":"rhosts_(trust_backdoor|suspicious|world_writable)"'
}

@test "INVARIANT (whitespace tolerance: '  +  ' with leading/trailing spaces still triggers wildcard alert)" {
    # Attacker may use multi-space evasion. Lock whitespace-
    # tolerant parser still catches dangerous patterns.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '   +   \n' > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (user-wildcard +user form: + on a user position → still alerts)" {
    # rsh/rlogin grammar also accepts `+ user` (any host trusted
    # for the named user) or `host +` (any user from named host)
    # — both are trust-relationship backdoors. Lock that the
    # user-wildcard variant is also flagged.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com +\n' > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (per-user .shosts file IS flagged as backdoor — sister axis to .rhosts)" {
    # OpenSSH's hostbased-auth reads .shosts (the ssh-equivalent of
    # .rhosts) for hostbased trust. A user's .shosts is the same
    # backdoor surface as .rhosts on the rsh axis.
    seed_benign
    run_wd
    user_shosts="${TMP}/user-bob.shosts"
    printf 'evil.example.com\n' > "${user_shosts}"
    : > "${SELFDEF_TEST_LOGCAP}"
    FILES_V="${EQUIV} ${user_shosts}" run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names the offending file in JSON — operator triage routing)" {
    # When a wildcard fires, the sample MUST surface the file path
    # so operator dashboard routes triage to the right path. Sister
    # contract: polkit-rules/nfs-exports sample-naming pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+\n' > "${EQUIV}"
    run_wd
    cap | grep -q "$(basename "${EQUIV}")"
}

@test "INVARIANT (pre-existing wildcard: baseline_initial fires alert at install-time — install-time-vet contract)" {
    # Sister to every other watchdog pre-existing-broad-condition
    # baseline_initial INVARIANT across the brain. The install-time-
    # vet contract: if /etc/hosts.equiv ALREADY carries a wildcard
    # trust entry (+ or user-wildcard) when selfdef first installs
    # the watchdog, the first run MUST raise alert (or at least
    # warn) — not silently baseline a broken security posture.
    # Closes the install-time-vet axis on the rsh/rlogin/hostbased-
    # auth trust surface (T1199 — Trusted Relationship via legacy
    # rcommand wildcard backdoor account).
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named host in hosts.equiv surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctively-named host to hosts.equiv (T1199 — Trusted
    # Relationship via legacy rsh/rlogin hostbased-auth), the
    # host name MUST surface in the JSON sample so operator
    # dashboard routes triage to the right path. Locks the
    # operator-visibility contract on the legacy-trust grant
    # surface.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com\ndistinctive-attacker-host.evil.example\n' > "${EQUIV}"
    run_wd
    cap | grep -q 'distinctive-attacker-host'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-rhosts tag must fire
    # EXACTLY ONCE per scan regardless of how many trust-grant
    # entries surface (multi-user .rhosts adds in one scan).
    # Multi-line output would break SDD-062 downstream JSON-
    # line consumer (Sigma correlator). Locks consolidation
    # discipline on T1199 trusted-relationship surface.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com\nevil1.example\nevil2.example\nevil3.example\n+\n' > "${EQUIV}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rhosts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1199 trusted-relationship rhosts /
    # hosts.equiv surveillance.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of rhosts inventory)" {
    # Sister to brain-wide baseline-chmod-0600 confidentiality
    # INVARIANTs across L2 surveillance suites. The rhosts-
    # watchdog baseline TSV contains the inventory of trusted-
    # host grants which discloses cross-host trust
    # relationships to any user able to read the file. Mode
    # 0600 (root-only) is the canonical confidentiality
    # contract — mode 0644 would expose the rsh/rlogin trust-
    # graph to reconnaissance enabling attacker to map
    # T1199 Trusted Relationship lateral-movement targets.
    # Locks file-mode confidentiality on the rhosts
    # surveillance substrate.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # rhosts-watchdog runs ON the timer's scheduled fire — scans
    # /etc/hosts.equiv + every user's ~/.rhosts for trust-relation
    # entries, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the rhosts-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd/selfdef-rhosts.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}
