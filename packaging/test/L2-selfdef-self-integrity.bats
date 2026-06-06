#!/usr/bin/env bats
# L2 bats functional tests for the selfdef-self-integrity meta-watchdog.
#
# "Who watches the watchers" — hashes selfdef's own trust root (every
# watchdog baseline .tsv + the detection wrapper .sh scripts) and alerts when
# one changes outside a re-baseline, since an attacker who edits a baseline
# can make a watchdog go silent. Severity:
#   ok    → no change since the manifest
#   warn  → a module config .toml changed
#   alert → a baseline .tsv or wrapper .sh changed/removed/added (detector tamper)
#
# Drives it with sandbox STATE_DIR (baselines) + LIBEXEC_DIR (wrappers) knobs.
# The config-changed (warn) path reads a hardcoded /etc/selfdef/modules dir
# with no input knob, so it is NOT hermetically testable here (would require
# mutating real /etc) — deliberately not covered.
#
# Run with: bats packaging/test/L2-selfdef-self-integrity.bats

WD="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd/selfdef-self-integrity.sh"

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
    MANIFEST="${TMP}/manifest.tsv"
    STATE="${TMP}/state"; mkdir -p "${STATE}"
    LIBEXEC="${TMP}/libexec"; mkdir -p "${LIBEXEC}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_SELFINT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SELFINT_MANIFEST="${MANIFEST}" \
    SELFDEF_STATE_DIR="${STATE}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_trust_root() {
    printf 'file\t/etc/passwd\tabc123\n' > "${STATE}/account-baseline.tsv"
    printf 'file\t/etc/crontab\tdef456\n' > "${STATE}/cron-job-baseline.tsv"
    printf '#!/bin/sh\n# account-watchdog\nexit 0\n' > "${LIBEXEC}/account-watchdog.sh"
}

@test "first run → ok / manifest_initial" {
    seed_trust_root
    run_wd
    cap | grep -q '"event":"manifest_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${MANIFEST}" ]
}

@test "unchanged trust root on second run → ok / trust_root_intact" {
    seed_trust_root
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a tampered baseline .tsv → alert / trust_root_tampered" {
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"   # attacker edited the baseline
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "a tampered wrapper .sh → alert / trust_root_tampered" {
    seed_trust_root
    run_wd
    printf '#!/bin/sh\n# account-watchdog PATCHED to lie\nexit 0\n' > "${LIBEXEC}/account-watchdog.sh"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "a removed baseline .tsv → alert / trust_root_tampered" {
    seed_trust_root
    run_wd
    rm -f "${STATE}/cron-job-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on trust-root tamper" {
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "manifest is chmod 0600 (confidentiality — self-integrity hashes enumerate the trust root)" {
    seed_trust_root
    run_wd
    [ "$(stat -c '%a' "${MANIFEST}")" = "600" ]
}

@test "DELTA detect — ADDED baseline .tsv (new watchdog deployed) → alert / trust_root_tampered" {
    # An added baseline .tsv is the legitimate operator-action
    # case (deploy a new watchdog module), but it's also the
    # canonical attacker-action case (drop a stub baseline that
    # silences a real-baseline-overwrite). Both flow through
    # the same critical-class path → alert. Locks the contract.
    seed_trust_root
    run_wd
    # Attacker (or operator) deploys a new watchdog baseline.
    printf 'file\t/etc/passwd\tabc999\n' > "${STATE}/host-sentinel-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — ADDED wrapper .sh (new detector deployed) → alert / trust_root_tampered" {
    seed_trust_root
    run_wd
    # Attacker (or operator) deploys a new wrapper script.
    printf '#!/bin/sh\n# new-watchdog.sh\nexit 0\n' > "${LIBEXEC}/new-watchdog.sh"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "tracked/added/removed/critical counts surface in JSON (operator triage observability)" {
    seed_trust_root
    run_wd
    # Two critical-class events: one tampered baseline + one removed wrapper.
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    rm -f "${LIBEXEC}/account-watchdog.sh"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"tracked":[0-9]+'
    cap | grep -qE '"critical":[1-9]'
}

@test "INVARIANT (auto-trust): selfdef-self-integrity DOES refresh the manifest on delta (the META watchdog's distinct contract)" {
    # CONTRAST against the no-auto-trust family. This watchdog
    # IS the meta-watchdog (watches the watchers) — auto-refresh
    # is correct here because the alert fires for THIS run, then
    # the manifest catches up on the next run (legitimate
    # operator re-baseline / module update). This test locks the
    # asymmetry against a regression that copies the no-auto-trust
    # pattern here (which would cause persistent alerts after
    # every legitimate watchdog re-baseline event).
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert CLEARED
    cap | grep -q '"event":"trust_root_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_trust_root
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-self-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are operator-pull advisory)" {
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-event aggregation: 2 tampered baselines + 1 removed wrapper → critical=5 in JSON; per-line counting)" {
    # Locks accurate counting when multiple critical events occur
    # in the same scan. Each tampered baseline surfaces as 2 lines
    # (old removed + new added) per the comm -23 / comm -13
    # split — so 2 tampered baselines = 4 critical lines + 1
    # removed wrapper = 5 critical. Lock the per-line counting
    # contract so operator dashboards don't undercount.
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    printf 'file\t/etc/crontab\tEVIL888\n' > "${STATE}/cron-job-baseline.tsv"
    rm -f "${LIBEXEC}/account-watchdog.sh"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"critical":5'
}

@test "INVARIANT (BOTH .tsv-class and .sh-class tampers in same scan: both flow through critical-class path → single alert)" {
    # A coordinated attack edits BOTH a baseline (.tsv) AND a
    # wrapper (.sh) — both should escalate to alert in the same
    # scan; only one alert JSON line emitted (the consolidated
    # one).
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    printf '#!/bin/sh\n# PATCHED\nexit 0\n' > "${LIBEXEC}/account-watchdog.sh"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-self-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (manifest TSV format: each line has at least 3 fields — kind\\tpath\\thash for diff replay)" {
    # Locks the manifest schema for downstream selfdef-relabel
    # + integrity-restore tooling. A regression to 2-field format
    # would lose the kind classification (tsv vs sh).
    seed_trust_root
    run_wd
    [ -s "${MANIFEST}" ]
    awk -F'\t' '{if(NF<3) bad=1} END{exit bad?1:0}' "${MANIFEST}"
}

@test "INVARIANT (auto-trust SAME-scan timing: alert fires AND manifest gets refreshed in the SAME scan; second-run sees intact)" {
    # Locks the auto-trust meta-watchdog timing contract: alert
    # for THIS run, but the manifest is updated atomically with
    # the alert so the NEXT run reports intact. Locks against a
    # regression that refreshes BEFORE alert (would suppress) OR
    # that doesn't refresh at all (would re-alert forever).
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'                  # this run alerts
    cap | grep -q '"severity":"alert"'
    # Verify the manifest got refreshed — the new EVIL999 hash
    # must now be in the manifest, so the next run sees intact.
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_intact"'
    cap | grep -q '"severity":"ok"'
}
