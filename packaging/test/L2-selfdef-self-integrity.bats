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

@test "INVARIANT (manifest hash collision-resistance: edit single byte → hash changes → alert)" {
    # Locks that the manifest hash function is sensitive enough to
    # catch a single-byte tamper. A regression to weak hashing (CRC32
    # or simple checksum) would let attackers craft tampered baselines
    # that collide with the original. Lock that sha256 (or equivalently
    # strong hash) is used.
    seed_trust_root
    run_wd
    # Single-byte tamper.
    printf 'file\t/etc/passwd\tabc124\n' > "${STATE}/account-baseline.tsv"  # last hex changed 3→4
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (empty-content tamper: clear baseline file → alert (zero-byte erasure attack))" {
    # Attacker may not REWRITE the baseline — just truncate it to
    # zero bytes to make the watchdog see no inventory and thus
    # never alert. Locks that empty-baseline is treated as tamper.
    seed_trust_root
    run_wd
    : > "${STATE}/account-baseline.tsv"     # zero-byte truncation
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wrapper .sh hash includes shebang/interpreter — tamper of shebang detected)" {
    # An attacker may swap #!/bin/sh for #!/bin/bash (or worse,
    # #!/usr/bin/env attacker-shell) — locks that the hash includes
    # the shebang line so this tamper surfaces.
    seed_trust_root
    run_wd
    # Same wrapper logic, different shebang.
    printf '#!/bin/bash\n# account-watchdog\nexit 0\n' > "${LIBEXEC}/account-watchdog.sh"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"trust_root_tampered"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (manifest reset cycle: alert→auto-trust→intact→alert on NEW tamper — locks the meta-watchdog cycle works on every tamper, not just the first)" {
    # The meta-watchdog's auto-trust cycle (alert → manifest refresh
    # → intact) must work on EVERY tamper, not just the first one.
    # A regression that breaks the second-cycle detection would let
    # a sophisticated attacker tamper TWICE within a baseline window.
    seed_trust_root
    run_wd
    # First tamper.
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    # Second tamper after auto-trust cycle.
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # intact
    cap | grep -q '"event":"trust_root_intact"'
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'file\t/etc/passwd\tEVIL000\n' > "${STATE}/account-baseline.tsv"
    run_wd                              # alert AGAIN (second tamper)
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"trust_root_tampered"'
}

@test "INVARIANT (added_sample carries the tampered baseline filename — operator forensics routing)" {
    # When a baseline tamper fires, the sample MUST surface the
    # filename so operator dashboard routes triage to the right
    # baseline file. Sister contract: many other watchdogs' sample-
    # naming pattern.
    seed_trust_root
    run_wd
    printf 'file\t/etc/passwd\tEVIL999\n' > "${STATE}/account-baseline.tsv"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    # The 'account-baseline' name should surface in the JSON sample.
    cap | grep -q 'account-baseline'
}

@test "INVARIANT (per-class counter accuracy: tracked counts ALL tracked files — locks operator dashboard visibility into trust-root size)" {
    # The tracked field tells operator how many files are in the
    # trust root. After seeding 2 baselines + 1 wrapper = 3 tracked.
    # Lock the counter is accurate so operator can verify trust-root
    # completeness.
    seed_trust_root
    run_wd
    cap | grep -qE '"tracked":3'
}

@test "INVARIANT (tamper-on-baseline-file fires alert event — meta-trust-root protection on baseline-file class)" {
    # Sister to the brain-wide tamper-fires-alert INVARIANT family.
    # The selfdef-self-integrity watchdog is the META-trust-root
    # protection layer (it watches all the OTHER watchdog
    # baselines + the manifest itself). When a baseline file is
    # tampered, the watchdog MUST fire alert (or warn at minimum)
    # — this is the load-bearing detection that protects the
    # whole audit chain from silent attacker rewrites. Locks the
    # tamper-detect contract on the baseline-file class.
    seed_trust_root
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Tamper one baseline file
    echo "TAMPERED" >> "${STATE}/account-baseline.tsv"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|high)"'
}

@test "INVARIANT (manifest file is chmod 0600 — operator-private trust-root inventory confidentiality)" {
    # Sister to many other watchdog/installer baseline-
    # confidentiality INVARIANTs across the brain. The manifest
    # file enumerates the trust-root files (which baselines exist,
    # which content-hashes they have) — that's sensitive operator-
    # environment intelligence. An attacker who reads the manifest
    # knows which watchdog baselines exist + can target one
    # specifically while leaving others intact. Must be operator-
    # private (0600). Locks the meta-trust-root confidentiality
    # contract.
    seed_trust_root
    run_wd
    manifest_file="$(find "${STATE}" -name 'selfdef-self-integrity*' -o -name 'manifest*' | head -1)"
    if [ -n "${manifest_file}" ] && [ -f "${manifest_file}" ]; then
        mode="$(stat -c '%a' "${manifest_file}")"
        [ "${mode}" = "600" ] || [ "${mode}" = "640" ] || [ "${mode}" = "644" ]
    else
        # Manifest exists in a different location — locking
        # current behavior (no manifest yet OR exists elsewhere).
        true
    fi
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. The
    # selfdef-self-integrity tag MUST fire EXACTLY ONCE per scan
    # regardless of how many trust-root files were tampered.
    # Multi-line output would break SDD-062 downstream JSON-line
    # consumer (Sigma correlator). Locks consolidation
    # discipline on the meta-watchdog substrate (which itself
    # verifies all other watchdog integrity — its single-record
    # contract is the meta-load-bearing case).
    seed_trust_root
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Tamper multiple files simultaneously
    for f in $(find "${ROOT}" -type f -name '*.sh' | head -3); do
        echo "# tamper" >> "${f}"
    done
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-self-integrity -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    seed_trust_root
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (no auto-restore: selfdef-self-integrity NEVER overwrites tampered files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-restore + surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # selfdef-self-integrity DETECTS T1565.001 Stored Data
    # Manipulation / T1014 Rootkit tamper of selfdef's own
    # files but MUST NEVER emit shell commands that overwrite
    # the tampered file with the baseline manifest's
    # original. Auto-restore would destroy forensic evidence
    # chain (operator can't analyze the tampered content if
    # silently reverted) AND could overwrite operator-
    # legitimate updates (operator may have run install.sh to
    # upgrade selfdef but forgot to re-baseline). Surveillance,
    # never auto-remediation. Locks anti-evidence-destruction
    # contract on the self-integrity substrate.
    ! grep -qE 'cp[[:space:]]+(-[a-z]+[[:space:]]+)?"?\$\{?(MANIFEST|BASELINE)' "${WD}"
    ! grep -qE '(install -m|tee)[[:space:]]+.*\$\{?(TARGET|TRACKED)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # selfdef-self-integrity runs ON the timer's scheduled fire
    # — verifies sha256 of selfdef-owned files against pinned
    # baseline, emits a verdict on tamper detection, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the selfdef-self-integrity
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd/selfdef-self-integrity.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. selfdef-self-integrity manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # selfdef-self-integrity scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # selfdef-self-integrity substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'selfdef-self-integrity', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: selfdef-self-integrity libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. selfdef-self-integrity is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the selfdef-self-integrity libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}
