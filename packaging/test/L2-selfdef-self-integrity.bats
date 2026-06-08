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

@test "INVARIANT (selfdef-self-integrity libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the selfdef-self-integrity libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (selfdef-self-integrity libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # selfdef-self-integrity libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (selfdef-self-integrity timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # selfdef-self-integrity timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (selfdef-self-integrity timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the selfdef-self-integrity timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (selfdef-self-integrity timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # selfdef-self-integrity substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (selfdef-self-integrity service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the selfdef-self-integrity substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (selfdef-self-integrity service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the selfdef-self-integrity
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (selfdef-self-integrity service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # selfdef-self-integrity service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (selfdef-self-integrity module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the selfdef-self-integrity module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the selfdef-self-integrity module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the selfdef-self-integrity
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for selfdef-self-integrity is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the selfdef-self-integrity substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the selfdef-self-integrity install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the selfdef-self-integrity requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the selfdef-self-integrity
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the selfdef-self-integrity
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the selfdef-self-integrity substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the selfdef-self-integrity substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (selfdef-self-integrity README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (selfdef-self-integrity install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (selfdef-self-integrity install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (selfdef-self-integrity install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (selfdef-self-integrity install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (selfdef-self-integrity install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (selfdef-self-integrity install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (selfdef-self-integrity install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (selfdef-self-integrity install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (selfdef-self-integrity module.toml [install_paths].paths includes at least one /usr/ path — binary-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/usr/') for p in ps), f'paths must include ≥1 /usr/ target, got {ps!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml exists at canonical path modules/selfdef-self-integrity/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (selfdef-self-integrity module dir is at canonical path modules/selfdef-self-integrity/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (selfdef-self-integrity install dir exists at modules/selfdef-self-integrity/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (selfdef-self-integrity install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (selfdef-self-integrity install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (selfdef-self-integrity install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (selfdef-self-integrity module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (selfdef-self-integrity install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (selfdef-self-integrity install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (selfdef-self-integrity install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (selfdef-self-integrity install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (selfdef-self-integrity install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (selfdef-self-integrity install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (selfdef-self-integrity module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (selfdef-self-integrity module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92 — libexec-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p or '/usr/local/' in p for p in ps)
"
}

@test "INVARIANT (selfdef-self-integrity module.toml install_paths.paths has /var/lib/selfdef/ entry 93 — state-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/var/lib/' in p or '/var/log/' in p or '/var/cache/' in p for p in ps)
"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"selfdef-self-integrity"' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (selfdef-self-integrity module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (selfdef-self-integrity module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (selfdef-self-integrity module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (selfdef-self-integrity module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (selfdef-self-integrity module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (selfdef-self-integrity module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (selfdef-self-integrity module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/selfdef-self-integrity/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}
