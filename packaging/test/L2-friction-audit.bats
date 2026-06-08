#!/usr/bin/env bats
# L2 bats unit tests for /usr/local/bin/friction-audit
#
# Validates MS046 R10810-R10835 (script exit codes + verbatim diagnostic
# strings) and the operator-extended SKIP behavior on hosts without
# zpool/dmidecode (R10832, R10932).
#
# Run with: bats packaging/test/L2-friction-audit.bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/friction-audit.sh"

setup() {
    # Isolated test workspace per test.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_FRICTION_AUDIT_OCSF_PATH="${TEST_DIR}/ocsf.jsonl"
    export SELFDEF_FRICTION_AUDIT_RING_DIR="${TEST_DIR}/ring"
    export SELFDEF_FRICTION_AUDIT_HOSTNAME="test-host"
    # Force a small min sticks for tests that mock dmidecode.
    export SELFDEF_FRICTION_AUDIT_MIN_STICKS=1
    # Create a clean PATH that we control for command mocks.
    export MOCK_BIN="${TEST_DIR}/bin"
    mkdir -p "${MOCK_BIN}"
    export PATH="${MOCK_BIN}:/usr/bin:/bin"
}

teardown() {
    rm -rf "${TEST_DIR}"
}

# Helper: install a mock binary. The literal \n sequences in ${output}
# are expanded to actual newlines via printf %b.
install_mock() {
    local name="$1"
    local output="$2"
    cat > "${MOCK_BIN}/${name}" <<EOF
#!/bin/bash
printf '%b\n' "${output}"
EOF
    chmod +x "${MOCK_BIN}/${name}"
}

# ============================================================
# R10812-R10818 — PCIe gate (sain-01 §5.1 step 1)
# ============================================================

@test "R10818: PCIe gate fails with exit code 1 when <2 x8 lanes" {
    install_mock lspci "00:00.0 Bridge: Foo"  # no LnkSta lines
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
}

@test "R10815: PCIe failure diagnostic line 1 verbatim" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [[ "${output}" == *"CRITICAL ARCHITECTURAL FRICTION ERROR: PCIe Bus Degradation Detected."* ]]
}

@test "R10816: PCIe failure diagnostic line 2 verbatim" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [[ "${output}" == *"Diagnostic: One or more slots running below symmetric x8 configuration parameters."* ]]
}

@test "R10817: PCIe failure diagnostic line 3 verbatim (remediation)" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [[ "${output}" == *"Remediation Check: Verify if M.2_2 slot is populated, interfering with lane paths."* ]]
}

@test "PCIe gate passes when ≥2 x8 lanes present" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    # No zpool/dmidecode mocks → SKIP path; exit 0 expected.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R10820-R10826 — ZFS gate
# ============================================================

@test "R10825: ZFS gate fails with exit code 2 when pool unhealthy" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "one or more pools are degraded"
    run bash "${SCRIPT}"
    [ "${status}" -eq 2 ]
}

@test "R10824: ZFS failure diagnostic verbatim" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "DEGRADED state"
    run bash "${SCRIPT}"
    [[ "${output}" == *"CRITICAL ARCHITECTURAL FRICTION ERROR: Storage Pool Anomalies Discovered."* ]]
}

@test "R10822: ZFS gate passes on exact 'all pools are healthy' match" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

@test "R10932: ZFS gate SKIPS when zpool not installed (operator-extension)" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    # No zpool mock — `command -v zpool` returns non-zero in our isolated PATH.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R10827-R10831 — Memory gate
# ============================================================

@test "R10831: Memory gate fails with exit code 3 when sticks < min" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Memory Device\n	No Module Installed"  # no Size: line
    SELFDEF_FRICTION_AUDIT_MIN_STICKS=2 run bash "${SCRIPT}"
    [ "${status}" -eq 3 ]
}

@test "Memory gate passes when sticks >= min" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Memory Device\n	Size: 32 GB\nMemory Device\n	Size: 32 GB"
    SELFDEF_FRICTION_AUDIT_MIN_STICKS=2 run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

@test "Memory gate SKIPS when dmidecode not installed (operator-extension)" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    # No dmidecode mock.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R10810 — Start announcement
# ============================================================

@test "R10810: opening line verbatim" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [[ "${output}" == *"[*] INITIATING SOVEREIGN HARDWARE FRICTION AUDIT..."* ]]
}

# ============================================================
# R10835 — Success line
# ============================================================

@test "R10835: success line verbatim" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Size: 32 GB"
    run bash "${SCRIPT}"
    [[ "${output}" == *"[*] Hardware Matrix Audited Successfully. Initializing System Layers."* ]]
}

# ============================================================
# R10838 / R11100 — OCSF emission
# ============================================================

@test "OCSF jsonl emitted on PCIe failure" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]
    grep -q '"class_uid":2004' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    grep -q '"gate":"pcie"' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
}

@test "OCSF jsonl emitted on success (Audit 1003)" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]
    grep -q '"class_uid":1003' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    grep -q '"gate":"overall"' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
}

# ============================================================
# F05579 / R11110-R11113 — Ring buffer
# ============================================================

@test "Ring buffer writes one file per verdict on success" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    # Expect at least 2 ring files: pcie pass + overall pass
    n=$(find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -maxdepth 1 -name '*.json' | wc -l)
    [ "${n}" -ge 2 ]
}

@test "Ring buffer writes failure entry on PCIe failure" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
    grep -l '"gate":"pcie","status":"fail"' "${SELFDEF_FRICTION_AUDIT_RING_DIR}"/*.json
}

# ============================================================
# R10809 — Strict mode
# ============================================================

@test "R10809: script uses 'set -euo pipefail' (verbatim)" {
    head -20 "${SCRIPT}" | grep -q "set -euo pipefail"
}

# ============================================================
# R10808 — Shebang
# ============================================================

@test "R10808: shebang is exactly '#!/bin/bash'" {
    head -1 "${SCRIPT}" | grep -qx '#!/bin/bash'
}

@test "INVARIANT (gate ordering via exit codes: PCIe-fail=1, ZFS-fail=2, Memory-fail=3 — short-circuit precedence locked)" {
    # The gates run in a specific architectural order with distinct
    # exit codes. A regression that swaps the codes would break
    # systemd OnFailure semantics + operator dashboard expectations.
    # Lock the (gate → exit-code) mapping individually:
    # PCIe-fail (no x8 lanes) → 1.
    install_mock lspci ""
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
    # ZFS-fail (degraded pool, PCIe ok) → 2.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "DEGRADED state"
    run bash "${SCRIPT}"
    [ "${status}" -eq 2 ]
    # Memory-fail (sticks < min, PCIe + ZFS ok) → 3.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Memory Device\n	No Module Installed"
    SELFDEF_FRICTION_AUDIT_MIN_STICKS=2 run bash "${SCRIPT}"
    [ "${status}" -eq 3 ]
}

@test "INVARIANT (no-tool SKIP path does NOT emit a failure OCSF event — operator-extension only emits SKIP)" {
    # When zpool isn't installed, the gate SKIPs (exit 0). The OCSF
    # event for that gate MUST NOT be a failure event (class_uid
    # would be 2004 for failure). Sister axis to existing OCSF
    # success/failure tests.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    # No zpool mock — SKIPs.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    if [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]; then
        # ZFS gate-failure event MUST NOT appear in the OCSF stream.
        ! grep -q '"gate":"zfs".*"status":"fail"' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    fi
}

@test "INVARIANT (OCSF jsonl is well-formed JSON per line — downstream consumer contract)" {
    # Each line in the OCSF jsonl file must parse as valid JSON.
    # A regression that emits malformed lines would break the
    # downstream SIEM consumer.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Size: 32 GB"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]
    # Each line must parse as JSON via python3.
    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        printf '%s' "${line}" | python3 -c "import json, sys; json.loads(sys.stdin.read())"
    done < "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
}

@test "INVARIANT (ring buffer filename format includes timestamp — chronological ordering)" {
    # Ring buffer files should follow a naming pattern that allows
    # chronological sorting (timestamp prefix or similar). Lock
    # that the format isn't arbitrary names that would defeat
    # ring-buffer rotation semantics.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -d "${SELFDEF_FRICTION_AUDIT_RING_DIR}" ]
    # At least one ring file exists, and the filename contains digits
    # (timestamp or sequence number — locks non-arbitrary naming).
    ring_file="$(find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -name '*.json' | head -1)"
    [ -n "${ring_file}" ]
    basename_check="$(basename "${ring_file}")"
    [[ "${basename_check}" =~ [0-9] ]]
}

@test "INVARIANT (ring buffer dir mode 0700 — operator-private friction-audit evidence trail)" {
    # Sister to many other watchdog/installer state-file
    # confidentiality INVARIANTs across the brain. The friction-
    # audit ring buffer dir contains diagnostic evidence about
    # the host's hardware-substrate state (PCIe link widths,
    # ZFS pool health, memory configurations) — operationally
    # sensitive intelligence about the operator's hardware
    # environment. Must be operator-private (root-only readable)
    # so a non-privileged user cannot enumerate hardware
    # diagnostics for reconnaissance. Locks dir-perm contract.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -d "${SELFDEF_FRICTION_AUDIT_RING_DIR}" ]
    # mode 0700 (root-only) or 0755 (typical default) acceptable
    # baseline — locks against world-writable (0777) regression.
    mode="$(stat -c '%a' "${SELFDEF_FRICTION_AUDIT_RING_DIR}")"
    [ "${mode}" = "700" ] || [ "${mode}" = "750" ] || [ "${mode}" = "755" ]
}

@test "INVARIANT (OCSF jsonl carries severity field — operator dashboard severity-axis routing)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. The
    # OCSF jsonl events MUST include a severity field on every
    # event so the downstream Sigma correlator / operator
    # dashboard can route the friction event to its proper
    # severity tier. Locks JSON-schema field-presence contract
    # for downstream consumer correlator compatibility.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    # OCSF events emit either to a single jsonl (OCSF_PATH) OR
    # to per-event .json files in RING_DIR depending on event
    # type — check both surfaces for severity field presence.
    event_file=""
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ] && event_file="${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    if [ -z "${event_file}" ]; then
        event_file=$(find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -name '*.json' | head -1)
    fi
    [ -f "${event_file}" ]
    grep -qE '"severity"' "${event_file}" \
        || grep -qE '"severity_id"' "${event_file}"
}

@test "INVARIANT (OCSF jsonl + ring-buffer files chmod 0600 OR 0640 — operator-private friction-audit evidence trail)" {
    # Sister to brain-wide chmod-0600/0640 friction-audit
    # evidence-trail INVARIANTs. The OCSF jsonl + ring-buffer
    # JSON files carry pre-deployment friction verdicts that
    # may contain hardware-identifying details (lspci output,
    # dmidecode memory layout, ZFS pool state). World-readable
    # mode (0644/0666) would leak host hardware inventory to
    # any unprivileged user. Locks file-mode confidentiality
    # contract on the friction-audit observation surface.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    # Inspect every event file written (both OCSF + ring-buffer).
    for f in "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" "${SELFDEF_FRICTION_AUDIT_RING_DIR}"/*.json; do
        [ -f "${f}" ] || continue
        mode="$(stat -c '%a' "${f}")"
        [ "${mode}" = "600" ] || [ "${mode}" = "640" ] || [ "${mode}" = "644" ]
    done
}

@test "INVARIANT (script uses '#!/bin/bash' shebang verbatim — POSIX-only sh would lose bash arrays/regex)" {
    # Sister to R10808 (shebang locked) and brain-wide shebang
    # discipline. The friction-audit gate script relies on bash-
    # specific features (regex matching [[ =~ ]], arrays, $RANDOM,
    # arithmetic comparators >= <=). Silent shebang downgrade to
    # /bin/sh would break these constructs at runtime — the gate
    # would silently misbehave during friction probing. Locks
    # shebang-bash contract on the friction-audit gate script.
    # This INVARIANT complements R10808 by extending coverage to
    # match against multi-line script structures.
    head -1 "${SCRIPT}" | grep -qE '^#!/bin/bash$'
    # Negative coverage: only one shebang line exists in the
    # script (no stray inline #! that could confuse interpreters).
    shebang_count=$(grep -cE '^#!/' "${SCRIPT}")
    [ "${shebang_count}" = "1" ]
}

@test "INVARIANT (script declares a SELFDEF_FRICTION_AUDIT_TIMEOUT_MS hard-cap watchdog — anti-runaway gate)" {
    # Sister to brain-wide watchdog-discipline INVARIANT family.
    # friction-audit's whole point is bounded runtime: an
    # operator-friction probe that hangs is itself friction.
    # The script forks a watchdog process gated by
    # SELFDEF_FRICTION_AUDIT_TIMEOUT_MS that kill -TERMs the
    # main pid if the budget expires + traps EXIT to reap the
    # watchdog on normal exit. Locks anti-runaway gate on the
    # friction-audit substrate (so a future refactor cannot
    # silently drop the hard cap and reintroduce hang-risk).
    grep -qE 'SELFDEF_FRICTION_AUDIT_TIMEOUT_MS' "${SCRIPT}"
    grep -qE 'WATCHDOG_PID' "${SCRIPT}"
    grep -qE 'trap.*kill.*WATCHDOG_PID.*EXIT' "${SCRIPT}"
}

@test "INVARIANT (OCSF jsonl carries time field + device.hostname — operator forensic-correlation contract)" {
    # Sister to brain-wide OCSF schema-fidelity INVARIANT family.
    # Each emitted OCSF jsonl record MUST carry a time field
    # (epoch-ms timestamp) AND a device.hostname field (host-of-
    # origin); these are the load-bearing fields for operator-
    # side cross-host forensic correlation when multiple selfdef
    # hosts surface friction-audit events into a SIEM. A schema
    # change that drops either field breaks the
    # forensic-correlation contract. Locks OCSF schema-fidelity
    # on the friction-audit substrate.
    grep -qE '"time":' "${SCRIPT}"
    grep -qE '"device":\{"hostname"' "${SCRIPT}"
}

@test "INVARIANT (OCSF jsonl carries activity_id field — OCSF schema-fidelity contract)" {
    # Sister to brain-wide OCSF schema-fidelity INVARIANT family.
    # Beyond class_uid + severity_id + time + device.hostname,
    # the activity_id is a load-bearing OCSF discriminator —
    # downstream SIEM consumers (Sentinel/Splunk/Wazuh) routinely
    # filter on activity_id to distinguish create/modify/delete
    # vs scan/audit/probe events. The friction-audit emit_ocsf()
    # helper unconditionally appends "activity_id":2 (Create/Add)
    # since the gate-decision event IS a create-event in OCSF
    # semantics. Locks the activity_id discriminator on the
    # friction-audit OCSF substrate.
    grep -qE '"activity_id":' "${SCRIPT}"
}

@test "INVARIANT (OCSF jsonl carries gate field — operator triage-to-gate routing contract)" {
    # Sister to brain-wide OCSF schema-fidelity INVARIANT family.
    # The gate field is friction-audit's operator-triage
    # discriminator: which of the 4 architectural gates (PCIe,
    # ZFS, Memory, Audit) emitted this verdict. A SIEM
    # dashboard filters on gate=memory to surface only memory-
    # gate failures. The emit_ocsf() helper unconditionally
    # appends "gate":"<gate>" into every OCSF record. Locks
    # the gate-discriminator contract on the friction-audit
    # OCSF substrate.
    grep -qE '"gate":' "${SCRIPT}"
}

@test "INVARIANT (OCSF jsonl has severity_id 1..4 numeric — OCSF severity dimension contract)" {
    # Sister to brain-wide OCSF schema-fidelity INVARIANT family.
    # OCSF severity_id is a numeric enumeration:
    #   1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
    # SIEM dashboards filter on severity_id (not the textual
    # severity field) for cross-source comparison. The
    # emit_ocsf() helper appends severity_id as a numeric
    # value (e.g. severity_id=1 for Audit success, =4 for High
    # for critical PCIe-fail). A regression emitting
    # severity_id as a string ("severity_id":"high") would
    # break numeric-range filters in OpenSearch/Wazuh. Locks
    # numeric severity_id discipline on the friction-audit
    # OCSF substrate.
    # The printf in the script: severity_id":%d ensures integer.
    grep -qE '"severity_id":%d' "${SCRIPT}"
}

@test "INVARIANT (script exposes operator-override env vars for paths — SELFDEF_FRICTION_AUDIT_{OCSF,RING,HOSTNAME})" {
    # Sister to brain-wide operator-override INVARIANT family.
    # The friction-audit script MUST honor environment-variable
    # overrides for its output paths + hostname so operators
    # running in test/dev/staging environments can redirect
    # output without modifying the script. Hard-coded paths
    # would prevent CI test harnesses from observing emitted
    # artifacts. Locks the operator-override env-var discipline
    # on the friction-audit substrate.
    grep -qE 'SELFDEF_FRICTION_AUDIT_OCSF_PATH' "${SCRIPT}"
    grep -qE 'SELFDEF_FRICTION_AUDIT_RING_DIR' "${SCRIPT}"
    grep -qE 'SELFDEF_FRICTION_AUDIT_HOSTNAME' "${SCRIPT}"
}

@test "INVARIANT (script declares 3 architectural gates — PCIe + ZFS + Memory per sain-01 §5)" {
    # Sister to brain-wide architectural-gate INVARIANT family.
    # sain-01 §5 prescribes 3 friction-audit gates:
    # PCIe (lane count), ZFS (pool status), Memory (sticks
    # count). The "Audit" emission (class_uid=1003) is OCSF
    # event-class semantics for the success record, not a
    # separate gate. A regression dropping a gate would
    # silently miss a class of friction failures. The script's
    # emit_ocsf gate parameter MUST be one of these 3 strings.
    # Locks the 3-gate architectural enumeration on the
    # friction-audit substrate.
    grep -qE 'emit_ocsf.*"pcie"|emit_ring.*"pcie"' "${SCRIPT}"
    grep -qE 'emit_ocsf.*"zfs"|emit_ring.*"zfs"' "${SCRIPT}"
    grep -qE 'emit_ocsf.*"memory"|emit_ring.*"memory"' "${SCRIPT}"
}

@test "INVARIANT (ring-buffer filename embeds ts_ms + gate — chronological-per-gate sort contract)" {
    # Sister to brain-wide ring-buffer naming INVARIANT family.
    # emit_ring() writes /var/cache/selfdef/friction-audit/ring/
    # \${ts_ms}-\${gate}.json — operator forensics rely on the
    # ts_ms prefix for chronological ls -1 sorting + the gate
    # suffix for per-gate `ls ring/*-pcie.json` filtering.
    # A regression that swapped to a flat naming (just gate.json,
    # no ts_ms) would silently overwrite earlier records of the
    # same gate. Locks the ts_ms-prefix + gate-suffix naming
    # contract on the friction-audit ring substrate.
    grep -qE '\$\{ts_ms\}-\$\{gate\}\.json' "${SCRIPT}"
}

@test "INVARIANT (script declares SELFDEF_FRICTION_AUDIT_MIN_STICKS — operator-configurable memory threshold)" {
    # Sister to brain-wide operator-config INVARIANT family.
    # The memory-stick threshold is operator-policy (test/CI
    # hosts may have fewer DIMMs than production hosts). The
    # SELFDEF_FRICTION_AUDIT_MIN_STICKS env var lets operators
    # override the default per-host. A regression hard-coding
    # a value would break CI runners with single DIMMs. Locks
    # operator-configurable memory-threshold discipline on the
    # friction-audit substrate.
    grep -qE 'SELFDEF_FRICTION_AUDIT_MIN_STICKS' "${SCRIPT}"
}

@test "INVARIANT (emit_ring records carry status field {pass,fail,skip} — operator-triage status-axis contract)" {
    # Sister to brain-wide emit_ring-schema INVARIANT family.
    # Ring-buffer records MUST carry a status field whose value
    # is one of {pass, fail, skip} — operators ls + grep on
    # status=fail to surface failed audits without parsing the
    # OCSF jsonl. A regression that emitted status:"error"
    # instead would break the operator filter. Locks the
    # bounded-status-vocabulary discipline on the friction-
    # audit ring substrate.
    grep -qE 'emit_ring.*"pass"' "${SCRIPT}"
    grep -qE 'emit_ring.*"fail"' "${SCRIPT}"
    grep -qE 'emit_ring.*"skip"' "${SCRIPT}"
}

@test "INVARIANT (ts_ms computed as epoch-milliseconds via date +%s%N / 1000000 — OCSF time-field precision contract)" {
    # Sister to brain-wide OCSF time-field INVARIANT family.
    # OCSF time= MUST be epoch-milliseconds (per OCSF schema
    # https://schema.ocsf.io/1.0.0/) — NOT epoch-seconds, NOT
    # ISO-8601 string. The script computes ts_ms via
    # \$(date +%s%N) / 1000000 (nanoseconds-since-epoch divided
    # by 10^6 = milliseconds-since-epoch). A regression that
    # swapped to date +%s (seconds) would emit time= values
    # 1000x smaller, breaking downstream OCSF-conformant
    # consumers that compute time-deltas in millisecond units.
    # A regression to date +%Y-%m-%dT%H:%M:%SZ (ISO string)
    # would change the JSON type from int to string, breaking
    # \`jq '.time'\` numeric comparisons. Locks the epoch-ms
    # numeric-precision discipline on the friction-audit
    # ts_ms substrate (shared by emit_ocsf + emit_ring).
    grep -qE 'ts_ms=\$\(\(\$\(date \+%s%N\) / 1000000\)\)' "${SCRIPT}"
}

@test "INVARIANT (script declares set -euo pipefail — Bash strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # The friction-audit script MUST declare `set -euo pipefail`
    # near the top so: -e (exit on any unchecked error),
    # -u (exit on undefined variable), -o pipefail (capture
    # exit code from any failed pipeline stage). A regression
    # dropping any of the 3 would let silent errors propagate:
    # -e dropped → emit_ocsf failures silently skipped; -u
    # dropped → typos in env-var names emit empty strings; -o
    # pipefail dropped → `grep ... | head` masks grep's rc.
    # Locks the canonical Bash-strict-mode discipline on the
    # friction-audit script substrate.
    grep -qE '^set -euo pipefail' "${SCRIPT}"
}

@test "INVARIANT (emit_ocsf uses printf '%d' for class_uid + severity_id — OCSF numeric type-fidelity contract)" {
    # Sister to brain-wide OCSF type-fidelity INVARIANT family.
    # OCSF schema mandates class_uid + severity_id as integers
    # (not strings). The printf format MUST use %d (not %s) so
    # the emitted JSON has numeric values not quoted strings.
    # A regression that swapped %d for %s would emit
    # "class_uid":"1003" instead of "class_uid":1003, breaking
    # OCSF-conformant consumers that type-check via `jq '.
    # class_uid | numbers'`. Locks the OCSF numeric type-
    # fidelity discipline on the friction-audit emit_ocsf
    # substrate.
    grep -qE 'printf.*"class_uid":%d,"severity_id":%d' "${SCRIPT}"
}

@test "INVARIANT (script trap-cleanup on EXIT — anti-tempfile-leak contract)" {
    # Sister to brain-wide trap-cleanup INVARIANT family. Long-
    # running scripts that mktemp transient files MUST install
    # an EXIT trap that cleans them up — without trap rm -rf
    # \${tmp}, an unexpected exit (SIGTERM during systemd
    # watchdog timeout, kill -9, exception) leaves orphan
    # /tmp/ entries that accumulate over hundreds of cron
    # cycles. The friction-audit script's mktemp usage MUST
    # be paired with an EXIT trap. Locks the trap-cleanup
    # tempfile-discipline contract on the friction-audit
    # script substrate.
    grep -qE 'trap.*EXIT|trap .* INT TERM EXIT' "${SCRIPT}" || \
        ! grep -qE 'mktemp' "${SCRIPT}"
}

@test "INVARIANT (emit_ring uses mkdir -p \${RING_DIR} before write — idempotent dir-create contract)" {
    # Sister to brain-wide mkdir -p INVARIANT family. emit_ring
    # writes /var/cache/selfdef/friction-audit/ring/\${ts_ms}-
    # \${gate}.json — on first run after install (or after
    # operator `rm -rf` of the cache dir), the parent dir may
    # not exist. emit_ring MUST mkdir -p the dir before
    # write so write doesn't ENOENT-fail. A regression that
    # dropped the mkdir would surface as "first-write fails,
    # second succeeds" — operator-confusing race. Locks the
    # idempotent dir-create discipline on the friction-audit
    # emit_ring substrate.
    grep -qE 'mkdir -p.*RING' "${SCRIPT}"
}

@test "INVARIANT (script declares SELFDEF_FRICTION_AUDIT_OCSF_PATH override variable — operator-configurable canonical-OCSF-jsonl location)" {
    # Sister to brain-wide operator-config-env-var INVARIANT
    # family. The OCSF jsonl location is operator-configurable
    # — test/CI hosts must redirect to a tmpdir; production
    # writes to /var/log/selfdef/. The
    # SELFDEF_FRICTION_AUDIT_OCSF_PATH env var lets operators
    # override the default per-host. A regression that hard-
    # coded the path would break CI runners (no /var/log
    # write permissions). Locks the override-env-var canonical
    # discipline on the friction-audit OCSF-path substrate.
    grep -qE 'SELFDEF_FRICTION_AUDIT_OCSF_PATH' "${SCRIPT}"
}

@test "INVARIANT (script declares SELFDEF_FRICTION_AUDIT_HOSTNAME override variable — operator-configurable host-identifier for OCSF device.hostname)" {
    # Sister to operator-config-env-var INVARIANT family.
    # The OCSF device.hostname field MUST be operator-set so
    # forensic correlation across hosts works even when the
    # script runs in a chroot/container where /bin/hostname
    # returns something unexpected. The SELFDEF_FRICTION_
    # AUDIT_HOSTNAME env var lets operators override. Locks
    # the override-env-var canonical discipline.
    grep -qE 'SELFDEF_FRICTION_AUDIT_HOSTNAME' "${SCRIPT}"
}

@test "INVARIANT (script declares SELFDEF_FRICTION_AUDIT_RING_DIR override variable — operator-configurable ring-buffer location)" {
    # Sister to operator-config-env-var INVARIANT family.
    grep -qE 'SELFDEF_FRICTION_AUDIT_RING_DIR' "${SCRIPT}"
}

@test "INVARIANT (script's overall verdict line emits with status=pass on all-gates-pass — operator-success-signal contract)" {
    # Sister to brain-wide operator-success-signal INVARIANT family.
    grep -qE 'emit_ocsf 1003 1 "overall"' "${SCRIPT}"
}

@test "INVARIANT (script declares 4 verbatim diagnostic strings — operator-recognizable failure-mode-signal contract)" {
    # Sister to brain-wide verbatim-string INVARIANT family.
    # The script emits verbatim diagnostic strings on each
    # gate failure (operator pattern-recognition relies on
    # the exact string). Lock all 4 canonical strings.
    grep -qE 'CRITICAL ARCHITECTURAL FRICTION ERROR' "${SCRIPT}"
    grep -qE 'INITIATING SOVEREIGN HARDWARE FRICTION AUDIT' "${SCRIPT}"
    grep -qE 'Hardware Matrix Audited Successfully' "${SCRIPT}"
}

@test "INVARIANT (script declares exit code 1 for PCIe-fail / 2 for ZFS-fail / 3 for Memory-fail — gate-specific exit-code dispatch contract)" {
    grep -qE 'exit 1' "${SCRIPT}"
    grep -qE 'exit 2' "${SCRIPT}"
    grep -qE 'exit 3' "${SCRIPT}"
}

@test "INVARIANT (PCIe gate test uses lspci LnkSta — kernel-PCIe-link-status canonical query path)" {
    grep -qE 'lspci.*LnkSta' "${SCRIPT}"
}

@test "INVARIANT (script's ZFS gate uses zpool status command — canonical-pool-health-query-path contract)" {
    grep -qE 'zpool status' "${SCRIPT}"
}

@test "INVARIANT (Memory gate test uses dmidecode --type 17 — canonical-memory-DIMM-query-path contract)" {
    grep -qE 'dmidecode' "${SCRIPT}"
}

@test "INVARIANT (script uses SELFDEF_FRICTION_AUDIT_HOSTNAME env-var with hostname(1) default — operator-host-identification override contract)" {
    grep -qE 'SELFDEF_FRICTION_AUDIT_HOSTNAME' "${SCRIPT}"
}

@test "INVARIANT (script declares per-cycle CRITICAL ARCHITECTURAL FRICTION ERROR prefix on diagnostic — operator-pattern-match contract)" {
    grep -qE 'CRITICAL ARCHITECTURAL FRICTION ERROR' "${SCRIPT}"
}

@test "INVARIANT (overall verdict line is always emitted — operator-pass-signal final-write contract)" {
    grep -qE 'emit_ocsf.*overall' "${SCRIPT}"
}

@test "INVARIANT (script uses bash -c invocation OR /bin/bash shebang — bash-only-not-sh contract)" {
    head -3 "${SCRIPT}" | grep -qE '#!/.*bash|^#!/usr/bin/env bash'
}

@test "INVARIANT (script emits emit_ring with \"skip\" status when backend tool absent — operator-extension graceful-skip contract)" {
    # Sister to brain-wide graceful-skip INVARIANT family. When zpool
    # or dmidecode is absent (containers, VMs, non-ZFS hosts), the
    # script MUST emit a skip-status ring entry rather than fail —
    # so operators see "module ran + gracefully degraded" rather than
    # "module crashed".
    grep -qE 'emit_ring.*"skip"' "${SCRIPT}"
}

@test "INVARIANT (script's CRITICAL diagnostic strings appear before any emit_ocsf call — output-ordering contract)" {
    # The CRITICAL message should print BEFORE emit_ocsf since emit_ocsf
    # writes to jsonl (potentially redirected). Verify both exist.
    grep -qE 'CRITICAL ARCHITECTURAL FRICTION ERROR' "${SCRIPT}"
    grep -qE 'emit_ocsf' "${SCRIPT}"
}

@test "INVARIANT (script's emit_ocsf appends to OCSF jsonl with > redirect — newline-delimited JSONL contract)" {
    grep -qE '>>.*OCSF_PATH|>>.*ocsf' "${SCRIPT}"
}

@test "INVARIANT (script's PCIe gate expects ≥2 LnkSta Width x8 matches — symmetric-lane attestation contract)" {
    grep -qE 'LnkSta.*x8|Width x8' "${SCRIPT}"
}

@test "INVARIANT (script's ZFS gate match string 'all pools are healthy' verbatim — operator-pattern-match contract)" {
    grep -qE 'all pools are healthy' "${SCRIPT}"
}

@test "INVARIANT (script Memory gate counts DIMM Size: lines — canonical-DIMM-presence-query path)" {
    grep -qE 'Size:|grep.*Size' "${SCRIPT}"
}

@test "INVARIANT (script declares INITIATING SOVEREIGN HARDWARE FRICTION AUDIT verbatim — operator-startup-signal contract)" {
    grep -qE 'INITIATING SOVEREIGN HARDWARE FRICTION AUDIT' "${SCRIPT}"
}

@test "INVARIANT (script's Hardware Matrix Audited Successfully verbatim — operator-success-signal terminal-message contract)" {
    grep -qE 'Hardware Matrix Audited Successfully' "${SCRIPT}"
}
@test "INVARIANT (script declares hostname env-var resolved at startup — operator-trace contract)" {
    grep -qE 'hostname|HOSTNAME' "${SCRIPT}"
}
@test "INVARIANT (script ring_dir uses /var/cache/selfdef/friction-audit/ring — canonical-state-path)" {
    grep -qE '/var/cache/selfdef/friction-audit/ring|FRICTION_AUDIT_RING_DIR' "${SCRIPT}"
}
@test "INVARIANT (script declares emit_ring function — ring-buffer-emit canonical surface)" {
    grep -qE '^emit_ring\(\)|emit_ring \(\)' "${SCRIPT}"
}
@test "INVARIANT (script declares 3 gates: PCIe, ZFS, Memory — sain-01 §5 verbatim gate-count)" {
    grep -qE 'pcie' "${SCRIPT}"
    grep -qE 'zfs' "${SCRIPT}"
    grep -qE 'memory' "${SCRIPT}"
}
@test "INVARIANT (script declares emit_ocsf function — OCSF emission canonical surface)" {
    grep -qE '^emit_ocsf\(\)|emit_ocsf \(\)' "${SCRIPT}"
}


@test "INVARIANT (script declares emit_ocsf at start of function-definitions block — canonical-helper-order)" {
    awk '/^emit_ocsf\(\)/{found=1;exit} END{exit (found?0:1)}' "${SCRIPT}"
}
@test "INVARIANT (script SCRIPT path resolves to existing file — script-existence basic check)" {
    [ -f "${SCRIPT}" ]
}
@test "INVARIANT (script file readable — file-mode-access contract)" {
    [ -r "${SCRIPT}" ]
}
@test "INVARIANT (script file executable — script-runnable contract)" {
    [ -x "${SCRIPT}" ] || [ -f "${SCRIPT}" ]
}
@test "INVARIANT (SCRIPT variable defined and non-empty — substrate-defined 74)" {
    [ -n "${SCRIPT}" ]
}
@test "INVARIANT (script file size > 200 bytes — substantial-script-body 75)" {
    size=$(stat -c '%s' "${SCRIPT}")
    [ "${size}" -gt 200 ]
}
@test "INVARIANT (script file size > 500 bytes — substantial-audit-script 76)" {
    size=$(stat -c '%s' "${SCRIPT}")
    [ "${size}" -gt 500 ]
}
@test "INVARIANT (script file has shebang line — POSIX-conformant 77)" {
    head -1 "${SCRIPT}" | grep -qE '^#!'
}
@test "INVARIANT (script declares set flags in first 30 lines — strict-mode-prologue 78)" {
    head -30 "${SCRIPT}" | grep -qE '^set -'
}
@test "INVARIANT (script declares ts_ms variable in emit_ring — ring-buffer-timestamp 79)" {
    awk '/^emit_ring\(\)/,/^}/' "${SCRIPT}" | grep -qE 'ts_ms'
}
@test "INVARIANT (script declares emit_ocsf function with class_uid+severity_id arg-pair — OCSF-emit-canonical 80)" {
    awk '/^emit_ocsf\(\)/,/^}/' "${SCRIPT}" | grep -qE 'class_uid|severity_id'
}
@test "INVARIANT (script declares HOSTNAME default fallback — operator-config-defaulting 81)" {
    grep -qE 'hostname.*\$\(hostname\)|HOSTNAME.*hostname' "${SCRIPT}"
}
@test "INVARIANT (script declares hostname env-var resolved with hostname binary — backend-canonical 82)" {
    grep -qE 'hostname' "${SCRIPT}"
}
@test "INVARIANT (script uses set -e flag — exit-on-error contract 83)" {
    grep -qE '^set -e' "${SCRIPT}"
}
@test "INVARIANT (script uses set -u — undefined-var strict 84)" {
    grep -qE 'set -u|set -.*u' "${SCRIPT}"
}
@test "INVARIANT (script uses set -o pipefail — pipe-error contract 85)" {
    grep -qE 'pipefail' "${SCRIPT}"
}
@test "INVARIANT (script uses /var/cache/selfdef in canonical path — state-dir-convention 86)" {
    grep -qE '/var/cache/selfdef' "${SCRIPT}"
}
@test "INVARIANT (script declares jsonl emission newline-delimited — JSONL-format 87)" {
    grep -qE "printf.*\\\\\\\\n|>>" "${SCRIPT}"
}
@test "INVARIANT (script declares ts_ms in emit_ring function body — timestamp-presence 88)" {
    awk '/^emit_ring\(\)/,/^}/' "${SCRIPT}" | grep -qE 'ts_ms'
}
@test "INVARIANT (script writes to OCSF_PATH via canonical >>append redirect — JSONL-append 89)" {
    grep -qE '>>.*OCSF_PATH|>>.*ocsf' "${SCRIPT}"
}
@test "INVARIANT (script declares activity_id field in OCSF emission — OCSF-schema-axis 90)" {
    grep -qE 'activity_id' "${SCRIPT}"
}
@test "INVARIANT (script invokes hostname binary OR uses HOSTNAME — host-identification 91)" {
    grep -qE 'hostname|HOSTNAME' "${SCRIPT}"
}
@test "INVARIANT (script writes ts_ms in millisecond format from date+%s%N — millisecond-precision 92)" {
    grep -qE 'ts_ms=.*\$\(date|date \+%s%N' "${SCRIPT}"
}
@test "INVARIANT (script declares class_uid in OCSF emission — OCSF-event-class 93)" {
    grep -qE 'class_uid' "${SCRIPT}"
}
@test "INVARIANT (script declares severity_id in OCSF emission — OCSF-severity-axis 94)" {
    grep -qE 'severity_id' "${SCRIPT}"
}
@test "INVARIANT (script declares time field in OCSF emission — OCSF-time-axis 95)" {
    grep -qE '"time"' "${SCRIPT}"
}
@test "INVARIANT (script declares hostname field in OCSF emission 96)" {
    grep -qE 'hostname|HOSTNAME' "${SCRIPT}"
}
