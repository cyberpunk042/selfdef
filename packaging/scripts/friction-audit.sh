#!/bin/bash
# friction-audit — boot-time hardware-integrity gate
#
# Verbatim transposition of sain-01 §5 (lines 338-378) with explicit
# operator-extensions tagged inline. Implements MS046 catalog rows
# R10801-R11040.
#
# Source dump: ~/infohub/raw/dumps/2026-05-15-sain-01-master-spec-
# other-conversation-transposition.md §5
# SDD: docs/sdd/027-friction-audit-system.md
#
# Standing rule: We do not minimize anything.

set -euo pipefail

# OPERATOR-EXTENSION (MS046 F05492): hard timeout watchdog. The sain-01
# baseline has no time budget. We add a 2000ms hard cap to prevent a
# hung lspci/zpool/dmidecode from blocking boot forever. Exit code 4 on
# timeout.
SELFDEF_FRICTION_AUDIT_TIMEOUT_MS="${SELFDEF_FRICTION_AUDIT_TIMEOUT_MS:-2000}"
SELFDEF_FRICTION_AUDIT_OCSF_PATH="${SELFDEF_FRICTION_AUDIT_OCSF_PATH:-/var/log/selfdef/friction-audit.ocsf.jsonl}"
SELFDEF_FRICTION_AUDIT_RING_DIR="${SELFDEF_FRICTION_AUDIT_RING_DIR:-/var/cache/selfdef/friction-audit/ring}"
SELFDEF_FRICTION_AUDIT_HOSTNAME="${SELFDEF_FRICTION_AUDIT_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"

# OPERATOR-EXTENSION: timeout watchdog. Spawn a sleeper that SIGTERMs us
# after the budget. The sleeper itself exits when the script exits
# (parent-PID cleanup).
{
  sleep "$(awk "BEGIN{print ${SELFDEF_FRICTION_AUDIT_TIMEOUT_MS}/1000}")" 2>/dev/null
  # If we get here, the script is still running past the budget.
  echo "CRITICAL ARCHITECTURAL FRICTION ERROR: friction-audit exceeded ${SELFDEF_FRICTION_AUDIT_TIMEOUT_MS}ms hard cap." >&2
  kill -TERM $$ 2>/dev/null || true
} &
WATCHDOG_PID=$!
# shellcheck disable=SC2064
trap "kill ${WATCHDOG_PID} 2>/dev/null || true" EXIT

# Emit OCSF event (best-effort; non-blocking on emit failure per MS046
# R11102 + R10849). $1=class_uid, $2=severity_id, $3=gate, $4=extra-json.
emit_ocsf() {
  local class_uid="$1"
  local severity_id="$2"
  local gate="$3"
  local extra="${4:-}"
  local ts_ms
  ts_ms=$(($(date +%s%N) / 1000000))
  mkdir -p "$(dirname "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}")" 2>/dev/null || return 0
  printf '{"class_uid":%d,"severity_id":%d,"time":%d,"device":{"hostname":"%s"},"gate":"%s","activity_id":2%s}\n' \
    "${class_uid}" "${severity_id}" "${ts_ms}" "${SELFDEF_FRICTION_AUDIT_HOSTNAME}" "${gate}" "${extra}" \
    >> "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" 2>/dev/null || true
}

# Append to ring buffer (1-file-per-verdict, FIFO eviction at 256).
emit_ring() {
  local gate="$1"
  local status="$2"
  local ts_ms
  ts_ms=$(($(date +%s%N) / 1000000))
  mkdir -p "${SELFDEF_FRICTION_AUDIT_RING_DIR}" 2>/dev/null || return 0
  local fname="${SELFDEF_FRICTION_AUDIT_RING_DIR}/${ts_ms}-${gate}.json"
  printf '{"gate":"%s","status":"%s","ts_ms":%d,"hostname":"%s"}\n' \
    "${gate}" "${status}" "${ts_ms}" "${SELFDEF_FRICTION_AUDIT_HOSTNAME}" \
    > "${fname}" 2>/dev/null || true
  # FIFO eviction beyond 256 entries (newest-first via mtime; drop tail).
  find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -maxdepth 1 -name '*.json' -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | tail -n +257 \
    | awk '{ $1=""; sub(/^ /,""); print }' \
    | xargs -r rm -f 2>/dev/null || true
}

echo "[*] INITIATING SOVEREIGN HARDWARE FRICTION AUDIT..."

# ----------------------------------------------------------------
# 1. Check for True Physical PCIe Bifurcation Symmetry (x8/x8 Link Width)
# ----------------------------------------------------------------
# OPERATOR-EXTENSION: SKIP for hosts without lspci (containers, VMs) — mirrors
# the zfs + memory gate skip-guards below. Without this guard an absent lspci
# left LANE_AUDIT_COUNT=0 (empty pipe under `set -o pipefail` + `|| true`),
# which is < 2 and hard-failed the gate (exit 1) on every non-PCIe host —
# blocking BEFORE the zfs/memory skip-guards were even reachable. When lspci IS
# present the gate is unchanged: a real < 2 x8-lane reading still fails exit 1.
if command -v lspci >/dev/null 2>&1; then
    LANE_AUDIT_COUNT=$(lspci -vvv 2>/dev/null | grep -c "LnkSta:.*Width x8" || true)
    if [ "${LANE_AUDIT_COUNT}" -lt 2 ]; then
        echo "CRITICAL ARCHITECTURAL FRICTION ERROR: PCIe Bus Degradation Detected." >&2
        echo "Diagnostic: One or more slots running below symmetric x8 configuration parameters." >&2
        echo "Remediation Check: Verify if M.2_2 slot is populated, interfering with lane paths." >&2
        emit_ocsf 2004 4 "pcie" ",\"lane_count\":${LANE_AUDIT_COUNT}"
        emit_ring "pcie" "fail"
        exit 1
    fi
    emit_ring "pcie" "pass"
else
    # OPERATOR-EXTENSION: SKIP audit for hosts without lspci.
    emit_ocsf 1003 1 "pcie" ",\"note\":\"lspci not installed; skipped\""
    emit_ring "pcie" "skip"
fi

# ----------------------------------------------------------------
# 2. Check ZFS Array Integrity status
# ----------------------------------------------------------------
# Skip if zpool is not installed (deployment.target != sain01 baseline).
# OPERATOR-EXTENSION: silently skip when zpool absent so non-ZFS hosts
# don't false-fail; the gate still emits a SKIP audit event.
if command -v zpool >/dev/null 2>&1; then
    POOL_STATUS=$(zpool status -x 2>/dev/null || echo "zpool unavailable")
    if [ "${POOL_STATUS}" != "all pools are healthy" ]; then
        echo "CRITICAL ARCHITECTURAL FRICTION ERROR: Storage Pool Anomalies Discovered." >&2
        emit_ocsf 2004 4 "zfs" ",\"pool_status\":\"$(echo "${POOL_STATUS}" | head -1 | tr -d '"' | head -c 200)\""
        emit_ring "zfs" "fail"
        exit 2
    fi
    emit_ring "zfs" "pass"
else
    # OPERATOR-EXTENSION: SKIP audit for hosts without zpool.
    emit_ocsf 1003 1 "zfs" ",\"note\":\"zpool not installed; skipped\""
    emit_ring "zfs" "skip"
fi

# ----------------------------------------------------------------
# 3. Verify System Memory Geometry Mapping
# ----------------------------------------------------------------
# OPERATOR-EXTENSION (MS046 F05491, R10831): sain-01 §5.1 leaves the
# threshold open. We use SELFDEF_FRICTION_AUDIT_MIN_STICKS (default 1).
# Hosts that expect a specific count (e.g. 4 for ProArt znver5) set the
# env to their value.
SELFDEF_FRICTION_AUDIT_MIN_STICKS="${SELFDEF_FRICTION_AUDIT_MIN_STICKS:-1}"
if command -v dmidecode >/dev/null 2>&1; then
    TOTAL_RECOGNIZED_STICKS=$(dmidecode -t memory 2>/dev/null | grep -c "Size: [0-9]" || true)
    if [ "${TOTAL_RECOGNIZED_STICKS}" -lt "${SELFDEF_FRICTION_AUDIT_MIN_STICKS}" ]; then
        echo "ARCHITECTURAL FRICTION WARNING: Memory geometry mismatch." >&2
        echo "Diagnostic: detected ${TOTAL_RECOGNIZED_STICKS} populated DIMM slot(s); expected ≥ ${SELFDEF_FRICTION_AUDIT_MIN_STICKS}." >&2
        echo "Remediation Check: Verify DIMM seating and slot population per board manual." >&2
        emit_ocsf 2004 3 "memory" ",\"sticks\":${TOTAL_RECOGNIZED_STICKS},\"required\":${SELFDEF_FRICTION_AUDIT_MIN_STICKS}"
        emit_ring "memory" "fail"
        exit 3
    fi
    emit_ring "memory" "pass"
else
    # OPERATOR-EXTENSION: SKIP for hosts without dmidecode (containers, VMs).
    emit_ocsf 1003 1 "memory" ",\"note\":\"dmidecode not installed; skipped\""
    emit_ring "memory" "skip"
fi

# ----------------------------------------------------------------
# Success
# ----------------------------------------------------------------
echo "[*] Hardware Matrix Audited Successfully. Initializing System Layers."
emit_ocsf 1003 1 "overall"
emit_ring "overall" "pass"
exit 0
