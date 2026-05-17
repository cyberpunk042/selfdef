#!/usr/bin/env bash
# slm-cpu-loop — apply (SD-R72).
#
# Provisions /etc/selfdef/slm-loop.env with the operator-tuned defaults
# for running a small language model (Phi-4-mini-instruct / Qwen3-1.7B
# / any catalog class=slm entry) in a CPU-pinned agent loop.
#
# The env file is consumed by systemd-run / systemd unit drop-ins that
# the operator writes; this module just centralises the canonical
# defaults so operators don't reinvent CCD-0 pinning + thread count
# math per host.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware. Composes with SD-R66/R67/R70.

set -euo pipefail

MODULE="slm-cpu-loop"
ENV_FILE="${SELFDEF_SLM_LOOP_ENV:-/etc/selfdef/slm-loop.env}"
TUNE_FILE="${SELFDEF_HARDWARE_TUNE_ENV:-/etc/selfdef/hardware-tune.env}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would write ${ENV_FILE}"
    exit 0
fi

mkdir -p "$(dirname "${ENV_FILE}")"

# CCD-0 cores on Zen 5 9900X = 0-5 physical / 0-11 with SMT. The loop
# is best-effort tuned for the 6-physical-core CCD-0; operators with
# different topologies override SELFDEF_SLM_AFFINITY in their service
# unit.
DEFAULT_AFFINITY="0-5"
DEFAULT_THREADS="6"

# Probe the host's CPU model name for a tuning hint when available.
CPU_MODEL=""
if [ -r /proc/cpuinfo ]; then
    CPU_MODEL="$(awk -F: '/^model name/ {gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo)"
fi

cat > "${ENV_FILE}" <<EOF
# slm-cpu-loop env file — SD-R72.
# Sourced by operator-supplied systemd units or systemd-run wrappers.
# Override any value via /etc/systemd/system/<unit>.service.d/*.conf.
#
# Generated on host: ${CPU_MODEL:-(unknown)}
# Generated at:     $(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---- Affinity --------------------------------------------------------
# CCD-0 cores on Zen 5 (master spec § 17.1 Pulse Vector Core). On
# 9900X this is cores 0-5 physical (0-11 with SMT). Override per host
# topology — e.g. SELFDEF_SLM_AFFINITY="0-7" on a 9950X.
SELFDEF_SLM_AFFINITY="${DEFAULT_AFFINITY}"
SELFDEF_SLM_THREADS="${DEFAULT_THREADS}"

# ---- Model selection -------------------------------------------------
# Operator-set. Should match a sovereign-os models/catalog.yaml entry
# with class=slm (Phi-4-mini-instruct / Qwen3-1.7B-Instruct as of
# R212). Discover via: sovereign-osctl models query --class slm
SELFDEF_SLM_MODEL=""
SELFDEF_SLM_MODEL_PATH=""

# ---- Engine selection ------------------------------------------------
# llama.cpp recommended for GGUF Phi-4-mini; vllm for bf16 Qwen3.
# Set to match the catalog entry's 'engine' field.
SELFDEF_SLM_ENGINE="llama.cpp"

# ---- Optional: KV cache + context ------------------------------------
# Phi-4-mini supports 128k context but the operator loop typically
# uses far less. Tune to actual operator query depth.
SELFDEF_SLM_CONTEXT_TOKENS="8192"
SELFDEF_SLM_KV_DTYPE="fp16"

# ---- Worked invocation example ---------------------------------------
# taskset -c \${SELFDEF_SLM_AFFINITY} llama-server \\
#   -m \${SELFDEF_SLM_MODEL_PATH} \\
#   -t \${SELFDEF_SLM_THREADS} \\
#   -c \${SELFDEF_SLM_CONTEXT_TOKENS} \\
#   --port 8082
EOF

emit_status "ok" "wrote ${ENV_FILE}; operator sets SELFDEF_SLM_MODEL{,_PATH}"
