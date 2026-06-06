#!/usr/bin/env bash
# tensor-parallel-inference — apply (SD-R58).
#
# Provisions /etc/selfdef/tensor-parallel/ with:
#   slice-plan.json — per-GPU slice assignment based on equal split
#                     across detected GPUs (every GPU gets 1/N).
#   runtime.env     — sources hardware-tune.env + sets TP_* knobs

set -euo pipefail

MODULE="tensor-parallel-inference"

emit_status() {
    local status="$1"
    local message="${2:-}"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "${MODULE}" "${status}" "${message}"
}

ETC_DIR="${SELFDEF_TENSOR_PARALLEL_ETC_DIR:-/etc/selfdef/tensor-parallel}"
TUNE_FILE="${SELFDEF_HARDWARE_TUNE_ENV:-/etc/selfdef/hardware-tune.env}"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

if [ "${DRY_RUN}" = "1" ]; then
    emit_status "skipped" "DRY-RUN — would provision ${ETC_DIR}"
    exit 0
fi

mkdir -p "${ETC_DIR}"
chmod 0755 "${ETC_DIR}"

# Slice plan: count GPU device nodes; assign each a rank in [0, N).
rank=0
nranks=0
for _i in 0 1 2 3 4 5 6 7; do
    [ -e "/dev/nvidia${_i}" ] && nranks=$((nranks + 1))
done

tmp_plan="$(mktemp "${ETC_DIR}/slice-plan.json.XXXXXX")"
trap 'rm -f "${tmp_plan}"' EXIT
{
    printf '{\n'
    printf '  "schema_version": "1.0.0",\n'
    printf '  "ranks": %s,\n' "${nranks}"
    printf '  "slices": [\n'
    first=1
    for _i in 0 1 2 3 4 5 6 7; do
        if [ -e "/dev/nvidia${_i}" ]; then
            [ "${first}" = "0" ] && printf ',\n'
            printf '    {"rank": %s, "gpu_index": %s, "share_pct": %s}' \
                "${rank}" "${_i}" "$((100 / (nranks == 0 ? 1 : nranks)))"
            rank=$((rank + 1))
            first=0
        fi
    done
    printf '\n  ]\n'
    printf '}\n'
} > "${tmp_plan}"
chmod 0644 "${tmp_plan}"
# Idempotency: skip rewrite when content unchanged.
if [[ -f "${ETC_DIR}/slice-plan.json" ]] && cmp -s "${tmp_plan}" "${ETC_DIR}/slice-plan.json"; then
    rm -f "${tmp_plan}"
else
    mv -f "${tmp_plan}" "${ETC_DIR}/slice-plan.json"
fi
trap - EXIT

# Runtime env file — sources hardware-tune-cache output + TP knobs.
# Build atomically via mktemp + cmp -s so a no-op apply does not
# touch the file (the prior `cat > … <<EOF` + repeated `>>`-append
# rewrite-rewrite pattern was a variant-A idempotency bug — 2026-06-06).
tmp_env="$(mktemp "${ETC_DIR}/runtime.env.XXXXXX")"
trap 'rm -f "${tmp_env}"' EXIT
{
    echo "# tensor-parallel-inference runtime env (SD-R58)"
    if [ -r "${TUNE_FILE}" ]; then
        echo ". \"${TUNE_FILE}\""
    fi
    echo "TP_SLICE_PLAN=\"${ETC_DIR}/slice-plan.json\""
    echo "TP_NRANKS=\"${nranks}\""
} > "${tmp_env}"
chmod 0644 "${tmp_env}"
if [[ -f "${ETC_DIR}/runtime.env" ]] && cmp -s "${tmp_env}" "${ETC_DIR}/runtime.env"; then
    rm -f "${tmp_env}"
else
    mv -f "${tmp_env}" "${ETC_DIR}/runtime.env"
fi
trap - EXIT

emit_status "ok" "provisioned ${ETC_DIR} (${nranks} rank(s))"
