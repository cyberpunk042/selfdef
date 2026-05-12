# Shared helpers for agent-guard apply / check / uninstall.
# Sourced, not executed. Caller must have set:
#   MODULE      — "agent-guard"
#   DRY_RUN     — 0 | 1
#   CONFIG_FILE — path to the rendered host config

# shellcheck disable=SC2034

log() { echo "[agent-guard] $*" >&2; }

emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}

die() { emit_status "failed" "$*"; exit 1; }

run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@"
    fi
}

toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}

# Resolve the effective action for one policy.
#   $1 — profile (audit | enforce)
#   $2 — per-policy action setting from config (default | post | sigkill)
# Echoes the YAML action name Tetragon expects: "Post" or "Sigkill".
resolve_action() {
    local profile="$1" override="$2"
    case "$override" in
        post|Post)        echo "Post"; return ;;
        sigkill|Sigkill)  echo "Sigkill"; return ;;
        default|"")       ;;
        *) die "invalid action override: $override (expected default|post|sigkill)" ;;
    esac
    case "$profile" in
        audit)   echo "Post" ;;
        enforce) echo "Sigkill" ;;
        *) die "invalid profile: $profile" ;;
    esac
}

# Render a source policy YAML into `policy_dir` with the chosen
# action substituted for the literal `action: Post` line. We only
# substitute the *first* `action:` line per policy file so a
# multi-selector policy with mixed actions wouldn't be rewritten in
# bulk — the ship-in-tree policies have one action each.
#
#   $1 — source policy path
#   $2 — destination path
#   $3 — desired action ("Post" | "Sigkill")
render_policy() {
    local src="$1" dst="$2" action="$3"
    [[ -r "$src" ]] || die "policy source not readable: $src"
    if [[ "$action" == "Post" ]]; then
        cp "$src" "$dst"
    else
        sed "0,/- action: Post/{s/- action: Post/- action: ${action}/}" "$src" > "$dst"
    fi
}

# Rewrite the egress policy's CIDR list. The source YAML carries a
# single `0.0.0.0/0` placeholder under `NotDAddr` — when the
# operator supplies a CSV allowlist, we replace that with one
# `values:` entry per CIDR.
#
#   $1 — destination YAML (already rendered with the chosen action)
#   $2 — CSV allowlist (e.g. "10.0.0.0/24,192.0.2.5/32")
render_egress_allowlist() {
    local dst="$1" csv="$2"
    if [[ -z "$csv" ]]; then
        # Empty allowlist: the policy keeps its `0.0.0.0/0` literal,
        # which inverts under NotDAddr to "match nothing". Audit
        # mode is silent; enforce mode kills nothing. That's the
        # safe default for unconfigured deployments.
        return
    fi
    local block="" ip
    IFS=',' read -ra cidrs <<<"$csv"
    for ip in "${cidrs[@]}"; do
        ip="${ip## }"; ip="${ip%% }"
        [[ -z "$ip" ]] && continue
        block="${block}                - \"${ip}\"\n"
    done
    # Replace the placeholder block under NotDAddr. We anchor on
    # the literal `- "0.0.0.0/0"` line we ship in the source.
    sed -i "s|                - \"0.0.0.0/0\"|${block%\\n}|" "$dst"
}

# Substitute the SecureMessage endpoint placeholder. No-op if unset.
render_securemessage_endpoint() {
    local dst="$1" endpoint="$2"
    [[ -z "$endpoint" ]] && return 0
    # Escape `/` for the sed expression.
    local esc
    esc=$(printf '%s' "$endpoint" | sed 's|/|\\/|g')
    sed -i "s|__SELFDEF_SECUREMESSAGE_DISABLED__|${esc}|" "$dst"
}
