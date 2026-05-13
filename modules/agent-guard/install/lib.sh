# Module-specific helpers for agent-guard. Shared helpers (log,
# emit_status, die, run, toml_get) come from
# /usr/share/selfdef/lib/module-lib.sh.
#
# Caller must have set:
#   MODULE      — "agent-guard"
#   DRY_RUN     — 0 | 1
#   CONFIG_FILE — path to the rendered host config

# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
# Locate the shared module-lib. Precedence:
#   1. $SELFDEF_MODULE_LIB exported by selfdefctl (workspace
#      runs hit this).
#   2. Workspace-relative path (this lib.sh sits at
#      modules/<slug>/install/lib.sh; the shared lib is at
#      packaging/lib/module-lib.sh). Catches direct script
#      invocations from integration tests + ad-hoc runs.
#   3. Installed system path (.deb-shipped).
if [[ -n "${SELFDEF_MODULE_LIB:-}" && -r "${SELFDEF_MODULE_LIB}" ]]; then
    _selfdef_lib="${SELFDEF_MODULE_LIB}"
elif [[ -r "${BASH_SOURCE[0]%/*}/../../../packaging/lib/module-lib.sh" ]]; then
    _selfdef_lib="${BASH_SOURCE[0]%/*}/../../../packaging/lib/module-lib.sh"
else
    _selfdef_lib="/usr/share/selfdef/lib/module-lib.sh"
fi
# shellcheck disable=SC1090
source "$_selfdef_lib"
unset _selfdef_lib

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

# Swap the shipped `matchNamespaces` container-scope block for a
# `matchPodSelector` block that filters by Kubernetes pod labels.
# Used on k8s hosts where the cluster's container scoping is
# already labelled — narrower than the namespace-only default.
#
# Must run *after* render_gpu_policy() because that helper's
# matchBinaries-drop awk anchors on the matchNamespaces line.
#
#   $1 — destination YAML (already action-rendered)
#   $2 — pod label key   (e.g. "selfdef.io/agent")
#   $3 — pod label value (e.g. "true")
render_pod_scope() {
    local dst="$1" key="$2" val="$3"
    [[ -z "$key" || -z "$val" ]] && \
        die "scope=pod-label requires pod_label_key and pod_label_value"
    awk -v key="$key" -v val="$val" '
        /^          matchNamespaces:/ { in_block = 1; next }
        in_block && /^          matchActions:/ {
            printf "          matchPodSelector:\n"
            printf "            matchLabels:\n"
            printf "              %s: \"%s\"\n", key, val
            in_block = 0
            print
            next
        }
        in_block { next }
        { print }
    ' "$dst" > "${dst}.tmp" && mv "${dst}.tmp" "$dst"
}

# Rewrite the GPU device guard's device-prefix list and binary
# allowlist. The source YAML ships with NVIDIA's prefix set inline
# and a `__SELFDEF_GPU_ALLOWLIST_PLACEHOLDER__` sentinel in the
# `matchBinaries: NotIn` values block.
#
#   $1 — destination YAML (already rendered with the chosen action)
#   $2 — CSV of device-path prefixes (empty = keep the shipped default)
#   $3 — CSV of binary paths permitted to open those devices
#        (empty = drop the matchBinaries selector so EVERY in-container
#        process matches; populated = match only binaries NOT in the
#        list)
render_gpu_policy() {
    local dst="$1" paths_csv="$2" allow_csv="$3"

    # 1. Device prefix list. Replace the shipped block only if the
    #    operator overrode it. Two-state awk:
    #      seen_prefix=1 — we passed the `operator: "Prefix"` line
    #                       and are waiting for the `values:` line.
    #                       Comment lines in between are printed
    #                       unchanged.
    #      in_values=1  — inside the value list. Drop the old
    #                       `- "..."` entries; exit the mode on the
    #                       first non-list line.
    if [[ -n "$paths_csv" ]]; then
        local prefix_block="" p
        IFS=',' read -ra prefixes <<<"$paths_csv"
        for p in "${prefixes[@]}"; do
            p="${p## }"; p="${p%% }"
            [[ -z "$p" ]] && continue
            prefix_block="${prefix_block}                - \"${p}\"\n"
        done
        awk -v block="${prefix_block%\\n}" '
            /operator: "Prefix"/ { seen_prefix = 1; print; next }
            seen_prefix && /^[[:space:]]+values:/ {
                print
                printf "%s\n", block
                seen_prefix = 0
                in_values = 1
                next
            }
            in_values && /^[[:space:]]+-[[:space:]]+"/ { next }
            in_values && !/^[[:space:]]+-/ { in_values = 0 }
            { print }
        ' "$dst" > "${dst}.tmp" && mv "${dst}.tmp" "$dst"
    fi

    # 2. Binary allowlist. Two cases:
    #
    #    Empty CSV → drop the entire matchBinaries selector so the
    #    rule matches every binary (the default "any non-host
    #    process touching /dev/nvidia* is suspect" stance).
    #
    #    Non-empty → splice the values list, leaving the NotIn
    #    operator intact ("kill anything NOT in this list").
    if [[ -z "$allow_csv" ]]; then
        # Remove the four-line matchBinaries block (header + operator +
        # values: + one placeholder value). Anchored on the unique
        # placeholder string we ship.
        awk '
            /matchBinaries:/  { in_mb = 1; next }
            in_mb && /^[[:space:]]*- operator:/ { next }
            in_mb && /^[[:space:]]*values:/     { next }
            in_mb && /__SELFDEF_GPU_ALLOWLIST_PLACEHOLDER__/ { next }
            in_mb && /^[[:space:]]*matchNamespaces:/ { in_mb = 0; print; next }
            in_mb { next }
            { print }
        ' "$dst" > "${dst}.tmp" && mv "${dst}.tmp" "$dst"
    else
        local allow_block="" b
        IFS=',' read -ra bins <<<"$allow_csv"
        for b in "${bins[@]}"; do
            b="${b## }"; b="${b%% }"
            [[ -z "$b" ]] && continue
            allow_block="${allow_block}                - \"${b}\"\n"
        done
        sed -i "s|                - \"__SELFDEF_GPU_ALLOWLIST_PLACEHOLDER__\"|${allow_block%\\n}|" "$dst"
    fi
}
