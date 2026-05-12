#!/usr/bin/env bash
# suricata — apply.
#
# Owns Suricata's *attachment* to the bridge and the service state.
# Does NOT own /etc/suricata/suricata.yaml — see modules/suricata/README.md.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware. Emits one JSON status line at end.

set -euo pipefail

MODULE="suricata"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SURICATA_CONFIG:-/etc/selfdef/modules/suricata.toml}"
TEMPLATE_DIR="${SELFDEF_SURICATA_TEMPLATES:-/usr/share/selfdef/modules/suricata/templates}"

# ---------------------------------------------------------------- helpers
log() { echo "[suricata] $*" >&2; }
emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}
die() { emit_status "failed" "$*"; exit 1; }
run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "$DRY_RUN" == "1" ]]; then
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

# ---------------------------------------------------------------- preflight
[[ -r "$CONFIG_FILE" ]] || die "config file not readable: $CONFIG_FILE"
command -v suricata  >/dev/null || die "suricata(1) missing"
command -v nft       >/dev/null || die "nft(8) missing"
command -v systemctl >/dev/null || die "systemctl missing"

MODE=$(toml_get mode "$CONFIG_FILE" || echo "nfqueue")
QUEUE_NUM=$(toml_get queue_num "$CONFIG_FILE" || echo "0")

case "$MODE" in
    nfqueue|af-packet) ;;
    *) die "mode must be nfqueue|af-packet, got '$MODE'" ;;
esac

changes=0

# ---------------------------------------------------------------- nftables (nfqueue only)
NFT_HAS_TABLE=0
if nft list table inet selfdef_bridge >/dev/null 2>&1; then
    NFT_HAS_TABLE=1
fi

want_nfqueue_rule() { [[ "$MODE" == "nfqueue" ]]; }

# Look for an existing selfdef-suricata jump in the forward_hook chain.
have_nfqueue_rule() {
    [[ "$NFT_HAS_TABLE" == "1" ]] || return 1
    nft -a list chain inet selfdef_bridge forward_hook 2>/dev/null \
        | grep -q 'comment "selfdef-suricata"' || return 1
}

if want_nfqueue_rule; then
    [[ "$NFT_HAS_TABLE" == "1" ]] || die "bridge-l2 nftables table not loaded; install bridge-l2 first"
    if have_nfqueue_rule; then
        log "NFQUEUE rule already present in forward_hook"
    else
        TEMPLATE="$TEMPLATE_DIR/nfqueue.rule.tmpl"
        [[ -r "$TEMPLATE" ]] || die "template missing: $TEMPLATE"
        RENDERED=$(mktemp)
        trap 'rm -f "$RENDERED"' EXIT
        sed -e "s|@@QUEUE_NUM@@|${QUEUE_NUM}|g" "$TEMPLATE" > "$RENDERED"
        run "load NFQUEUE jump into forward_hook (queue $QUEUE_NUM, bypass)" \
            -- nft -f "$RENDERED"
        changes=$((changes + 1))
    fi
else
    # AF_PACKET mode: remove any stale NFQUEUE rule we previously added.
    if have_nfqueue_rule; then
        handle=$(nft -a list chain inet selfdef_bridge forward_hook \
            | awk '/comment "selfdef-suricata"/ {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}')
        if [[ -n "$handle" ]]; then
            run "remove stale NFQUEUE rule (handle $handle)" \
                -- nft delete rule inet selfdef_bridge forward_hook handle "$handle"
            changes=$((changes + 1))
        fi
    fi
fi

# ---------------------------------------------------------------- service
service_active() { systemctl is-active --quiet suricata.service; }
service_enabled() { systemctl is-enabled --quiet suricata.service 2>/dev/null; }

if service_enabled; then
    log "suricata.service already enabled"
else
    run "enable suricata.service" -- systemctl enable suricata.service
    changes=$((changes + 1))
fi

if service_active; then
    log "suricata.service already running — issuing reload"
    run "reload suricata.service" -- systemctl reload-or-restart suricata.service
else
    run "start suricata.service" -- systemctl start suricata.service
    changes=$((changes + 1))
fi

# ---------------------------------------------------------------- finalise
if [[ "$changes" -eq 0 ]]; then
    emit_status "skipped" "already at target state"
else
    emit_status "ok" "applied $changes change(s)"
fi
