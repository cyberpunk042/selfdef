# Profile: relay-via-server.
#
# Both endpoints WireGuard to an operator-provided public relay.
# This file is sourced by apply.sh / check.sh / uninstall.sh — it
# does not execute on its own.
#
# SDD-003: multi-instance honesty. Per-instance defaults are
# derived from $SELFDEF_INSTANCE_ID:
#   • interface default  → selfdef-${INST}  (was: wg0)
#   • nft table sentinel → selfdef_vpn_bridge_${INST}
#   • nft state file     → /etc/nftables.d/selfdef-vpn-bridge-${INST}.conf
# When no instance is set, $SELFDEF_INSTANCE_ID is empty and the
# legacy single-instance defaults remain (interface "wg0",
# table "selfdef_vpn_bridge", file
# "/etc/nftables.d/selfdef-vpn-bridge.conf").

# Compute per-instance defaults from $SELFDEF_INSTANCE_ID. Sourced
# by every profile_* function so all three see the same names.
#
# F-2027-025: SELFDEF_INSTANCE_ID flows from operator-controlled
# /etc/selfdef/modules.toml today, but it ends up interpolated
# directly into nftables table names (illegal chars => silent rule
# load failure) and per-instance config paths (illegal chars =>
# arbitrary fs traversal in pathological cases). safe_name is the
# defense — it accepts only [a-zA-Z0-9_./:-], which is the same
# character class iface / table names elsewhere in this file get
# checked against. Cheap belt-and-suspenders defense-in-depth.
_relay_inst_defaults() {
    INST="${SELFDEF_INSTANCE_ID:-}"
    if [[ -n "$INST" ]]; then
        safe_name "$INST" || die "SELFDEF_INSTANCE_ID has unsafe characters: '$INST' (allowed: [a-zA-Z0-9_./:-])"
        # SDD-003 Q-C / D-005: WireGuard interface name 'selfdef-${INST}' must
        # fit Linux's 15-char IFNAMSIZ limit. 'selfdef-' is 8 chars, so INST
        # caps at 7. Refuse cleanly here rather than silently truncating at
        # 'ip link add'.
        if (( ${#INST} > 7 )); then
            die "SELFDEF_INSTANCE_ID too long: '$INST' (${#INST} chars); max 7 chars so the WireGuard interface name 'selfdef-\${INST}' fits Linux's 15-char IFNAMSIZ limit"
        fi
        DEFAULT_IFACE="selfdef-${INST}"
        DEFAULT_NFT_TABLE="selfdef_vpn_bridge_${INST}"
        DEFAULT_NFT_PATH="/etc/nftables.d/selfdef-vpn-bridge-${INST}.conf"
    else
        DEFAULT_IFACE="wg0"
        DEFAULT_NFT_TABLE="selfdef_vpn_bridge"
        DEFAULT_NFT_PATH="/etc/nftables.d/selfdef-vpn-bridge.conf"
    fi
}

profile_apply() {
    command -v wg        >/dev/null || die "wg(8) missing"
    command -v wg-quick  >/dev/null || die "wg-quick(8) missing"
    command -v ip        >/dev/null || die "ip(8) missing"
    command -v nft       >/dev/null || die "nft(8) missing"
    command -v systemctl >/dev/null || die "systemctl missing"

    _relay_inst_defaults

    local role iface forward_to_lan
    role=$(toml_get role "$CONFIG_FILE" || echo "endpoint")
    iface=$(toml_get interface "$CONFIG_FILE" || echo "$DEFAULT_IFACE")
    forward_to_lan=$(toml_get forward_to_lan "$CONFIG_FILE" || echo "")

    case "$role" in
        endpoint|relay) ;;
        *) die "role must be endpoint|relay, got '$role'" ;;
    esac
    safe_name "$iface" || die "interface name has unsafe characters: '$iface'"

    local wg_dir wg_conf nft_path nft_table template_dir
    wg_dir="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"
    wg_conf="${wg_dir}/${iface}.conf"
    nft_path="${SELFDEF_VPN_BRIDGE_NFT_PATH:-${DEFAULT_NFT_PATH}}"
    nft_table="${SELFDEF_VPN_BRIDGE_NFT_TABLE:-${DEFAULT_NFT_TABLE}}"
    template_dir="${SELFDEF_VPN_BRIDGE_TEMPLATES:-/usr/share/selfdef/modules/vpn-bridge/templates}"

    if [[ ! -r "$wg_conf" ]]; then
        die "wg-quick config missing: $wg_conf — see modules/vpn-bridge/README.md"
    fi

    local changes=0
    local service="wg-quick@${iface}.service"

    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log "$service already enabled"
    else
        run "enable $service" -- systemctl enable "$service"
        changes=$((changes + 1))
    fi

    if systemctl is-active --quiet "$service"; then
        log "$service already running — reload-or-restart"
        run "reload-or-restart $service" -- systemctl reload-or-restart "$service"
    else
        run "start $service" -- systemctl start "$service"
        changes=$((changes + 1))
    fi

    local have_table=0
    nft list table inet "$nft_table" >/dev/null 2>&1 && have_table=1

    if [[ -n "$forward_to_lan" ]]; then
        safe_name "$forward_to_lan" || die "forward_to_lan has unsafe characters: '$forward_to_lan'"
        local template="${template_dir}/forward.rule.tmpl"
        [[ -r "$template" ]] || die "template missing: $template"

        local rendered
        rendered=$(mktemp)
        # shellcheck disable=SC2064  # expand $rendered at trap-set time
        trap "rm -f '$rendered'" EXIT
        sed \
            -e "s|@@WG_IFACE@@|${iface}|g" \
            -e "s|@@LAN_IFACE@@|${forward_to_lan}|g" \
            -e "s|@@NFT_TABLE@@|${nft_table}|g" \
            "$template" > "$rendered"

        if [[ -r "$nft_path" ]] && cmp -s "$rendered" "$nft_path" && [[ "$have_table" == "1" ]]; then
            log "nftables forward rules already at target state"
        else
            run "install forward rules to $nft_path" -- install -D -m 0644 "$rendered" "$nft_path"
            run "load forward rules" -- nft -f "$nft_path"
            changes=$((changes + 2))
        fi
        # F-2028-015: track the rendered forward-rules file in the
        # per-module manifest so uninstall enumerates from disk
        # rather than hard-coding the path. Critical for the
        # multi-instance case where `$nft_path` includes
        # `${SELFDEF_INSTANCE_ID}` — the manifest is per-instance
        # too, so uninstall finds exactly the files apply wrote.
        module_record_file "$nft_path"
    else
        if [[ "$have_table" == "1" ]]; then
            run "remove stale forward table (forward_to_lan unset)" \
                -- nft delete table inet "$nft_table"
            changes=$((changes + 1))
        fi
        if [[ -f "$nft_path" ]]; then
            run "remove stale $nft_path" -- rm -f "$nft_path"
            changes=$((changes + 1))
        fi
    fi

    if [[ "$changes" -eq 0 ]]; then
        emit_status "skipped" "already at target state ($role on $iface)"
    else
        emit_status "ok" "applied $changes change(s)"
    fi
}

profile_check() {
    _relay_inst_defaults
    local iface forward_to_lan wg_dir nft_table
    iface=$(toml_get interface "$CONFIG_FILE" || echo "$DEFAULT_IFACE")
    forward_to_lan=$(toml_get forward_to_lan "$CONFIG_FILE" || echo "")
    wg_dir="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"
    nft_table="${SELFDEF_VPN_BRIDGE_NFT_TABLE:-${DEFAULT_NFT_TABLE}}"

    local -a problems=()

    if [[ ! -r "${wg_dir}/${iface}.conf" ]]; then
        problems+=("wg-quick config missing: ${wg_dir}/${iface}.conf")
    fi
    if command -v systemctl >/dev/null; then
        if ! systemctl is-active --quiet "wg-quick@${iface}.service"; then
            problems+=("wg-quick@${iface}.service not active")
        fi
    fi
    if command -v ip >/dev/null; then
        if ! ip -o link show "$iface" >/dev/null 2>&1; then
            problems+=("wireguard interface $iface not present")
        fi
    fi
    if [[ -n "$forward_to_lan" ]] && command -v nft >/dev/null; then
        if ! nft list table inet "$nft_table" >/dev/null 2>&1; then
            problems+=("nftables forward table inet $nft_table not loaded")
        fi
    fi

    if [[ "${#problems[@]}" -eq 0 ]]; then
        emit_status "ok" "wg-quick@${iface} active; ${forward_to_lan:+forward → $forward_to_lan; }overlay live"
        return 0
    fi
    local msg
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
}

profile_uninstall() {
    _relay_inst_defaults
    local iface
    iface=$(toml_get interface "$CONFIG_FILE" 2>/dev/null || echo "$DEFAULT_IFACE")
    local service="wg-quick@${iface}.service"
    local nft_path="${SELFDEF_VPN_BRIDGE_NFT_PATH:-${DEFAULT_NFT_PATH}}"
    local nft_table="${SELFDEF_VPN_BRIDGE_NFT_TABLE:-${DEFAULT_NFT_TABLE}}"

    if command -v systemctl >/dev/null; then
        if systemctl is-active --quiet "$service"; then
            run "stop $service" -- systemctl stop "$service" || log "(continuing past failure)"
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            run "disable $service" -- systemctl disable "$service" || log "(continuing past failure)"
        fi
    fi
    if command -v nft >/dev/null && nft list table inet "$nft_table" >/dev/null 2>&1; then
        run "delete forward table $nft_table" -- nft delete table inet "$nft_table" || log "(continuing)"
    fi
    # F-2028-015: enumerate-and-remove from the per-module manifest
    # instead of hard-coding `$nft_path`. The legacy fallback below
    # handles pre-v2 installs where the manifest doesn't exist yet
    # (operator who installed under v1 then upgraded — first uninstall
    # after upgrade still removes the legacy hard-coded path).
    local removed=0
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if [[ -f "$f" ]]; then
            run "remove $f" -- rm -f "$f" || log "(continuing past failure removing $f)"
            removed=$((removed + 1))
        fi
    done < <(module_render_files 2>/dev/null || true)
    if [[ "$removed" -eq 0 && -f "$nft_path" ]]; then
        # Legacy fallback: pre-v2 install, no manifest. Remove the
        # path the apply-time defaults would have written.
        run "remove $nft_path (legacy)" -- rm -f "$nft_path" || log "(continuing)"
    fi
    module_clear_manifest 2>/dev/null || true
    emit_status "ok" "uninstalled (wg.conf + keys preserved)"
}
