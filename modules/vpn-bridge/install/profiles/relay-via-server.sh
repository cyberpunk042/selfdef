# Profile: relay-via-server.
#
# Both endpoints WireGuard to an operator-provided public relay.
# This file is sourced by apply.sh / check.sh / uninstall.sh — it
# does not execute on its own.

profile_apply() {
    command -v wg        >/dev/null || die "wg(8) missing"
    command -v wg-quick  >/dev/null || die "wg-quick(8) missing"
    command -v ip        >/dev/null || die "ip(8) missing"
    command -v nft       >/dev/null || die "nft(8) missing"
    command -v systemctl >/dev/null || die "systemctl missing"

    local role iface forward_to_lan
    role=$(toml_get role "$CONFIG_FILE" || echo "endpoint")
    iface=$(toml_get interface "$CONFIG_FILE" || echo "wg0")
    forward_to_lan=$(toml_get forward_to_lan "$CONFIG_FILE" || echo "")

    case "$role" in
        endpoint|relay) ;;
        *) die "role must be endpoint|relay, got '$role'" ;;
    esac
    safe_name "$iface" || die "interface name has unsafe characters: '$iface'"

    local wg_dir wg_conf nft_path template_dir
    wg_dir="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"
    wg_conf="${wg_dir}/${iface}.conf"
    nft_path="${SELFDEF_VPN_BRIDGE_NFT_PATH:-/etc/nftables.d/selfdef-vpn-bridge.conf}"
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
    nft list table inet selfdef_vpn_bridge >/dev/null 2>&1 && have_table=1

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
            "$template" > "$rendered"

        if [[ -r "$nft_path" ]] && cmp -s "$rendered" "$nft_path" && [[ "$have_table" == "1" ]]; then
            log "nftables forward rules already at target state"
        else
            run "install forward rules to $nft_path" -- install -D -m 0644 "$rendered" "$nft_path"
            run "load forward rules" -- nft -f "$nft_path"
            changes=$((changes + 2))
        fi
    else
        if [[ "$have_table" == "1" ]]; then
            run "remove stale forward table (forward_to_lan unset)" \
                -- nft delete table inet selfdef_vpn_bridge
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
    local iface forward_to_lan wg_dir
    iface=$(toml_get interface "$CONFIG_FILE" || echo "wg0")
    forward_to_lan=$(toml_get forward_to_lan "$CONFIG_FILE" || echo "")
    wg_dir="${SELFDEF_VPN_BRIDGE_WG_DIR:-/etc/wireguard}"

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
        if ! nft list table inet selfdef_vpn_bridge >/dev/null 2>&1; then
            problems+=("nftables forward table inet selfdef_vpn_bridge not loaded")
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
    local iface
    iface=$(toml_get interface "$CONFIG_FILE" 2>/dev/null || echo "wg0")
    local service="wg-quick@${iface}.service"
    local nft_path="${SELFDEF_VPN_BRIDGE_NFT_PATH:-/etc/nftables.d/selfdef-vpn-bridge.conf}"

    if command -v systemctl >/dev/null; then
        if systemctl is-active --quiet "$service"; then
            run "stop $service" -- systemctl stop "$service" || log "(continuing past failure)"
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            run "disable $service" -- systemctl disable "$service" || log "(continuing past failure)"
        fi
    fi
    if command -v nft >/dev/null && nft list table inet selfdef_vpn_bridge >/dev/null 2>&1; then
        run "delete forward table" -- nft delete table inet selfdef_vpn_bridge || log "(continuing)"
    fi
    if [[ -f "$nft_path" ]]; then
        run "remove $nft_path" -- rm -f "$nft_path" || log "(continuing)"
    fi
    emit_status "ok" "uninstalled (wg.conf + keys preserved)"
}
