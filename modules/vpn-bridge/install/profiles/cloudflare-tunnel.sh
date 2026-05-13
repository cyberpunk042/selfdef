# Profile: cloudflare-tunnel.
#
# Outbound L7 tunnel via Cloudflare's `cloudflared`. This is a
# DIFFERENT PARADIGM from relay-via-server / tailscale: it exposes
# a host's services (HTTP, SSH, TCP) to a Cloudflare-fronted hostname
# rather than building a peer-to-peer overlay. You can't ping across
# it; you can publish a service through it. See README §
# "Decision matrix" for when to pick this over the overlay profiles.
#
# SDD-003 defence-in-depth: the `cloudflared service install`
# subcommand writes /etc/systemd/system/cloudflared.service with
# the token baked in. A second vpn-bridge instance running this
# profile would overwrite the first one's token. The CLI resolver
# already refuses `vpn-bridge#instance` for this profile via
# `[profiles.details.cloudflare-tunnel].instanced = false`, but
# if something ever bypasses that, this guard fires first.
_cf_guard_singleton() {
    if [[ -n "${SELFDEF_INSTANCE_ID:-}" ]]; then
        die "cloudflare-tunnel profile is singleton-only (manages \
cloudflared.service host-wide); SELFDEF_INSTANCE_ID='${SELFDEF_INSTANCE_ID}' \
is set, which means the resolver was bypassed. Refusing to apply."
    fi
}
#
# Required config keys:
#   profile           = "cloudflare-tunnel"
#   tunnel_token_path = "/etc/cloudflared/token"    # 0600, operator-managed
# OR, for config-file mode:
#   tunnel_id         = "<uuid>"
#   credentials_path  = "/etc/cloudflared/<id>.json"
#   config_path       = "/etc/cloudflared/config.yml"

_cf_read_config() {
    TUNNEL_TOKEN_PATH=$(toml_get tunnel_token_path "$CONFIG_FILE" || echo "")
    TUNNEL_ID=$(toml_get tunnel_id "$CONFIG_FILE" || echo "")
    CREDENTIALS_PATH=$(toml_get credentials_path "$CONFIG_FILE" || echo "")
    CONFIG_PATH=$(toml_get config_path "$CONFIG_FILE" || echo "")
}

profile_apply() {
    _cf_guard_singleton
    command -v cloudflared >/dev/null || die "cloudflared(1) missing — install the cloudflared package first"
    command -v systemctl   >/dev/null || die "systemctl missing"

    _cf_read_config

    local mode="" token=""
    if [[ -n "$TUNNEL_TOKEN_PATH" ]]; then
        mode="token"
        safe_name "$TUNNEL_TOKEN_PATH" || die "tunnel_token_path has unsafe characters"
        [[ -r "$TUNNEL_TOKEN_PATH" ]] || die "tunnel_token_path not readable: $TUNNEL_TOKEN_PATH"
        token=$(tr -d '[:space:]' < "$TUNNEL_TOKEN_PATH")
        [[ -n "$token" ]] || die "tunnel_token_path is empty"
    elif [[ -n "$TUNNEL_ID" && -n "$CREDENTIALS_PATH" && -n "$CONFIG_PATH" ]]; then
        mode="config-file"
        safe_name "$TUNNEL_ID"        || die "tunnel_id has unsafe characters"
        safe_name "$CREDENTIALS_PATH" || die "credentials_path has unsafe characters"
        safe_name "$CONFIG_PATH"      || die "config_path has unsafe characters"
        [[ -r "$CREDENTIALS_PATH" ]] || die "credentials_path not readable: $CREDENTIALS_PATH"
        [[ -r "$CONFIG_PATH"      ]] || die "config_path not readable: $CONFIG_PATH"
    else
        die "either tunnel_token_path OR (tunnel_id + credentials_path + config_path) is required"
    fi

    local changes=0

    # cloudflared ships its own service-install command which writes
    # the systemd unit. Re-invoking it with the same token is a
    # no-op aside from rewriting the unit (idempotent enough).
    if systemctl is-enabled --quiet cloudflared.service 2>/dev/null; then
        log "cloudflared.service already enabled"
    else
        if [[ "$mode" == "token" ]]; then
            run "cloudflared service install (token mode)" \
                -- cloudflared service install "$token"
        else
            run "cloudflared service install (config-file mode)" \
                -- cloudflared --config "$CONFIG_PATH" service install
        fi
        changes=$((changes + 1))
    fi

    if ! systemctl is-active --quiet cloudflared.service; then
        run "start cloudflared.service" -- systemctl start cloudflared.service
        changes=$((changes + 1))
    fi

    emit_status "ok" "cloudflared active (${mode} mode)"
}

profile_check() {
    local -a problems=()
    if command -v systemctl >/dev/null; then
        if ! systemctl is-active --quiet cloudflared.service; then
            problems+=("cloudflared.service not active")
        fi
    fi
    if command -v cloudflared >/dev/null; then
        # `cloudflared tunnel info` requires auth; the lightest health
        # probe is whether the binary responds to --version.
        if ! cloudflared --version >/dev/null 2>&1; then
            problems+=("cloudflared --version failed")
        fi
    fi

    if [[ "${#problems[@]}" -eq 0 ]]; then
        emit_status "ok" "cloudflared.service active"
        return 0
    fi
    local msg
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
}

profile_uninstall() {
    _cf_guard_singleton
    if command -v systemctl >/dev/null; then
        if systemctl is-active --quiet cloudflared.service; then
            run "stop cloudflared.service" -- systemctl stop cloudflared.service || log "(continuing)"
        fi
    fi
    if command -v cloudflared >/dev/null; then
        run "cloudflared service uninstall" -- cloudflared service uninstall || log "(continuing)"
    fi
    emit_status "ok" "uninstalled (cloudflared package + credentials preserved)"
}
