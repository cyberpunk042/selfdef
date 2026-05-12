# Profile: tailscale.
#
# Defer NAT-traversal entirely to Tailscale (commercial control plane)
# or a self-hosted Headscale. The module installs the systemd unit
# state and runs `tailscale up` with operator-supplied parameters; it
# does NOT manage the auth-key file beyond reading the path the
# operator gives.
#
# Required config keys:
#   profile        = "tailscale"
#   auth_key_path  = "/etc/tailscale/auth.key"    # 0600, operator-managed
#   control_url    = ""                            # empty = Tailscale hosted; set = Headscale
#   hostname       = "" (optional)
#   advertise_routes = "" (optional, comma-sep CIDRs)
#   accept_routes  = "false"
#   tags           = "" (optional, comma-sep, e.g. "tag:home,tag:lab")

_tailscale_read_config() {
    AUTH_KEY_PATH=$(toml_get auth_key_path "$CONFIG_FILE" || echo "")
    CONTROL_URL=$(toml_get control_url "$CONFIG_FILE" || echo "")
    HOSTNAME_OPT=$(toml_get hostname "$CONFIG_FILE" || echo "")
    ADVERTISE_ROUTES=$(toml_get advertise_routes "$CONFIG_FILE" || echo "")
    ACCEPT_ROUTES=$(toml_get accept_routes "$CONFIG_FILE" || echo "false")
    TAGS=$(toml_get tags "$CONFIG_FILE" || echo "")
}

profile_apply() {
    command -v tailscale >/dev/null || die "tailscale(1) missing — install the tailscale package first"
    command -v systemctl >/dev/null || die "systemctl missing"

    _tailscale_read_config

    [[ -n "$AUTH_KEY_PATH" ]] || die "auth_key_path is required for the tailscale profile"
    [[ -r "$AUTH_KEY_PATH" ]] || die "auth_key_path not readable: $AUTH_KEY_PATH"
    safe_name "$AUTH_KEY_PATH" || die "auth_key_path has unsafe characters: '$AUTH_KEY_PATH'"
    [[ -z "$CONTROL_URL"      || "$CONTROL_URL"      =~ ^https?://[A-Za-z0-9._/:-]+$ ]] || die "control_url must be http(s) URL: '$CONTROL_URL'"
    [[ -z "$HOSTNAME_OPT"     ]] || safe_name "$HOSTNAME_OPT"     || die "hostname has unsafe characters: '$HOSTNAME_OPT'"
    [[ -z "$ADVERTISE_ROUTES" || "$ADVERTISE_ROUTES" =~ ^[0-9a-fA-F:./,]+$ ]] || die "advertise_routes must be CIDRs: '$ADVERTISE_ROUTES'"
    [[ -z "$TAGS"             || "$TAGS"             =~ ^[A-Za-z0-9:_,-]+$ ]] || die "tags has unsafe characters: '$TAGS'"

    local changes=0
    local service="tailscaled.service"

    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log "$service already enabled"
    else
        run "enable $service" -- systemctl enable "$service"
        changes=$((changes + 1))
    fi
    if ! systemctl is-active --quiet "$service"; then
        run "start $service" -- systemctl start "$service"
        changes=$((changes + 1))
    fi

    # Build the `tailscale up` argument list. `tailscale up` is itself
    # idempotent — re-issuing with the same args is a no-op aside from
    # a single API roundtrip. We always run it; the daemon decides
    # whether anything changes.
    local -a args=( "up" "--reset" "--auth-key=file:${AUTH_KEY_PATH}" )
    [[ -n "$CONTROL_URL"      ]] && args+=( "--login-server=${CONTROL_URL}" )
    [[ -n "$HOSTNAME_OPT"     ]] && args+=( "--hostname=${HOSTNAME_OPT}" )
    [[ -n "$ADVERTISE_ROUTES" ]] && args+=( "--advertise-routes=${ADVERTISE_ROUTES}" )
    [[ "$ACCEPT_ROUTES" == "true" ]] && args+=( "--accept-routes" )
    [[ -n "$TAGS"             ]] && args+=( "--advertise-tags=${TAGS}" )

    run "tailscale ${args[*]}" -- tailscale "${args[@]}"
    changes=$((changes + 1))

    emit_status "ok" "tailscaled active; tailscale up issued (${CONTROL_URL:-tailscale.com})"
}

profile_check() {
    local -a problems=()
    if command -v systemctl >/dev/null; then
        if ! systemctl is-active --quiet tailscaled.service; then
            problems+=("tailscaled.service not active")
        fi
    fi
    if command -v tailscale >/dev/null; then
        # `tailscale status --json` is non-zero when not logged in.
        if ! tailscale status --json >/dev/null 2>&1; then
            problems+=("tailscale status reports not logged in")
        fi
    fi

    if [[ "${#problems[@]}" -eq 0 ]]; then
        emit_status "ok" "tailscaled active and logged in"
        return 0
    fi
    local msg
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
}

profile_uninstall() {
    if command -v tailscale >/dev/null; then
        run "tailscale logout" -- tailscale logout || log "(continuing)"
    fi
    if command -v systemctl >/dev/null; then
        if systemctl is-active --quiet tailscaled.service; then
            run "stop tailscaled.service" -- systemctl stop tailscaled.service || log "(continuing)"
        fi
        if systemctl is-enabled --quiet tailscaled.service 2>/dev/null; then
            run "disable tailscaled.service" -- systemctl disable tailscaled.service || log "(continuing)"
        fi
    fi
    emit_status "ok" "uninstalled (tailscale package preserved)"
}
