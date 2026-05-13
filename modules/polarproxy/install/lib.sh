# Shared helpers for polarproxy. log, emit_status, die, run,
# toml_get all come from /usr/share/selfdef/lib/module-lib.sh.
#
# Caller must have already set:
#   MODULE       — "polarproxy"
#   DRY_RUN      — 0 | 1
#   CONFIG_FILE  — path to the rendered host config

# F-2027-024: opted into v2 to use module_record_file /
# module_render_files / module_clear_manifest, replacing the
# hand-curated UNIT_PATH + NFT_RULESET_PATH duplication between
# apply.sh and uninstall.sh.
# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
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
