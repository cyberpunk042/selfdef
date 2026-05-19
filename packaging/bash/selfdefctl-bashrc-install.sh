#!/usr/bin/env bash
# packaging/bash/selfdefctl-bashrc-install.sh — SD-R-BASHRC-1.
#
# Cross-repo binding to sovereign-os R447 (E11.M6, bashrc opt-in).
# Per operator §1g VERBATIM:
#
#   "the bashrc we can offer to configure it too and we can add our
#    autocompletes and aliases and manual / helps and menus"
#
# Installs a sentinel-bounded block in ~/.bashrc (operator-overrideable
# via SELFDEF_BASHRC_PATH) shipping:
#   - operator-discoverable aliases (sdctl / sdstatus / sdmodules /
#     sddoctor / sdcheck / sdhelp)
#   - bash tab-completion for `selfdefctl` covering 14 top-level
#     subcommands + nested action menus
#   - a `sdhelp-menu` quick-help function (categorized command
#     groupings)
#
# The sentinel pattern means edits OUTSIDE the sentinels survive every
# install/uninstall cycle (operator-anti-destruction discipline,
# matching the sovereign-os R447 contract).
#
# Verbs:
#   install     idempotent install (re-run replaces block)
#   uninstall   reversible (keeps .selfdef-bashrc-bak backup)
#   status      show installed block + checksums
#   dump        print the managed block to stdout
#
# Env vars:
#   SELFDEF_BASHRC_PATH    target bashrc path (default ~/.bashrc;
#                          set to ~/.zshrc on zsh)
#   SELFDEF_BASHRC_DRY_RUN logs intent; no file writes
#   SOVEREIGN_OS_DRY_RUN   same effect (cross-repo sovereign-wide
#                          env name honored for operator convenience)
#
# Exit codes:
#   0  ok
#   1  unknown verb
#   2  file-write failed
#   3  not idempotent — sentinel block already present + --no-replace

set -euo pipefail

readonly BLOCK_BEGIN="# >>> selfdef-bashrc (SD-R-BASHRC-1) begin >>>"
readonly BLOCK_END="# <<< selfdef-bashrc (SD-R-BASHRC-1) end <<<"
readonly DEFAULT_BASHRC="${HOME}/.bashrc"
readonly BACKUP_SUFFIX=".selfdef-bashrc-bak"
readonly DRY_RUN="${SELFDEF_BASHRC_DRY_RUN:-${SOVEREIGN_OS_DRY_RUN:-}}"

bashrc_path() {
  echo "${SELFDEF_BASHRC_PATH:-${DEFAULT_BASHRC}}"
}

generate_block() {
  cat <<'EOBLOCK'
# >>> selfdef-bashrc (SD-R-BASHRC-1) begin >>>
# Managed by `selfdefctl-bashrc-install.sh`. Edits OUTSIDE this block
# survive uninstall/reinstall. Operator §1g cross-repo (E11.M6).

# --- Operator-discoverable aliases ---
alias sdctl='selfdefctl'
alias sdstatus='selfdefctl status'
alias sdmodules='selfdefctl modules list'
alias sddoctor='selfdefctl doctor'
alias sdcheck='selfdefctl modules check'
alias sdevents='selfdefctl events tail'
alias sdkeys='selfdefctl keys list'
alias sdrbac='selfdefctl rbac check'
alias sdnotify='selfdefctl notify list'
alias sdinit='selfdefctl init checklist'

# --- Quick-help menu (categorized) ---
sdhelp-menu() {
  cat <<'EOH'
selfdefctl — operator quick reference (SD-R-BASHRC-1)

  Daemon              sdctl status         (overall daemon state)
                      sdctl reload         (SIGHUP — rules reload)

  Events              sdevents             (tail event stream)
                      sdctl events list    (paged history)
                      sdctl events get <id>

  Modules             sdmodules            (list modules)
                      sdcheck              (per-module health)
                      sdctl modules info <name>

  Audit / Doctor      sddoctor             (cross-cutting state)
                      sddoctor --json      (CI-friendly output)
                      sdrbac               (k8s RBAC posture)

  Rules / Keys        sdctl rules list
                      sdkeys               (operator signing keys)

  Notify              sdnotify             (pending escalations)
                      sdctl notify ack <id>
                      sdctl notify forget <id>

  Init / Bootstrap    sdinit               (first-run checklist)
                      sdctl init config    (write starter daemon cfg)
                      sdctl init modules   (write starter modules cfg)

  Forensics           sdctl forensics list
                      sdctl forensics get <id>

  API surface         sdctl api token-rotate

  Cross-repo          sovereign-osctl bashrc status (R447 sister surface)

EOH
}

# --- Tab completion ---
_selfdefctl_complete() {
  local cur prev words cword
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local top_verbs="status events reload rules panic forensics modules api notify keys rbac doctor init version --config --help"
  case "${prev}" in
    selfdefctl)
      mapfile -t COMPREPLY < <(compgen -W "${top_verbs}" -- "${cur}")
      return 0
      ;;
    events)
      mapfile -t COMPREPLY < <(compgen -W "list tail get" -- "${cur}")
      return 0
      ;;
    rules)
      mapfile -t COMPREPLY < <(compgen -W "list show enable disable check-sig" -- "${cur}")
      return 0
      ;;
    forensics)
      mapfile -t COMPREPLY < <(compgen -W "list get create" -- "${cur}")
      return 0
      ;;
    modules)
      mapfile -t COMPREPLY < <(compgen -W "list info check apply" -- "${cur}")
      return 0
      ;;
    api)
      mapfile -t COMPREPLY < <(compgen -W "token-rotate token-show" -- "${cur}")
      return 0
      ;;
    notify)
      mapfile -t COMPREPLY < <(compgen -W "list ack forget" -- "${cur}")
      return 0
      ;;
    keys)
      mapfile -t COMPREPLY < <(compgen -W "list gen import" -- "${cur}")
      return 0
      ;;
    rbac)
      mapfile -t COMPREPLY < <(compgen -W "check report" -- "${cur}")
      return 0
      ;;
    init)
      mapfile -t COMPREPLY < <(compgen -W "config modules checklist" -- "${cur}")
      return 0
      ;;
    doctor)
      mapfile -t COMPREPLY < <(compgen -W "--json" -- "${cur}")
      return 0
      ;;
  esac
  mapfile -t COMPREPLY < <(compgen -W "${top_verbs}" -- "${cur}")
}
complete -F _selfdefctl_complete selfdefctl
complete -F _selfdefctl_complete sdctl
# <<< selfdef-bashrc (SD-R-BASHRC-1) end <<<
EOBLOCK
}

cmd_install() {
  local path
  path="$(bashrc_path)"
  if [ -n "${DRY_RUN}" ]; then
    echo "DRY-RUN: would install selfdef-bashrc block to ${path}"
    return 0
  fi
  # Backup before mutation (operator-anti-destruction).
  if [ -f "${path}" ]; then
    cp -p "${path}" "${path}${BACKUP_SUFFIX}"
  else
    touch "${path}"
  fi
  # Remove any existing sentinel block (idempotent re-install).
  local tmp
  tmp="$(mktemp)"
  awk -v B="${BLOCK_BEGIN}" -v E="${BLOCK_END}" '
    $0 == B { skipping=1; next }
    $0 == E { skipping=0; next }
    !skipping { print }
  ' "${path}" > "${tmp}"
  generate_block >> "${tmp}"
  mv "${tmp}" "${path}"
  echo "installed selfdef-bashrc block at ${path}"
  echo "backup: ${path}${BACKUP_SUFFIX}"
  echo "re-source: source ${path}   (or open a new shell)"
}

cmd_uninstall() {
  local path
  path="$(bashrc_path)"
  if [ ! -f "${path}" ]; then
    echo "no bashrc at ${path}; nothing to remove"
    return 0
  fi
  if [ -n "${DRY_RUN}" ]; then
    echo "DRY-RUN: would remove sentinel block from ${path}"
    return 0
  fi
  cp -p "${path}" "${path}${BACKUP_SUFFIX}"
  local tmp
  tmp="$(mktemp)"
  awk -v B="${BLOCK_BEGIN}" -v E="${BLOCK_END}" '
    $0 == B { skipping=1; next }
    $0 == E { skipping=0; next }
    !skipping { print }
  ' "${path}" > "${tmp}"
  mv "${tmp}" "${path}"
  echo "uninstalled selfdef-bashrc block from ${path}"
  echo "backup: ${path}${BACKUP_SUFFIX}"
}

cmd_status() {
  local path
  path="$(bashrc_path)"
  if [ ! -f "${path}" ]; then
    echo "no bashrc at ${path} — not installed"
    return 0
  fi
  if grep -qF "${BLOCK_BEGIN}" "${path}"; then
    local block_lines
    block_lines=$(awk -v B="${BLOCK_BEGIN}" -v E="${BLOCK_END}" '
      $0 == B { in_block=1 }
      in_block { count++ }
      $0 == E { in_block=0 }
      END { print count }
    ' "${path}")
    echo "installed at ${path}"
    echo "block size: ${block_lines} lines"
    if [ -f "${path}${BACKUP_SUFFIX}" ]; then
      echo "backup present: ${path}${BACKUP_SUFFIX}"
    fi
  else
    echo "not installed at ${path}"
  fi
}

cmd_dump() {
  generate_block
}

usage() {
  cat <<EOU
usage: selfdefctl-bashrc-install.sh <install|uninstall|status|dump>

  install     install sentinel-bounded block in ~/.bashrc
              (SELFDEF_BASHRC_PATH env-override; idempotent)
  uninstall   reversible removal (keeps ${BACKUP_SUFFIX} backup)
  status      show installed block presence + line-count
  dump        print the managed block to stdout

  Env:
    SELFDEF_BASHRC_PATH      target file (default ~/.bashrc)
    SELFDEF_BASHRC_DRY_RUN   logs intent; no writes
    SOVEREIGN_OS_DRY_RUN     cross-repo dry-run honored

Cross-repo binding: SD-R-BASHRC-1 (sovereign-os R447 sister surface).
EOU
}

main() {
  local verb="${1:-}"
  case "${verb}" in
    install)   cmd_install ;;
    uninstall) cmd_uninstall ;;
    status)    cmd_status ;;
    dump)      cmd_dump ;;
    -h|--help|help|"") usage ;;
    *)
      echo "unknown verb: ${verb}" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
