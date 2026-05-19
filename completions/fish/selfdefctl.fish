# selfdefctl fish completion
# Install: /usr/share/fish/vendor_completions.d/selfdefctl.fish
# Per MS043 R10134.

# disable file completion at top level (subcommands first)
complete -c selfdefctl -f

# top-level subcommand namespaces (mirrors selfdef-cli-mirror surface)
complete -c selfdefctl -n "__fish_use_subcommand" -a "grant"      -d "grant lifecycle (filesystem/network/capability/communication/sandbox)"
complete -c selfdefctl -n "__fish_use_subcommand" -a "token"      -d "capability_word token lifecycle"
complete -c selfdefctl -n "__fish_use_subcommand" -a "rule"       -d "nftables ruleset (Ring 0..4)"
complete -c selfdefctl -n "__fish_use_subcommand" -a "sandbox"    -d "MS036 Tier A/B/C/D allocations"
complete -c selfdefctl -n "__fish_use_subcommand" -a "quarantine" -d "MS042 declaration-vs-observed triage"
complete -c selfdefctl -n "__fish_use_subcommand" -a "trust"      -d "per-tool trust score (0..1000)"
complete -c selfdefctl -n "__fish_use_subcommand" -a "audit"      -d "MS009 audit chain inspection"
complete -c selfdefctl -n "__fish_use_subcommand" -a "rollback"   -d "rollback preview + apply (ZFS + MS041 receipts)"
complete -c selfdefctl -n "__fish_use_subcommand" -a "snapshot"   -d "ZFS snapshot management"
complete -c selfdefctl -n "__fish_use_subcommand" -a "commit"     -d "MS041 commit log + receipt inspection"
complete -c selfdefctl -n "__fish_use_subcommand" -a "notify"     -d "12-channel notification triage"
complete -c selfdefctl -n "__fish_use_subcommand" -a "config"     -d "daemon configuration"
complete -c selfdefctl -n "__fish_use_subcommand" -a "status"     -d "system overview surfaces"
complete -c selfdefctl -n "__fish_use_subcommand" -a "version"    -d "build identity"

# second-level — grant
complete -c selfdefctl -n "__fish_seen_subcommand_from grant" -a "list request approve deny revoke inspect"
# second-level — token
complete -c selfdefctl -n "__fish_seen_subcommand_from token" -a "list mint derive revoke inspect trace"
# second-level — rule
complete -c selfdefctl -n "__fish_seen_subcommand_from rule" -a "list add remove inspect reload"
# second-level — sandbox
complete -c selfdefctl -n "__fish_seen_subcommand_from sandbox" -a "list allocate checkpoint resume release"
# second-level — quarantine
complete -c selfdefctl -n "__fish_seen_subcommand_from quarantine" -a "list inspect trace release forfeit"
# second-level — trust
complete -c selfdefctl -n "__fish_seen_subcommand_from trust" -a "list show adjust forfeit"
# second-level — audit
complete -c selfdefctl -n "__fish_seen_subcommand_from audit" -a "tail verify export"
# second-level — rollback
complete -c selfdefctl -n "__fish_seen_subcommand_from rollback" -a "preview apply"
# second-level — snapshot
complete -c selfdefctl -n "__fish_seen_subcommand_from snapshot" -a "list create diff prune"
# second-level — commit
complete -c selfdefctl -n "__fish_seen_subcommand_from commit" -a "log inspect"
# second-level — notify
complete -c selfdefctl -n "__fish_seen_subcommand_from notify" -a "resend list-channels"
# second-level — config
complete -c selfdefctl -n "__fish_seen_subcommand_from config" -a "get set list"
# second-level — status
complete -c selfdefctl -n "__fish_seen_subcommand_from status" -a "overview ring tier audit-chain"

# flag value completions
complete -c selfdefctl -l ring        -d "Ring 0..4"             -xa "ring0 ring1 ring2 ring3 ring4"
complete -c selfdefctl -l tier        -d "MS036 tier"            -xa "A B C D"
complete -c selfdefctl -l kind        -d "grant kind"            -xa "filesystem network capability communication sandbox"
complete -c selfdefctl -l verdict     -d "rule verdict"          -xa "allow deny log"
complete -c selfdefctl -l authority   -d "MS039 authority level" -xa "l0_observe l1_suggest l2_simulate l3_prepare l4_execute l5_commit l6_persist"
complete -c selfdefctl -l profile     -d "MS040 profile"         -xa "private fast careful autonomous experimental production"
complete -c selfdefctl -l band        -d "trust band"            -xa "trusted watched suspect untrusted"
complete -c selfdefctl -l severity    -d "mismatch severity"     -xa "informational minor major critical"
complete -c selfdefctl -l output -s o -d "output format"         -xa "json yaml text"

# generic flags
complete -c selfdefctl -l help    -s h -d "show help"
complete -c selfdefctl -l json         -d "JSON output"
complete -c selfdefctl -l yaml         -d "YAML output"
complete -c selfdefctl -l watch        -d "continuous updates"
complete -c selfdefctl -l quiet  -s q  -d "suppress non-essential output"
complete -c selfdefctl -l verbose -s v -d "verbose output"
complete -c selfdefctl -l dry-run      -d "simulate, no side effects"
complete -c selfdefctl -l confirm      -d "confirm destructive action"
complete -c selfdefctl -l signed-by    -d "operator fingerprint"
complete -c selfdefctl -l reason       -d "audit reason (non-empty per MS041 R09657)"
complete -c selfdefctl -l ttl          -d "TTL (e.g. 1h, 30m)"
complete -c selfdefctl -l since        -d "time window start"
complete -c selfdefctl -l until        -d "time window end"
