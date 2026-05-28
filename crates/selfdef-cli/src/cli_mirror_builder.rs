//! `selfdef-cli-mirror` PRODUCER — walks the live clap App tree the
//! binary actually exposes and projects it into the wire-stable
//! [`CliMirrorSnapshot`] the sovereign-os D-XX cockpit consumes
//! (introspection / completion / "how do I do X" cross-links).
//!
//! Self-introspection design: the source of truth is the clap App
//! defined in `main.rs` itself, so any new subcommand the operator adds
//! shows up in the mirror with zero parallel hand-maintained metadata.
//! Effect class + min_authority + requires_signature + p95_target_ms
//! are inferred from the leaf-verb name + the parent command via a
//! deterministic classifier (see [`classify_effect`]).
//!
//! Per MS043 R10297 (verbatim):
//!
//! > "Fullstack at the edges"
//!
//! Per MS043 R10281: schema published READ-ONLY; the daemon owns
//! subcommand registration. Consumers MUST NOT synthesize invocations
//! beyond the published schema.

use clap::{Arg, ArgAction, Command};
use selfdef_cli_mirror::{
    ArgKind, ArgSpec, CliMirrorSnapshot, DOCTRINE_FULLSTACK_AT_THE_EDGES, EffectClass,
    SCHEMA_VERSION, SubcommandEntry,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Build the CliMirrorSnapshot from a live clap App. The caller is
/// expected to pass the same `Command` the binary was built with so
/// the snapshot reflects exactly the surface the operator can invoke.
#[must_use]
pub(crate) fn build_snapshot(app: &Command) -> CliMirrorSnapshot {
    let mut subcommands = Vec::new();
    walk(app, "", &mut subcommands);
    // Build summaries by counting per effect class.
    let summaries = recompute_effect_summaries(&subcommands);
    CliMirrorSnapshot {
        schema_version: SCHEMA_VERSION.into(),
        cli_build_version: env!("CARGO_PKG_VERSION").into(),
        doctrine: DOCTRINE_FULLSTACK_AT_THE_EDGES.into(),
        captured_at: now_rfc3339(),
        summaries,
        subcommands,
        // Signature is computed by the daemon-side signer (MS003 verify-
        // only doctrine: operators sign externally with minisign; the
        // selfdef-signing crate does not have a programmatic signer).
        // We leave this empty for the publisher pipeline to fill.
        signature: String::new(),
    }
}

/// Recursively walk a clap Command tree, projecting each LEAF
/// subcommand into a SubcommandEntry. Non-leaf intermediate commands
/// (e.g. `selfdefctl trust-scores` parent of `trust-scores admit`)
/// are not emitted — the dot-separated path captures the hierarchy.
fn walk(cmd: &Command, prefix: &str, out: &mut Vec<SubcommandEntry>) {
    let subs: Vec<&Command> = cmd.get_subcommands().collect();
    if subs.is_empty() && !prefix.is_empty() {
        // Leaf — emit this node.
        let path = prefix.to_string();
        let help_summary = cmd.get_about().map_or_else(String::new, |a| a.to_string());
        let help_long = cmd
            .get_long_about()
            .map_or_else(|| help_summary.clone(), |a| a.to_string());
        let (effect_class, min_authority, requires_signature, p95_target_ms) =
            classify_effect(&path, &help_summary, cmd);
        let args = cmd.get_arguments().map(project_arg).collect();
        let mirror = infer_mirror(&path);
        out.push(SubcommandEntry {
            path,
            help_summary,
            help_long,
            effect_class,
            min_authority: min_authority.into(),
            args,
            mirror,
            requires_signature,
            p95_target_ms,
            signature: String::new(),
        });
        return;
    }
    // Non-leaf — descend.
    for sub in subs {
        let name = sub.get_name();
        // Skip auto-generated `help`.
        if name == "help" {
            continue;
        }
        let new_prefix = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        walk(sub, &new_prefix, out);
    }
}

fn project_arg(a: &Arg) -> ArgSpec {
    let kind = match a.get_action() {
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count => ArgKind::Flag,
        ArgAction::Append => ArgKind::MultiOption,
        ArgAction::Set => {
            if a.is_positional() {
                ArgKind::Positional
            } else {
                ArgKind::Option
            }
        }
        _ => {
            if a.is_positional() {
                ArgKind::Positional
            } else {
                ArgKind::Option
            }
        }
    };
    ArgSpec {
        name: a.get_id().to_string(),
        kind,
        required: a.is_required_set(),
        help: a.get_help().map_or_else(String::new, |h| h.to_string()),
        default: a
            .get_default_values()
            .first()
            .map(|v| v.to_string_lossy().into_owned()),
        allowed_values: a
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_string())
            .collect(),
    }
}

/// Classify a leaf subcommand path → (effect_class, min_authority,
/// requires_signature, p95_target_ms). Deterministic, doctrine-rooted
/// per MS039 authority levels + MS043 R10286 latency targets.
fn classify_effect(
    path: &str,
    help: &str,
    cmd: &Command,
) -> (EffectClass, &'static str, bool, u32) {
    let path_lower = path.to_ascii_lowercase();
    let last_segment = path_lower.rsplit('.').next().unwrap_or(&path_lower);

    // Heuristics first by leaf verb, then by full path.

    // Destructive — irreversible (R10212 + operator-confirm gate).
    if matches!(
        last_segment,
        "forfeit" | "purge" | "rollback" | "destroy" | "wipe" | "delete" | "delete-all"
    ) || path_lower.contains("--purge")
    {
        return (EffectClass::Destructive, "l5_commit", true, 5000);
    }

    // Commit — durable change with receipt + operator MS003 signature.
    if matches!(
        last_segment,
        "issue"
            | "revoke"
            | "admit"
            | "set"
            | "switch"
            | "operator-delta"
            | "release"
            | "checkpoint"
            | "allocate"
            | "rotate"
            | "trust"
    ) {
        return (EffectClass::Commit, "l5_commit", true, 1500);
    }

    // Execute — ephemeral side effect (process kill, sandbox run).
    if matches!(
        last_segment,
        "run" | "exec" | "start" | "stop" | "panic" | "trigger" | "kill"
    ) {
        return (EffectClass::Execute, "l4_execute", true, 1000);
    }

    // Prepare — stages durable change awaiting commit.
    if matches!(
        last_segment,
        "prepare" | "stage" | "plan" | "propose" | "draft"
    ) {
        return (EffectClass::Prepare, "l3_prepare", true, 800);
    }

    // Simulate — dry-run with side-effect equivalence.
    if matches!(last_segment, "simulate" | "dry-run") {
        return (EffectClass::Simulate, "l2_simulate", false, 500);
    }

    // Diagnostic — runs probes / health checks / m060-doctor / friction-audit.
    if matches!(
        last_segment,
        "doctor" | "verify" | "check" | "audit" | "smoke" | "probe"
    ) || path_lower.starts_with("m060-doctor")
    {
        return (EffectClass::Diagnostic, "l1_suggest", false, 800);
    }

    // Default: read-only. Includes show / list / snapshot / summaries
    // / status / integrity / show / get / inspect / trace / history.
    let _ = (help, cmd);
    (EffectClass::ReadOnly, "l0_observe", false, 250)
}

/// Infer which selfdef-XXX-mirror this subcommand operates against,
/// based on the path prefix. Empty when no mirror association.
fn infer_mirror(path: &str) -> String {
    let prefix = path.split('.').next().unwrap_or("");
    let prefix_lc = prefix.to_ascii_lowercase();
    match prefix_lc.as_str() {
        "grants" => "selfdef-grants-mirror".into(),
        "capability-tokens" | "capability-tokens-registry" => "selfdef-capability-mirror".into(),
        "sandboxes" | "sandbox-registry" => "selfdef-sandbox-mirror".into(),
        "quarantine" => "selfdef-quarantine-mirror".into(),
        "trust-scores" => "selfdef-trust-score-mirror".into(),
        "audit-chains" => "selfdef-audit-mirror".into(),
        "rules-mirror" => "selfdef-rules-mirror".into(),
        "flex-profile" | "profile" => "selfdef-profile-mirror".into(),
        "friction-audit" => "selfdef-friction-audit-mirror".into(),
        "perimeter" => "selfdef-perimeter-mirror".into(),
        "guardian" => "selfdef-guardian-mirror".into(),
        "scheduler" => "selfdef-scheduler-mirror".into(),
        _ => String::new(),
    }
}

fn recompute_effect_summaries(subs: &[SubcommandEntry]) -> Vec<selfdef_cli_mirror::EffectSummary> {
    use std::collections::HashMap;
    let mut by_class: HashMap<EffectClass, u32> = HashMap::new();
    for s in subs {
        *by_class.entry(s.effect_class).or_insert(0) += 1;
    }
    let mut out: Vec<_> = by_class
        .into_iter()
        .map(|(effect, count)| selfdef_cli_mirror::EffectSummary { effect, count })
        .collect();
    // Order by EffectClass discriminant for stable output.
    out.sort_by_key(|s| effect_class_order(s.effect));
    out
}

fn effect_class_order(c: EffectClass) -> u8 {
    match c {
        EffectClass::ReadOnly => 0,
        EffectClass::Diagnostic => 1,
        EffectClass::Simulate => 2,
        EffectClass::Prepare => 3,
        EffectClass::Execute => 4,
        EffectClass::Commit => 5,
        EffectClass::Persist => 6,
        EffectClass::Destructive => 7,
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command};

    fn test_app() -> Command {
        Command::new("test")
            .subcommand(
                Command::new("grants")
                    .subcommand(
                        Command::new("show")
                            .about("Show grants")
                            .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
                    )
                    .subcommand(
                        Command::new("issue")
                            .about("Issue a grant")
                            .arg(Arg::new("scope").long("scope").required(true)),
                    )
                    .subcommand(
                        Command::new("revoke")
                            .about("Revoke a grant")
                            .arg(Arg::new("grant-id").long("grant-id").required(true)),
                    ),
            )
            .subcommand(
                Command::new("trust-scores")
                    .subcommand(Command::new("admit").about("Admit a tool"))
                    .subcommand(Command::new("show").about("Show scores")),
            )
            .subcommand(
                Command::new("quarantine").subcommand(
                    Command::new("forfeit").about("Forfeit + purge a quarantined item"),
                ),
            )
            .subcommand(Command::new("doctor").about("Run diagnostics"))
            .subcommand(
                Command::new("rules-mirror")
                    .subcommand(Command::new("status").about("D-12 rules health status"))
                    .subcommand(Command::new("list").about("Flat rule table")),
            )
    }

    fn snap() -> CliMirrorSnapshot {
        build_snapshot(&test_app())
    }

    #[test]
    fn snapshot_carries_schema_version_and_doctrine_verbatim() {
        let s = snap();
        assert_eq!(s.schema_version, SCHEMA_VERSION);
        assert_eq!(s.doctrine, DOCTRINE_FULLSTACK_AT_THE_EDGES);
        assert!(!s.cli_build_version.is_empty());
        assert!(s.captured_at.contains('T'));
        assert!(s.captured_at.ends_with('Z'));
    }

    #[test]
    fn snapshot_lists_each_leaf_subcommand() {
        let s = snap();
        let paths: Vec<&str> = s.subcommands.iter().map(|e| e.path.as_str()).collect();
        for expected in [
            "grants.show",
            "grants.issue",
            "grants.revoke",
            "trust-scores.admit",
            "trust-scores.show",
            "quarantine.forfeit",
            "doctor",
            "rules-mirror.status",
            "rules-mirror.list",
        ] {
            assert!(
                paths.contains(&expected),
                "missing path {expected} in {paths:?}"
            );
        }
    }

    #[test]
    fn snapshot_skips_intermediate_nodes() {
        // "grants" and "trust-scores" are non-leaf — must not appear.
        let s = snap();
        let paths: Vec<&str> = s.subcommands.iter().map(|e| e.path.as_str()).collect();
        assert!(!paths.contains(&"grants"));
        assert!(!paths.contains(&"trust-scores"));
        assert!(!paths.contains(&"rules-mirror"));
    }

    #[test]
    fn snapshot_skips_auto_help_subcommand() {
        let s = snap();
        assert!(!s.subcommands.iter().any(|e| e.path == "help"));
        assert!(!s.subcommands.iter().any(|e| e.path.ends_with(".help")));
    }

    #[test]
    fn show_is_read_only_with_l0_observe_no_signature() {
        let s = snap();
        let show = s
            .subcommands
            .iter()
            .find(|e| e.path == "grants.show")
            .unwrap();
        assert_eq!(show.effect_class, EffectClass::ReadOnly);
        assert_eq!(show.min_authority, "l0_observe");
        assert!(!show.requires_signature);
        assert!(show.p95_target_ms <= 500);
    }

    #[test]
    fn issue_is_commit_with_l5_commit_signature_required() {
        let s = snap();
        let issue = s
            .subcommands
            .iter()
            .find(|e| e.path == "grants.issue")
            .unwrap();
        assert_eq!(issue.effect_class, EffectClass::Commit);
        assert_eq!(issue.min_authority, "l5_commit");
        assert!(issue.requires_signature);
    }

    #[test]
    fn forfeit_is_destructive_with_l5_commit_signature_required() {
        let s = snap();
        let f = s
            .subcommands
            .iter()
            .find(|e| e.path == "quarantine.forfeit")
            .unwrap();
        assert_eq!(f.effect_class, EffectClass::Destructive);
        assert!(f.requires_signature);
        assert!(f.p95_target_ms >= 1000);
    }

    #[test]
    fn doctor_is_diagnostic() {
        let s = snap();
        let d = s.subcommands.iter().find(|e| e.path == "doctor").unwrap();
        assert_eq!(d.effect_class, EffectClass::Diagnostic);
        assert_eq!(d.min_authority, "l1_suggest");
        assert!(!d.requires_signature);
    }

    #[test]
    fn mirror_inferred_from_path_prefix() {
        let s = snap();
        let g = s
            .subcommands
            .iter()
            .find(|e| e.path == "grants.show")
            .unwrap();
        assert_eq!(g.mirror, "selfdef-grants-mirror");
        let t = s
            .subcommands
            .iter()
            .find(|e| e.path == "trust-scores.admit")
            .unwrap();
        assert_eq!(t.mirror, "selfdef-trust-score-mirror");
        let r = s
            .subcommands
            .iter()
            .find(|e| e.path == "rules-mirror.status")
            .unwrap();
        assert_eq!(r.mirror, "selfdef-rules-mirror");
        let d = s.subcommands.iter().find(|e| e.path == "doctor").unwrap();
        assert_eq!(d.mirror, ""); // unmapped prefix
    }

    #[test]
    fn args_projected_with_correct_kind() {
        let s = snap();
        let issue = s
            .subcommands
            .iter()
            .find(|e| e.path == "grants.issue")
            .unwrap();
        let scope = issue.args.iter().find(|a| a.name == "scope").unwrap();
        assert_eq!(scope.kind, ArgKind::Option);
        assert!(scope.required);
        let show = s
            .subcommands
            .iter()
            .find(|e| e.path == "grants.show")
            .unwrap();
        let jflag = show.args.iter().find(|a| a.name == "json").unwrap();
        assert_eq!(jflag.kind, ArgKind::Flag);
    }

    #[test]
    fn summaries_count_matches_effect_class_distribution() {
        let s = snap();
        let total_via_summaries: u32 = s.summaries.iter().map(|x| x.count).sum();
        assert_eq!(total_via_summaries as usize, s.subcommands.len());
        // Order is by effect_class discriminant — stable for clients.
        let order: Vec<u8> = s
            .summaries
            .iter()
            .map(|x| effect_class_order(x.effect))
            .collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
    }

    #[test]
    fn validate_schema_and_doctrine_pass_on_built_snapshot() {
        let s = snap();
        s.validate_schema().unwrap();
        s.validate_doctrine().unwrap();
    }

    #[test]
    fn build_snapshot_is_deterministic_modulo_timestamp() {
        // captured_at differs; everything else should match.
        let a = snap();
        let b = snap();
        assert_eq!(a.schema_version, b.schema_version);
        assert_eq!(a.doctrine, b.doctrine);
        assert_eq!(a.subcommands, b.subcommands);
        assert_eq!(a.summaries, b.summaries);
    }
}
