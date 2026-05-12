//! Rule lint: opinionated checks that catch missing metadata, duplicated
//! IDs, condition typos, missing ATT&CK tags, and other surface mistakes.
//!
//! Run via `selfdefctl rules lint`, or in CI by loading the rule set and
//! calling [`lint_rules`].

use std::collections::HashMap;

use crate::sigma::{CompiledRule, Condition};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Issue {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.severity {
            Severity::Error => "ERROR",
            Severity::Warn => "WARN",
        };
        write!(f, "{:<5} [{}] {}", tag, self.rule_id, self.message)
    }
}

/// Lint the rule set as a whole. Cross-rule issues (e.g. duplicate IDs)
/// are emitted in addition to per-rule issues.
#[must_use]
pub fn lint_rules(rules: &[CompiledRule]) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut seen_ids: HashMap<&str, usize> = HashMap::new();
    for rule in rules {
        *seen_ids.entry(rule.id.as_str()).or_insert(0) += 1;
        out.extend(lint_rule(rule));
    }
    for (id, count) in &seen_ids {
        if *count > 1 {
            out.push(Issue {
                rule_id: (*id).to_string(),
                severity: Severity::Error,
                message: format!("duplicate rule id (appears in {count} rule files)"),
            });
        }
    }
    out
}

#[must_use]
pub fn lint_rule(rule: &CompiledRule) -> Vec<Issue> {
    let mut out = Vec::new();

    if rule.title.trim().is_empty() {
        out.push(error(rule, "title is empty"));
    }
    if rule.description.as_deref().unwrap_or("").trim().is_empty() {
        out.push(warn(rule, "missing or empty `description`"));
    }
    if rule.tags.is_empty() {
        out.push(warn(
            rule,
            "no tags; rules should carry at least one `attack.*` tag",
        ));
    } else {
        let has_attack = rule.tags.iter().any(|t| t.starts_with("attack."));
        if !has_attack {
            out.push(warn(
                rule,
                "no `attack.*` tag; ATT&CK coverage will not increase",
            ));
        }
        let has_technique = rule.tags.iter().any(|t| {
            t.strip_prefix("attack.t")
                .is_some_and(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
        });
        if !has_technique {
            out.push(warn(rule, "no `attack.tNNNN[.NNN]` technique tag"));
        }
    }
    if rule.falsepositives.is_empty() {
        out.push(warn(
            rule,
            "no `falsepositives` documented; high-confidence rules should still list known FP sources",
        ));
    }
    if rule.author.is_none() {
        out.push(warn(rule, "no `author` field"));
    }

    // Sanity check on the condition: the named selection must exist in `matchers`.
    let referenced = match &rule.condition {
        Condition::Single(n) => n,
        Condition::Count { selection, .. } => selection,
    };
    if !rule.matchers.contains_key(referenced) {
        out.push(error(
            rule,
            &format!("condition references undefined selection `{referenced}`"),
        ));
    }

    // Count-by field must look like a known event path.
    if let Condition::Count { group_by_field, .. } = &rule.condition {
        if !looks_like_event_path(group_by_field) {
            out.push(warn(
                rule,
                &format!(
                    "count() by `{group_by_field}` doesn't look like a known event field — \
                     typo? known top-level fields include src_endpoint, dst_endpoint, actor, file, process"
                ),
            ));
        }
    }

    out
}

fn error(rule: &CompiledRule, msg: &str) -> Issue {
    Issue {
        rule_id: rule.id.clone(),
        severity: Severity::Error,
        message: msg.to_string(),
    }
}
fn warn(rule: &CompiledRule, msg: &str) -> Issue {
    Issue {
        rule_id: rule.id.clone(),
        severity: Severity::Warn,
        message: msg.to_string(),
    }
}

fn looks_like_event_path(path: &str) -> bool {
    const KNOWN_ROOTS: &[&str] = &[
        "src_endpoint",
        "dst_endpoint",
        "actor",
        "file",
        "process",
        "network",
        "host_tag",
        "source",
        "metadata",
        "raw",
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "severity_id",
        "status_id",
        "message",
        "schema",
        "id",
        "time_dt",
    ];
    let root = path.split('.').next().unwrap_or("");
    KNOWN_ROOTS.contains(&root)
}
