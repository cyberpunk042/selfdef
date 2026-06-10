//! Sigma-subset rule engine.
//!
//! Supports the subset of [Sigma](https://sigmahq.io/) needed for selfdef's
//! initial rule set:
//!
//! - **Metadata**: `id`, `title`, `description`, `level`, `tags`, `author`,
//!   `references`, `falsepositives`, `status`, `date`.
//! - **logsource** filter (optional `product`, `service`).
//! - **detection.<selection>**: map of `field` → value or list of values.
//!   - Modifiers via `field|contains`, `field|startswith`, `field|endswith`,
//!     `field|re`.
//!   - Dot-notation for nested fields: `src_endpoint.ip`, `actor.user.name`.
//!   - List of values = logical OR within the field.
//! - **detection.timeframe**: e.g. `60s`, `5m`, `1h`.
//! - **detection.condition**: one of
//!   - `<selection_name>` — fire on any event matching the selection.
//!   - `<selection_name> | count() by <field> > <N>` — fire when MORE THAN `N`
//!     matches (i.e. the `N+1`-th) share a value of `<field>` within
//!     `timeframe`. The `>` is strict: `> 5` fires on the 6th match, not the
//!     5th (matching standard Sigma `count()` semantics).
//!
//! Complex boolean conditions (`and`, `or`, `not`, multiple selections) are
//! a later milestone.

#![allow(clippy::module_name_repetitions)]

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use regex::Regex;
use selfdef_core::attack::{Tactic, TechniqueRef};
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

const FINDING_CREATE: u32 = 1;

#[derive(Debug, Error)]
pub enum SigmaError {
    #[error("yaml parse error in {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid rule {id}: {reason}")]
    InvalidRule { id: String, reason: String },
    #[error("invalid regex: {0}")]
    Regex(#[from] regex::Error),
    #[error("invalid timeframe: {0}")]
    InvalidTimeframe(String),
    #[error("invalid condition: {0}")]
    InvalidCondition(String),
    /// SDD-004: rule signature did not verify under the
    /// configured public key (only emitted when
    /// `[security].require_signed_rules = true`).
    #[error("signature check failed for {path}: {source}")]
    Signature {
        path: PathBuf,
        #[source]
        source: selfdef_signing::SigningError,
    },
}

// ============================================================ raw YAML

#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub level: SigmaLevel,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
    #[serde(default)]
    pub logsource: LogSource,
    pub detection: RawDetection,
}

#[derive(Debug, Default, Deserialize)]
pub struct LogSource {
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum SigmaLevel {
    Informational,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl SigmaLevel {
    pub const fn to_severity(self) -> SeverityId {
        match self {
            Self::Informational => SeverityId::Informational,
            Self::Low => SeverityId::Low,
            Self::Medium => SeverityId::Medium,
            Self::High => SeverityId::High,
            Self::Critical => SeverityId::Critical,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RawDetection {
    #[serde(flatten)]
    pub selections: HashMap<String, serde_yaml_ng::Value>,
    #[serde(default)]
    pub timeframe: Option<String>,
    pub condition: String,
}

// ============================================================ compiled

#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub level: SigmaLevel,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub author: Option<String>,
    pub falsepositives: Vec<String>,
    pub logsource: LogSource,
    pub source_path: PathBuf,

    pub matchers: HashMap<String, SelectionMatcher>,
    pub condition: Condition,
    pub timeframe: Option<Duration>,

    /// Aggregator state (if condition uses `count() by`).
    pub aggregator: Option<Aggregator>,
}

#[derive(Debug)]
pub enum Condition {
    /// Fire on any event matching the named selection.
    Single(String),
    /// Fire when the count of matching events sharing the same value of
    /// `group_by_field` within `timeframe` STRICTLY EXCEEDS `threshold` (i.e.
    /// on the `threshold + 1`-th match — `Aggregator::observe` fires on
    /// `len > threshold`, matching the strict `> N` Sigma syntax).
    Count {
        selection: String,
        group_by_field: String,
        threshold: u32,
    },
}

// ---------------------------------- selection matcher

#[derive(Debug)]
pub struct SelectionMatcher {
    fields: Vec<FieldClause>,
}

#[derive(Debug)]
pub struct FieldClause {
    path: String,
    op: FieldOp,
    /// Multiple values = OR within the clause.
    values: Vec<MatchValue>,
}

#[derive(Debug, Clone, Copy)]
pub enum FieldOp {
    Eq,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

#[derive(Debug)]
pub enum MatchValue {
    String(String),
    Int(i64),
    Bool(bool),
    Regex(Regex),
}

impl MatchValue {
    fn matches_json(&self, v: &serde_json::Value, op: FieldOp) -> bool {
        // Sigma compares strings case-insensitively by default (only the `|re`
        // modifier is case-sensitive, and it carries its own `(?i)` if needed).
        // Folding ASCII case here covers the fields these rules key on — process
        // images, binary paths, syscall names — without which a rule written as
        // `...|endswith: '\powershell.exe'` would silently miss `PowerShell.EXE`.
        match (self, op) {
            (Self::String(s), FieldOp::Eq) => v.as_str().is_some_and(|x| x.eq_ignore_ascii_case(s)),
            (Self::String(s), FieldOp::Contains) => v
                .as_str()
                .is_some_and(|x| x.to_ascii_lowercase().contains(&s.to_ascii_lowercase())),
            (Self::String(s), FieldOp::StartsWith) => v
                .as_str()
                .is_some_and(|x| x.to_ascii_lowercase().starts_with(&s.to_ascii_lowercase())),
            (Self::String(s), FieldOp::EndsWith) => v
                .as_str()
                .is_some_and(|x| x.to_ascii_lowercase().ends_with(&s.to_ascii_lowercase())),
            (Self::Int(n), FieldOp::Eq) => v.as_i64() == Some(*n) || v.as_u64() == Some(*n as u64),
            (Self::Bool(b), FieldOp::Eq) => v.as_bool() == Some(*b),
            (Self::Regex(r), FieldOp::Regex) => v.as_str().is_some_and(|x| r.is_match(x)),
            _ => false,
        }
    }
}

// ---------------------------------- aggregator

/// Run an opportunistic stale-group sweep once every this many observations.
/// The aggregator keys on `group_by_field` (e.g. source IP, username, pid),
/// which is attacker-influenced: a flood of distinct one-shot values would
/// otherwise park one map entry per value forever, since a group is only
/// pruned when that same key is observed again. Sweeping on a fixed cadence
/// reclaims groups whose newest observation has already aged out of the
/// window, bounding memory to (groups active within the window) + at most one
/// cadence of stragglers. Gated on a counter, not on map size, so the sweep
/// amortizes to O(1) per observe instead of O(n) every call — an O(n)-per-event
/// sweep would make a high-cardinality flood worse, not better.
const GC_EVERY: u64 = 1024;

/// Aggregator state behind the lock: the per-group observation deques plus a
/// monotonic observe counter that drives the periodic GC sweep.
#[derive(Debug, Default)]
struct AggState {
    /// (group key) -> deque of observation times (front = oldest).
    groups: HashMap<String, VecDeque<Instant>>,
    /// Total observations since construction; gates the GC sweep cadence.
    observes: u64,
}

#[derive(Debug)]
pub struct Aggregator {
    state: Mutex<AggState>,
    threshold: u32,
    window: Duration,
}

impl Aggregator {
    fn new(threshold: u32, window: Duration) -> Self {
        Self {
            state: Mutex::new(AggState::default()),
            threshold,
            window,
        }
    }

    /// Returns Some(key) if observation pushes that group over threshold.
    /// Removes the group's entry on fire so we don't double-fire and so a
    /// fired group doesn't leave an empty deque parked in the map.
    ///
    /// `now` is injected (rather than read from `Instant::now()` here) so the
    /// window and GC behaviour are deterministically testable; the production
    /// caller passes `Instant::now()`.
    fn observe(&self, key: String, now: Instant) -> Option<String> {
        let window = self.window;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.observes = state.observes.wrapping_add(1);

        // Periodic GC: drop groups whose most-recent observation is already
        // older than the window. Such a group would prune to empty the next
        // time it is touched, but a group that is never seen again would
        // otherwise linger forever — the unbounded-growth vector for
        // high-cardinality, attacker-influenced group-by values. Active groups
        // (newest observation within the window) are kept, so verdicts are
        // unaffected.
        if state.observes % GC_EVERY == 0 {
            state.groups.retain(|_, q| {
                q.back()
                    .is_some_and(|&last| now.duration_since(last) <= window)
            });
        }

        let queue = state.groups.entry(key.clone()).or_default();
        queue.push_back(now);
        while let Some(&front) = queue.front() {
            if now.duration_since(front) > window {
                queue.pop_front();
            } else {
                break;
            }
        }
        let fired = queue.len() as u32 > self.threshold;
        if fired {
            state.groups.remove(&key);
            Some(key)
        } else {
            None
        }
    }

    /// Number of tracked groups (test-only; asserts the GC bound).
    #[cfg(test)]
    fn group_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .groups
            .len()
    }
}

// ============================================================ compile

pub fn compile_rule(raw: RawRule, source_path: PathBuf) -> Result<CompiledRule, SigmaError> {
    // Parse condition.
    let (condition, threshold_group_by) = parse_condition(&raw.detection.condition)
        .ok_or_else(|| SigmaError::InvalidCondition(raw.detection.condition.clone()))?;

    // Validate the selection named in the condition exists.
    let sel_name = match &condition {
        Condition::Single(n) => n,
        Condition::Count { selection, .. } => selection,
    };
    if !raw.detection.selections.contains_key(sel_name) {
        return Err(SigmaError::InvalidRule {
            id: raw.id.clone(),
            reason: format!("condition references unknown selection '{sel_name}'"),
        });
    }

    // Compile each selection.
    let mut matchers = HashMap::with_capacity(raw.detection.selections.len());
    for (name, value) in raw.detection.selections {
        let matcher =
            compile_selection(&name, value).map_err(|reason| SigmaError::InvalidRule {
                id: raw.id.clone(),
                reason,
            })?;
        matchers.insert(name, matcher);
    }

    let timeframe = raw
        .detection
        .timeframe
        .as_deref()
        .map(parse_duration)
        .transpose()?;

    // If condition is Count, an aggregator is required.
    let aggregator = if let (Condition::Count { threshold, .. }, Some(dur), Some(_)) =
        (&condition, timeframe, threshold_group_by.as_ref())
    {
        Some(Aggregator::new(*threshold, dur))
    } else if matches!(condition, Condition::Count { .. }) {
        return Err(SigmaError::InvalidRule {
            id: raw.id.clone(),
            reason: "count() condition requires `timeframe`".into(),
        });
    } else {
        None
    };

    Ok(CompiledRule {
        id: raw.id,
        title: raw.title,
        description: raw.description,
        level: raw.level,
        tags: raw.tags,
        references: raw.references,
        author: raw.author,
        falsepositives: raw.falsepositives,
        logsource: raw.logsource,
        source_path,
        matchers,
        condition,
        timeframe,
        aggregator,
    })
}

fn compile_selection(name: &str, value: serde_yaml_ng::Value) -> Result<SelectionMatcher, String> {
    let map = value
        .as_mapping()
        .ok_or_else(|| format!("selection '{name}' must be a mapping"))?;

    let mut fields = Vec::with_capacity(map.len());
    for (k, v) in map {
        let key_str = k
            .as_str()
            .ok_or_else(|| format!("selection '{name}': field key must be a string"))?;
        let (path, op) = parse_field_spec(key_str);
        let values = compile_values(v, op)
            .map_err(|e| format!("selection '{name}' field '{key_str}': {e}"))?;
        fields.push(FieldClause {
            path: path.to_string(),
            op,
            values,
        });
    }
    Ok(SelectionMatcher { fields })
}

fn parse_field_spec(spec: &str) -> (&str, FieldOp) {
    if let Some((path, modifier)) = spec.split_once('|') {
        let op = match modifier {
            "contains" => FieldOp::Contains,
            "startswith" => FieldOp::StartsWith,
            "endswith" => FieldOp::EndsWith,
            "re" => FieldOp::Regex,
            _ => FieldOp::Eq,
        };
        (path, op)
    } else {
        (spec, FieldOp::Eq)
    }
}

fn compile_values(v: &serde_yaml_ng::Value, op: FieldOp) -> Result<Vec<MatchValue>, String> {
    if let Some(seq) = v.as_sequence() {
        seq.iter().map(|item| compile_value(item, op)).collect()
    } else {
        Ok(vec![compile_value(v, op)?])
    }
}

fn compile_value(v: &serde_yaml_ng::Value, op: FieldOp) -> Result<MatchValue, String> {
    if let Some(s) = v.as_str() {
        if matches!(op, FieldOp::Regex) {
            let r = Regex::new(s).map_err(|e| format!("bad regex: {e}"))?;
            return Ok(MatchValue::Regex(r));
        }
        return Ok(MatchValue::String(s.to_string()));
    }
    if let Some(n) = v.as_i64() {
        return Ok(MatchValue::Int(n));
    }
    if let Some(n) = v.as_u64() {
        return Ok(MatchValue::Int(n as i64));
    }
    if let Some(b) = v.as_bool() {
        return Ok(MatchValue::Bool(b));
    }
    Err(format!("unsupported value type: {v:?}"))
}

/// Parse a duration string like `60s`, `5m`, `1h`, `1d`.
pub fn parse_duration(s: &str) -> Result<Duration, SigmaError> {
    let s = s.trim();
    // Split off the trailing unit by *character*, not by byte: `s.split_at(
    // s.len() - 1)` panics when the last char is multibyte (e.g. a stray
    // non-ASCII unit), because byte `len - 1` is not a char boundary. Rule
    // files are operator-authored input on the load/SIGHUP path, so a
    // malformed timeframe must surface as InvalidTimeframe, never a panic that
    // aborts a rule reload.
    let unit = s
        .chars()
        .next_back()
        .ok_or_else(|| SigmaError::InvalidTimeframe(s.into()))?;
    let num_part = &s[..s.len() - unit.len_utf8()];
    if num_part.is_empty() {
        return Err(SigmaError::InvalidTimeframe(s.into()));
    }
    let n: u64 = num_part
        .parse()
        .map_err(|_| SigmaError::InvalidTimeframe(s.into()))?;
    let mult: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return Err(SigmaError::InvalidTimeframe(s.into())),
    };
    // checked_mul: a large `n` (e.g. a huge day count) would otherwise overflow
    // u64 — a debug panic / silent release wrap. Treat overflow as malformed.
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| SigmaError::InvalidTimeframe(s.into()))?;
    Ok(Duration::from_secs(secs))
}

/// Parse a condition string. Returns the parsed condition plus the
/// group-by-field if it's a Count condition (for ergonomic checking above).
fn parse_condition(s: &str) -> Option<(Condition, Option<String>)> {
    let s = s.trim();
    // `<sel> | count() by <field> > <N>`
    if let Some((left, right)) = s.split_once('|') {
        let selection = left.trim().to_string();
        let right = right.trim();
        // expect: count() by <field> > <N>
        let prefix = "count() by ";
        let rest = right.strip_prefix(prefix)?;
        let (field_part, num_part) = rest.split_once('>')?;
        let group_by_field = field_part.trim().to_string();
        let threshold: u32 = num_part.trim().parse().ok()?;
        return Some((
            Condition::Count {
                selection,
                group_by_field: group_by_field.clone(),
                threshold,
            },
            Some(group_by_field),
        ));
    }
    // single selection
    if s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Some((Condition::Single(s.to_string()), None));
    }
    None
}

// ============================================================ matching

/// Extract a field by dot-notation from a JSON value.
fn extract<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

impl SelectionMatcher {
    fn matches(&self, event_json: &serde_json::Value) -> bool {
        // All fields must match (AND).
        for clause in &self.fields {
            let v = match extract(event_json, &clause.path) {
                Some(v) => v,
                None => return false,
            };
            // At least one value must match (OR).
            let any = clause
                .values
                .iter()
                .any(|val| val.matches_json(v, clause.op));
            if !any {
                return false;
            }
        }
        true
    }
}

// ============================================================ engine

#[derive(Debug)]
pub struct Engine {
    rules: Vec<CompiledRule>,
}

/// Summary of ATT&CK techniques and tactics covered by the loaded rules.
#[derive(Debug, Default)]
pub struct AttackCoverage {
    pub techniques: std::collections::BTreeSet<String>,
    pub tactics: std::collections::BTreeSet<Tactic>,
    pub rules_per_tactic: std::collections::BTreeMap<Tactic, usize>,
}

impl Engine {
    pub const fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Construct from a pre-compiled rule set. Useful for tests.
    #[must_use]
    pub fn with_rules(rules: Vec<CompiledRule>) -> Self {
        Self { rules }
    }

    /// Load every `*.yml` / `*.yaml` file under `dir` (recursively).
    /// `*.tests.yaml` files are excluded — those are test fixtures, not rules.
    pub fn load_dir(dir: &Path) -> Result<Self, SigmaError> {
        Self::load_dir_maybe_verified(dir, None)
    }

    /// SDD-004 / rule signing: like `load_dir`, but every loaded
    /// rule must carry a valid detached minisign signature
    /// (`<rule>.minisig`) under `verifier`. A missing or invalid
    /// signature aborts the load with [`SigmaError::Signature`];
    /// the correlator's existing "keep prior ruleset on failure"
    /// semantics in `load_rules()` mean an unsigned drop never
    /// affects the running rule set.
    pub fn load_dir_verified(
        dir: &Path,
        verifier: &selfdef_signing::Verifier,
    ) -> Result<Self, SigmaError> {
        Self::load_dir_maybe_verified(dir, Some(verifier))
    }

    fn load_dir_maybe_verified(
        dir: &Path,
        verifier: Option<&selfdef_signing::Verifier>,
    ) -> Result<Self, SigmaError> {
        let mut rules = Vec::new();
        for entry in walk_yaml(dir)? {
            // Skip test fixture files.
            if entry
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".tests.yaml") || s.ends_with(".tests.yml"))
            {
                continue;
            }
            // F-2027-034: parse YAML *before* verifying the
            // signature. The pre-fix order returned a confusing
            // `SigmaError::Signature` error for a malformed-but-
            // signed rule — operators chasing a YAML typo got a
            // "signature check failed" message instead of "YAML
            // parse error at line N". Parsing first means the
            // operator sees the *real* failure mode: bad YAML
            // returns `Yaml`, bad signature returns `Signature`.
            // The signature is still verified before the rule is
            // added to the engine, so the security contract
            // ("only signed rules are loaded") is unchanged.
            let yaml_bytes = std::fs::read(&entry)?;
            let raw: RawRule =
                serde_yaml_ng::from_slice(&yaml_bytes).map_err(|source| SigmaError::Yaml {
                    path: entry.clone(),
                    source,
                })?;
            if let Some(v) = verifier {
                v.verify_detached_file(&entry)
                    .map_err(|source| SigmaError::Signature {
                        path: entry.clone(),
                        source,
                    })?;
            }
            let compiled = compile_rule(raw, entry)?;
            rules.push(compiled);
        }
        Ok(Self { rules })
    }

    /// Compute ATT&CK coverage across the loaded rules.
    #[must_use]
    pub fn attack_coverage(&self) -> AttackCoverage {
        let mut out = AttackCoverage::default();
        for rule in &self.rules {
            let mut rule_tactics = std::collections::BTreeSet::new();
            for tag in &rule.tags {
                if let Some(t) = parse_tactic_tag(tag) {
                    out.tactics.insert(t);
                    rule_tactics.insert(t);
                }
                if let Some(id) = parse_technique_tag(tag) {
                    out.techniques.insert(id);
                }
            }
            for t in rule_tactics {
                *out.rules_per_tactic.entry(t).or_insert(0) += 1;
            }
        }
        out
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Evaluate one event against all rules. Returns 0+ Finding events.
    pub fn process(&self, event: &Event, host_tag: &str, sequence: &AtomicU64) -> Vec<Event> {
        let event_json = match serde_json::to_value(event) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to serialize event for matching");
                return Vec::new();
            }
        };

        let mut findings = Vec::new();
        for rule in &self.rules {
            if !logsource_matches(&rule.logsource, event) {
                continue;
            }
            let sel_name = match &rule.condition {
                Condition::Single(n) => n,
                Condition::Count { selection, .. } => selection,
            };
            let matcher = match rule.matchers.get(sel_name) {
                Some(m) => m,
                None => continue,
            };
            if !matcher.matches(&event_json) {
                continue;
            }

            // Selection matched. Check aggregation.
            match (&rule.condition, &rule.aggregator) {
                (Condition::Single(_), _) => {
                    findings.push(build_finding(rule, event, host_tag, sequence, None));
                }
                (Condition::Count { group_by_field, .. }, Some(agg)) => {
                    let key = extract(&event_json, group_by_field)
                        .and_then(|v| {
                            v.as_str()
                                .map(str::to_owned)
                                .or_else(|| Some(v.to_string()))
                        })
                        .unwrap_or_default();
                    if let Some(k) = agg.observe(key, Instant::now()) {
                        findings.push(build_finding(rule, event, host_tag, sequence, Some(k)));
                    }
                }
                (Condition::Count { .. }, None) => {
                    debug!(rule = %rule.id, "count condition without aggregator (compile bug)");
                }
            }
        }
        findings
    }
}

fn walk_yaml(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_yaml_inner(dir, &mut out)?;
    // F-2027-033: `std::fs::read_dir` iteration order is
    // undefined per the standard library docs. Two rules with
    // the same priority (`level: high`, same logsource) that
    // happen to match the same event would otherwise fire in
    // filesystem-enumeration order — kernel-version /
    // filesystem-version dependent. Sort lexicographically so
    // operators can predict precedence by file naming alone.
    out.sort();
    Ok(out)
}

fn walk_yaml_inner(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_yaml_inner(&path, out)?;
        } else if path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s == "yml" || s == "yaml")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn logsource_matches(ls: &LogSource, event: &Event) -> bool {
    if let Some(service) = &ls.service {
        if event.source != *service {
            return false;
        }
    }
    // product/category are advisory in M5; not enforced (no event field for product yet).
    let _ = ls.product;
    let _ = ls.category;
    true
}

fn build_finding(
    rule: &CompiledRule,
    triggering: &Event,
    host_tag: &str,
    sequence: &AtomicU64,
    group_key: Option<String>,
) -> Event {
    let seq = sequence.fetch_add(1, Ordering::Relaxed);
    let message = if let Some(k) = &group_key {
        format!("{} (group={k})", rule.title)
    } else {
        rule.title.clone()
    };
    let mut ev = Event::new(
        ClassUid::DETECTION_FINDING,
        FINDING_CREATE,
        rule.level.to_severity(),
        host_tag,
        format!("selfdef.correlator.{}", rule.id),
        seq,
    )
    .with_message(message);

    // Preserve link to the triggering event in raw.
    let raw = serde_json::json!({
        "rule_id":    rule.id,
        "rule_title": rule.title,
        "rule_path":  rule.source_path.display().to_string(),
        "trigger_id": triggering.id.to_string(),
        "group_key":  group_key,
        "tags":       rule.tags,
        "references": rule.references,
    });
    ev = ev.with_raw(raw);

    // Carry src_endpoint forward where present (most useful for IP-based findings).
    if let Some(src) = &triggering.src_endpoint {
        ev = ev.with_src_endpoint(src.clone());
    }

    // ATT&CK overlay from tags.
    for technique in parse_attack_tags(&rule.tags) {
        ev = ev.with_attack(technique);
    }

    ev
}

fn parse_attack_tags(tags: &[String]) -> Vec<TechniqueRef> {
    let mut tactic = Tactic::Reconnaissance; // default; overridden if tactic tag present
    for tag in tags {
        if let Some(t) = parse_tactic_tag(tag) {
            tactic = t;
            break;
        }
    }
    let mut out = Vec::new();
    for tag in tags {
        if let Some(id) = parse_technique_tag(tag) {
            out.push(TechniqueRef::new(id, "(from rule tag)", tactic));
        }
    }
    out
}

fn parse_technique_tag(tag: &str) -> Option<String> {
    let rest = tag.strip_prefix("attack.t")?;
    // rest like "1110" or "1110.001"
    let head = rest.split('.').next()?;
    if head.chars().all(|c| c.is_ascii_digit()) {
        Some(format!("T{rest}").to_uppercase())
    } else {
        None
    }
}

fn parse_tactic_tag(tag: &str) -> Option<Tactic> {
    let rest = tag.strip_prefix("attack.")?;
    match rest {
        "reconnaissance" => Some(Tactic::Reconnaissance),
        "resource_development" => Some(Tactic::ResourceDevelopment),
        "initial_access" => Some(Tactic::InitialAccess),
        "execution" => Some(Tactic::Execution),
        "persistence" => Some(Tactic::Persistence),
        "privilege_escalation" => Some(Tactic::PrivilegeEscalation),
        "defense_evasion" => Some(Tactic::DefenseEvasion),
        "credential_access" => Some(Tactic::CredentialAccess),
        "discovery" => Some(Tactic::Discovery),
        "lateral_movement" => Some(Tactic::LateralMovement),
        "collection" => Some(Tactic::Collection),
        "command_and_control" => Some(Tactic::CommandAndControl),
        "exfiltration" => Some(Tactic::Exfiltration),
        "impact" => Some(Tactic::Impact),
        _ => None,
    }
}

// ============================================================ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_failure_event() -> Event {
        Event::new(
            ClassUid::AUTHENTICATION,
            1,
            SeverityId::Medium,
            "host",
            "auditd",
            1,
        )
        .with_status(StatusId::Failure)
        .with_src_endpoint(Endpoint {
            ip: Some("192.0.2.5".parse().unwrap()),
            ..Endpoint::default()
        })
    }

    #[test]
    fn parse_simple_condition() {
        let (c, by) = parse_condition("failed_auth").unwrap();
        assert!(matches!(c, Condition::Single(ref n) if n == "failed_auth"));
        assert!(by.is_none());
    }

    #[test]
    fn string_matching_is_case_insensitive_per_sigma() {
        use serde_json::json;
        // Sigma matches strings case-insensitively by default. A case-sensitive
        // engine misses detections: a rule `Image|endswith: '\powershell.exe'`
        // must fire on `...\PowerShell.EXE`, and an exact/contains/startswith
        // value must match regardless of the casing in the event.
        let ends = MatchValue::String("powershell.exe".to_string());
        assert!(ends.matches_json(
            &json!("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE"),
            FieldOp::EndsWith
        ));
        let eq = MatchValue::String("PowerShell.EXE".to_string());
        assert!(eq.matches_json(&json!("powershell.exe"), FieldOp::Eq));
        let contains = MatchValue::String("MIMIKATZ".to_string());
        assert!(contains.matches_json(&json!("launched mimikatz.exe"), FieldOp::Contains));
        let starts = MatchValue::String("/USR/BIN/".to_string());
        assert!(starts.matches_json(&json!("/usr/bin/python3"), FieldOp::StartsWith));
        // A genuine non-match still does not match.
        let other = MatchValue::String("cmd.exe".to_string());
        assert!(!other.matches_json(&json!("powershell.exe"), FieldOp::Eq));
    }

    #[test]
    fn parse_count_condition() {
        let (c, by) = parse_condition("failed_auth | count() by src_endpoint.ip > 2").unwrap();
        match c {
            Condition::Count {
                selection,
                group_by_field,
                threshold,
            } => {
                assert_eq!(selection, "failed_auth");
                assert_eq!(group_by_field, "src_endpoint.ip");
                assert_eq!(threshold, 2);
            }
            _ => panic!("expected Count"),
        }
        assert_eq!(by.as_deref(), Some("src_endpoint.ip"));
    }

    #[test]
    fn parse_durations() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert!(parse_duration("60").is_err());
        assert!(parse_duration("60z").is_err());
        // Robustness: malformed timeframes must error, never panic.
        assert!(parse_duration("").is_err());
        assert!(parse_duration("s").is_err());
        // Multibyte trailing char must not panic on a non-char-boundary split.
        assert!(parse_duration("5é").is_err());
        assert!(parse_duration("héh").is_err());
        // Overflowing day count must error via checked_mul, not wrap/panic.
        assert!(parse_duration("100000000000000000d").is_err());
        // Whitespace is tolerated (trimmed).
        assert_eq!(parse_duration("  30s ").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_technique_tags() {
        assert_eq!(parse_technique_tag("attack.t1110"), Some("T1110".into()));
        assert_eq!(
            parse_technique_tag("attack.t1110.001"),
            Some("T1110.001".into())
        );
        assert_eq!(parse_technique_tag("attack.credential_access"), None);
    }

    #[test]
    fn single_selection_rule_fires() {
        let yaml = r#"
id: test-1
title: Any auth failure
detection:
  failed:
    class_uid: 3002
    status_id: 2
  condition: failed
level: medium
"#;
        let raw: RawRule = serde_yaml_ng::from_str(yaml).unwrap();
        let rule = compile_rule(raw, PathBuf::from("inline.yml")).unwrap();
        let engine = Engine { rules: vec![rule] };
        let seq = AtomicU64::new(0);
        let findings = engine.process(&ssh_failure_event(), "host", &seq);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].class_uid, ClassUid::DETECTION_FINDING);
        assert_eq!(findings[0].severity_id, SeverityId::Medium);
    }

    #[test]
    fn count_rule_fires_after_threshold() {
        let yaml = r#"
id: test-2
title: SSH brute force
tags: [attack.credential_access, attack.t1110]
detection:
  failed_auth:
    class_uid: 3002
    status_id: 2
  timeframe: 60s
  condition: failed_auth | count() by src_endpoint.ip > 2
level: high
"#;
        let raw: RawRule = serde_yaml_ng::from_str(yaml).unwrap();
        let rule = compile_rule(raw, PathBuf::from("inline.yml")).unwrap();
        let engine = Engine { rules: vec![rule] };
        let seq = AtomicU64::new(0);
        // `> 2` is STRICT: the 1st AND the 2nd (the threshold-th) match must NOT
        // fire — only MORE THAN 2 (the 3rd) does. Locks the `> N` semantics
        // against a regression to `>= N` (which would fire one match early).
        for _ in 0..2 {
            let f = engine.process(&ssh_failure_event(), "host", &seq);
            assert!(f.is_empty());
        }
        let f = engine.process(&ssh_failure_event(), "host", &seq);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity_id, SeverityId::High);
        assert!(!f[0].attack.is_empty());
        assert_eq!(f[0].attack[0].id, "T1110");
    }

    #[test]
    fn fired_group_is_removed_from_state() {
        // `count() > 0` fires on the first match of each group. Each fired
        // group must be removed from the map, not left as an empty deque —
        // otherwise a stream of distinct one-shot group-by values (e.g.
        // spoofed source IPs) parks one residual entry per value forever.
        let agg = Aggregator::new(0, Duration::from_secs(60));
        let t = Instant::now();
        assert_eq!(agg.observe("ip-a".into(), t), Some("ip-a".into()));
        assert_eq!(agg.observe("ip-b".into(), t), Some("ip-b".into()));
        assert_eq!(agg.observe("ip-c".into(), t), Some("ip-c".into()));
        assert_eq!(agg.group_count(), 0, "fired groups leave no residue");
    }

    #[test]
    fn stale_silent_groups_are_swept() {
        // A group keyed on an attacker-influenced field that is seen once and
        // never again would linger forever without the periodic GC. Observe a
        // large set of distinct one-shot keys, advance past the window so they
        // are all stale, then drive enough further observes to cross a GC
        // cadence — the stale silent groups must be reclaimed, leaving the map
        // bounded rather than monotonically growing.
        let window = Duration::from_millis(10);
        let agg = Aggregator::new(1_000_000, window); // threshold never met
        let t0 = Instant::now();
        for i in 0..2000 {
            assert!(agg.observe(format!("k{i}"), t0).is_none());
        }
        assert_eq!(agg.group_count(), 2000);

        // Past the window: every `k*` is now stale. Drive one GC cadence worth
        // of fresh observes; the sweep that fires mid-loop drops the stale
        // groups while keeping the fresh ones.
        let t1 = t0 + window + Duration::from_millis(1);
        for i in 0..GC_EVERY {
            agg.observe(format!("fresh{i}"), t1);
        }
        assert!(
            agg.group_count() < 2000,
            "stale silent groups reclaimed by GC (was {})",
            agg.group_count()
        );
    }

    #[test]
    fn contains_modifier() {
        let yaml = r#"
id: test-3
title: sudoers tamper
detection:
  sel:
    class_uid: 1001
    file.path|contains: "/etc/sudoers"
  condition: sel
level: high
"#;
        let raw: RawRule = serde_yaml_ng::from_str(yaml).unwrap();
        let rule = compile_rule(raw, PathBuf::from("inline.yml")).unwrap();
        let engine = Engine { rules: vec![rule] };
        let seq = AtomicU64::new(0);

        let event = Event::new(
            ClassUid::FILE_SYSTEM_ACTIVITY,
            3,
            SeverityId::Medium,
            "host",
            "auditd",
            1,
        )
        .with_file(File::at_path("/etc/sudoers.d/00_admin"));

        let f = engine.process(&event, "host", &seq);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn list_of_values_is_or() {
        let yaml = r#"
id: test-4
title: list-or
detection:
  sel:
    source: [auditd, journald]
    severity_id: 3
  condition: sel
level: low
"#;
        let raw: RawRule = serde_yaml_ng::from_str(yaml).unwrap();
        let rule = compile_rule(raw, PathBuf::from("inline.yml")).unwrap();
        let engine = Engine { rules: vec![rule] };
        let seq = AtomicU64::new(0);
        let f = engine.process(&ssh_failure_event(), "host", &seq);
        assert_eq!(f.len(), 1);
    }
}
