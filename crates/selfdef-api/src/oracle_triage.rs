//! `GET /v1/oracle-triage` — SDD-016 oracle-triage channel discovery.
//!
//! Surfaces the oracle-triage notifier channel doctrine: tier-routing
//! via sovereign-os inference router, opt-in posture, wire format,
//! severity-floor filter. Operators + dashboards consume this to
//! verify which classifier the daemon is wired to use.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct OracleTriageSchema {
    pub default_endpoint: &'static str,
    pub default_timeout_seconds: u64,
    pub default_model: &'static str,
    pub default_min_severity: &'static str,
    pub doctrine: &'static [&'static str],
    pub wire_format: &'static [&'static str],
    pub tier_routing: &'static [&'static str],
}

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8080";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_MODEL: &str = "auto";
const DEFAULT_MIN_SEVERITY: &str = "Medium";

const DOCTRINE: &[&str] = &[
    "Decoupling preserved (SDD-012 Q-D core): selfdef remains the event-detection authority; sovereign-os inference stack remains the dispatch authority.",
    "selfdef NEVER picks the tier — the router's classify() does.",
    "Opt-in only (SDD-016 § 2): NEVER auto-enabled, even on SAIN-01. Operator's explicit `[notifier.oracle_triage] enabled = true` is required.",
    "Severity-floor filter applies BEFORE the router call — events below `min_severity` are dropped without spending a router round-trip.",
];

const WIRE_FORMAT: &[&str] = &[
    "OpenAI chat-completions request (compatible with the inference router's REST surface)",
    "`response_format: json_object` — router returns structured triage block",
    "Triage-specific system prompt (operator-overridable via `[notifier.oracle_triage] system_prompt_file`)",
    "Request body carries the selfdef Event envelope (OCSF-aligned) as user-message payload",
];

const TIER_ROUTING: &[&str] = &[
    "Pulse        — fastest tier; quick triage on routine events",
    "Logic Engine — medium tier; structured analysis with tool calls",
    "Oracle Core  — slowest tier; deep reasoning on critical events",
    "The router's classify() picks the tier based on request shape + event content; selfdef does NOT pick.",
];

pub(crate) async fn show() -> Json<OracleTriageSchema> {
    Json(OracleTriageSchema {
        default_endpoint: DEFAULT_ENDPOINT,
        default_timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        default_model: DEFAULT_MODEL,
        default_min_severity: DEFAULT_MIN_SEVERITY,
        doctrine: DOCTRINE,
        wire_format: WIRE_FORMAT,
        tier_routing: TIER_ROUTING,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_match_sdd_016() {
        assert_eq!(DOCTRINE.len(), 4);
        assert_eq!(WIRE_FORMAT.len(), 4);
        assert_eq!(TIER_ROUTING.len(), 4);
        assert_eq!(DEFAULT_TIMEOUT_SECONDS, 30);
        assert!(DEFAULT_ENDPOINT.starts_with("http://"));
    }
}
