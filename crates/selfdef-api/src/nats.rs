//! `GET /v1/nats` — MS015 / SDD-053 D-2 schema discovery.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct NatsSchema {
    pub subject_schema: &'static [&'static str],
    pub echo_defense: &'static str,
    pub modes: &'static [&'static str],
    pub config_example: &'static [&'static str],
    pub cross_host_invariants: &'static [&'static str],
}

const SUBJECT_SCHEMA: &[&str] = &[
    "Outbound publish: <subject_prefix>.<host_tag>",
    "Inbound subscribe: <subject_prefix>.>  (wildcard subtopic)",
];

const ECHO_DEFENSE: &str =
    "Drop inbound events whose Event::host_tag matches the local host_tag";

const MODES: &[&str] = &[
    "passive — mirror inbound to local bus only (read-only fleet view)",
    "active  — full two-way pump (publish + republish)",
];

const CONFIG_EXAMPLE: &[&str] = &[
    "[nats]",
    "url            = \"tls://nats.example.com:4222\"",
    "subject_prefix = \"selfdef.events\"",
    "mode           = \"active\"   # passive | active",
];

const CROSS_HOST_INVARIANTS: &[&str] = &[
    "Each host's audit chain stays independent (no merge across hosts)",
    "Events received from other hosts are tagged via Event::host_tag",
    "Local store + correlator respect host_tag boundaries",
];

pub(crate) async fn show() -> Json<NatsSchema> {
    Json(NatsSchema {
        subject_schema: SUBJECT_SCHEMA,
        echo_defense: ECHO_DEFENSE,
        modes: MODES,
        config_example: CONFIG_EXAMPLE,
        cross_host_invariants: CROSS_HOST_INVARIANTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_match_sdd_053() {
        assert_eq!(SUBJECT_SCHEMA.len(), 2);
        assert_eq!(MODES.len(), 2);
        assert_eq!(CONFIG_EXAMPLE.len(), 4);
        assert_eq!(CROSS_HOST_INVARIANTS.len(), 3);
        assert!(ECHO_DEFENSE.contains("host_tag"));
    }
}
