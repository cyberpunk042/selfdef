//! `GET /v1/quarantine` — MS042 / SDD-064 D-064.1 schema discovery surface.
//!
//! Returns the static tool-quarantine-archive doctrine as JSON so agents
//! (MCP / dashboard / external tooling / the sovereign-os D-17 mirror) can
//! learn the observed-discipline contract without reading the Rust source.
//!
//! The IPS daemon is the observed-behavior arbiter (MS042): every tool call
//! enters with a 7-field signed declaration; the IPS observes actual behavior
//! through 5 monitors; on declaration-vs-observed mismatch the response is the
//! 3-step block + quarantine + trace protocol (dump 17437-17445).
//!
//! Static-only — the doctrine doesn't change at runtime. Live archive contents
//! and the restore/purge/export verbs are MS003-signed CLI-only (D-064.2); this
//! surface publishes the CONTRACT, never mutates.
//!
//! Source: SDD-064 + MS042 (E0421-E0430, M01094, F05027-F05029).

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct QuarantineSchema {
    pub declaration_fields: &'static [DeclarationField],
    pub observed_monitors: &'static [ObservedMonitor],
    pub response_protocol: &'static [ResponseStep],
    pub record_schema: &'static [&'static str],
    pub archive_operations: &'static [ArchiveOp],
    pub persistence_path: &'static str,
    pub mutation_doctrine: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeclarationField {
    pub order: u8,
    pub name: &'static str,
    pub declares: &'static str,
    pub observed_by: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ObservedMonitor {
    pub mechanism: &'static str,
    pub watches: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResponseStep {
    pub order: u8,
    pub step: &'static str,
    pub crate_name: &'static str,
    pub effect: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ArchiveOp {
    pub op: &'static str,
    pub authority: &'static str,
}

// 7 declaration fields (MS042 E0421-E0427, dump 17424-17430).
const DECLARATION_FIELDS: &[DeclarationField] = &[
    DeclarationField {
        order: 1,
        name: "read_paths",
        declares: "filesystem paths it will read",
        observed_by: "fanotify (MS037)",
    },
    DeclarationField {
        order: 2,
        name: "write_paths",
        declares: "filesystem paths it will modify",
        observed_by: "fanotify (MS037)",
    },
    DeclarationField {
        order: 3,
        name: "network_domains",
        declares: "domains it will connect to",
        observed_by: "eBPF connect()/sendmsg() (MS024+MS038)",
    },
    DeclarationField {
        order: 4,
        name: "environment_variables",
        declares: "env vars it will read",
        observed_by: "ptrace+seccomp getenv()",
    },
    DeclarationField {
        order: 5,
        name: "secret_access",
        declares: "secrets it will touch",
        observed_by: "kernel keyring keyctl()",
    },
    DeclarationField {
        order: 6,
        name: "expected_side_effects",
        declares: "side-effect class",
        observed_by: "MS036 sandbox introspector",
    },
    DeclarationField {
        order: 7,
        name: "rollback",
        declares: "rollback availability",
        observed_by: "MS041 commit authority",
    },
];

// 5 observed-behavior monitors (MS042 E0428, M01080-M01084).
const OBSERVED_MONITORS: &[ObservedMonitor] = &[
    ObservedMonitor {
        mechanism: "fanotify",
        watches: "file read/modify vs declared read_paths/write_paths",
    },
    ObservedMonitor {
        mechanism: "eBPF",
        watches: "connect()/sendmsg() vs declared network_domains",
    },
    ObservedMonitor {
        mechanism: "ptrace+seccomp",
        watches: "getenv() vs declared environment_variables",
    },
    ObservedMonitor {
        mechanism: "kernel-keyring",
        watches: "keyctl() vs declared secret_access",
    },
    ObservedMonitor {
        mechanism: "sandbox-introspector",
        watches: "syscalls vs declared expected_side_effects (MS036)",
    },
];

// 3-step mismatch response (MS042 E0430, M01088-M01090, dump 17444).
const RESPONSE_PROTOCOL: &[ResponseStep] = &[
    ResponseStep {
        order: 1,
        step: "block",
        crate_name: "selfdef-tool-response-blocker",
        effect: "halt the tool mid-flight",
    },
    ResponseStep {
        order: 2,
        step: "quarantine",
        crate_name: "selfdef-tool-response-quarantiner",
        effect: "freeze the call + artifacts into the archive (M01094)",
    },
    ResponseStep {
        order: 3,
        step: "trace",
        crate_name: "selfdef-tool-response-tracer",
        effect: "emit OCSF 2004 detection finding into the audit chain (MS026+MS009)",
    },
];

// Quarantine record fields (SDD-064 Surface 1).
const RECORD_SCHEMA: &[&str] = &[
    "quarantine_id",
    "tool_id",
    "declaration (7-field)",
    "observed (per-field)",
    "mismatch_field",
    "mismatch_detail",
    "response (block/quarantine/trace)",
    "trace_id (OCSF 2004 link)",
    "quarantined_at",
    "status (quarantined/restored/exported/purged)",
];

// Operator archive operations (MS042 F05027-F05029).
const ARCHIVE_OPERATIONS: &[ArchiveOp] = &[
    ArchiveOp {
        op: "review",
        authority: "read-only (dashboard / HTTP / mirror)",
    },
    ArchiveOp {
        op: "restore",
        authority: "MS003-signed CLI (false-positive recovery)",
    },
    ArchiveOp {
        op: "export",
        authority: "MS003-signed CLI (forensic export)",
    },
    ArchiveOp {
        op: "purge",
        authority: "MS003-signed CLI (export-before-purge guard)",
    },
];

const PERSISTENCE_PATH: &str = "/var/lib/selfdef/tool-quarantine/";
const MUTATION_DOCTRINE: &str = "read-only HTTP surface; restore/export/purge are MS003-signed CLI verbs only (SDD-064 D-064.2)";

/// `GET /v1/quarantine` handler.
pub(crate) async fn show() -> Json<QuarantineSchema> {
    Json(QuarantineSchema {
        declaration_fields: DECLARATION_FIELDS,
        observed_monitors: OBSERVED_MONITORS,
        response_protocol: RESPONSE_PROTOCOL,
        record_schema: RECORD_SCHEMA,
        archive_operations: ARCHIVE_OPERATIONS,
        persistence_path: PERSISTENCE_PATH,
        mutation_doctrine: MUTATION_DOCTRINE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_match_ms042() {
        // 7 declaration fields (E0421-E0427)
        assert_eq!(DECLARATION_FIELDS.len(), 7);
        assert_eq!(DECLARATION_FIELDS[0].name, "read_paths");
        assert_eq!(DECLARATION_FIELDS[6].name, "rollback");
        // 5 observed monitors (E0428)
        assert_eq!(OBSERVED_MONITORS.len(), 5);
        // 3-step block+quarantine+trace response (E0430)
        assert_eq!(RESPONSE_PROTOCOL.len(), 3);
        assert_eq!(RESPONSE_PROTOCOL[0].step, "block");
        assert_eq!(RESPONSE_PROTOCOL[1].step, "quarantine");
        assert_eq!(RESPONSE_PROTOCOL[2].step, "trace");
        assert!(PERSISTENCE_PATH.starts_with("/var/lib/selfdef/"));
    }

    #[test]
    fn declaration_fields_orders_monotonic() {
        let mut last = 0u8;
        for f in DECLARATION_FIELDS {
            assert!(f.order > last, "declaration fields must be 1..7 monotonic");
            last = f.order;
        }
    }

    #[test]
    fn response_protocol_orders_monotonic() {
        let mut last = 0u8;
        for s in RESPONSE_PROTOCOL {
            assert!(s.order > last, "response protocol must be 1..3 monotonic");
            last = s.order;
        }
    }
}
