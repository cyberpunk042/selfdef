//! `selfdefctl events emit` — append a pre-formed OCSF event to a
//! JSONL stream the daemon's `eventstream` collector tails.
//!
//! The contract:
//!
//! 1. Build a `selfdef_core::Event` from the supplied taxonomy +
//!    severity, so the on-disk JSON is guaranteed to match the
//!    envelope the daemon expects.
//! 2. Append one line, with `O_APPEND` so concurrent writers from
//!    different scripts don't interleave (POSIX guarantees atomic
//!    short appends under PIPE_BUF, which a single Event line stays
//!    well under).
//!
//! Modules use this instead of hand-rolling JSON in bash. The first
//! caller is `integrity-sentinel`, which uses it to surface SHA256
//! drift onto the bus so the existing notifier chain
//! (ntfy / Signal) fires.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use selfdef_core::Event;
use selfdef_core::category::ClassUid;
use selfdef_core::severity::SeverityId;

pub(crate) struct EmitArgs<'a> {
    pub(crate) class_uid: u32,
    pub(crate) activity_id: u32,
    pub(crate) severity: &'a str,
    pub(crate) source: &'a str,
    pub(crate) message: Option<&'a str>,
    pub(crate) host_tag: Option<&'a str>,
    pub(crate) out: &'a Path,
}

pub(crate) fn emit_event(args: EmitArgs<'_>) -> Result<()> {
    let severity = parse_severity(args.severity)
        .with_context(|| format!("unknown severity: {}", args.severity))?;
    let host_tag = args
        .host_tag
        .map(str::to_owned)
        .unwrap_or_else(resolve_host_tag);
    if args.source.trim().is_empty() {
        bail!("--source must not be empty");
    }

    let mut event = Event::new(
        ClassUid::new(args.class_uid),
        args.activity_id,
        severity,
        host_tag,
        args.source.to_string(),
        // `sequence` is per-host monotonic — for one-shot CLI emissions
        // we have no peer context, so 0 is the documented placeholder.
        // The daemon's correlator does not rely on it.
        0,
    );
    if let Some(m) = args.message {
        event = event.with_message(m);
    }

    let line = serde_json::to_string(&event).context("serialising event")?;

    if let Some(parent) = args.out.parent() {
        // Best-effort: create the parent directory. We never panic if it
        // already exists — that's the common case in production.
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent of {}", args.out.display()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(args.out)
        .with_context(|| format!("opening {}", args.out.display()))?;
    writeln!(file, "{line}").with_context(|| format!("writing to {}", args.out.display()))?;
    Ok(())
}

fn parse_severity(s: &str) -> Result<SeverityId> {
    match s.to_ascii_lowercase().as_str() {
        "informational" | "info" => Ok(SeverityId::Informational),
        "low" => Ok(SeverityId::Low),
        "medium" => Ok(SeverityId::Medium),
        "high" => Ok(SeverityId::High),
        "critical" => Ok(SeverityId::Critical),
        "fatal" => Ok(SeverityId::Fatal),
        other => {
            bail!("expected one of informational|low|medium|high|critical|fatal, got `{other}`")
        }
    }
}

fn resolve_host_tag() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::CategoryUid;

    #[test]
    fn writes_a_valid_event_jsonl_line() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("eventstream.jsonl");
        emit_event(EmitArgs {
            class_uid: 2004,
            activity_id: 1,
            severity: "high",
            source: "selfdef.integrity-sentinel",
            message: Some("DRIFT detected"),
            host_tag: Some("test-host"),
            out: &out,
        })
        .unwrap();

        let content = std::fs::read_to_string(&out).unwrap();
        let line = content.trim_end_matches('\n');
        assert!(!line.is_empty());
        let event: Event = serde_json::from_str(line).expect("round-trips through Event");
        assert_eq!(event.class_uid, ClassUid::DETECTION_FINDING);
        assert_eq!(event.category_uid, CategoryUid::Findings);
        assert_eq!(event.severity_id, SeverityId::High);
        assert_eq!(event.host_tag, "test-host");
        assert_eq!(event.source, "selfdef.integrity-sentinel");
        assert_eq!(event.message.as_deref(), Some("DRIFT detected"));
        // type_uid = class_uid * 100 + activity_id
        assert_eq!(event.type_uid, 200_401);
    }

    #[test]
    fn appends_without_clobbering_existing_lines() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("stream.jsonl");
        for severity in ["low", "high"] {
            emit_event(EmitArgs {
                class_uid: 2004,
                activity_id: 1,
                severity,
                source: "selfdef.test",
                message: None,
                host_tag: Some("h"),
                out: &out,
            })
            .unwrap();
        }
        let lines: Vec<_> = std::fs::read_to_string(&out)
            .unwrap()
            .lines()
            .map(|l| l.to_string())
            .collect();
        assert_eq!(lines.len(), 2, "expected two appended lines");
        for line in &lines {
            // Each line must independently parse back into an Event.
            let _: Event = serde_json::from_str(line).expect("each line parses");
        }
    }

    #[test]
    fn rejects_unknown_severity() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("x.jsonl");
        let err = emit_event(EmitArgs {
            class_uid: 2004,
            activity_id: 1,
            severity: "spicy",
            source: "selfdef.test",
            message: None,
            host_tag: Some("h"),
            out: &out,
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown severity"), "got: {err}");
        assert!(
            !out.exists(),
            "must not have created the output file on input error",
        );
    }

    #[test]
    fn rejects_empty_source() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("x.jsonl");
        let err = emit_event(EmitArgs {
            class_uid: 2004,
            activity_id: 1,
            severity: "low",
            source: "   ",
            message: None,
            host_tag: Some("h"),
            out: &out,
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("source"), "got: {err}");
    }

    #[test]
    fn creates_parent_directory_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("nested/sub/eventstream.jsonl");
        emit_event(EmitArgs {
            class_uid: 2004,
            activity_id: 1,
            severity: "low",
            source: "selfdef.test",
            message: None,
            host_tag: Some("h"),
            out: &out,
        })
        .unwrap();
        assert!(out.exists());
    }
}
