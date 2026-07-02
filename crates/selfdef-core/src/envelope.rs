//! The event envelope itself.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::SCHEMA_VERSION;
use crate::attack::TechniqueRef;
use crate::category::{CategoryUid, ClassUid};
use crate::metadata::Metadata;
use crate::observable::{Actor, Endpoint, File, NetworkConnection, Process};
use crate::severity::SeverityId;
use crate::status::StatusId;

/// A single observation in the selfdef event bus.
///
/// The shape is OCSF-aligned: `category_uid`, `class_uid`, `activity_id`,
/// `type_uid`, `severity_id`, `status_id`, and the named observable fields
/// all match OCSF naming so downstream tools can consume this directly.
///
/// Required fields:
/// - `schema`, `id`, `time_dt` — envelope identity.
/// - `category_uid`, `class_uid`, `activity_id`, `type_uid` — what kind of event.
/// - `severity_id` — how bad.
/// - `host_tag`, `source` — where and who reported.
/// - `metadata` — processing info.
///
/// Optional observables fill in based on the class: an Authentication event
/// will typically have `actor.user`, `src_endpoint`, `dst_endpoint`; a
/// Process Activity event will have `process` and `actor.process`; etc.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Event {
    /// Envelope schema version. See [`SCHEMA_VERSION`].
    pub schema: u32,

    /// Stable unique identifier (UUIDv7 — time-ordered).
    pub id: Uuid,

    /// Wall-clock time at observation, RFC3339 on the wire.
    #[serde(with = "time::serde::rfc3339")]
    pub time_dt: OffsetDateTime,

    // ---- OCSF taxonomy ----
    pub category_uid: CategoryUid,
    pub class_uid: ClassUid,
    pub activity_id: u32,
    /// Derived: `class_uid * 100 + activity_id`. Populated automatically by
    /// constructors; preserved if deserialized.
    pub type_uid: u64,
    pub severity_id: SeverityId,

    // ---- selfdef-specific identity ----
    pub host_tag: String,
    pub source: String,

    // ---- optional shape ----
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<StatusId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConnection>,

    /// MITRE ATT&CK techniques attached by collector or rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<TechniqueRef>,

    pub metadata: Metadata,

    /// Original collector payload, preserved for forensics. Always carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,

    /// Local provenance marker: `true` when this event entered THIS daemon from
    /// another host via the NATS bridge (set at inbound republish), rather than
    /// from a local collector. It is a per-receiving-daemon view, never part of
    /// the wire form — `#[serde(skip)]` keeps it off the NATS payload and out of
    /// the forensic store, and it defaults to `false` on decode. The correlator
    /// propagates it onto derived findings so the responder can apply a
    /// federation trust-boundary policy (see F-2026-111) without the local
    /// host_tag laundering the remote origin.
    #[serde(skip)]
    pub federated: bool,

    /// Local provenance marker: `true` when this federated event arrived inside
    /// a NATS envelope whose detached signature verified against a CONFIGURED
    /// TRUSTED-PEER key (F-2026-111 option c). Like `federated`, it is a
    /// per-receiving-daemon view, never on the wire (`#[serde(skip)]`), and the
    /// correlator propagates it onto derived findings. A verified federated
    /// finding is authenticated to a trusted peer, so the responder treats it
    /// like a local finding (it bypasses the fail-closed `act_on_federated`
    /// refusal); an UNverified federated finding stays refused when fail-closed.
    /// Always `false` unless inbound signature verification set it.
    #[serde(skip)]
    pub federation_verified: bool,
}

impl Event {
    /// Construct an event with the required core fields. Optional observables
    /// are filled in with the `with_*` setters.
    #[must_use]
    pub fn new(
        class_uid: ClassUid,
        activity_id: u32,
        severity_id: SeverityId,
        host_tag: impl Into<String>,
        source: impl Into<String>,
        sequence: u64,
    ) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            id: Uuid::now_v7(),
            time_dt: OffsetDateTime::now_utc(),
            category_uid: class_uid.category(),
            class_uid,
            activity_id,
            type_uid: class_uid.type_uid(activity_id),
            severity_id,
            host_tag: host_tag.into(),
            source: source.into(),
            status_id: None,
            message: None,
            actor: None,
            process: None,
            file: None,
            src_endpoint: None,
            dst_endpoint: None,
            network: None,
            attack: Vec::new(),
            metadata: Metadata::now(sequence),
            raw: None,
            federated: false,
            federation_verified: false,
        }
    }

    #[must_use]
    pub fn with_status(mut self, status: StatusId) -> Self {
        self.status_id = Some(status);
        self
    }

    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    #[must_use]
    pub fn with_actor(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    #[must_use]
    pub fn with_process(mut self, process: Process) -> Self {
        self.process = Some(process);
        self
    }

    #[must_use]
    pub fn with_file(mut self, file: File) -> Self {
        self.file = Some(file);
        self
    }

    #[must_use]
    pub fn with_src_endpoint(mut self, ep: Endpoint) -> Self {
        self.src_endpoint = Some(ep);
        self
    }

    #[must_use]
    pub fn with_dst_endpoint(mut self, ep: Endpoint) -> Self {
        self.dst_endpoint = Some(ep);
        self
    }

    #[must_use]
    pub fn with_network(mut self, network: NetworkConnection) -> Self {
        self.network = Some(network);
        self
    }

    #[must_use]
    pub fn with_attack(mut self, technique: TechniqueRef) -> Self {
        self.attack.push(technique);
        self
    }

    #[must_use]
    pub fn with_raw(mut self, raw: serde_json::Value) -> Self {
        self.raw = Some(raw);
        self
    }

    /// Mark this event as federated-origin (received from another host via the
    /// NATS bridge). Set at inbound republish; propagated onto correlator
    /// findings. See the `federated` field. Builder-style.
    #[must_use]
    pub fn with_federated(mut self, federated: bool) -> Self {
        self.federated = federated;
        self
    }

    /// Mark this federated event as signature-verified to a trusted peer
    /// (F-2026-111 c). Set at inbound only after the envelope signature checked
    /// out; propagated onto correlator findings. See `federation_verified`.
    #[must_use]
    pub fn with_federation_verified(mut self, verified: bool) -> Self {
        self.federation_verified = verified;
        self
    }

    /// Validate basic envelope invariants. Cheap; call before emitting.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.schema != SCHEMA_VERSION {
            return Err(crate::Error::unsupported_schema(self.schema));
        }
        if self.host_tag.is_empty() {
            return Err(crate::Error::validation("host_tag must not be empty"));
        }
        if self.source.is_empty() {
            return Err(crate::Error::validation("source must not be empty"));
        }
        let expected = self.class_uid.type_uid(self.activity_id);
        if self.type_uid != expected {
            return Err(crate::Error::validation(format!(
                "type_uid {} != class_uid*100+activity_id ({})",
                self.type_uid, expected
            )));
        }
        Ok(())
    }
}

// -------- helper: serde for Option<OffsetDateTime> as RFC3339 --------
//
// `time::serde::rfc3339` doesn't have an Option variant in stable; we wrap it.
pub(crate) mod opt_rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    pub(crate) fn serialize<S: Serializer>(
        value: &Option<OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(dt) => dt
                .format(&Rfc3339)
                .map_err(serde::ser::Error::custom)?
                .serialize(s),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => OffsetDateTime::parse(&s, &Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::AuthenticationActivity;
    use crate::attack::TechniqueRef;
    use crate::observable::{Actor, Endpoint, User};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_auth_failure() -> Event {
        Event::new(
            ClassUid::AUTHENTICATION,
            AuthenticationActivity::Logon as u32,
            SeverityId::Medium,
            "test-host",
            "auditd",
            1,
        )
        .with_status(StatusId::Failure)
        .with_message("Failed SSH password for alice from 192.0.2.5")
        .with_actor(Actor {
            user: Some(User::local(1000, "alice")),
            ..Actor::default()
        })
        .with_src_endpoint(Endpoint::ip_port(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            51234,
        ))
        .with_dst_endpoint(Endpoint::ip_port(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            22,
        ))
        .with_attack(TechniqueRef::brute_force())
    }

    #[test]
    fn new_event_has_consistent_taxonomy() {
        let e = make_auth_failure();
        assert_eq!(e.schema, SCHEMA_VERSION);
        assert_eq!(e.category_uid, CategoryUid::Iam);
        assert_eq!(e.class_uid, ClassUid::AUTHENTICATION);
        assert_eq!(e.activity_id, 1);
        assert_eq!(e.type_uid, 300_201);
        assert_eq!(e.severity_id, SeverityId::Medium);
        assert_eq!(e.status_id, Some(StatusId::Failure));
    }

    #[test]
    fn round_trips_through_json() {
        let e = make_auth_failure();
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, e.id);
        assert_eq!(back.class_uid, e.class_uid);
        assert_eq!(back.attack.len(), 1);
        assert_eq!(back.attack[0].id, "T1110");
    }

    #[test]
    fn validate_accepts_normal_event() {
        let e = make_auth_failure();
        assert!(e.validate().is_ok());
    }

    #[test]
    fn federated_marker_defaults_false_is_skipped_from_wire_and_builds() {
        let e = make_auth_failure();
        assert!(!e.federated, "events are local-origin by default");
        // The marker is a local-only provenance view: it must NOT appear on the
        // wire/store form, and an event decoded from the wire is local (false).
        let v = serde_json::to_value(&e).unwrap();
        assert!(
            v.get("federated").is_none(),
            "federated must be #[serde(skip)] — never serialized"
        );
        let back: Event = serde_json::from_value(v).unwrap();
        assert!(
            !back.federated,
            "decode defaults the marker to false (local)"
        );
        // Builder sets it (used by the NATS inbound republish path).
        assert!(e.with_federated(true).federated);
    }

    #[test]
    fn validate_rejects_empty_host() {
        let mut e = make_auth_failure();
        e.host_tag.clear();
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_rejects_type_uid_mismatch() {
        let mut e = make_auth_failure();
        e.type_uid = 0;
        assert!(e.validate().is_err());
    }

    #[test]
    fn omitted_fields_are_not_in_json() {
        let minimal = Event::new(
            ClassUid::PROCESS_ACTIVITY,
            1,
            SeverityId::Informational,
            "h",
            "s",
            0,
        );
        let v = serde_json::to_value(&minimal).unwrap();
        assert!(v.get("actor").is_none());
        assert!(v.get("file").is_none());
        assert!(v.get("status_id").is_none());
        assert!(v.get("message").is_none());
        // But required fields are always present.
        assert!(v.get("schema").is_some());
        assert!(v.get("metadata").is_some());
    }
}
