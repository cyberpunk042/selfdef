//! `selfdef-communication-boundary` — MS034 8-message-type schema.
//!
//! Per MS034 + E0342-E0349 + dump 3450-3488:
//!
//! **4 transports** (E0342): virtio-vsock / gRPC-over-vsock / Unix-socket-proxy
//! / shared-folder (explicit exchange dirs only).
//!
//! **8 message types** (E0343-E0345):
//! - DraftRequest (host → VM, generate)
//! - DraftResult (VM → host, drafts)
//! - EmbeddingRequest (host → VM, embed)
//! - RerankResult (VM → host, reranked candidates)
//! - VisionResult (VM → host, vision/GUI output)
//! - ToolPlan (VM → host, proposed tool calls)
//! - RiskAssessment (VM → host, scored risk)
//! - PatchProposal (VM → host, file patches)
//!
//! Doctrines preserved verbatim:
//!
//! > "Never let the VM directly mutate host truth" (E0346 dump 3477)
//!
//! > "The VM proposes. Host commits." (E0347 dump 3479)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine verbatim per E0346 dump 3477.
pub const DOCTRINE_VM_NEVER_MUTATES: &str = "Never let the VM directly mutate host truth";

/// Doctrine verbatim per E0347 dump 3479.
pub const DOCTRINE_VM_PROPOSES_HOST_COMMITS: &str = "The VM proposes. Host commits.";

/// 4 transport options per E0342 dump 3456-3462.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// AF_VSOCK virtio socket (host↔VM kernel-level).
    VirtioVsock,
    /// gRPC over AF_VSOCK channel.
    GrpcOverVsock,
    /// Unix-socket proxy (forwards over shared mount).
    UnixSocketProxy,
    /// Shared folder (explicit exchange dirs only per MS037).
    SharedFolder,
}

/// 8 canonical message types per E0343-E0345.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageType {
    /// host → VM: ask for draft generation (dump 3466).
    DraftRequest,
    /// VM → host: drafts response (dump 3467).
    DraftResult,
    /// host → VM: ask for embeddings (dump 3468).
    EmbeddingRequest,
    /// VM → host: reranked candidates (dump 3469).
    RerankResult,
    /// VM → host: vision / GUI / perception output (dump 3470).
    VisionResult,
    /// VM → host: proposed tool calls (dump 3471).
    ToolPlan,
    /// VM → host: scored risk (dump 3472).
    RiskAssessment,
    /// VM → host: file patches (dump 3473).
    PatchProposal,
}

impl MessageType {
    /// Direction (host→VM or VM→host).
    pub fn direction(self) -> Direction {
        match self {
            MessageType::DraftRequest | MessageType::EmbeddingRequest => Direction::HostToVm,
            _ => Direction::VmToHost,
        }
    }
    /// Whether this message type can carry a mutation proposal (VM→host non-recall).
    pub fn is_proposal(self) -> bool {
        matches!(
            self,
            MessageType::ToolPlan | MessageType::PatchProposal | MessageType::RiskAssessment
        )
    }
}

/// Message direction per E0342.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// host → VM.
    HostToVm,
    /// VM → host.
    VmToHost,
}

/// Common envelope (every message carries these fields).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// Wire-stable schema version.
    pub schema_version: String,
    /// Message type.
    pub message_type: MessageType,
    /// Transport in use.
    pub transport: Transport,
    /// Trace ID per M049 (every message MUST carry one).
    pub trace_id: String,
    /// Profile name at message time (MS040).
    pub profile: String,
    /// Budget reservation in micro-USD (mandatory for DraftRequest + EmbeddingRequest per F04037).
    pub budget_micro_usd: u64,
    /// capability_word (MS035 — bits 16..23 carry network_scope hint per F04525).
    pub capability_word: String,
    /// Payload (free-form serialised JSON sub-schema; type depends on message_type).
    pub payload: String,
    /// MS003 signature over the canonical-JSON encoding.
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CommError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// trace_id missing (F03942 — every message emits trace).
    #[error("envelope missing trace_id")]
    TraceIdMissing,
    /// profile missing.
    #[error("envelope missing profile")]
    ProfileMissing,
    /// capability_word missing (F04525).
    #[error("envelope missing capability_word")]
    CapabilityWordMissing,
    /// signature missing.
    #[error("envelope unsigned")]
    Unsigned,
    /// DraftRequest / EmbeddingRequest missing budget field (F04037).
    #[error("budget required for {0:?}")]
    BudgetMissing(MessageType),
    /// Doctrine surface tampered.
    #[error("doctrine tampered: expected verbatim {expected:?}")]
    DoctrineTampered {
        /// Expected.
        expected: String,
    },
}

impl MessageEnvelope {
    /// Validate envelope-level invariants.
    pub fn validate(&self) -> Result<(), CommError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CommError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.trace_id.is_empty() {
            return Err(CommError::TraceIdMissing);
        }
        if self.profile.is_empty() {
            return Err(CommError::ProfileMissing);
        }
        if self.capability_word.is_empty() {
            return Err(CommError::CapabilityWordMissing);
        }
        if self.signature.is_empty() {
            return Err(CommError::Unsigned);
        }
        // F04037 — DraftRequest + EmbeddingRequest MUST carry budget.
        if matches!(self.message_type, MessageType::DraftRequest | MessageType::EmbeddingRequest)
            && self.budget_micro_usd == 0
        {
            return Err(CommError::BudgetMissing(self.message_type));
        }
        Ok(())
    }
}

/// Assert both communication-boundary doctrines are intact.
pub fn assert_doctrines_intact(vm_never: &str, vm_proposes: &str) -> Result<(), CommError> {
    if vm_never != DOCTRINE_VM_NEVER_MUTATES {
        return Err(CommError::DoctrineTampered { expected: DOCTRINE_VM_NEVER_MUTATES.into() });
    }
    if vm_proposes != DOCTRINE_VM_PROPOSES_HOST_COMMITS {
        return Err(CommError::DoctrineTampered { expected: DOCTRINE_VM_PROPOSES_HOST_COMMITS.into() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_envelope(mt: MessageType) -> MessageEnvelope {
        MessageEnvelope {
            schema_version: SCHEMA_VERSION.into(),
            message_type: mt,
            transport: Transport::GrpcOverVsock,
            trace_id: "trace-001".into(),
            profile: "careful".into(),
            budget_micro_usd: 1_000_000,  // 1 USD
            capability_word: "0xff00ff00ff00ff00".into(),
            payload: "{}".into(),
            signature: "ms003-sig".into(),
        }
    }

    // --- 8 message types ---

    #[test]
    fn eight_message_types_enumerated() {
        let kinds = [
            MessageType::DraftRequest, MessageType::DraftResult,
            MessageType::EmbeddingRequest, MessageType::RerankResult,
            MessageType::VisionResult, MessageType::ToolPlan,
            MessageType::RiskAssessment, MessageType::PatchProposal,
        ];
        assert_eq!(kinds.len(), 8);
    }

    #[test]
    fn direction_per_type() {
        assert_eq!(MessageType::DraftRequest.direction(), Direction::HostToVm);
        assert_eq!(MessageType::EmbeddingRequest.direction(), Direction::HostToVm);
        for vm_to_host in [
            MessageType::DraftResult, MessageType::RerankResult,
            MessageType::VisionResult, MessageType::ToolPlan,
            MessageType::RiskAssessment, MessageType::PatchProposal,
        ] {
            assert_eq!(vm_to_host.direction(), Direction::VmToHost);
        }
    }

    #[test]
    fn proposal_classification() {
        assert!(MessageType::ToolPlan.is_proposal());
        assert!(MessageType::PatchProposal.is_proposal());
        assert!(MessageType::RiskAssessment.is_proposal());
        assert!(!MessageType::DraftResult.is_proposal());
        assert!(!MessageType::DraftRequest.is_proposal());
    }

    // --- 4 transports ---

    #[test]
    fn four_transports_serde_kebab() {
        assert_eq!(serde_json::to_string(&Transport::VirtioVsock).unwrap(), "\"virtio-vsock\"");
        assert_eq!(serde_json::to_string(&Transport::GrpcOverVsock).unwrap(), "\"grpc-over-vsock\"");
        assert_eq!(serde_json::to_string(&Transport::UnixSocketProxy).unwrap(), "\"unix-socket-proxy\"");
        assert_eq!(serde_json::to_string(&Transport::SharedFolder).unwrap(), "\"shared-folder\"");
    }

    // --- Envelope validation ---

    #[test]
    fn ok_envelope_validates() {
        ok_envelope(MessageType::ToolPlan).validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = ok_envelope(MessageType::DraftRequest);
        e.schema_version = "9.9.9".into();
        assert!(matches!(e.validate().unwrap_err(), CommError::SchemaMismatch { .. }));
    }

    #[test]
    fn missing_trace_id_rejected() {
        let mut e = ok_envelope(MessageType::ToolPlan);
        e.trace_id = String::new();
        assert!(matches!(e.validate().unwrap_err(), CommError::TraceIdMissing));
    }

    #[test]
    fn missing_profile_rejected() {
        let mut e = ok_envelope(MessageType::ToolPlan);
        e.profile = String::new();
        assert!(matches!(e.validate().unwrap_err(), CommError::ProfileMissing));
    }

    #[test]
    fn missing_capability_word_rejected() {
        let mut e = ok_envelope(MessageType::ToolPlan);
        e.capability_word = String::new();
        assert!(matches!(e.validate().unwrap_err(), CommError::CapabilityWordMissing));
    }

    #[test]
    fn unsigned_rejected() {
        let mut e = ok_envelope(MessageType::ToolPlan);
        e.signature = String::new();
        assert!(matches!(e.validate().unwrap_err(), CommError::Unsigned));
    }

    #[test]
    fn draft_request_zero_budget_rejected() {
        let mut e = ok_envelope(MessageType::DraftRequest);
        e.budget_micro_usd = 0;
        assert!(matches!(e.validate().unwrap_err(), CommError::BudgetMissing(MessageType::DraftRequest)));
    }

    #[test]
    fn embedding_request_zero_budget_rejected() {
        let mut e = ok_envelope(MessageType::EmbeddingRequest);
        e.budget_micro_usd = 0;
        assert!(matches!(e.validate().unwrap_err(), CommError::BudgetMissing(MessageType::EmbeddingRequest)));
    }

    #[test]
    fn vm_to_host_messages_allow_zero_budget() {
        // ToolPlan etc. don't require host-side budget reservation
        let mut e = ok_envelope(MessageType::ToolPlan);
        e.budget_micro_usd = 0;
        e.validate().unwrap();
    }

    // --- Doctrines ---

    #[test]
    fn doctrines_verbatim() {
        assert_eq!(DOCTRINE_VM_NEVER_MUTATES, "Never let the VM directly mutate host truth");
        assert_eq!(DOCTRINE_VM_PROPOSES_HOST_COMMITS, "The VM proposes. Host commits.");
        assert_doctrines_intact(
            "Never let the VM directly mutate host truth",
            "The VM proposes. Host commits.",
        ).unwrap();
    }

    #[test]
    fn doctrine_tamper_caught() {
        let err = assert_doctrines_intact("WRONG", "The VM proposes. Host commits.").unwrap_err();
        assert!(matches!(err, CommError::DoctrineTampered { .. }));
        let err2 = assert_doctrines_intact("Never let the VM directly mutate host truth", "WRONG").unwrap_err();
        assert!(matches!(err2, CommError::DoctrineTampered { .. }));
    }

    // --- Serde ---

    #[test]
    fn message_type_serde_kebab() {
        assert_eq!(serde_json::to_string(&MessageType::PatchProposal).unwrap(), "\"patch-proposal\"");
        assert_eq!(serde_json::to_string(&MessageType::RiskAssessment).unwrap(), "\"risk-assessment\"");
        assert_eq!(serde_json::to_string(&MessageType::EmbeddingRequest).unwrap(), "\"embedding-request\"");
    }

    #[test]
    fn direction_serde_kebab() {
        assert_eq!(serde_json::to_string(&Direction::HostToVm).unwrap(), "\"host-to-vm\"");
        assert_eq!(serde_json::to_string(&Direction::VmToHost).unwrap(), "\"vm-to-host\"");
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let e = ok_envelope(MessageType::PatchProposal);
        let j = serde_json::to_string(&e).unwrap();
        let back: MessageEnvelope = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
