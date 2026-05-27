//! `GET /v1/communication-boundary` — MS034 / SDD-048 D-2 discovery.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct CommunicationBoundarySchema {
    pub transports: &'static [TransportDescriptor],
    pub message_types: &'static [MessageDescriptor],
    pub doctrines: &'static [&'static str],
    pub proposal_to_commit: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub(crate) struct TransportDescriptor {
    pub name: &'static str,
    pub scope: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct MessageDescriptor {
    pub kind: &'static str,
    pub direction: &'static str,
    pub content: &'static str,
    pub is_proposal: bool,
}

const TRANSPORTS: &[TransportDescriptor] = &[
    TransportDescriptor {
        name: "VirtioVsock",
        scope: "AF_VSOCK virtio socket (host↔VM kernel-level)",
    },
    TransportDescriptor {
        name: "GrpcOverVsock",
        scope: "gRPC framed over AF_VSOCK",
    },
    TransportDescriptor {
        name: "UnixSocketProxy",
        scope: "Unix-socket forwarded over shared mount",
    },
    TransportDescriptor {
        name: "SharedFolder",
        scope: "explicit-exchange dirs per SDD-045 (slowest; large payloads)",
    },
];

const MESSAGE_TYPES: &[MessageDescriptor] = &[
    MessageDescriptor {
        kind: "DraftRequest",
        direction: "host→VM",
        content: "ask for generation",
        is_proposal: false,
    },
    MessageDescriptor {
        kind: "DraftResult",
        direction: "VM→host",
        content: "drafts response",
        is_proposal: false,
    },
    MessageDescriptor {
        kind: "EmbeddingRequest",
        direction: "host→VM",
        content: "ask for embeddings",
        is_proposal: false,
    },
    MessageDescriptor {
        kind: "RerankResult",
        direction: "VM→host",
        content: "reranked candidates",
        is_proposal: false,
    },
    MessageDescriptor {
        kind: "VisionResult",
        direction: "VM→host",
        content: "vision / GUI / perception output",
        is_proposal: false,
    },
    MessageDescriptor {
        kind: "ToolPlan",
        direction: "VM→host",
        content: "proposed tool calls (PROPOSAL)",
        is_proposal: true,
    },
    MessageDescriptor {
        kind: "RiskAssessment",
        direction: "VM→host",
        content: "scored risk (PROPOSAL)",
        is_proposal: true,
    },
    MessageDescriptor {
        kind: "PatchProposal",
        direction: "VM→host",
        content: "file patches (PROPOSAL — SDD-045 flow)",
        is_proposal: true,
    },
];

const DOCTRINES: &[&str] = &[
    "Never let the VM directly mutate host truth",
    "The VM proposes. Host commits.",
];

const PROPOSAL_TO_COMMIT: &[&str] = &[
    "ToolPlan       → SDD-043 commit_type = ToolSideEffect",
    "RiskAssessment → SDD-043 commit_type = RiskAssessment",
    "PatchProposal  → SDD-043 commit_type = FileWrite (via SDD-045 import pipeline)",
];

pub(crate) async fn show() -> Json<CommunicationBoundarySchema> {
    Json(CommunicationBoundarySchema {
        transports: TRANSPORTS,
        message_types: MESSAGE_TYPES,
        doctrines: DOCTRINES,
        proposal_to_commit: PROPOSAL_TO_COMMIT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_048() {
        assert_eq!(TRANSPORTS.len(), 4);
        assert_eq!(MESSAGE_TYPES.len(), 8);
        // Exactly 3 message types are proposals
        let proposals = MESSAGE_TYPES.iter().filter(|m| m.is_proposal).count();
        assert_eq!(proposals, 3);
        assert_eq!(DOCTRINES.len(), 2);
        assert_eq!(PROPOSAL_TO_COMMIT.len(), 3);
    }
}
