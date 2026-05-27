//! `selfdef-actor-attestation-chain` — operator → agent → service chain.
//!
//! 3 actor tiers: Operator (human, MS003), Agent (delegated), Service
//! (program/account). A privileged action carries an attestation chain
//! Operator → Agent → Service where each parent signs the child.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Actor tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorTier {
    /// Operator (human).
    Operator,
    /// Agent (delegated).
    Agent,
    /// Service (program / account).
    Service,
}

/// One link in the chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationLink {
    /// Actor tier.
    pub tier: ActorTier,
    /// Actor id (MS003 fingerprint for Operator, agent_id for Agent, service_name for Service).
    pub actor_id: String,
    /// Parent's signature over this link (hex). For the Operator (first link),
    /// `parent_signature` is `actor_id` itself (self-anchored).
    pub parent_signature: String,
}

/// Attestation chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationChain {
    /// Schema version.
    pub schema_version: String,
    /// Ordered links (Operator first, then Agent, then Service).
    pub links: Vec<AttestationLink>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ChainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty chain.
    #[error("chain empty")]
    Empty,
    /// First link is not Operator.
    #[error("first link must be Operator, got {0:?}")]
    FirstNotOperator(ActorTier),
    /// Out-of-order tiers.
    #[error("tier {tier:?} cannot follow {prev:?}")]
    OutOfOrder {
        /// prev.
        prev: ActorTier,
        /// tier.
        tier: ActorTier,
    },
    /// Empty actor id.
    #[error("link {idx} actor_id empty")]
    EmptyActorId {
        /// idx.
        idx: usize,
    },
    /// Empty signature on non-operator link.
    #[error("link {idx} parent_signature empty")]
    EmptySignature {
        /// idx.
        idx: usize,
    },
    /// Operator self-anchor mismatch (parent_signature must equal actor_id).
    #[error("operator link self-anchor mismatch")]
    OperatorSelfAnchorMismatch,
}

fn next_allowed(prev: ActorTier) -> &'static [ActorTier] {
    match prev {
        ActorTier::Operator => &[ActorTier::Agent, ActorTier::Service],
        ActorTier::Agent => &[ActorTier::Service],
        ActorTier::Service => &[],
    }
}

impl AttestationChain {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            links: Vec::new(),
        }
    }

    /// Append a link.
    pub fn append(&mut self, link: AttestationLink) -> Result<(), ChainError> {
        let idx = self.links.len();
        if link.actor_id.is_empty() {
            return Err(ChainError::EmptyActorId { idx });
        }
        if self.links.is_empty() {
            if link.tier != ActorTier::Operator {
                return Err(ChainError::FirstNotOperator(link.tier));
            }
            if link.parent_signature != link.actor_id {
                return Err(ChainError::OperatorSelfAnchorMismatch);
            }
        } else {
            let prev_tier = self.links.last().unwrap().tier;
            if !next_allowed(prev_tier).contains(&link.tier) {
                return Err(ChainError::OutOfOrder {
                    prev: prev_tier,
                    tier: link.tier,
                });
            }
            if link.parent_signature.is_empty() {
                return Err(ChainError::EmptySignature { idx });
            }
        }
        self.links.push(link);
        Ok(())
    }

    /// Walk the chain top-down. Returns the leaf (last) link's actor_id.
    pub fn leaf_actor(&self) -> Option<&str> {
        self.links.last().map(|l| l.actor_id.as_str())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ChainError::SchemaMismatch);
        }
        if self.links.is_empty() {
            return Err(ChainError::Empty);
        }
        if self.links[0].tier != ActorTier::Operator {
            return Err(ChainError::FirstNotOperator(self.links[0].tier));
        }
        if self.links[0].parent_signature != self.links[0].actor_id {
            return Err(ChainError::OperatorSelfAnchorMismatch);
        }
        for (i, l) in self.links.iter().enumerate() {
            if l.actor_id.is_empty() {
                return Err(ChainError::EmptyActorId { idx: i });
            }
            if i == 0 {
                continue;
            }
            let prev = self.links[i - 1].tier;
            if !next_allowed(prev).contains(&l.tier) {
                return Err(ChainError::OutOfOrder { prev, tier: l.tier });
            }
            if l.parent_signature.is_empty() {
                return Err(ChainError::EmptySignature { idx: i });
            }
        }
        Ok(())
    }
}

impl Default for AttestationChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(tier: ActorTier, actor_id: &str, parent_signature: &str) -> AttestationLink {
        AttestationLink {
            tier,
            actor_id: actor_id.into(),
            parent_signature: parent_signature.into(),
        }
    }

    #[test]
    fn empty_chain_rejected_on_validate() {
        let c = AttestationChain::new();
        assert!(matches!(c.validate().unwrap_err(), ChainError::Empty));
    }

    #[test]
    fn full_chain_validates() {
        let mut c = AttestationChain::new();
        c.append(link(ActorTier::Operator, "op-fp", "op-fp"))
            .unwrap();
        c.append(link(ActorTier::Agent, "agent-007", "op-sig-over-agent"))
            .unwrap();
        c.append(link(ActorTier::Service, "svc-build", "agent-sig-over-svc"))
            .unwrap();
        c.validate().unwrap();
        assert_eq!(c.leaf_actor(), Some("svc-build"));
    }

    #[test]
    fn first_not_operator_rejected() {
        let mut c = AttestationChain::new();
        let err = c
            .append(link(ActorTier::Agent, "agent", "sig"))
            .unwrap_err();
        assert!(matches!(err, ChainError::FirstNotOperator(_)));
    }

    #[test]
    fn out_of_order_rejected() {
        let mut c = AttestationChain::new();
        c.append(link(ActorTier::Operator, "op", "op")).unwrap();
        c.append(link(ActorTier::Service, "svc", "sig")).unwrap();
        // Can't append Agent after Service.
        let err = c
            .append(link(ActorTier::Agent, "agent", "sig"))
            .unwrap_err();
        assert!(matches!(err, ChainError::OutOfOrder { .. }));
    }

    #[test]
    fn empty_signature_rejected() {
        let mut c = AttestationChain::new();
        c.append(link(ActorTier::Operator, "op", "op")).unwrap();
        let err = c.append(link(ActorTier::Agent, "agent", "")).unwrap_err();
        assert!(matches!(err, ChainError::EmptySignature { .. }));
    }

    #[test]
    fn operator_self_anchor_mismatch_rejected() {
        let mut c = AttestationChain::new();
        let err = c
            .append(link(ActorTier::Operator, "op", "other-sig"))
            .unwrap_err();
        assert!(matches!(err, ChainError::OperatorSelfAnchorMismatch));
    }

    #[test]
    fn operator_only_chain_ok() {
        let mut c = AttestationChain::new();
        c.append(link(ActorTier::Operator, "op-fp", "op-fp"))
            .unwrap();
        c.validate().unwrap();
    }

    #[test]
    fn operator_then_service_ok_skip_agent() {
        let mut c = AttestationChain::new();
        c.append(link(ActorTier::Operator, "op", "op")).unwrap();
        c.append(link(ActorTier::Service, "svc", "op-sig-over-svc"))
            .unwrap();
        c.validate().unwrap();
    }

    #[test]
    fn empty_actor_id_rejected() {
        let mut c = AttestationChain::new();
        let err = c.append(link(ActorTier::Operator, "", "")).unwrap_err();
        assert!(matches!(err, ChainError::EmptyActorId { .. }));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ActorTier::Operator).unwrap(),
            "\"operator\""
        );
        assert_eq!(
            serde_json::to_string(&ActorTier::Agent).unwrap(),
            "\"agent\""
        );
        assert_eq!(
            serde_json::to_string(&ActorTier::Service).unwrap(),
            "\"service\""
        );
    }

    #[test]
    fn chain_serde_roundtrip() {
        let mut c = AttestationChain::new();
        c.append(link(ActorTier::Operator, "op", "op")).unwrap();
        c.append(link(ActorTier::Agent, "agent", "sig")).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: AttestationChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
