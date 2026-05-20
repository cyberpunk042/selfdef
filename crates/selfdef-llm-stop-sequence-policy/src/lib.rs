//! `selfdef-llm-stop-sequence-policy` — per-Profile stop sequences.
//!
//! Each Profile carries `Vec<String>` of stop sequences. `should_stop
//! (profile, accumulated_text)` returns the first stop sequence
//! that occurs in `accumulated_text` (longest-match if multiple match
//! at the same position).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmStopSequencePolicy {
    /// Schema version.
    pub schema_version: String,
    /// profile → sequences.
    pub sequences: BTreeMap<Profile, Vec<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StopError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty sequence.
    #[error("stop sequence empty")]
    EmptySequence,
}

impl LlmStopSequencePolicy {
    /// Canonical: same set across all profiles.
    pub fn canonical() -> Self {
        let mut m = BTreeMap::new();
        let canon: Vec<String> = vec![
            "<|im_end|>".into(),
            "<|endoftext|>".into(),
            "\n\n\n".into(),
        ];
        for &p in &[Profile::Private, Profile::Fast, Profile::Careful, Profile::Autonomous, Profile::Experimental, Profile::Production] {
            m.insert(p, canon.clone());
        }
        Self {
            schema_version: SCHEMA_VERSION.into(),
            sequences: m,
        }
    }

    /// Add a sequence to a profile.
    pub fn add(&mut self, profile: Profile, sequence: &str) -> Result<(), StopError> {
        if sequence.is_empty() { return Err(StopError::EmptySequence); }
        self.sequences.entry(profile).or_default().push(sequence.into());
        Ok(())
    }

    /// Detect stop. Returns the matched sequence and its position in `text`.
    pub fn should_stop(&self, profile: Profile, accumulated_text: &str) -> Option<String> {
        let seqs = self.sequences.get(&profile)?;
        let mut earliest: Option<(usize, &str)> = None;
        for s in seqs {
            if let Some(pos) = accumulated_text.find(s.as_str()) {
                let candidate_len = s.len();
                match earliest {
                    None => earliest = Some((pos, s.as_str())),
                    Some((p, prev)) => {
                        if pos < p || (pos == p && candidate_len > prev.len()) {
                            earliest = Some((pos, s.as_str()));
                        }
                    }
                }
            }
        }
        earliest.map(|(_, s)| s.to_string())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StopError> {
        if self.schema_version != SCHEMA_VERSION { return Err(StopError::SchemaMismatch); }
        for seqs in self.sequences.values() {
            for s in seqs {
                if s.is_empty() { return Err(StopError::EmptySequence); }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        LlmStopSequencePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn stop_sequence_found() {
        let p = LlmStopSequencePolicy::canonical();
        let stop = p.should_stop(Profile::Fast, "hello world<|im_end|>more").unwrap();
        assert_eq!(stop, "<|im_end|>");
    }

    #[test]
    fn no_stop_returns_none() {
        let p = LlmStopSequencePolicy::canonical();
        assert!(p.should_stop(Profile::Fast, "normal text").is_none());
    }

    #[test]
    fn earliest_position_wins() {
        let mut p = LlmStopSequencePolicy::canonical();
        p.add(Profile::Fast, "STOP-EARLY").unwrap();
        let stop = p.should_stop(Profile::Fast, "STOP-EARLY then <|im_end|>").unwrap();
        assert_eq!(stop, "STOP-EARLY");
    }

    #[test]
    fn longest_match_at_same_position() {
        let mut p = LlmStopSequencePolicy { schema_version: SCHEMA_VERSION.into(), sequences: BTreeMap::new() };
        p.add(Profile::Fast, "ab").unwrap();
        p.add(Profile::Fast, "abcd").unwrap();
        let stop = p.should_stop(Profile::Fast, "abcd").unwrap();
        assert_eq!(stop, "abcd");
    }

    #[test]
    fn empty_sequence_rejected() {
        let mut p = LlmStopSequencePolicy::canonical();
        assert!(matches!(p.add(Profile::Fast, "").unwrap_err(), StopError::EmptySequence));
    }

    #[test]
    fn unconfigured_profile_none() {
        let mut p = LlmStopSequencePolicy::canonical();
        p.sequences.clear();
        assert!(p.should_stop(Profile::Fast, "anything").is_none());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = LlmStopSequencePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), StopError::SchemaMismatch));
    }

    #[test]
    fn stop_serde_roundtrip() {
        let p = LlmStopSequencePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: LlmStopSequencePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
