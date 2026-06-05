//! `failure_codes` — structured failure taxonomy (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Failure Codes Are Gold"** verbatim (dump
//! lines 4080-4100). *"Most agent systems just save chat history. Weak."* —
//! instead the runtime records structured failure codes so AVX-512 can scan
//! thousands of prior episodes for *"deterministic retrieval of lessons."*
//!
//! ```text
//! 0x01 invalid_schema        0x06 permission_denied
//! 0x02 bad_tool_args         0x07 timeout
//! 0x03 test_failed           0x08 duplicate_branch
//! 0x04 missing_context       0x09 low_oracle_agreement
//! 0x05 hallucinated_api      0x0A user_rejected
//! ```
//!
//! Episodes are scanned along five dimensions (dump 4094-4098): same task type
//! / same repo / same tool / same failure / same model route. Every code +
//! hex value + scan dimension is verbatim — none invented (operator rule: "you
//! cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump 4100, verbatim).
pub const DOCTRINE: &str = "deterministic retrieval of lessons.";

/// The five dimensions AVX-512 scans prior episodes along (dump 4094-4098).
pub const SCAN_DIMENSIONS: [&str; 5] = [
    "same task type",
    "same repo",
    "same tool",
    "same failure",
    "same model route",
];

/// The ten structured failure codes (dump 4086-4095) with their verbatim hex
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureCode {
    /// 0x01 invalid_schema.
    InvalidSchema,
    /// 0x02 bad_tool_args.
    BadToolArgs,
    /// 0x03 test_failed.
    TestFailed,
    /// 0x04 missing_context.
    MissingContext,
    /// 0x05 hallucinated_api.
    HallucinatedApi,
    /// 0x06 permission_denied.
    PermissionDenied,
    /// 0x07 timeout.
    Timeout,
    /// 0x08 duplicate_branch.
    DuplicateBranch,
    /// 0x09 low_oracle_agreement.
    LowOracleAgreement,
    /// 0x0A user_rejected.
    UserRejected,
}

impl FailureCode {
    /// The verbatim hex code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidSchema => 0x01,
            Self::BadToolArgs => 0x02,
            Self::TestFailed => 0x03,
            Self::MissingContext => 0x04,
            Self::HallucinatedApi => 0x05,
            Self::PermissionDenied => 0x06,
            Self::Timeout => 0x07,
            Self::DuplicateBranch => 0x08,
            Self::LowOracleAgreement => 0x09,
            Self::UserRejected => 0x0A,
        }
    }

    /// The verbatim snake_case name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidSchema => "invalid_schema",
            Self::BadToolArgs => "bad_tool_args",
            Self::TestFailed => "test_failed",
            Self::MissingContext => "missing_context",
            Self::HallucinatedApi => "hallucinated_api",
            Self::PermissionDenied => "permission_denied",
            Self::Timeout => "timeout",
            Self::DuplicateBranch => "duplicate_branch",
            Self::LowOracleAgreement => "low_oracle_agreement",
            Self::UserRejected => "user_rejected",
        }
    }

    /// Look up a failure code by its hex value.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::InvalidSchema),
            0x02 => Some(Self::BadToolArgs),
            0x03 => Some(Self::TestFailed),
            0x04 => Some(Self::MissingContext),
            0x05 => Some(Self::HallucinatedApi),
            0x06 => Some(Self::PermissionDenied),
            0x07 => Some(Self::Timeout),
            0x08 => Some(Self::DuplicateBranch),
            0x09 => Some(Self::LowOracleAgreement),
            0x0A => Some(Self::UserRejected),
            _ => None,
        }
    }
}

/// All ten failure codes in dump order.
#[must_use]
pub fn all_codes() -> [FailureCode; 10] {
    [
        FailureCode::InvalidSchema,
        FailureCode::BadToolArgs,
        FailureCode::TestFailed,
        FailureCode::MissingContext,
        FailureCode::HallucinatedApi,
        FailureCode::PermissionDenied,
        FailureCode::Timeout,
        FailureCode::DuplicateBranch,
        FailureCode::LowOracleAgreement,
        FailureCode::UserRejected,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_codes_with_verbatim_hex_and_names() {
        let c = all_codes();
        assert_eq!(c.len(), 10);
        assert_eq!(FailureCode::InvalidSchema.code(), 0x01);
        assert_eq!(FailureCode::InvalidSchema.name(), "invalid_schema");
        assert_eq!(FailureCode::UserRejected.code(), 0x0A);
        assert_eq!(FailureCode::UserRejected.name(), "user_rejected");
    }

    #[test]
    fn codes_are_contiguous_1_through_10() {
        for (i, c) in all_codes().iter().enumerate() {
            assert_eq!(c.code(), (i + 1) as u8);
        }
    }

    #[test]
    fn from_code_roundtrips() {
        for c in all_codes() {
            assert_eq!(FailureCode::from_code(c.code()), Some(c));
        }
        assert_eq!(FailureCode::from_code(0x00), None);
        assert_eq!(FailureCode::from_code(0x0B), None);
    }

    #[test]
    fn five_scan_dimensions_verbatim() {
        assert_eq!(SCAN_DIMENSIONS.len(), 5);
        assert_eq!(SCAN_DIMENSIONS[0], "same task type");
        assert_eq!(SCAN_DIMENSIONS[4], "same model route");
    }

    #[test]
    fn codes_and_names_distinct() {
        let c = all_codes();
        for i in 0..10 {
            for j in (i + 1)..10 {
                assert_ne!(c[i].code(), c[j].code());
                assert_ne!(c[i].name(), c[j].name());
            }
        }
    }

    #[test]
    fn doctrine_verbatim() {
        assert_eq!(DOCTRINE, "deterministic retrieval of lessons.");
    }

    #[test]
    fn serde_roundtrip() {
        for c in all_codes() {
            let j = serde_json::to_string(&c).unwrap();
            let back: FailureCode = serde_json::from_str(&j).unwrap();
            assert_eq!(c, back);
        }
    }
}
