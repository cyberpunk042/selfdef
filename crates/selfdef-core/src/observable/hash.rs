//! File / memory / artifact hashes.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF-aligned hash algorithm.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum HashAlgorithm {
    Unknown = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha256 = 3,
    Sha512 = 4,
    Ctph = 5,
    Tlsh = 6,
    QuickXorHash = 7,
    Other = 99,
}

/// A hash value paired with the algorithm that produced it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash {
    pub algorithm_id: HashAlgorithm,
    /// Lower-case hex digest.
    pub value: String,
}

impl Hash {
    #[must_use]
    pub fn sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm_id: HashAlgorithm::Sha256,
            value: value.into(),
        }
    }

    #[must_use]
    pub fn md5(value: impl Into<String>) -> Self {
        Self {
            algorithm_id: HashAlgorithm::Md5,
            value: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_round_trip() {
        let h = Hash::sha256("0123456789abcdef".repeat(4));
        let s = serde_json::to_string(&h).unwrap();
        let back: Hash = serde_json::from_str(&s).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn algorithm_serializes_as_int() {
        assert_eq!(serde_json::to_string(&HashAlgorithm::Sha256).unwrap(), "3");
    }
}
