//! Activity outcome status, OCSF `status_id`.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// Outcome of the observed activity. OCSF-aligned.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum StatusId {
    Unknown = 0,
    Success = 1,
    Failure = 2,
    Other = 99,
}

impl StatusId {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Success => "Success",
            Self::Failure => "Failure",
            Self::Other => "Other",
        }
    }
}

impl std::fmt::Display for StatusId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_is_integer() {
        assert_eq!(serde_json::to_string(&StatusId::Failure).unwrap(), "2");
    }
}
