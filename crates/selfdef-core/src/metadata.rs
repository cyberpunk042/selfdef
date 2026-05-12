//! Metadata about the event's processing: who produced it, when it was
//! logged, what sequence number, what OCSF profiles apply.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

impl Default for Product {
    fn default() -> Self {
        Self {
            name: "selfdef-daemon".into(),
            vendor_name: "selfdef".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// Per-event processing metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub product: Product,
    /// Wall-clock time the event was *logged* (vs. observed; they differ
    /// when an event is replayed from a buffer or warm store).
    #[serde(with = "time::serde::rfc3339")]
    pub logged_time_dt: OffsetDateTime,
    /// Monotonic per-host sequence number — useful for ordering and gap
    /// detection in cold archives.
    pub sequence: u64,
    /// OCSF profiles applicable to this event (e.g. `["host", "linux"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
}

impl Metadata {
    /// Construct with `logged_time_dt = now()` and a caller-supplied sequence.
    #[must_use]
    pub fn now(sequence: u64) -> Self {
        Self {
            product: Product::default(),
            logged_time_dt: OffsetDateTime::now_utc(),
            sequence,
            profiles: vec!["host".into(), "linux".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_uses_crate_version() {
        let p = Product::default();
        assert_eq!(p.name, "selfdef-daemon");
        assert!(!p.version.is_empty());
    }

    #[test]
    fn metadata_round_trips() {
        let m = Metadata::now(42);
        let s = serde_json::to_string(&m).unwrap();
        let back: Metadata = serde_json::from_str(&s).unwrap();
        assert_eq!(back.sequence, 42);
        assert_eq!(back.profiles, vec!["host", "linux"]);
    }
}
