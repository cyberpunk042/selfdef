//! `tool_schema_kv` — invariant-prefix KV caching + content addressing (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The Killer Optimization: Tool Schema
//! KV"** verbatim (dump lines 2543-2570). Tool schemas, system prompts, repo
//! instructions, coding policy, JSON schemas, grammar descriptions are
//! *"repeated constantly"* — so prefill and cache them, turning each request
//! into a *"cached invariant prefix + small live delta"*. Complements
//! [`crate::kv_context_scheduling`] (routing prefs), [`crate::branch_kv_fusion`]
//! (branch KV ownership), and [`crate::memory_admission`] (what to cache).
//!
//! The six cacheable invariant prefixes (dump 2549-2556):
//!
//! ```text
//! system prompt KV / tool schema KV / project policy KV /
//! repo summary KV / user preference KV / grammar/task template KV
//! ```
//!
//! Reuse is decided by **content addressing** (dump 2566): a cache entry is
//! keyed on `hash(model_id, tokenizer_id, prompt_bytes, schema_version)` — *"If
//! identical, reuse. If not identical, recompute."* Every prefix class + the
//! addressing tuple is verbatim — none invented (operator rule: "you cannot
//! invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The request decomposition doctrine (dump 2560, verbatim).
pub const REQUEST_SHAPE: &str = "cached invariant prefix + small live delta";

/// The six invariant prefix classes worth prefilling + caching (dump 2549-2556).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CacheablePrefix {
    /// system prompt KV.
    SystemPrompt,
    /// tool schema KV.
    ToolSchema,
    /// project policy KV.
    ProjectPolicy,
    /// repo summary KV.
    RepoSummary,
    /// user preference KV.
    UserPreference,
    /// grammar/task template KV.
    GrammarTaskTemplate,
}

impl CacheablePrefix {
    /// The verbatim prefix name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SystemPrompt => "system prompt KV",
            Self::ToolSchema => "tool schema KV",
            Self::ProjectPolicy => "project policy KV",
            Self::RepoSummary => "repo summary KV",
            Self::UserPreference => "user preference KV",
            Self::GrammarTaskTemplate => "grammar/task template KV",
        }
    }
}

/// All six cacheable prefixes in dump order.
#[must_use]
pub fn all_prefixes() -> [CacheablePrefix; 6] {
    [
        CacheablePrefix::SystemPrompt,
        CacheablePrefix::ToolSchema,
        CacheablePrefix::ProjectPolicy,
        CacheablePrefix::RepoSummary,
        CacheablePrefix::UserPreference,
        CacheablePrefix::GrammarTaskTemplate,
    ]
}

/// Compute the content address of a cacheable prefix (dump 2566):
/// `hash(model_id, tokenizer_id, prompt_bytes, schema_version)`. Returns a
/// hex SHA-256 digest; two prefixes reuse the same KV iff their addresses are
/// equal. The fields are length-prefixed before hashing so concatenation
/// boundaries cannot collide (e.g. `"ab"+"c"` vs `"a"+"bc"`).
#[must_use]
pub fn content_address(
    model_id: &str,
    tokenizer_id: &str,
    prompt_bytes: &[u8],
    schema_version: u32,
) -> String {
    let mut h = Sha256::new();
    for field in [model_id.as_bytes(), tokenizer_id.as_bytes(), prompt_bytes] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field);
    }
    h.update(schema_version.to_le_bytes());
    format!("{:x}", h.finalize())
}

/// Reuse decision (dump 2568-2570): reuse the cached KV iff the two content
/// addresses are identical.
#[must_use]
pub fn may_reuse(addr_a: &str, addr_b: &str) -> bool {
    addr_a == addr_b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_prefixes_with_verbatim_names() {
        let p = all_prefixes();
        assert_eq!(p.len(), 6);
        assert_eq!(p[0].name(), "system prompt KV");
        assert_eq!(p[5].name(), "grammar/task template KV");
        assert_eq!(CacheablePrefix::ToolSchema.name(), "tool schema KV");
    }

    #[test]
    fn prefixes_distinct() {
        let p = all_prefixes();
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(p[i], p[j]);
                assert_ne!(p[i].name(), p[j].name());
            }
        }
    }

    #[test]
    fn identical_inputs_address_identically_reuse() {
        let a = content_address("ling-2.6", "tok-v1", b"system prompt...", 3);
        let b = content_address("ling-2.6", "tok-v1", b"system prompt...", 3);
        assert_eq!(a, b);
        assert!(may_reuse(&a, &b));
    }

    #[test]
    fn different_model_recomputes() {
        let a = content_address("ling-2.6", "tok-v1", b"p", 1);
        let b = content_address("nemotron-3", "tok-v1", b"p", 1);
        assert_ne!(a, b);
        assert!(!may_reuse(&a, &b));
    }

    #[test]
    fn different_schema_version_recomputes() {
        let a = content_address("m", "t", b"p", 1);
        let b = content_address("m", "t", b"p", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefixing_prevents_boundary_collisions() {
        // "ab"+"c" must not collide with "a"+"bc" for (model_id, tokenizer_id).
        let a = content_address("ab", "c", b"", 0);
        let b = content_address("a", "bc", b"", 0);
        assert_ne!(a, b);
    }

    #[test]
    fn address_is_hex_sha256_length() {
        let a = content_address("m", "t", b"p", 1);
        assert_eq!(a.len(), 64); // 32 bytes hex
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn request_shape_doctrine_verbatim() {
        assert_eq!(REQUEST_SHAPE, "cached invariant prefix + small live delta");
    }

    #[test]
    fn serde_roundtrip() {
        for p in all_prefixes() {
            let j = serde_json::to_string(&p).unwrap();
            let back: CacheablePrefix = serde_json::from_str(&j).unwrap();
            assert_eq!(p, back);
        }
    }
}
