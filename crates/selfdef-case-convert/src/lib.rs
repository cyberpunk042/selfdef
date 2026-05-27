//! `selfdef-case-convert` — ASCII case conversion.
//!
//! tokenize splits an input into words by:
//! - explicit separators (-, _, space)
//! - capital→lower transitions (in camel/Pascal).
//!
//! to_snake / to_kebab / to_camel / to_pascal regenerate.
//! Pure data; ASCII only — non-ASCII chars pass through.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Errors.
#[derive(Debug, Error)]
pub enum CaseError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("input empty")]
    EmptyInput,
}

/// Versioned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseConvertState {
    /// Schema version.
    pub schema_version: String,
    /// Last input.
    pub last: Option<String>,
}

/// Tokenize into lowercased words.
pub fn tokenize(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_lower_or_digit = false;
    for c in s.chars() {
        if c == '-' || c == '_' || c == ' ' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower_or_digit = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower_or_digit && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        for lc in c.to_lowercase() {
            cur.push(lc);
        }
        prev_lower_or_digit = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// snake_case.
pub fn to_snake(s: &str) -> String {
    tokenize(s).join("_")
}

/// kebab-case.
pub fn to_kebab(s: &str) -> String {
    tokenize(s).join("-")
}

/// camelCase.
pub fn to_camel(s: &str) -> String {
    let tokens = tokenize(s);
    let mut out = String::new();
    for (i, t) in tokens.iter().enumerate() {
        if i == 0 {
            out.push_str(t);
        } else {
            let mut chars = t.chars();
            if let Some(first) = chars.next() {
                for u in first.to_uppercase() {
                    out.push(u);
                }
            }
            out.push_str(chars.as_str());
        }
    }
    out
}

/// PascalCase.
pub fn to_pascal(s: &str) -> String {
    let tokens = tokenize(s);
    let mut out = String::new();
    for t in tokens {
        let mut chars = t.chars();
        if let Some(first) = chars.next() {
            for u in first.to_uppercase() {
                out.push(u);
            }
        }
        out.push_str(chars.as_str());
    }
    out
}

impl CaseConvertState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: None,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CaseError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CaseError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for CaseConvertState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_snake() {
        assert_eq!(tokenize("hello_world_foo"), vec!["hello", "world", "foo"]);
    }

    #[test]
    fn tokenize_camel() {
        assert_eq!(tokenize("helloWorldFoo"), vec!["hello", "world", "foo"]);
    }

    #[test]
    fn tokenize_pascal() {
        assert_eq!(tokenize("HelloWorldFoo"), vec!["hello", "world", "foo"]);
    }

    #[test]
    fn tokenize_kebab() {
        assert_eq!(tokenize("hello-world-foo"), vec!["hello", "world", "foo"]);
    }

    #[test]
    fn to_snake_from_camel() {
        assert_eq!(to_snake("helloWorld"), "hello_world");
    }

    #[test]
    fn to_camel_from_snake() {
        assert_eq!(to_camel("hello_world"), "helloWorld");
    }

    #[test]
    fn to_pascal_from_kebab() {
        assert_eq!(to_pascal("hello-world"), "HelloWorld");
    }

    #[test]
    fn to_kebab_from_pascal() {
        assert_eq!(to_kebab("HelloWorld"), "hello-world");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = CaseConvertState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            CaseError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = CaseConvertState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: CaseConvertState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
