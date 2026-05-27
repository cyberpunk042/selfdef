//! `selfdef-csv-line` — single-line CSV split.
//!
//! split(line, sep, quote) parses one line. Quoted fields handle
//! escaped quotes (sequence quote+quote → literal quote). Outside
//! quotes, `sep` ends the field. Unbalanced quotes error.
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
pub enum CsvError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unbalanced quote.
    #[error("unbalanced quote")]
    UnbalancedQuote,
}

/// Versioned state placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsvLineState {
    /// Schema version.
    pub schema_version: String,
}

/// Split a single CSV line into fields.
pub fn split(line: &str, sep: char, quote: char) -> Result<Vec<String>, CsvError> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == quote {
                if chars.peek() == Some(&quote) {
                    cur.push(quote);
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == quote {
            in_quotes = true;
        } else if c == sep {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if in_quotes {
        return Err(CsvError::UnbalancedQuote);
    }
    out.push(cur);
    Ok(out)
}

impl CsvLineState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CsvError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CsvError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for CsvLineState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_split() {
        let v = split("a,b,c", ',', '"').unwrap();
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn empty_fields() {
        let v = split("a,,c", ',', '"').unwrap();
        assert_eq!(v, vec!["a", "", "c"]);
    }

    #[test]
    fn quoted_with_separator() {
        let v = split(r#"a,"b,c",d"#, ',', '"').unwrap();
        assert_eq!(v, vec!["a", "b,c", "d"]);
    }

    #[test]
    fn escaped_quote() {
        let v = split(r#"a,"b""c",d"#, ',', '"').unwrap();
        assert_eq!(v, vec!["a", "b\"c", "d"]);
    }

    #[test]
    fn unbalanced_quote_rejected() {
        let r = split("a,\"unclosed", ',', '"');
        assert!(matches!(r.unwrap_err(), CsvError::UnbalancedQuote));
    }

    #[test]
    fn tsv_separator() {
        let v = split("a\tb\tc", '\t', '"').unwrap();
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = CsvLineState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            CsvError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = CsvLineState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: CsvLineState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
