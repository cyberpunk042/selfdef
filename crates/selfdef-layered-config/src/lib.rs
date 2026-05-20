//! `selfdef-layered-config` — n-layer override resolver.
//!
//! Layer{name, entries: key→value}. Layers in order of priority:
//! layers[0] is the lowest, layers[N-1] is the highest. lookup
//! walks high → low, returning the first hit + source layer name.
//! set(layer, key, value) writes; push_layer/pop_layer mutate
//! stack.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Layer {
    /// Name.
    pub name: String,
    /// Entries.
    pub entries: BTreeMap<String, String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LayeredConfig {
    /// Schema version.
    pub schema_version: String,
    /// Layers low → high.
    pub layers: Vec<Layer>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Empty.
    #[error("value empty")]
    EmptyValue,
    /// Duplicate.
    #[error("duplicate layer: {0}")]
    DuplicateLayer(String),
    /// Unknown.
    #[error("unknown layer: {0}")]
    UnknownLayer(String),
}

impl LayeredConfig {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            layers: Vec::new(),
        }
    }

    /// Push a layer (becomes highest priority).
    pub fn push_layer(&mut self, name: &str) -> Result<(), ConfigError> {
        if name.is_empty() { return Err(ConfigError::EmptyName); }
        if self.layers.iter().any(|l| l.name == name) {
            return Err(ConfigError::DuplicateLayer(name.into()));
        }
        self.layers.push(Layer { name: name.into(), entries: BTreeMap::new() });
        Ok(())
    }

    /// Pop top layer.
    pub fn pop_layer(&mut self) -> Option<Layer> {
        self.layers.pop()
    }

    /// Set key=value in a named layer.
    pub fn set(&mut self, layer: &str, key: &str, value: &str) -> Result<(), ConfigError> {
        if key.is_empty() { return Err(ConfigError::EmptyKey); }
        if value.is_empty() { return Err(ConfigError::EmptyValue); }
        let l = self.layers.iter_mut().find(|l| l.name == layer)
            .ok_or_else(|| ConfigError::UnknownLayer(layer.into()))?;
        l.entries.insert(key.into(), value.into());
        Ok(())
    }

    /// Look up key; returns (value, source-layer-name) of highest layer that defines it.
    pub fn lookup(&self, key: &str) -> Option<(&str, &str)> {
        for layer in self.layers.iter().rev() {
            if let Some(v) = layer.entries.get(key) {
                return Some((v.as_str(), layer.name.as_str()));
            }
        }
        None
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ConfigError::SchemaMismatch); }
        for l in &self.layers {
            if l.name.is_empty() { return Err(ConfigError::EmptyName); }
            for (k, v) in &l.entries {
                if k.is_empty() { return Err(ConfigError::EmptyKey); }
                if v.is_empty() { return Err(ConfigError::EmptyValue); }
            }
        }
        Ok(())
    }
}

impl Default for LayeredConfig {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_layer_lookup() {
        let mut c = LayeredConfig::new();
        c.push_layer("default").unwrap();
        c.set("default", "host", "localhost").unwrap();
        assert_eq!(c.lookup("host"), Some(("localhost", "default")));
        assert_eq!(c.lookup("missing"), None);
    }

    #[test]
    fn higher_layer_overrides() {
        let mut c = LayeredConfig::new();
        c.push_layer("default").unwrap();
        c.push_layer("env").unwrap();
        c.set("default", "host", "localhost").unwrap();
        c.set("env", "host", "prod.example.com").unwrap();
        assert_eq!(c.lookup("host"), Some(("prod.example.com", "env")));
    }

    #[test]
    fn lower_layer_falls_through() {
        let mut c = LayeredConfig::new();
        c.push_layer("default").unwrap();
        c.push_layer("env").unwrap();
        c.set("default", "port", "8080").unwrap();
        // env doesn't define port.
        assert_eq!(c.lookup("port"), Some(("8080", "default")));
    }

    #[test]
    fn pop_layer_drops() {
        let mut c = LayeredConfig::new();
        c.push_layer("a").unwrap();
        c.push_layer("b").unwrap();
        c.set("b", "k", "v").unwrap();
        c.pop_layer();
        assert_eq!(c.lookup("k"), None);
    }

    #[test]
    fn duplicate_layer_rejected() {
        let mut c = LayeredConfig::new();
        c.push_layer("a").unwrap();
        assert!(matches!(c.push_layer("a").unwrap_err(), ConfigError::DuplicateLayer(_)));
    }

    #[test]
    fn unknown_set_rejected() {
        let mut c = LayeredConfig::new();
        assert!(matches!(c.set("nope", "k", "v").unwrap_err(), ConfigError::UnknownLayer(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut c = LayeredConfig::new();
        assert!(matches!(c.push_layer("").unwrap_err(), ConfigError::EmptyName));
        c.push_layer("a").unwrap();
        assert!(matches!(c.set("a", "", "v").unwrap_err(), ConfigError::EmptyKey));
        assert!(matches!(c.set("a", "k", "").unwrap_err(), ConfigError::EmptyValue));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = LayeredConfig::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), ConfigError::SchemaMismatch));
    }

    #[test]
    fn config_serde_roundtrip() {
        let mut c = LayeredConfig::new();
        c.push_layer("default").unwrap();
        c.set("default", "host", "localhost").unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: LayeredConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
