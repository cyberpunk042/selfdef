//! `selfdef-capability-word` — MS035 64-bit capability_word bit-field.
//!
//! Per MS035 + E0352 + dump 3496-3504, capability_word is a 64-bit
//! authority handle every action carries:
//!
//! | bits      | field                | encoding                   |
//! |-----------|----------------------|----------------------------|
//! | 0..7      | allowed_tools        | bitmap of 8 tool classes   |
//! | 8..15     | filesystem_scope     | enum 0..255 of FS reach    |
//! | 16..23    | network_scope        | matches NetworkProfile bits|
//! | 24..31    | max_runtime          | minutes (255 = uncapped)   |
//! | 32..39    | max_memory_mib       | MiB / 64 (255 = uncapped)  |
//! | 40..47    | output_type          | enum 0..255                |
//! | 48..55    | trust_level          | Ring 0..4 (high nibble unused) |
//! | 56..63    | flags                | bitmap (e.g. cloud / pii)  |
//!
//! Composes with selfdef-network-boundary (bits 16..23 = NetworkProfile policy_bits).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version of the helper layer (not the wire format itself, which is fixed).
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Allowed-tools bit positions (within byte 0 = bits 0..7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolClass {
    /// bit 0 — read-only host tools (rg, parsers).
    ReadOnlyHost,
    /// bit 1 — write tools (file edits, package managers).
    WriteHost,
    /// bit 2 — test tools (cargo test, pytest).
    Tests,
    /// bit 3 — build tools.
    Builds,
    /// bit 4 — network egress.
    NetworkEgress,
    /// bit 5 — GPU compute (3090 / Blackwell).
    GpuCompute,
    /// bit 6 — VM / sandbox spawn.
    VmSpawn,
    /// bit 7 — browser / GUI sandbox.
    Browser,
}

impl ToolClass {
    /// Bit position 0..7.
    pub fn bit(self) -> u8 {
        match self {
            ToolClass::ReadOnlyHost => 0,
            ToolClass::WriteHost => 1,
            ToolClass::Tests => 2,
            ToolClass::Builds => 3,
            ToolClass::NetworkEgress => 4,
            ToolClass::GpuCompute => 5,
            ToolClass::VmSpawn => 6,
            ToolClass::Browser => 7,
        }
    }
}

/// Filesystem-scope enum stored in byte 1 (bits 8..15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemScope {
    /// Read-only access to source tree only.
    SourceReadOnly,
    /// Workspace-write only.
    WorkspaceWrite,
    /// + scratch dir (/tmp/scratch).
    WorkspaceScratch,
    /// + system /etc read (config inspection).
    EtcRead,
    /// Full host read.
    HostRead,
    /// Full host read+write (operator-only).
    HostReadWrite,
}

impl FilesystemScope {
    /// 8-bit encoding.
    pub fn encode(self) -> u8 {
        match self {
            FilesystemScope::SourceReadOnly => 0x01,
            FilesystemScope::WorkspaceWrite => 0x02,
            FilesystemScope::WorkspaceScratch => 0x03,
            FilesystemScope::EtcRead => 0x04,
            FilesystemScope::HostRead => 0x05,
            FilesystemScope::HostReadWrite => 0x06,
        }
    }
    /// Decode 8-bit.
    pub fn decode(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(FilesystemScope::SourceReadOnly),
            0x02 => Some(FilesystemScope::WorkspaceWrite),
            0x03 => Some(FilesystemScope::WorkspaceScratch),
            0x04 => Some(FilesystemScope::EtcRead),
            0x05 => Some(FilesystemScope::HostRead),
            0x06 => Some(FilesystemScope::HostReadWrite),
            _ => None,
        }
    }
}

/// 8 flag bits in byte 7 (bits 56..63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapFlag {
    /// bit 0 — cloud egress permitted.
    CloudOk,
    /// bit 1 — PII handling permitted.
    PiiOk,
    /// bit 2 — high-risk action permitted.
    HighRisk,
    /// bit 3 — operator-signed envelope present.
    OperatorSigned,
    /// bit 4 — adapter-promotion path enabled.
    AdapterPromote,
    /// bit 5 — replay mode (test harness).
    ReplayMode,
    /// bit 6 — reserved.
    Reserved6,
    /// bit 7 — reserved.
    Reserved7,
}

impl CapFlag {
    /// Bit position 0..7.
    pub fn bit(self) -> u8 {
        match self {
            CapFlag::CloudOk => 0,
            CapFlag::PiiOk => 1,
            CapFlag::HighRisk => 2,
            CapFlag::OperatorSigned => 3,
            CapFlag::AdapterPromote => 4,
            CapFlag::ReplayMode => 5,
            CapFlag::Reserved6 => 6,
            CapFlag::Reserved7 => 7,
        }
    }
}

/// 64-bit capability_word with typed accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilityWord(pub u64);

/// Errors.
#[derive(Debug, Error)]
pub enum CapError {
    /// Filesystem scope byte not in defined set.
    #[error("filesystem scope byte {0:#04x} not in defined enum")]
    InvalidFilesystemScope(u8),
    /// Trust level byte too high (>4).
    #[error("trust level byte {0} > 4 (max Ring)")]
    InvalidTrustLevel(u8),
    /// Network-scope byte not in MS038 5-profile set.
    #[error("network scope byte {0:#04x} not in MS038 5-profile set")]
    InvalidNetworkScope(u8),
}

impl CapabilityWord {
    /// Construct empty.
    pub fn empty() -> Self {
        CapabilityWord(0)
    }

    /// Construct from 8 component bytes (allowed_tools / fs / net / runtime / mem / output / trust / flags).
    pub fn from_bytes(b: [u8; 8]) -> Self {
        let mut w: u64 = 0;
        for (i, byte) in b.iter().enumerate() {
            w |= (*byte as u64) << (i * 8);
        }
        CapabilityWord(w)
    }

    /// Extract the 8 component bytes (little-endian order matching from_bytes).
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = ((self.0 >> (i * 8)) & 0xff) as u8;
        }
        b
    }

    /// Get byte at slot (0..8).
    pub fn byte(self, slot: u8) -> u8 {
        ((self.0 >> (slot as u64 * 8)) & 0xff) as u8
    }

    /// Set byte at slot.
    pub fn set_byte(&mut self, slot: u8, value: u8) {
        let mask: u64 = 0xffu64 << (slot as u64 * 8);
        self.0 = (self.0 & !mask) | ((value as u64) << (slot as u64 * 8));
    }

    /// Whether the tool class bit is set in byte 0.
    pub fn has_tool(self, t: ToolClass) -> bool {
        (self.byte(0) >> t.bit()) & 1 == 1
    }

    /// Set the tool class bit in byte 0.
    pub fn allow_tool(&mut self, t: ToolClass) {
        let b = self.byte(0) | (1u8 << t.bit());
        self.set_byte(0, b);
    }

    /// Filesystem scope (byte 1).
    pub fn fs_scope(self) -> Result<Option<FilesystemScope>, CapError> {
        let b = self.byte(1);
        if b == 0 {
            return Ok(None);
        }
        FilesystemScope::decode(b)
            .map(Some)
            .ok_or(CapError::InvalidFilesystemScope(b))
    }

    /// Set filesystem scope.
    pub fn set_fs_scope(&mut self, s: FilesystemScope) {
        self.set_byte(1, s.encode());
    }

    /// Network scope byte (byte 2). Returns the 8-bit value; the
    /// MS038 NetworkProfile::from_policy_bits() can decode it.
    pub fn network_scope_byte(self) -> u8 {
        self.byte(2)
    }

    /// Max runtime in minutes (byte 3). 255 = uncapped.
    pub fn max_runtime_minutes(self) -> u8 {
        self.byte(3)
    }

    /// Max memory in MiB-units of 64. 255 = uncapped → 16 GiB.
    pub fn max_memory_mib(self) -> u32 {
        let b = self.byte(4);
        if b == 0xff {
            return u32::MAX;
        }
        (b as u32) * 64
    }

    /// Output-type byte (byte 5).
    pub fn output_type(self) -> u8 {
        self.byte(5)
    }

    /// Trust level (Ring 0..4) — byte 6.
    pub fn trust_level(self) -> Result<u8, CapError> {
        let b = self.byte(6);
        if b > 4 {
            return Err(CapError::InvalidTrustLevel(b));
        }
        Ok(b)
    }

    /// Set trust level.
    pub fn set_trust_level(&mut self, level: u8) -> Result<(), CapError> {
        if level > 4 {
            return Err(CapError::InvalidTrustLevel(level));
        }
        self.set_byte(6, level);
        Ok(())
    }

    /// Whether a flag bit is set in byte 7.
    pub fn has_flag(self, f: CapFlag) -> bool {
        (self.byte(7) >> f.bit()) & 1 == 1
    }

    /// Set a flag bit in byte 7.
    pub fn set_flag(&mut self, f: CapFlag) {
        let b = self.byte(7) | (1u8 << f.bit());
        self.set_byte(7, b);
    }

    /// Clear a flag bit.
    pub fn clear_flag(&mut self, f: CapFlag) {
        let b = self.byte(7) & !(1u8 << f.bit());
        self.set_byte(7, b);
    }

    /// Hex string for wire format ("0x" + 16 hex digits, lowercase).
    pub fn to_hex(self) -> String {
        format!("0x{:016x}", self.0)
    }

    /// Parse hex string back.
    pub fn from_hex(s: &str) -> Option<Self> {
        let stripped = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if stripped.len() != 16 {
            return None;
        }
        u64::from_str_radix(stripped, 16).ok().map(CapabilityWord)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 64-bit width + 8-byte layout ---

    #[test]
    fn empty_is_zero() {
        assert_eq!(CapabilityWord::empty().0, 0);
        assert_eq!(CapabilityWord::empty().to_bytes(), [0u8; 8]);
    }

    #[test]
    fn from_bytes_to_bytes_roundtrip() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let w = CapabilityWord::from_bytes(bytes);
        assert_eq!(w.to_bytes(), bytes);
    }

    #[test]
    fn byte_at_each_slot() {
        let w = CapabilityWord::from_bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);
        assert_eq!(w.byte(0), 0xaa);
        assert_eq!(w.byte(7), 0x22);
    }

    #[test]
    fn set_byte_preserves_others() {
        let mut w = CapabilityWord::from_bytes([0xff; 8]);
        w.set_byte(3, 0x00);
        assert_eq!(w.byte(0), 0xff);
        assert_eq!(w.byte(3), 0x00);
        assert_eq!(w.byte(7), 0xff);
    }

    // --- Allowed-tools bitmap ---

    #[test]
    fn allow_tool_sets_bit() {
        let mut w = CapabilityWord::empty();
        assert!(!w.has_tool(ToolClass::ReadOnlyHost));
        w.allow_tool(ToolClass::ReadOnlyHost);
        assert!(w.has_tool(ToolClass::ReadOnlyHost));
        w.allow_tool(ToolClass::Browser);
        assert!(w.has_tool(ToolClass::Browser));
        assert!(!w.has_tool(ToolClass::WriteHost)); // unrelated bit stays 0
    }

    #[test]
    fn tool_bits_distinct_0_to_7() {
        for (i, t) in [
            ToolClass::ReadOnlyHost,
            ToolClass::WriteHost,
            ToolClass::Tests,
            ToolClass::Builds,
            ToolClass::NetworkEgress,
            ToolClass::GpuCompute,
            ToolClass::VmSpawn,
            ToolClass::Browser,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(t.bit(), i as u8);
        }
    }

    // --- Filesystem scope ---

    #[test]
    fn fs_scope_encode_decode_roundtrip() {
        for s in [
            FilesystemScope::SourceReadOnly,
            FilesystemScope::WorkspaceWrite,
            FilesystemScope::WorkspaceScratch,
            FilesystemScope::EtcRead,
            FilesystemScope::HostRead,
            FilesystemScope::HostReadWrite,
        ] {
            assert_eq!(FilesystemScope::decode(s.encode()), Some(s));
        }
    }

    #[test]
    fn fs_scope_invalid_byte_caught() {
        let w = CapabilityWord::from_bytes([0, 0xff, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            w.fs_scope().unwrap_err(),
            CapError::InvalidFilesystemScope(0xff)
        ));
    }

    #[test]
    fn fs_scope_zero_byte_returns_none() {
        let w = CapabilityWord::empty();
        assert!(w.fs_scope().unwrap().is_none());
    }

    #[test]
    fn set_fs_scope_sets_byte_1() {
        let mut w = CapabilityWord::empty();
        w.set_fs_scope(FilesystemScope::WorkspaceWrite);
        assert_eq!(w.fs_scope().unwrap(), Some(FilesystemScope::WorkspaceWrite));
        assert_eq!(w.byte(1), 0x02);
    }

    // --- Runtime / memory / trust ---

    #[test]
    fn max_runtime_minutes_zero_by_default() {
        assert_eq!(CapabilityWord::empty().max_runtime_minutes(), 0);
    }

    #[test]
    fn max_memory_mib_units_of_64() {
        let mut w = CapabilityWord::empty();
        w.set_byte(4, 16); // 16 * 64 = 1024 MiB
        assert_eq!(w.max_memory_mib(), 1024);
        w.set_byte(4, 255); // uncapped
        assert_eq!(w.max_memory_mib(), u32::MAX);
    }

    #[test]
    fn trust_level_in_range_0_4() {
        let mut w = CapabilityWord::empty();
        w.set_trust_level(2).unwrap();
        assert_eq!(w.trust_level().unwrap(), 2);
        assert!(matches!(
            w.set_trust_level(7).unwrap_err(),
            CapError::InvalidTrustLevel(7)
        ));
        // Byte unchanged after rejected set.
        assert_eq!(w.byte(6), 2);
    }

    // --- Flags ---

    #[test]
    fn flag_set_clear_has() {
        let mut w = CapabilityWord::empty();
        assert!(!w.has_flag(CapFlag::CloudOk));
        w.set_flag(CapFlag::CloudOk);
        assert!(w.has_flag(CapFlag::CloudOk));
        w.clear_flag(CapFlag::CloudOk);
        assert!(!w.has_flag(CapFlag::CloudOk));
    }

    #[test]
    fn flag_bits_distinct() {
        for (i, f) in [
            CapFlag::CloudOk,
            CapFlag::PiiOk,
            CapFlag::HighRisk,
            CapFlag::OperatorSigned,
            CapFlag::AdapterPromote,
            CapFlag::ReplayMode,
            CapFlag::Reserved6,
            CapFlag::Reserved7,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(f.bit(), i as u8);
        }
    }

    // --- Hex roundtrip ---

    #[test]
    fn to_hex_16_lowercase_digits() {
        let w = CapabilityWord(0xdeadbeefcafef00d);
        assert_eq!(w.to_hex(), "0xdeadbeefcafef00d");
    }

    #[test]
    fn from_hex_roundtrip_with_prefix() {
        let original = CapabilityWord(0xdeadbeefcafef00d);
        let h = original.to_hex();
        let back = CapabilityWord::from_hex(&h).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn from_hex_invalid_returns_none() {
        assert!(CapabilityWord::from_hex("0xff").is_none()); // too short
        assert!(CapabilityWord::from_hex("not-hex").is_none()); // garbage
        assert!(CapabilityWord::from_hex("0xzzzzzzzzzzzzzzzz").is_none()); // bad chars
    }

    // --- Composition (cross-byte invariants) ---

    #[test]
    fn full_composition_preserves_all_fields() {
        let mut w = CapabilityWord::empty();
        w.allow_tool(ToolClass::ReadOnlyHost);
        w.allow_tool(ToolClass::Tests);
        w.set_fs_scope(FilesystemScope::WorkspaceWrite);
        w.set_byte(2, 0b00000111); // arbitrary-web network profile
        w.set_byte(3, 60); // 60-min runtime
        w.set_byte(4, 16); // 1024 MiB
        w.set_trust_level(2).unwrap();
        w.set_flag(CapFlag::OperatorSigned);
        // Verify every byte slot independently.
        assert!(w.has_tool(ToolClass::ReadOnlyHost));
        assert!(w.has_tool(ToolClass::Tests));
        assert!(!w.has_tool(ToolClass::Browser));
        assert_eq!(w.fs_scope().unwrap(), Some(FilesystemScope::WorkspaceWrite));
        assert_eq!(w.network_scope_byte(), 0b00000111);
        assert_eq!(w.max_runtime_minutes(), 60);
        assert_eq!(w.max_memory_mib(), 1024);
        assert_eq!(w.trust_level().unwrap(), 2);
        assert!(w.has_flag(CapFlag::OperatorSigned));
        assert!(!w.has_flag(CapFlag::CloudOk));
    }

    #[test]
    fn capability_word_serde_roundtrip() {
        let original = CapabilityWord(0xdeadbeefcafef00d);
        let j = serde_json::to_string(&original).unwrap();
        let back: CapabilityWord = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
    }
}
