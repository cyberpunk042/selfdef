//! Network observables: endpoints and connections.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::IpAddr;

/// Direction of a network observation, OCSF-aligned.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum Direction {
    Unknown = 0,
    Inbound = 1,
    Outbound = 2,
    Lateral = 3,
    Other = 99,
}

/// One side of a network conversation. `src_endpoint` and `dst_endpoint` on
/// [`crate::Event`] each carry one of these.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Geolocation country code (ISO 3166-1 alpha-2), enriched downstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// AS number, enriched downstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// Interface name (`eth0`, `wg0`, ...), for local endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Endpoint {
    #[must_use]
    pub fn ip_port(ip: IpAddr, port: u16) -> Self {
        Self {
            ip: Some(ip),
            port: Some(port),
            ..Self::default()
        }
    }
}

/// Connection-level metadata. `src_endpoint`/`dst_endpoint` live on the event
/// envelope itself; this struct carries protocol and flag info.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnection {
    /// `"tcp"`, `"udp"`, `"icmp"`, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_name: Option<String>,
    /// IANA protocol number, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_num: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    /// Bytes transferred in this observation window, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// TCP flags as observed (`"SYN"`, `"SYN,ACK"`, `"RST"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn endpoint_round_trip() {
        let e = Endpoint::ip_port(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)), 22);
        let s = serde_json::to_string(&e).unwrap();
        let back: Endpoint = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn direction_is_int() {
        assert_eq!(serde_json::to_string(&Direction::Outbound).unwrap(), "2");
    }
}
