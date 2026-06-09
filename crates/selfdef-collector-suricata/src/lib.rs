//! Suricata EVE JSON → bus collector.
//!
//! Tails Suricata's `eve.json` (one JSON object per line). Recognizes the
//! event types most useful for selfdef: `alert`, `dns`, `tls`, `http`, `flow`.
//!
//! Alert records are mapped directly to `DETECTION_FINDING` — Suricata IS
//! detection, so its alerts go straight to the responder for notification.
//! Flow / DNS / TLS records become network-class events that the correlator
//! can match Sigma rules against.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    Start,
    End,
}

impl ReadFrom {
    pub fn parse(s: &str) -> Self {
        match s {
            "start" => Self::Start,
            _ => Self::End,
        }
    }
}

#[derive(Debug, Error)]
pub enum SuricataError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct SuricataCollector {
    input_path: PathBuf,
    read_from: ReadFrom,
    publisher: Publisher,
    host_tag: String,
    sequence: AtomicU64,
}

impl SuricataCollector {
    pub fn new(
        input_path: PathBuf,
        read_from: ReadFrom,
        publisher: Publisher,
        host_tag: String,
    ) -> Self {
        Self {
            input_path,
            read_from,
            publisher,
            host_tag,
            sequence: AtomicU64::new(0),
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), SuricataError> {
        info!(path = %self.input_path.display(), "suricata collector starting");
        wait_for_file(&self.input_path, &shutdown).await;

        let mut file = tokio::fs::File::open(&self.input_path).await?;
        if self.read_from == ReadFrom::End {
            file.seek(std::io::SeekFrom::End(0)).await?;
        }
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        // Buffers a partial line read before its terminating newline arrived,
        // so a write racing the reader can't split + drop an EVE event.
        let mut pending = String::new();

        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            buf.clear();
            let n = tokio::select! {
                r = reader.read_line(&mut buf) => r?,
                () = shutdown.cancelled() => return Ok(()),
            };
            if n == 0 {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            pending.push_str(&buf);
            for line in selfdef_collector_util::drain_complete_lines(&mut pending) {
                self.process_line(&line);
            }
        }
    }

    fn process_line(&self, line: &str) {
        if line.is_empty() {
            return;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "ignored unparseable EVE line");
                return;
            }
        };
        let Some(event_type) = v.get("event_type").and_then(|s| s.as_str()) else {
            return;
        };
        let event = match event_type {
            "alert" => self.build_alert(&v),
            "flow" => self.build_network(&v, ClassUid::NETWORK_ACTIVITY, 6),
            "dns" => self.build_network(&v, ClassUid::DNS_ACTIVITY, 6),
            "tls" => self.build_network(&v, ClassUid::NETWORK_ACTIVITY, 6),
            "http" => self.build_network(&v, ClassUid::HTTP_ACTIVITY, 6),
            _ => self.build_generic(&v),
        };
        self.publisher.publish_lossy(event);
    }

    fn next_seq(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn build_alert(&self, v: &serde_json::Value) -> Event {
        let alert = v.get("alert");
        let signature = alert
            .and_then(|a| a.get("signature"))
            .and_then(|s| s.as_str())
            .unwrap_or("Suricata alert")
            .to_string();
        let category = alert
            .and_then(|a| a.get("category"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        // Suricata severity: 1=highest, 3=lowest. Map inversely.
        let suri_sev = alert
            .and_then(|a| a.get("severity"))
            .and_then(|s| s.as_u64())
            .unwrap_or(3);
        let severity = match suri_sev {
            1 => SeverityId::High,
            2 => SeverityId::Medium,
            _ => SeverityId::Low,
        };

        let src_endpoint = build_endpoint(v.get("src_ip"), v.get("src_port"));
        let dst_endpoint = build_endpoint(v.get("dest_ip"), v.get("dest_port"));

        let mut ev = Event::new(
            ClassUid::DETECTION_FINDING,
            1, // create
            severity,
            &self.host_tag,
            "suricata",
            self.next_seq(),
        )
        .with_message(format!("Suricata: {signature} [{category}]"))
        .with_raw(v.clone());
        if let Some(e) = src_endpoint {
            ev = ev.with_src_endpoint(e);
        }
        if let Some(e) = dst_endpoint {
            ev = ev.with_dst_endpoint(e);
        }
        ev
    }

    fn build_network(&self, v: &serde_json::Value, class: ClassUid, activity: u32) -> Event {
        let src_endpoint = build_endpoint(v.get("src_ip"), v.get("src_port"));
        let dst_endpoint = build_endpoint(v.get("dest_ip"), v.get("dest_port"));
        let mut ev = Event::new(
            class,
            activity,
            SeverityId::Informational,
            &self.host_tag,
            "suricata",
            self.next_seq(),
        )
        .with_raw(v.clone());
        if let Some(e) = src_endpoint {
            ev = ev.with_src_endpoint(e);
        }
        if let Some(e) = dst_endpoint {
            ev = ev.with_dst_endpoint(e);
        }
        ev
    }

    fn build_generic(&self, v: &serde_json::Value) -> Event {
        Event::new(
            ClassUid::new(0),
            0,
            SeverityId::Informational,
            &self.host_tag,
            "suricata",
            self.next_seq(),
        )
        .with_raw(v.clone())
    }
}

async fn wait_for_file(path: &Path, shutdown: &CancellationToken) {
    for _ in 0..10 {
        if path.exists() {
            return;
        }
        if shutdown.is_cancelled() {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn build_endpoint(
    ip: Option<&serde_json::Value>,
    port: Option<&serde_json::Value>,
) -> Option<Endpoint> {
    let ip_str = ip.and_then(|v| v.as_str())?;
    let parsed = ip_str.parse::<std::net::IpAddr>().ok()?;
    let port = port
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok());
    Some(Endpoint {
        ip: Some(parsed),
        port,
        ..Endpoint::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_bus::Bus;

    #[tokio::test(flavor = "current_thread")]
    async fn alert_becomes_finding() {
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();

        let collector = SuricataCollector::new(
            std::path::PathBuf::from("/dev/null"),
            ReadFrom::End,
            pub_,
            "h".into(),
        );
        let line = r#"{"event_type":"alert","src_ip":"192.0.2.5","src_port":51234,"dest_ip":"203.0.113.10","dest_port":22,"alert":{"signature":"ET SCAN nmap probe","category":"Attempted Information Leak","severity":2}}"#;
        collector.process_line(line);
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv())
            .await
            .expect("recv timed out")
            .expect("recv error");
        assert_eq!(event.class_uid, ClassUid::DETECTION_FINDING);
        assert_eq!(event.severity_id, SeverityId::Medium);
        assert!(event.message.unwrap().contains("nmap probe"));
    }
}
