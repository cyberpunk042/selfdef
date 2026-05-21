//! `selfdefctl nats` — operator surface for MS015 / SDD-053 NATS
//! bridge.

use anyhow::Result;

pub(crate) fn run_doctrine() -> Result<i32> {
    println!("MS015 / SDD-053 selfdef-nats two-way pump");
    println!();
    println!("Bridges the local in-proc selfdef-bus to a NATS subject-prefix");
    println!("tree so a fleet of selfdef hosts can correlate events without");
    println!("merging audit chains.");
    println!();
    println!("Subject schema:");
    println!("  - Outbound publish: <subject_prefix>.<host_tag>");
    println!("                      (e.g. selfdef.events.sain-01)");
    println!("  - Inbound subscribe: <subject_prefix>.>  (wildcard subtopic)");
    println!();
    println!("Echo defense:");
    println!("  - Drop inbound events whose Event::host_tag == local host_tag");
    println!();
    println!("2 modes (operator config):");
    println!("  - passive — mirror inbound to local bus only (read-only fleet view)");
    println!("  - active  — full two-way pump (publish + republish)");
    println!();
    println!("Config:");
    println!("  [nats]");
    println!("  url            = \"tls://nats.example.com:4222\"");
    println!("  subject_prefix = \"selfdef.events\"");
    println!("  mode           = \"active\"   # passive | active");
    println!();
    println!("Cross-host audit-chain invariant:");
    println!("  - Each host's audit chain stays independent (no merge).");
    println!("  - Events received from other hosts are tagged via Event::host_tag");
    println!("    and the local store + correlator respect that boundary.");
    Ok(0)
}
