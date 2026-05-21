//! `selfdefctl communication-boundary` — operator surface for MS034 /
//! SDD-048 4-transport + 8-message-type schema.

use anyhow::Result;

pub(crate) fn run_schema() -> Result<i32> {
    println!("MS034 / SDD-048 communication-boundary schema");
    println!();
    println!("4 transports (per E0342 dump 3456-3462):");
    for (t, scope) in &[
        ("VirtioVsock",     "AF_VSOCK virtio socket (host↔VM kernel-level)"),
        ("GrpcOverVsock",   "gRPC framed over AF_VSOCK"),
        ("UnixSocketProxy", "Unix-socket forwarded over shared mount"),
        ("SharedFolder",   "explicit-exchange dirs per SDD-045 (slowest; large payloads)"),
    ] {
        println!("  - {:<16} {}", t, scope);
    }
    println!();
    println!("8 canonical message types (per E0343-E0345 dump 3466-3473):");
    println!("type              direction  content");
    println!("-----------------------------------------------------------");
    for (m, dir, content) in &[
        ("DraftRequest",      "host→VM",  "ask for generation"),
        ("DraftResult",       "VM→host",  "drafts response"),
        ("EmbeddingRequest",  "host→VM",  "ask for embeddings"),
        ("RerankResult",      "VM→host",  "reranked candidates"),
        ("VisionResult",      "VM→host",  "vision / GUI / perception output"),
        ("ToolPlan",          "VM→host",  "proposed tool calls (PROPOSAL)"),
        ("RiskAssessment",    "VM→host",  "scored risk (PROPOSAL)"),
        ("PatchProposal",     "VM→host",  "file patches (PROPOSAL — SDD-045 flow)"),
    ] {
        println!("{:<18}{:<11}{}", m, dir, content);
    }
    println!();
    println!("Doctrines preserved verbatim (per E0346 + E0347):");
    println!("  \"Never let the VM directly mutate host truth\"");
    println!("  \"The VM proposes. Host commits.\"");
    println!();
    println!("3 proposal types (gated through SDD-043 commit-authority):");
    println!("  - ToolPlan       → commit_type = ToolSideEffect");
    println!("  - RiskAssessment → commit_type = RiskAssessment");
    println!("  - PatchProposal  → commit_type = FileWrite (via SDD-045 import pipeline)");
    Ok(0)
}
