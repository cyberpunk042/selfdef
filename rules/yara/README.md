# YARA rules

Pattern matching for files, memory regions, and on-disk artifacts.

Used by:
- Honeytoken triggers that hash and pattern-match exfiltrated content.
- Forensic triage on alert (matched against memory snapshots).
- Periodic scans of sensitive paths (cron-driven, not real-time).

Use `yara-x` (Rust rewrite) as the engine — faster and safer than libyara.
