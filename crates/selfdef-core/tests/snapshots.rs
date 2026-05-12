//! Snapshot tests: lock the wire shape of known event types.
//!
//! When schema drift would silently break downstream consumers, these tests
//! force the change to be intentional (snapshot review).
//!
//! Run `cargo insta review` after legitimate schema changes.

use selfdef_core::activity::{AuthenticationActivity, FileSystemActivity, ProcessActivity};
use selfdef_core::attack::TechniqueRef;
use selfdef_core::category::ClassUid;
use selfdef_core::observable::{Actor, Endpoint, File, Process, User};
use selfdef_core::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use time::macros::datetime;
use uuid::Uuid;

/// Build a deterministic event so snapshot diffs are stable.
fn deterministic<F: FnOnce(Event) -> Event>(class: ClassUid, activity: u32, modify: F) -> Event {
    let mut e = Event::new(class, activity, SeverityId::Medium, "test-host", "test-source", 0);
    // Pin id, time, metadata.logged_time so snapshots don't churn.
    e.id = Uuid::nil();
    e.time_dt = datetime!(2026-01-15 12:00:00 UTC);
    e.metadata.logged_time_dt = datetime!(2026-01-15 12:00:00 UTC);
    e.metadata.product.version = "0.1.0-test".into();
    modify(e)
}

#[test]
fn snapshot_authentication_failure() {
    let e = deterministic(
        ClassUid::AUTHENTICATION,
        AuthenticationActivity::Logon as u32,
        |e| {
            e.with_status(StatusId::Failure)
                .with_message("Failed SSH password for alice from 192.0.2.5")
                .with_actor(Actor {
                    user: Some(User::local(1000, "alice")),
                    ..Actor::default()
                })
                .with_src_endpoint(Endpoint::ip_port(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                    51234,
                ))
                .with_dst_endpoint(Endpoint::ip_port(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    22,
                ))
                .with_attack(TechniqueRef::brute_force())
        },
    );

    insta::assert_json_snapshot!(e);
}

#[test]
fn snapshot_process_launch() {
    let e = deterministic(
        ClassUid::PROCESS_ACTIVITY,
        ProcessActivity::Launch as u32,
        |e| {
            e.with_message("Process launched: /usr/bin/sudo")
                .with_actor(Actor {
                    user: Some(User::local(1000, "alice")),
                    process: Some(Process {
                        pid: 1000,
                        name: Some("bash".into()),
                        ..Process::default()
                    }),
                    ..Actor::default()
                })
                .with_process(Process {
                    pid: 1042,
                    parent_pid: Some(1000),
                    name: Some("sudo".into()),
                    path: Some("/usr/bin/sudo".into()),
                    cmdline: Some("sudo apt update".into()),
                    ..Process::default()
                })
        },
    );

    insta::assert_json_snapshot!(e);
}

#[test]
fn snapshot_file_modification() {
    let e = deterministic(
        ClassUid::FILE_SYSTEM_ACTIVITY,
        FileSystemActivity::Update as u32,
        |e| {
            e.with_message("File modified: /etc/passwd")
                .with_actor(Actor {
                    user: Some(User::local(0, "root")),
                    ..Actor::default()
                })
                .with_file(File::at_path("/etc/passwd"))
                .with_attack(TechniqueRef::new(
                    "T1136.001",
                    "Create Account: Local Account",
                    Tactic::Persistence,
                ))
        },
    );

    insta::assert_json_snapshot!(e);
}

#[test]
fn snapshot_minimal_event_has_only_required_fields() {
    let e = deterministic(ClassUid::PROCESS_ACTIVITY, 0, |e| e);
    insta::assert_json_snapshot!(e);
}
