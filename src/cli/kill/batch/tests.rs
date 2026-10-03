use std::cell::RefCell;

use super::{BatchIo, aggregate_exit, run_batch_kill_with};
use crate::cli::test_support::{entry_with_pid, no_context};
use crate::cli::{ExitReason, KillArgs, settle};
use crate::config::Config;
use crate::model::{PortEntry, Protocol};
use crate::observation::{NetworkSnapshot, snapshot_from_test_rows};
use crate::process::{ExitObservation, KillMode, KillTarget, TerminationOutcome};

fn by_pid(pids: &[u32], yes: bool) -> Vec<KillArgs> {
    pids.iter()
        .map(|pid| KillArgs {
            pid: Some(*pid),
            port: None,
            force: false,
            yes,
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        })
        .collect()
}

fn by_port(ports: &[u16]) -> Vec<KillArgs> {
    ports
        .iter()
        .map(|port| KillArgs {
            pid: None,
            port: Some(*port),
            force: false,
            yes: true,
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        })
        .collect()
}

fn rows() -> Vec<PortEntry> {
    vec![
        entry_with_pid(3000, Some(101), Protocol::Tcp, "web"),
        entry_with_pid(3001, Some(102), Protocol::Tcp, "api"),
        entry_with_pid(3002, Some(103), Protocol::Tcp, "docs"),
        // PID 103 owns a second port, so two selectors can name it.
        entry_with_pid(3003, Some(103), Protocol::Tcp, "docs"),
    ]
}

/// What a scripted batch run did.
#[derive(Default)]
struct Record {
    prompts: Vec<String>,
    prepared: Vec<u32>,
    terminated: Vec<u32>,
}

fn run(
    targets: &[KillArgs],
    config: &Config,
    snapshot: &NetworkSnapshot,
    fresh: &NetworkSnapshot,
    answer: &str,
    outcome: impl Fn(u32) -> TerminationOutcome,
) -> (ExitReason, Record) {
    let record = RefCell::new(Record::default());
    let reason = run_batch_kill_with(
        targets,
        config,
        snapshot,
        BatchIo {
            context: &mut no_context,
            prompt: &mut |text| {
                record.borrow_mut().prompts.push(text.to_owned());
                Ok(answer.to_owned())
            },
            fresh_snapshot: &mut || Ok(fresh.clone()),
            prepare: &mut |pid| {
                record.borrow_mut().prepared.push(pid);
                Ok(pid)
            },
            terminate: &mut |pid: &u32, _target: &KillTarget, _protected, mode| {
                assert_eq!(mode, KillMode::Terminate);
                record.borrow_mut().terminated.push(*pid);
                outcome(*pid)
            },
            settle: settle::SettleProbe {
                collect_ports: &mut || Ok(Vec::new()),
                observe_exit: &mut |_| ExitObservation::Exited,
                sleep: &mut |_| panic!("settled facts must not sleep"),
            },
        },
    );
    (reason, record.into_inner())
}

#[test]
fn one_confirmation_covers_every_target() {
    let snapshot = snapshot_from_test_rows(rows());

    let (reason, record) = run(
        &by_pid(&[101, 102], false),
        &Config::default(),
        &snapshot,
        &snapshot,
        "y",
        |_| TerminationOutcome::Success,
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(
        record.prompts,
        ["Type y to confirm all 2 kills, or press Enter to cancel: "]
    );
    assert_eq!(record.terminated, [101, 102]);
}

#[test]
fn a_declined_prompt_prepares_nothing() {
    let snapshot = snapshot_from_test_rows(rows());

    let (reason, record) = run(
        &by_pid(&[101, 102], false),
        &Config::default(),
        &snapshot,
        &snapshot,
        "",
        |_| panic!("a declined batch must not signal"),
    );

    assert_eq!(reason, ExitReason::KillCancelled);
    assert!(record.prepared.is_empty());
}

#[test]
fn one_unresolvable_target_stops_the_whole_batch() {
    let snapshot = snapshot_from_test_rows(rows());

    let (reason, record) = run(
        &by_pid(&[101, 999], true),
        &Config::default(),
        &snapshot,
        &snapshot,
        "",
        |_| panic!("nothing may be signalled"),
    );

    assert_eq!(reason, ExitReason::NoMatch);
    assert!(record.prompts.is_empty());
    assert!(record.prepared.is_empty());
}

#[test]
fn a_protected_target_must_be_killed_on_its_own() {
    let snapshot = snapshot_from_test_rows(rows());
    let config = Config {
        protected_processes: vec!["api".to_owned()],
        ..Config::default()
    };

    let (reason, record) = run(
        &by_pid(&[101, 102], false),
        &config,
        &snapshot,
        &snapshot,
        "y",
        |_| panic!("nothing may be signalled"),
    );

    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    assert!(record.prompts.is_empty());
    assert!(record.prepared.is_empty());
}

#[test]
fn a_target_that_changed_before_delivery_is_skipped_and_reported() {
    let snapshot = snapshot_from_test_rows(rows());
    // PID 102 released its port between confirmation and revalidation.
    let fresh = snapshot_from_test_rows(
        rows()
            .into_iter()
            .filter(|row| row.pid != Some(102))
            .collect(),
    );

    let (reason, record) = run(
        &by_pid(&[101, 102, 103], true),
        &Config::default(),
        &snapshot,
        &fresh,
        "",
        |_| TerminationOutcome::Success,
    );

    // Every handle was retained before the shared revalidation read.
    assert_eq!(record.prepared, [101, 102, 103]);
    assert_eq!(record.terminated, [101, 103]);
    assert_eq!(reason, ExitReason::NoMatch);
}

#[test]
fn a_delivery_failure_sets_the_exit_code_without_hiding_successes() {
    let snapshot = snapshot_from_test_rows(rows());

    let (reason, record) = run(
        &by_pid(&[101, 102], true),
        &Config::default(),
        &snapshot,
        &snapshot,
        "",
        |pid| {
            if pid == 102 {
                TerminationOutcome::PermissionDenied
            } else {
                TerminationOutcome::Success
            }
        },
    );

    assert_eq!(record.terminated, [101, 102]);
    assert_eq!(reason, ExitReason::PermissionDenied);
}

#[test]
fn two_ports_of_one_process_signal_it_once() {
    let snapshot = snapshot_from_test_rows(rows());

    let (reason, record) = run(
        &by_port(&[3002, 3003]),
        &Config::default(),
        &snapshot,
        &snapshot,
        "",
        |_| TerminationOutcome::Success,
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(record.terminated, [103]);
}

#[test]
fn exit_reasons_aggregate_by_severity() {
    use ExitReason::{Failure, KillCancelled, NoMatch, PermissionDenied, Success};

    assert_eq!(aggregate_exit([Success, Success].into_iter()), Success);
    assert_eq!(aggregate_exit([Success, NoMatch].into_iter()), NoMatch);
    assert_eq!(
        aggregate_exit([NoMatch, PermissionDenied, KillCancelled].into_iter()),
        PermissionDenied
    );
    assert_eq!(
        aggregate_exit([PermissionDenied, Failure].into_iter()),
        Failure
    );
    assert_eq!(
        aggregate_exit([ExitReason::ProtectedNeedsConfirmation, NoMatch].into_iter()),
        ExitReason::ProtectedNeedsConfirmation
    );
}

#[test]
fn summary_counts_outcomes_and_details_only_problems() {
    let rows = rows();
    let views = rows
        .iter()
        .map(crate::model::PortEntryView::from)
        .collect::<Vec<_>>();
    let web = KillTarget::from_entries(101, [views[0]], None);
    let api = KillTarget::from_entries(102, [views[1]], None);
    let docs = KillTarget::from_entries(103, [views[2]], None);
    let settled = settle::SettleReport {
        exited: vec![101],
        running: vec![103],
        unknown: Vec::new(),
        ports: settle::PortsStatus::StillVisible,
        visible_ports: docs.ports.clone(),
    };

    let lines = super::summary_lines(&super::Summary {
        mode: KillMode::Terminate,
        total: 3,
        delivered: &[&web, &docs],
        verified: 2,
        ports: 2,
        settled: &settled,
        failures: &[(&api, &TerminationOutcome::TargetChanged)],
    });

    assert_eq!(
        lines[0],
        "summary: sent SIGTERM to 2 of 3 process(es); 1 exited; 1 of 2 confirmed port(s) no longer visible; 1 failed"
    );
    assert_eq!(
        lines[1],
        "  failed: PID 102 (api) no longer owns the confirmed port target; no termination was sent"
    );
    assert_eq!(
        lines[2],
        "  still running 2.0s after SIGTERM: PID 103 (docs); rerun `kick kill --pid 103 --tree --force` to send SIGKILL (it also stops the process's children)"
    );
    assert!(
        lines[3].starts_with("  still visible: TCP 127.0.0.1:3002;"),
        "{lines:?}"
    );
    assert_eq!(lines.len(), 4);
}

#[test]
fn a_clean_batch_summary_is_one_line() {
    let rows = rows();
    let views = rows
        .iter()
        .map(crate::model::PortEntryView::from)
        .collect::<Vec<_>>();
    let web = KillTarget::from_entries(101, [views[0]], None);
    let settled = settle::SettleReport {
        exited: vec![101],
        running: Vec::new(),
        unknown: Vec::new(),
        ports: settle::PortsStatus::Cleared,
        visible_ports: Vec::new(),
    };

    let lines = super::summary_lines(&super::Summary {
        mode: KillMode::Terminate,
        total: 1,
        delivered: &[&web],
        verified: 1,
        ports: 1,
        settled: &settled,
        failures: &[],
    });

    assert_eq!(
        lines,
        [
            "summary: sent SIGTERM to 1 of 1 process(es); 1 exited; 1 of 1 confirmed port(s) no longer visible; 0 failed"
        ]
    );
}
