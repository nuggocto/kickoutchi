use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::scoped_report_lines;
use super::{
    PortsStatus, SETTLE_ATTEMPTS_MAX, SettleProbe, SettleReport, settle, settle_window_text,
    single_report_lines,
};
use crate::cli::test_support::entry;
use crate::collector::CollectorError;
use crate::model::{Platform, PortEntry, PortEntryView};
use crate::observation::{ProcessIdentity, ProcessStartMarker};
use crate::process::{ExitObservation, KillMode, KillTarget};

fn identity(pid: u32) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        start_marker: ProcessStartMarker::linux(55).expect("nonzero marker"),
    }
}

fn target_on(ports: &[u16]) -> KillTarget {
    // A kill target is built from at least one port row; a portless scoped
    // root is modelled by clearing the confirmed ports afterwards.
    let rows = ports
        .iter()
        .copied()
        .chain(ports.is_empty().then_some(3000))
        .map(entry)
        .collect::<Vec<_>>();
    let mut target = KillTarget::from_entries(18_422, rows.iter().map(PortEntryView::from), None);
    if ports.is_empty() {
        target.ports.clear();
    }
    target
}

/// Run `settle` with scripted reads and count polls and sleeps.
struct Script {
    port_polls: usize,
    exit_polls: usize,
    sleeps: usize,
}

impl Script {
    fn run(
        identities: &[ProcessIdentity],
        target: &KillTarget,
        mut ports: impl FnMut(usize) -> Result<Vec<PortEntry>, CollectorError>,
        mut exit: impl FnMut(usize, ProcessIdentity) -> ExitObservation,
    ) -> (SettleReport, Self) {
        let mut script = Self {
            port_polls: 0,
            exit_polls: 0,
            sleeps: 0,
        };
        let report = settle(
            identities,
            &target.ports,
            &mut SettleProbe {
                collect_ports: &mut || {
                    script.port_polls += 1;
                    ports(script.port_polls)
                },
                observe_exit: &mut |identity| {
                    script.exit_polls += 1;
                    exit(script.exit_polls, identity)
                },
                sleep: &mut |delay| {
                    assert_eq!(delay, Duration::from_millis(100));
                    script.sleeps += 1;
                },
            },
        );
        (report, script)
    }
}

#[test]
fn ports_clear_on_a_later_poll() {
    let target = target_on(&[3000]);
    let (report, script) = Script::run(
        &[],
        &target,
        |poll| {
            Ok(if poll < 3 {
                vec![entry(3000)]
            } else {
                Vec::new()
            })
        },
        |_, _| panic!("no identities were given"),
    );

    assert_eq!(report.ports, PortsStatus::Cleared);
    assert_eq!(script.port_polls, 3);
    assert_eq!(script.sleeps, 2);
}

#[test]
fn ports_still_visible_after_the_bounded_window() {
    let target = target_on(&[3000, 3001]);
    let (report, script) = Script::run(
        &[],
        &target,
        // Port 3000 closes immediately; 3001 never does.
        |_| Ok(vec![entry(3001)]),
        |_, _| panic!("no identities were given"),
    );

    assert_eq!(report.ports, PortsStatus::StillVisible);
    assert_eq!(script.port_polls, SETTLE_ATTEMPTS_MAX);
    // No sleep follows the final poll.
    assert_eq!(script.sleeps, SETTLE_ATTEMPTS_MAX - 1);
}

#[test]
fn a_port_refresh_error_is_reported_and_not_polled_again() {
    let target = target_on(&[3000]);
    let (report, script) = Script::run(
        &[],
        &target,
        |poll| {
            if poll == 1 {
                Ok(vec![entry(3000)])
            } else {
                Err(CollectorError::WorkerExited)
            }
        },
        |_, _| panic!("no identities were given"),
    );

    assert!(matches!(report.ports, PortsStatus::RefreshFailed(_)));
    assert_eq!(script.port_polls, 2);
    assert_eq!(script.sleeps, 1);
}

#[test]
fn closed_ports_do_not_end_the_wait_for_a_running_process() {
    // The reported incident: the listener closed, the process kept running.
    let target = target_on(&[3000]);
    let (report, script) = Script::run(
        &[identity(18_422)],
        &target,
        |_| Ok(Vec::new()),
        |_, _| ExitObservation::Running,
    );

    assert_eq!(report.ports, PortsStatus::Cleared);
    assert!(report.exited.is_empty());
    assert_eq!(report.running, vec![18_422]);
    assert_eq!(script.exit_polls, SETTLE_ATTEMPTS_MAX);
    // Ports cleared on the first poll and are not polled again.
    assert_eq!(script.port_polls, 1);
}

#[test]
fn an_exit_observed_later_ends_the_wait() {
    let target = target_on(&[3000]);
    let (report, script) = Script::run(
        &[identity(18_422)],
        &target,
        |_| Ok(Vec::new()),
        |poll, _| {
            if poll < 4 {
                ExitObservation::Running
            } else {
                ExitObservation::Exited
            }
        },
    );

    assert_eq!(report.exited, vec![18_422]);
    assert!(report.running.is_empty());
    assert!(report.unknown.is_empty());
    assert_eq!(script.exit_polls, 4);
    assert_eq!(script.sleeps, 3);
}

#[test]
fn only_a_persistent_check_failure_is_unknown() {
    let target = target_on(&[]);
    let (report, _) = Script::run(
        &[identity(10), identity(20)],
        &target,
        |_| panic!("no ports were confirmed"),
        |_, identity| match identity.pid {
            // PID 10 fails once, then is seen running: running wins.
            10 => ExitObservation::Running,
            _ => ExitObservation::Unknown("EIO".to_owned()),
        },
    );

    assert_eq!(report.ports, PortsStatus::NotChecked);
    assert_eq!(report.running, vec![10]);
    assert_eq!(report.unknown, vec![(20, "EIO".to_owned())]);
}

fn report(exited: &[u32], running: &[u32], ports: PortsStatus) -> SettleReport {
    SettleReport {
        exited: exited.to_vec(),
        running: running.to_vec(),
        unknown: Vec::new(),
        ports,
    }
}

#[test]
fn single_report_states_exit_and_ports_separately() {
    let target = target_on(&[3000]);

    let lines = single_report_lines(
        &target,
        KillMode::Terminate,
        true,
        &report(&[18_422], &[], PortsStatus::Cleared),
    );
    assert_eq!(
        lines,
        [
            "PID 18422 (node) exited",
            "confirmed target ports are no longer visible",
        ]
    );
}

#[test]
fn single_report_warns_when_the_process_outlives_sigterm() {
    let target = target_on(&[3000]);

    let lines = single_report_lines(
        &target,
        KillMode::Terminate,
        true,
        &report(&[], &[18_422], PortsStatus::Cleared),
    );

    assert_eq!(
        lines[0],
        format!(
            "warning: PID 18422 (node) is still running {} after SIGTERM; it may still be shutting down; rerun with --force to send SIGKILL",
            settle_window_text()
        )
    );
    assert_eq!(lines[1], "confirmed target ports are no longer visible");
}

#[test]
fn single_report_never_suggests_force_after_force() {
    let target = target_on(&[3000]);

    let lines = single_report_lines(
        &target,
        KillMode::Force,
        true,
        &report(&[], &[18_422], PortsStatus::StillVisible),
    );

    assert!(lines[0].contains("after SIGKILL"), "{lines:?}");
    assert!(!lines[0].contains("--force"), "{lines:?}");
}

#[test]
fn single_report_without_a_start_identity_claims_nothing() {
    let target = target_on(&[3000]);

    let lines = single_report_lines(
        &target,
        KillMode::Terminate,
        false,
        &report(&[], &[], PortsStatus::Cleared),
    );

    assert!(lines[0].starts_with("warning: could not confirm that PID 18422"));
    assert!(!lines.iter().any(|line| line.ends_with("exited")));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn scoped_report_counts_exits_and_names_survivors() {
    let root = target_on(&[]);

    let all = scoped_report_lines(
        &root,
        KillMode::Terminate,
        3,
        &report(&[1, 2, 3], &[], PortsStatus::NotChecked),
    );
    assert_eq!(all, ["all 3 signalled process(es) exited"]);

    let some = scoped_report_lines(
        &root,
        KillMode::Terminate,
        3,
        &report(&[1], &[2, 3], PortsStatus::NotChecked),
    );
    assert_eq!(some[0], "1 of 3 signalled process(es) exited");
    assert!(
        some[1].starts_with("warning: PID(s) 2, 3 still running"),
        "{some:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn scoped_report_flags_members_without_a_start_identity() {
    let root = target_on(&[]);

    let lines = scoped_report_lines(
        &root,
        KillMode::Terminate,
        2,
        &report(&[1], &[], PortsStatus::NotChecked),
    );

    assert_eq!(
        lines,
        [
            "1 of 2 signalled process(es) exited",
            "warning: could not confirm exit for 1 signalled process(es) without a start identity",
        ]
    );
}

#[test]
fn windows_reports_never_suggest_sigkill() {
    let mut target = target_on(&[3000]);
    target.platform = Platform::Windows;

    let lines = single_report_lines(
        &target,
        KillMode::Terminate,
        true,
        &report(&[], &[18_422], PortsStatus::Cleared),
    );

    assert!(!lines[0].contains("SIGKILL"), "{lines:?}");
}

#[test]
fn settle_window_text_matches_the_poll_budget() {
    assert_eq!(settle_window_text(), "2.0s");
}
