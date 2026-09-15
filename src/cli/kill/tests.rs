use crate::model::PortEntryView;
use crate::model::entry_views;
use std::cell::RefCell;

use super::{
    KillCollectors, KillTargetError, POST_KILL_SETTLE_ATTEMPTS_MAX, PostKillPortsStatus,
    read_confirmation_line_from, resolve_kill_target, run_kill_with,
    wait_for_confirmed_ports_to_clear,
};
use crate::cli::test_support::{entry, entry_with_pid, no_context};
use crate::cli::{ExitReason, KillArgs};
use crate::collector::{CollectorError, kill_ports_from_snapshot};
use crate::config::Config;
use crate::model::Protocol;
use crate::observation::ObservationError;
use crate::process::{
    CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome, UnsafePidReason,
};
use crate::test_support::permission_denied_owner_snapshot;

fn kill_pid(pid: u32, force: bool, yes: bool) -> KillArgs {
    KillArgs {
        pid: Some(pid),
        port: None,
        force,
        yes,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        tree: false,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        group: false,
    }
}

fn kill_port(port: u16, force: bool, yes: bool) -> KillArgs {
    KillArgs {
        pid: None,
        port: Some(port),
        force,
        yes,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        tree: false,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        group: false,
    }
}

#[test]
fn kill_port_resolution_refuses_ambiguous_pids() {
    let rows = vec![
        entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
        entry_with_pid(3000, Some(200), Protocol::Udp, "worker"),
    ];

    let error = resolve_kill_target(
        &kill_port(3000, false, true),
        &entry_views(&rows),
        no_context,
    )
    .expect_err("two PIDs on one port must be ambiguous");

    let KillTargetError::AmbiguousPort { port, candidates } = error else {
        panic!("expected ambiguous port error, got {error:?}");
    };
    assert_eq!(port, 3000);
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.contains("PID 100"))
    );
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.contains("PID 200"))
    );
}

#[test]
fn kill_port_resolution_refuses_rows_without_pids() {
    let rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

    let error = resolve_kill_target(
        &kill_port(3000, false, true),
        &entry_views(&rows),
        no_context,
    )
    .expect_err("a port without a PID is not killable");

    assert_eq!(error, KillTargetError::MissingPid { port: 3000 });
}

#[test]
fn kill_port_without_readable_pid_exits_permission_denied() {
    let rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_port(3000, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || panic!("missing PID target must fail before revalidation"),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("missing PID target must not prompt"),
        |_pid| -> Result<u32, TerminationOutcome> {
            panic!("missing PID target must not prepare termination")
        },
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::PermissionDenied);
    assert!(!terminated);
}

#[test]
fn kill_port_resolution_allows_one_pid_with_multiple_rows() {
    let rows = vec![
        entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
        entry_with_pid(3000, Some(100), Protocol::Udp, "node"),
    ];

    let target = resolve_kill_target(
        &kill_port(3000, false, true),
        &entry_views(&rows),
        no_context,
    )
    .expect("one PID can own multiple matching rows");

    assert_eq!(target.pid, 100);
    assert_eq!(
        target.ports_text(),
        "TCP 127.0.0.1:3000, UDP 127.0.0.1:3000"
    );
}

#[test]
fn kill_pid_resolution_blocks_unsafe_pids_before_lookup() {
    let error = resolve_kill_target(&kill_pid(1, false, true), &[], no_context)
        .expect_err("PID 1 must be blocked even if no row exists");

    assert_eq!(error, KillTargetError::UnsafePid(UnsafePidReason::One));
}

#[test]
fn resolution_pins_the_snapshot_owner_marker_not_detached_context_identity() {
    let rows = vec![entry(3000)];
    let target = resolve_kill_target(
        &kill_pid(18_422, false, true),
        &entry_views(&rows),
        |_pid| crate::model::ProcessContext {
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(99).ok(),
            ..crate::model::ProcessContext::default()
        },
    )
    .expect("verified snapshot row resolves");

    assert_eq!(
        target.process_start_time_marker,
        crate::observation::ProcessStartMarker::linux(55).ok(),
    );
}

#[test]
fn kill_yes_sends_signal_without_prompt_for_unprotected_target() {
    let rows = vec![entry(3000)];
    let mut terminated = None;
    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(rows.clone()),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes must skip normal prompts"),
        Ok::<u32, TerminationOutcome>,
        |pid: &u32, _target, _protected, mode| {
            terminated = Some((*pid, mode));
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(terminated, Some((18_422, KillMode::Terminate)));
}

#[test]
fn protected_process_yes_returns_exit_6_without_signalling() {
    let mut row = entry_with_pid(5432, Some(54_321), Protocol::Tcp, "postgres");
    row.protected = true;
    let rows = vec![row];
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_port(5432, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(rows.clone()),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("protected --yes must not prompt"),
        |_pid| -> Result<u32, TerminationOutcome> {
            panic!("protected --yes must not prepare termination")
        },
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    assert!(!terminated);
}

#[test]
fn force_kill_uses_force_word_confirmation_when_configured() {
    let rows = vec![entry(3000)];
    let mut prompted = None;
    let reason = run_kill_with(
        &kill_pid(18_422, true, false),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(rows.clone()),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, mode, requirement| {
            prompted = Some((mode, requirement));
            Ok(true)
        },
        Ok::<u32, TerminationOutcome>,
        |_pid: &u32, _target, _protected, _mode| TerminationOutcome::Success,
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(
        prompted,
        Some((KillMode::Force, ConfirmationRequirement::ForceWord)),
    );
}

#[test]
fn declined_confirmation_cancels_without_signalling() {
    let rows = vec![entry(3000)];
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, false),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(rows.clone()),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, requirement| {
            assert_eq!(requirement, ConfirmationRequirement::Yes);
            Ok(false)
        },
        |_pid| -> Result<u32, TerminationOutcome> {
            panic!("declined confirmation must not prepare termination")
        },
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::KillCancelled);
    assert!(!terminated);
}

#[test]
fn target_is_revalidated_after_confirmation_before_signal() {
    let rows = vec![entry(3000)];
    let fresh_rows = vec![entry_with_pid(4000, Some(18_422), Protocol::Tcp, "node")];
    let mut prepared = None;
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(fresh_rows.clone()),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        |pid| {
            prepared = Some(pid);
            Ok(pid)
        },
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::NoMatch);
    assert_eq!(prepared, Some(18_422));
    assert!(!terminated);
}

#[test]
fn prepare_failure_stops_before_revalidation_or_signal() {
    let rows = vec![entry(3000)];
    let mut collected = false;
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || {
                collected = true;
                Ok(rows.clone())
            },
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        |_pid| -> Result<u32, TerminationOutcome> { Err(TerminationOutcome::AlreadyExited) },
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::NoMatch);
    assert!(!collected);
    assert!(!terminated);
}

#[test]
fn target_losing_readable_pid_during_revalidation_exits_permission_denied() {
    let rows = vec![entry(3000)];
    let snapshot = permission_denied_owner_snapshot();
    let mut prepared = false;
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_port(3000, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        |pid| {
            prepared = true;
            Ok::<u32, TerminationOutcome>(pid)
        },
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::PermissionDenied);
    // The denial surfaces during post-prepare revalidation: the handle was
    // already prepared, but no signal may be delivered through it.
    assert!(prepared);
    assert!(!terminated);
}

#[test]
fn authoritative_snapshot_refusal_reaches_zero_delivery() {
    let rows = vec![entry(3000)];
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || {
                Err(CollectorError::Observation(
                    ObservationError::PartialSocketSet,
                ))
            },
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        Ok::<u32, TerminationOutcome>,
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert!(!terminated);
}

#[test]
fn port_owner_moving_after_handle_preparation_never_signals_old_owner() {
    let rows = vec![entry(3000)];
    let moved = vec![entry_with_pid(
        3000,
        Some(29_999),
        Protocol::Tcp,
        "replacement",
    )];
    let events = RefCell::new(Vec::new());

    let reason = run_kill_with(
        &kill_port(3000, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || {
                events.borrow_mut().push("collect");
                Ok(moved.clone())
            },
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        |pid| {
            assert_eq!(pid, 18_422);
            events.borrow_mut().push("prepare");
            Ok::<u32, TerminationOutcome>(pid)
        },
        |_handle: &u32, _target, _protected, _mode| {
            events.borrow_mut().push("deliver");
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert_eq!(*events.borrow(), ["prepare", "collect"]);
}

#[test]
fn kill_pid_losing_readable_owner_during_revalidation_exits_permission_denied() {
    let rows = vec![entry(3000)];
    let snapshot = permission_denied_owner_snapshot();
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        Ok::<u32, TerminationOutcome>,
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::PermissionDenied);
    assert!(!terminated);
}

#[test]
fn target_becoming_protected_after_confirmation_blocks_signal() {
    let rows = vec![entry(3000)];
    let mut protected = entry(3000);
    protected.protected = true;
    let fresh_rows = vec![protected];
    let mut terminated = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(fresh_rows.clone()),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        Ok::<u32, TerminationOutcome>,
        |_pid: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    assert!(!terminated);
}

#[test]
fn missing_fresh_protection_name_refuses_without_delivery() {
    let rows = vec![entry(3000)];
    let mut fresh = entry(3000);
    fresh.process_name = None;
    let mut delivered = false;

    let reason = run_kill_with(
        &kill_pid(18_422, false, true),
        &Config::default(),
        &entry_views(&rows),
        KillCollectors {
            context: &mut no_context,
            kill_ports: &mut || Ok(vec![fresh.clone()]),
            visibility_ports: &mut || Ok(Vec::new()),
        },
        |_target, _mode, _requirement| panic!("--yes skips prompts"),
        Ok::<u32, TerminationOutcome>,
        |_handle: &u32, _target, _protected, _mode| {
            delivered = true;
            TerminationOutcome::Success
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert!(!delivered);
}

#[test]
fn confirmation_input_accepts_utf8_at_the_byte_limit() {
    let exact_payload = format!("{}é", "x".repeat(CONFIRMATION_INPUT_MAX_BYTES - 2));
    assert_eq!(exact_payload.len(), CONFIRMATION_INPUT_MAX_BYTES);

    for framed in [
        exact_payload.clone(),
        format!("{exact_payload}\n"),
        format!("{exact_payload}\r\n"),
    ] {
        let mut input = std::io::Cursor::new(framed.into_bytes());
        let answer = read_confirmation_line_from(&mut input, CONFIRMATION_INPUT_MAX_BYTES)
            .expect("exact payload must fit with any supported line framing");

        assert_eq!(answer, exact_payload);
    }
}

#[test]
fn overlong_confirmation_stops_after_limit_plus_one_bytes() {
    let mut bytes = vec![b'x'; CONFIRMATION_INPUT_MAX_BYTES + 1];
    bytes.push(b'\n');
    let mut input = std::io::Cursor::new(bytes);

    let error = read_confirmation_line_from(&mut input, CONFIRMATION_INPUT_MAX_BYTES)
        .expect_err("first excess payload byte must be rejected");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains(&format!("{CONFIRMATION_INPUT_MAX_BYTES}-byte limit"))
    );
    assert_eq!(
        input.position(),
        u64::try_from(CONFIRMATION_INPUT_MAX_BYTES + 2).unwrap()
    );
}

#[test]
fn confirmation_input_handles_empty_lines_and_invalid_utf8() {
    for bytes in [b"".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
        let mut input = std::io::Cursor::new(bytes);
        assert_eq!(
            read_confirmation_line_from(&mut input, CONFIRMATION_INPUT_MAX_BYTES).unwrap(),
            ""
        );
    }

    let mut invalid = std::io::Cursor::new([0xff, b'\n']);
    let error = read_confirmation_line_from(&mut invalid, CONFIRMATION_INPUT_MAX_BYTES)
        .expect_err("invalid UTF-8 must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

fn settle_target() -> KillTarget {
    let row = entry(3000);
    KillTarget::from_entries(18_422, [PortEntryView::from(&row)], None)
}

#[test]
fn post_kill_settle_clears_when_ports_disappear_on_a_later_poll() {
    // Model asynchronous SIGTERM teardown across several polls.
    let target = settle_target();
    let mut collect_calls = 0;
    let mut sleeps = 0;

    let status = wait_for_confirmed_ports_to_clear(
        &target,
        &mut || {
            collect_calls += 1;
            if collect_calls < 3 {
                Ok(vec![entry(3000)])
            } else {
                Ok(Vec::new())
            }
        },
        |_delay| sleeps += 1,
    );

    assert_eq!(status, PostKillPortsStatus::Cleared);
    assert_eq!(collect_calls, 3);
    assert_eq!(sleeps, 2);
}

#[test]
fn post_kill_settle_reports_still_visible_after_bounded_attempts() {
    let target = settle_target();
    let mut collect_calls = 0;
    let mut sleeps = 0;

    let status = wait_for_confirmed_ports_to_clear(
        &target,
        &mut || {
            collect_calls += 1;
            Ok(vec![entry(3000)])
        },
        |_delay| sleeps += 1,
    );

    assert_eq!(status, PostKillPortsStatus::StillVisible);
    assert_eq!(collect_calls, POST_KILL_SETTLE_ATTEMPTS_MAX);
    // Do not sleep after the final poll.
    assert_eq!(sleeps, POST_KILL_SETTLE_ATTEMPTS_MAX - 1);
}

#[test]
fn post_kill_settle_stays_visible_while_any_confirmed_port_remains() {
    // One remaining port keeps a multi-port target visible.
    let row_a = entry(3000);
    let row_b = entry(3001);
    let target = KillTarget::from_entries(
        18_422,
        [PortEntryView::from(&row_a), PortEntryView::from(&row_b)],
        None,
    );
    let mut collect_calls = 0;
    let mut sleeps = 0;

    let status = wait_for_confirmed_ports_to_clear(
        &target,
        &mut || {
            collect_calls += 1;
            // Port 3000 closes immediately; 3001 never does.
            Ok(vec![entry(3001)])
        },
        |_delay| sleeps += 1,
    );

    assert_eq!(status, PostKillPortsStatus::StillVisible);
    assert_eq!(collect_calls, POST_KILL_SETTLE_ATTEMPTS_MAX);
    assert_eq!(sleeps, POST_KILL_SETTLE_ATTEMPTS_MAX - 1);
}

#[test]
fn post_kill_settle_fails_closed_when_refresh_errors() {
    let target = settle_target();
    let mut collect_calls = 0;
    let mut sleeps = 0;

    let status = wait_for_confirmed_ports_to_clear(
        &target,
        &mut || {
            collect_calls += 1;
            if collect_calls == 1 {
                Ok(vec![entry(3000)])
            } else {
                Err(CollectorError::WorkerExited)
            }
        },
        |_delay| sleeps += 1,
    );

    // A failed refresh must not be spun into "cleared" or polled forever;
    // it surfaces as the refresh warning immediately.
    assert!(matches!(status, PostKillPortsStatus::RefreshFailed(_)));
    assert_eq!(collect_calls, 2);
    assert_eq!(sleeps, 1);
}
