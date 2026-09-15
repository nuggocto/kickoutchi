use crate::model::PortEntryView;
use crate::model::entry_views;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::macos::macos_tree_stop_result;
use super::{
    ConfirmationRequirement, KillMode, KillTarget, KillWarning, TerminationOutcome,
    UnsafePidReason, WarningScope, confirmation_input_matches, confirmation_requirement,
    revalidate_confirmed_target, target_still_matches_confirmation, unsafe_pid_reason,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::{
    UnixProcessState, UnixProcessStatus, finish_stopped_termination, macos_cont_if_matches_with,
    macos_stop_observation_result, outcome_after_thaw, refuse_stopped_termination,
    run_before_stop_deadline,
};
#[cfg(target_os = "macos")]
use super::{finish_macos_stopped_process, macos_status_is_exited};
#[cfg(target_os = "linux")]
use super::{
    linux_process_state, linux_stop_observation_result, parse_linux_process_state,
    tree_cont_handle, tree_open_delivery_handle, tree_stop_handle,
};
#[cfg(windows)]
use super::{native_utf16_prefix, windows_api_outcome};
use crate::model::{
    ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
    Protocol, SocketState,
};
#[cfg(target_os = "macos")]
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};

#[cfg(target_os = "linux")]
struct ChildGuard(std::process::Child);

#[cfg(target_os = "linux")]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_proc_state_parser_classifies_lifecycle_states_and_identity() {
    for (stat, expected) in [
        (
            b"42 (worker with ) chars) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987 20"
                .as_slice(),
            UnixProcessStatus::Running,
        ),
        (
            b"42 (worker with ) chars) T 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987 20"
                .as_slice(),
            UnixProcessStatus::Stopped,
        ),
        (
            b"42 (worker with ) chars) Z 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987 20"
                .as_slice(),
            UnixProcessStatus::Exited,
        ),
    ] {
        let state = parse_linux_process_state(stat).expect("valid proc stat parses");
        assert_eq!(state.status, expected);
        assert_eq!(
            state.marker,
            crate::observation::ProcessStartMarker::linux(987).expect("nonzero marker")
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tree_stop_returns_only_after_stopped_state_is_observable() {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn test child");
    let mut child = ChildGuard(child);
    let pid = child.0.id();
    let handle = tree_open_delivery_handle(pid).expect("open child pidfd");

    assert_eq!(
        tree_stop_handle(
            &handle,
            std::time::Instant::now() + super::UNIX_STOP_ACKNOWLEDGEMENT_MAX
        ),
        crate::tree::TreeStopResult::Stopped { transitioned: true }
    );
    assert_eq!(
        linux_process_state(pid)
            .expect("child state remains readable")
            .status,
        UnixProcessStatus::Stopped,
    );

    assert_eq!(
        tree_cont_handle(&handle),
        crate::tree::TreeSignalResult::Delivered
    );
    child.0.kill().expect("terminate test child");
}

#[cfg(windows)]
#[test]
fn malformed_windows_native_name_length_fails_closed_without_panicking() {
    let buffer = [0_u16; 4];
    assert_eq!(native_utf16_prefix(&buffer, 5), None);
    assert_eq!(native_utf16_prefix(&buffer, u32::MAX), None);
    assert_eq!(native_utf16_prefix(&buffer, 4), Some(buffer.as_slice()));
}

fn entry(port: u16, protocol: Protocol) -> PortEntry {
    PortEntry {
        protocol,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: port,
        state: match protocol {
            Protocol::Tcp => SocketState::Listen,
            Protocol::Udp => SocketState::Bound,
        },
        pid: Some(18422),
        process_name: Some("node".into()),
        executable_path: None,
        command_line: None,
        parent_pid: None,
        parent_process_name: None,
        protected: false,
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        process_identity: Some(crate::observation::ProcessIdentity {
            pid: 18422,
            start_marker: crate::observation::ProcessStartMarker::linux(55)
                .expect("test marker is nonzero"),
        }),
        ipv6_scope: None,
    }
}

fn context(start_time_ticks: u64) -> ProcessContext {
    ProcessContext {
        owner_uid: Some(1000),
        process_start_time_marker: crate::observation::ProcessStartMarker::linux(start_time_ticks)
            .ok(),
        children: ChildProcessSnapshot::default(),
        docker: None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn single_process_thaw_failure_is_typed() {
    let outcome = outcome_after_thaw(
        42,
        TerminationOutcome::TargetChanged,
        crate::tree::TreeSignalResult::Denied,
    );
    assert!(matches!(
        outcome,
        TerminationOutcome::ThawFailed { pid: 42, prior }
            if *prior == TerminationOutcome::TargetChanged
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn successful_sigterm_continues_a_pre_stopped_single_process_but_failure_does_not() {
    let marker = crate::observation::ProcessStartMarker::linux(55).ok();
    let mut continued = Vec::new();

    let success = finish_stopped_termination(
        42,
        KillMode::Terminate,
        false,
        marker,
        |_| TerminationOutcome::Success,
        |pid, guarded_marker| {
            continued.push((pid, guarded_marker));
            crate::tree::TreeSignalResult::Delivered
        },
    );
    let failed = finish_stopped_termination(
        43,
        KillMode::Terminate,
        false,
        marker,
        |_| TerminationOutcome::PermissionDenied,
        |_, _| panic!("failed delivery must not resume a pre-stopped process"),
    );
    let refused = refuse_stopped_termination(
        44,
        false,
        marker,
        TerminationOutcome::TargetChanged,
        |_, _| panic!("refusal must not resume a pre-stopped process"),
    );

    assert_eq!(success, TerminationOutcome::Success);
    assert_eq!(failed, TerminationOutcome::PermissionDenied);
    assert_eq!(refused, TerminationOutcome::TargetChanged);
    assert_eq!(continued, [(42, marker)]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn thaw_failure_text_retains_the_primary_failure() {
    let outcome = outcome_after_thaw(
        42,
        TerminationOutcome::TargetChanged,
        crate::tree::TreeSignalResult::Denied,
    );

    assert_eq!(
        outcome.failure_cause_text(),
        "the confirmed process identity changed; cleanup could not continue PID 42"
    );
}

#[test]
fn direct_termination_descriptions_are_stable_across_interfaces() {
    let target = KillTarget {
        pid: 42,
        process_name: Some("node".to_owned()),
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: None,
        child_count: 0,
        children_truncated: false,
    };
    let cases = [
        (TerminationOutcome::Success, "sent SIGTERM to PID 42 (node)"),
        (
            TerminationOutcome::PermissionDenied,
            "permission denied sending SIGTERM to PID 42 (node)",
        ),
        (
            TerminationOutcome::OwnershipUnavailable,
            "ownership for PID 42 (node) became unavailable before SIGTERM; no termination was sent",
        ),
        (
            TerminationOutcome::AlreadyExited,
            "PID 42 (node) already exited before termination was sent",
        ),
        (TerminationOutcome::Cancelled, "kill cancelled"),
        (
            TerminationOutcome::ProtectedProcess,
            "PID 42 (node) is protected",
        ),
        (
            TerminationOutcome::TargetChanged,
            "PID 42 (node) no longer owns the confirmed port target; no termination was sent",
        ),
        (
            TerminationOutcome::UnsafePid(UnsafePidReason::CurrentProcess),
            "unsafe PID blocked: Kickoutchi cannot terminate itself",
        ),
        (
            TerminationOutcome::UnknownFailure("\x1b[31mboom\nnext".to_owned()),
            "sending SIGTERM to PID 42 (node) failed: boom next",
        ),
        (
            TerminationOutcome::ThawFailed {
                pid: 43,
                prior: Box::new(TerminationOutcome::TargetChanged),
            },
            "the confirmed process identity changed; cleanup could not continue PID 43; it may remain stopped and require SIGCONT",
        ),
    ];

    for (outcome, expected) in cases {
        assert_eq!(
            outcome.status_description(&target, KillMode::Terminate),
            expected,
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn deadline_recheck_prevents_a_delayed_sigstop_submission() {
    let start = std::time::Instant::now();
    let deadline = start + super::UNIX_STOP_ACKNOWLEDGEMENT_MAX;
    let signal_sent = std::cell::Cell::new(false);

    let failure = run_before_stop_deadline(deadline, || deadline, || signal_sent.set(true))
        .expect_err("an operation at the deadline must not run");

    assert!(!signal_sent.get());
    assert!(!failure.cleanup_required);
    assert!(matches!(
        failure.outcome,
        TerminationOutcome::UnknownFailure(_)
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn delayed_poll_does_not_acknowledge_a_stop_after_the_deadline() {
    let marker = crate::observation::ProcessStartMarker::linux(55).expect("test marker is nonzero");
    let before = UnixProcessState {
        marker,
        status: UnixProcessStatus::Running,
    };
    let observed = UnixProcessState {
        status: UnixProcessStatus::Stopped,
        ..before
    };

    let failure = macos_stop_observation_result(before, observed, true)
        .expect("stopped observation is terminal")
        .expect_err("late stopped observation must time out");

    assert!(failure.cleanup_required);
    assert_eq!(failure.rollback_start_time_marker, Some(marker));
    assert!(matches!(
        failure.outcome,
        TerminationOutcome::UnknownFailure(_)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_delayed_poll_does_not_acknowledge_a_stop_after_the_deadline() {
    let marker = crate::observation::ProcessStartMarker::linux(55).expect("test marker is nonzero");
    let before = UnixProcessState {
        marker,
        status: UnixProcessStatus::Running,
    };
    let observed = UnixProcessState {
        status: UnixProcessStatus::Stopped,
        ..before
    };

    let failure = linux_stop_observation_result(before, true, observed, true)
        .expect("stopped observation is terminal")
        .expect_err("late stopped observation must time out");

    assert!(failure.cleanup_required);
    assert!(matches!(
        failure.outcome,
        TerminationOutcome::UnknownFailure(_)
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn macos_pre_stopped_identity_replacement_is_guardedly_thawed_when_observed_stopped() {
    let original =
        crate::observation::ProcessStartMarker::macos(20, 30).expect("original marker is valid");
    let replacement =
        crate::observation::ProcessStartMarker::macos(21, 30).expect("replacement marker is valid");
    let before = UnixProcessState {
        marker: original,
        status: UnixProcessStatus::Stopped,
    };
    let observed = UnixProcessState {
        marker: replacement,
        status: UnixProcessStatus::Stopped,
    };

    let failure = macos_stop_observation_result(before, observed, false)
        .expect("identity replacement is terminal")
        .expect_err("replacement must refuse termination");
    assert!(failure.cleanup_required);
    assert_eq!(failure.rollback_start_time_marker, Some(replacement));

    let stop = macos_tree_stop_result(Err(failure));

    assert_eq!(
        stop,
        crate::tree::TreeStopResult::Failed {
            cleanup_required: true,
            rollback_start_time_marker: Some(replacement),
            error: crate::tree::TreeStopError::ObservationFailed(
                "stopped-state observation failed: TargetChanged".to_owned()
            ),
        }
    );

    let mut continued = Vec::new();
    let thaw = macos_cont_if_matches_with(
        42,
        Some(replacement),
        |_| Ok(replacement),
        |pid| {
            continued.push(pid);
            crate::tree::TreeSignalResult::Delivered
        },
    );
    assert_eq!(thaw, crate::tree::TreeSignalResult::Delivered);
    assert_eq!(continued, [42]);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_zombie_status_is_classified_as_exited() {
    assert!(macos_status_is_exited(libc::SZOMB));
    assert!(!macos_status_is_exited(libc::SSTOP));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_identity_change_rolls_back_the_post_stop_process_without_terminating_it() {
    let original_marker =
        crate::observation::ProcessStartMarker::macos(20, 30).expect("original marker is valid");
    let replacement_marker =
        crate::observation::ProcessStartMarker::macos(21, 30).expect("replacement marker is valid");
    let target = KillTarget {
        pid: 42,
        process_name: Some("node".to_owned()),
        platform: Platform::Macos,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: Some(original_marker),
        child_count: 0,
        children_truncated: false,
    };
    let fresh = Ok(FreshProcessEvidence {
        pid: 42,
        start_marker: replacement_marker,
        name: "replacement".to_owned(),
    });
    let mut continued = Vec::new();

    let outcome = finish_macos_stopped_process(
        42,
        &target,
        &[],
        KillMode::Terminate,
        true,
        fresh,
        |_| panic!("replacement identity must not receive a terminating signal"),
        |pid, rollback_marker| {
            continued.push((pid, rollback_marker));
            crate::tree::TreeSignalResult::Delivered
        },
    );

    assert_eq!(
        outcome,
        TerminationOutcome::UnknownFailure(
            "fresh process identity or protection name changed; refusing termination".to_owned()
        )
    );
    assert_eq!(continued, [(42, Some(replacement_marker))]);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_evidence_failure_rechecks_and_rolls_back_the_authorized_identity() {
    let original_marker =
        crate::observation::ProcessStartMarker::macos(20, 30).expect("original marker is valid");
    let target = KillTarget {
        pid: 42,
        process_name: Some("node".to_owned()),
        platform: Platform::Macos,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: Some(original_marker),
        child_count: 0,
        children_truncated: false,
    };
    let mut continued = Vec::new();

    let outcome = finish_macos_stopped_process(
        42,
        &target,
        &[],
        KillMode::Terminate,
        true,
        Err(ProcessEvidenceError::PermissionDenied { pid: 42 }),
        |_| panic!("incomplete evidence must prevent termination"),
        |pid, rollback_marker| {
            continued.push((pid, rollback_marker));
            crate::tree::TreeSignalResult::Delivered
        },
    );

    assert_eq!(outcome, TerminationOutcome::PermissionDenied);
    assert_eq!(continued, [(42, Some(original_marker))]);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_preexisting_stop_is_not_continued_on_refusal() {
    let marker = crate::observation::ProcessStartMarker::macos(20, 30).expect("marker is valid");
    let target = KillTarget {
        pid: 42,
        process_name: Some("node".to_owned()),
        platform: Platform::Macos,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: Some(marker),
        child_count: 0,
        children_truncated: false,
    };

    let outcome = finish_macos_stopped_process(
        42,
        &target,
        &[],
        KillMode::Terminate,
        false,
        Err(ProcessEvidenceError::PermissionDenied { pid: 42 }),
        |_| panic!("failed evidence must prevent termination"),
        |_, _| panic!("an externally stopped process must not receive SIGCONT"),
    );

    assert_eq!(outcome, TerminationOutcome::PermissionDenied);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_cleanup_refuses_a_second_identity_change() {
    let rollback_marker =
        crate::observation::ProcessStartMarker::macos(20, 30).expect("rollback marker is valid");
    let changed_marker =
        crate::observation::ProcessStartMarker::macos(21, 30).expect("changed marker is valid");

    let result = macos_cont_if_matches_with(
        42,
        Some(rollback_marker),
        |_| Ok(changed_marker),
        |_| panic!("changed identity must not receive SIGCONT"),
    );

    assert_eq!(result, crate::tree::TreeSignalResult::Denied);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_cleanup_treats_an_exited_process_as_already_thawed() {
    let rollback_marker =
        crate::observation::ProcessStartMarker::macos(20, 30).expect("rollback marker is valid");

    let result = macos_cont_if_matches_with(
        42,
        Some(rollback_marker),
        |_| Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
        |_| panic!("an exited process must not receive SIGCONT"),
    );

    assert_eq!(result, crate::tree::TreeSignalResult::NotFound);
    assert_eq!(
        outcome_after_thaw(42, TerminationOutcome::Success, result),
        TerminationOutcome::Success
    );
}

#[test]
fn kill_target_names_every_visible_port_once() {
    let rows = [
        entry(3000, Protocol::Tcp),
        entry(3000, Protocol::Udp),
        entry(3000, Protocol::Tcp),
    ];
    let context = ProcessContext {
        owner_uid: Some(1000),
        process_start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
        children: ChildProcessSnapshot {
            children: vec![ChildProcess {
                pid: 18423,
                process_name: Some("worker".to_owned()),
            }],
            truncated: false,
        },
        docker: None,
    };

    let target =
        KillTarget::from_entries(18422, rows.iter().map(PortEntryView::from), Some(&context));

    assert_eq!(target.identity(), "PID 18422 (node)");
    assert_eq!(
        target.ports_text(),
        "TCP 127.0.0.1:3000, UDP 127.0.0.1:3000"
    );
    assert_eq!(target.owner_uid, Some(1000));
    assert_eq!(target.child_count, 1);
    assert!(target.has_children());
    let child_warning = target
        .warnings()
        .into_iter()
        .find(|warning| matches!(warning, KillWarning::HasChildren { .. }))
        .expect("a target with children must retain a typed warning");
    assert_eq!(
        child_warning.text(WarningScope::Process),
        "target has 1 direct child process(es); termination targets only the confirmed PID",
    );
    assert_eq!(
        child_warning.text(WarningScope::Tree),
        "target has 1 direct child process(es); tree kill targets the bounded descendant tree shown above",
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(
        child_warning.text(WarningScope::Group),
        "target has 1 direct child process(es); group kill targets every group member shown above",
    );
}

#[test]
fn kill_target_port_labels_preserve_ipv6_scope() {
    let mut row = entry(3000, Protocol::Tcp);
    row.local_addr = IpAddr::V6("fe80::1".parse().expect("test address is valid"));
    row.ipv6_scope =
        Some(crate::observation::Ipv6Scope::interface_index(3).expect("test scope is valid"));

    let target = KillTarget::from_entries(18422, [PortEntryView::from(&row)], Some(&context(55)));

    assert_eq!(target.ports_text(), "TCP [fe80::1%3]:3000");
}

#[test]
fn kill_target_warns_for_system_processes() {
    let mut row = entry(3000, Protocol::Tcp);
    row.parent_pid = Some(1);

    let target = KillTarget::from_entries(18422, [PortEntryView::from(&row)], Some(&context(55)));

    assert!(target.system_process);
    assert!(target.warnings().contains(&KillWarning::SystemProcess));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn owner_warnings_distinguish_matching_and_foreign_uids() {
    let current_uid = super::current_user_id();
    let mut matching_context = context(55);
    matching_context.owner_uid = Some(current_uid);
    let matching = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&entry(3000, Protocol::Tcp))],
        Some(&matching_context),
    );
    assert!(
        !matching
            .warnings()
            .iter()
            .any(|warning| matches!(warning, KillWarning::OwnerMismatch { .. })),
        "the current user's process must not be reported as foreign",
    );

    let mut partial_row = entry(3000, Protocol::Tcp);
    partial_row.permission = PermissionStatus::Partial;
    let mut foreign_context = context(55);
    foreign_context.owner_uid = Some(current_uid ^ 1);
    let foreign = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&partial_row)],
        Some(&foreign_context),
    );
    let warnings = foreign.warnings();
    assert!(
        warnings.iter().any(|warning| matches!(
            warning,
            KillWarning::OwnerMismatch {
                owner_uid,
                current_uid: warning_current_uid,
            } if *owner_uid == current_uid ^ 1 && *warning_current_uid == current_uid
        )),
        "a foreign owner must retain the actionable UID warning",
    );
    assert!(
        !warnings.contains(&KillWarning::PartialMetadata),
        "the generic partial-metadata warning must not duplicate the UID warning",
    );
}

#[test]
fn confirmation_requirements_keep_yes_from_bypassing_protected_processes() {
    assert_eq!(
        confirmation_requirement(false, KillMode::Terminate, true, true),
        Ok(None),
    );
    assert_eq!(
        confirmation_requirement(false, KillMode::Terminate, false, true),
        Ok(Some(ConfirmationRequirement::Yes)),
    );
    assert_eq!(
        confirmation_requirement(false, KillMode::Terminate, false, false),
        Ok(Some(ConfirmationRequirement::Yes)),
    );
    assert_eq!(
        confirmation_requirement(false, KillMode::Force, false, true),
        Ok(Some(ConfirmationRequirement::ForceWord)),
    );
    assert_eq!(
        confirmation_requirement(false, KillMode::Force, false, false),
        Ok(Some(ConfirmationRequirement::Yes)),
    );
    assert_eq!(
        confirmation_requirement(true, KillMode::Terminate, false, true),
        Ok(Some(ConfirmationRequirement::ProtectedProcess)),
    );
    assert_eq!(
        confirmation_requirement(true, KillMode::Terminate, true, true),
        Err(TerminationOutcome::ProtectedProcess),
    );
}

#[test]
fn windows_termination_carries_a_force_warning() {
    assert!(
        KillMode::Terminate
            .force_warning(Platform::Windows)
            .is_some()
    );
}

#[test]
fn confirmation_input_is_specific_to_the_required_path() {
    let row = entry(3000, Protocol::Tcp);
    let target = KillTarget::from_entries(18422, [PortEntryView::from(&row)], Some(&context(55)));

    assert!(confirmation_input_matches(
        "yes",
        &target,
        ConfirmationRequirement::Yes,
    ));
    assert!(!confirmation_input_matches(
        "yes",
        &target,
        ConfirmationRequirement::ForceWord,
    ));
    assert!(confirmation_input_matches(
        "force",
        &target,
        ConfirmationRequirement::ForceWord,
    ));
    assert!(confirmation_input_matches(
        "FORCE",
        &target,
        ConfirmationRequirement::ForceWord,
    ));
    assert!(confirmation_input_matches(
        "18422",
        &target,
        ConfirmationRequirement::ProtectedProcess,
    ));
    assert!(confirmation_input_matches(
        "node",
        &target,
        ConfirmationRequirement::ProtectedProcess,
    ));
    assert!(!confirmation_input_matches(
        "NODE",
        &target,
        ConfirmationRequirement::ProtectedProcess,
    ));

    let mut windows_row = entry(3000, Protocol::Tcp);
    windows_row.platform = Platform::Windows;
    let windows_target = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&windows_row)],
        Some(&context(55)),
    );
    assert!(confirmation_input_matches(
        "NODE",
        &windows_target,
        ConfirmationRequirement::ProtectedProcess,
    ));
    let mut unicode_windows_target = windows_target;
    unicode_windows_target.process_name = Some("ÄPP.EXE".to_owned());
    assert!(confirmation_input_matches(
        "äpp.exe",
        &unicode_windows_target,
        ConfirmationRequirement::ProtectedProcess,
    ));
}

#[test]
fn unsafe_pid_guardrails_block_documented_targets() {
    assert_eq!(unsafe_pid_reason(0), Some(UnsafePidReason::Zero));
    assert_eq!(unsafe_pid_reason(1), Some(UnsafePidReason::One));
    #[cfg(windows)]
    assert_eq!(unsafe_pid_reason(4), Some(UnsafePidReason::WindowsSystem));
    assert_eq!(
        unsafe_pid_reason(std::process::id()),
        Some(UnsafePidReason::CurrentProcess),
    );
    assert_eq!(unsafe_pid_reason(u32::MAX), None);
}

#[test]
fn revalidation_requires_same_pid_name_and_confirmed_ports() {
    let confirmed_rows = [entry(3000, Protocol::Tcp), entry(3000, Protocol::Udp)];
    let confirmed = KillTarget::from_entries(
        18422,
        confirmed_rows.iter().map(PortEntryView::from),
        Some(&context(55)),
    );

    let fresh_rows = [entry(3000, Protocol::Tcp), entry(3000, Protocol::Udp)];
    let fresh =
        revalidate_confirmed_target(&confirmed, &entry_views(&fresh_rows), Some(&context(55)))
            .expect("same PID and ports are still valid");

    assert!(target_still_matches_confirmation(&confirmed, &fresh));
}

#[test]
fn revalidation_rejects_missing_or_changed_targets() {
    let confirmed_row = entry(3000, Protocol::Tcp);
    let confirmed = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&confirmed_row)],
        Some(&context(55)),
    );

    assert_eq!(
        revalidate_confirmed_target(&confirmed, &[], Some(&context(55))),
        Err(TerminationOutcome::TargetChanged),
    );

    let mut changed_name = entry(3000, Protocol::Tcp);
    changed_name.process_name = Some("other".into());
    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&changed_name)],
            Some(&context(55))
        ),
        Err(TerminationOutcome::TargetChanged),
    );

    let mut missing_name = entry(3000, Protocol::Tcp);
    missing_name.process_name = None;
    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&missing_name)],
            Some(&context(55))
        ),
        Err(TerminationOutcome::TargetChanged),
    );

    let changed_port = entry(4000, Protocol::Tcp);
    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&changed_port)],
            Some(&context(55))
        ),
        Err(TerminationOutcome::TargetChanged),
    );
}

#[test]
fn revalidation_rejects_pid_reuse_with_changed_start_time() {
    let confirmed_row = entry(3000, Protocol::Tcp);
    let confirmed = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&confirmed_row)],
        Some(&context(55)),
    );
    let mut fresh_row = entry(3000, Protocol::Tcp);
    fresh_row.process_identity = Some(crate::observation::ProcessIdentity {
        pid: 18422,
        start_marker: crate::observation::ProcessStartMarker::linux(99)
            .expect("test marker is nonzero"),
    });

    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&fresh_row)],
            Some(&context(99))
        ),
        Err(TerminationOutcome::TargetChanged),
    );
}

#[test]
fn revalidation_rejects_ipv6_interface_scope_movement() {
    let mut confirmed_row = entry(3000, Protocol::Tcp);
    confirmed_row.local_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    confirmed_row.ipv6_scope = Some(
        crate::observation::Ipv6Scope::interface_index(2).expect("test interface index is valid"),
    );
    let confirmed = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&confirmed_row)],
        Some(&context(55)),
    );
    let mut moved = confirmed_row;
    moved.ipv6_scope = Some(
        crate::observation::Ipv6Scope::interface_index(3).expect("test interface index is valid"),
    );

    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&moved)],
            Some(&context(55))
        ),
        Err(TerminationOutcome::TargetChanged),
    );
}

#[test]
fn revalidation_rejects_missing_start_time_identity() {
    let confirmed_row = entry(3000, Protocol::Tcp);
    let confirmed = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&confirmed_row)],
        Some(&context(55)),
    );
    let mut fresh_row = entry(3000, Protocol::Tcp);
    fresh_row.process_identity = None;

    assert_eq!(
        revalidate_confirmed_target(&confirmed, &[PortEntryView::from(&fresh_row)], None),
        Err(TerminationOutcome::TargetChanged),
    );
}

#[test]
fn revalidation_reports_ownership_unavailable_when_owning_pid_becomes_unreadable() {
    let confirmed_row = entry(3000, Protocol::Tcp);
    let confirmed = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&confirmed_row)],
        Some(&context(55)),
    );

    // The confirmed port is still listening, but we can't map its owner to a
    // PID anymore: that's permission/ownership loss, not the target moving.
    let mut unreadable = entry(3000, Protocol::Tcp);
    unreadable.pid = None;
    unreadable.permission = PermissionStatus::Partial;

    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&unreadable)],
            Some(&context(55))
        ),
        Err(TerminationOutcome::OwnershipUnavailable),
    );
}

#[test]
fn revalidation_reports_ownership_unavailable_when_any_confirmed_port_loses_pid() {
    let confirmed_rows = [entry(3000, Protocol::Tcp), entry(3000, Protocol::Udp)];
    let confirmed = KillTarget::from_entries(
        18422,
        confirmed_rows.iter().map(PortEntryView::from),
        Some(&context(55)),
    );
    let mut unreadable_udp = entry(3000, Protocol::Udp);
    unreadable_udp.pid = None;
    unreadable_udp.permission = PermissionStatus::Partial;

    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[
                PortEntryView::from(&entry(3000, Protocol::Tcp)),
                PortEntryView::from(&unreadable_udp),
            ],
            Some(&context(55)),
        ),
        Err(TerminationOutcome::OwnershipUnavailable),
    );
}

#[test]
fn revalidation_rejects_targets_that_become_protected() {
    let confirmed_row = entry(3000, Protocol::Tcp);
    let confirmed = KillTarget::from_entries(
        18422,
        [PortEntryView::from(&confirmed_row)],
        Some(&context(55)),
    );
    let mut protected = entry(3000, Protocol::Tcp);
    protected.protected = true;

    assert_eq!(
        revalidate_confirmed_target(
            &confirmed,
            &[PortEntryView::from(&protected)],
            Some(&context(55))
        ),
        Err(TerminationOutcome::ProtectedProcess),
    );
}

#[cfg(windows)]
#[test]
fn windows_termination_maps_permission_denied_and_missing_pid_separately() {
    let denied = std::io::Error::from_raw_os_error(
        i32::try_from(ERROR_ACCESS_DENIED).expect("Windows error code fits i32"),
    );
    let missing = std::io::Error::from_raw_os_error(
        i32::try_from(ERROR_INVALID_PARAMETER).expect("Windows error code fits i32"),
    );

    assert_eq!(
        windows_api_outcome("OpenProcess", &denied),
        TerminationOutcome::PermissionDenied,
    );
    assert_eq!(
        windows_api_outcome("OpenProcess", &missing),
        TerminationOutcome::AlreadyExited,
    );
}
