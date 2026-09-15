use crate::model::entry_views;
use std::cell::RefCell;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::io::Write;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::rc::Rc;

use super::tree_outcome_from_termination;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::{
    GROUP_YES_SKIP_MAX_PROCESSES, TreeConfirmDecision, TreeKillIo, confirm_tree_kill,
    group_confirmation, kill_target_from_tree_info, run_group_kill_with, run_tree_kill_with,
    tree_confirmation,
};
use crate::cli::ExitReason;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::cli::KillArgs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::cli::test_support::entry_with_pid;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::cli::test_support::{entry, no_context};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::config::Config;
use crate::model::{PermissionStatus, Platform, Protocol};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::model::{PortEntry, SocketState};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::observation::{
    EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot, OwnerCompleteness,
    SnapshotCompleteness,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::KillMode;
use crate::process::KillTarget;
use crate::process::TerminationOutcome;
#[cfg(windows)]
use crate::tree::windows::WindowsTreeTerminationState;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree::{ProcessTreeTarget, TreeProcessInfo, TreeProcessOps, TreeSignalResult};

#[test]
fn already_exited_single_outcome_maps_to_root_already_exited() {
    let confirmed = KillTarget {
        pid: 18_422,
        process_name: Some("node".to_owned()),
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: Some(1_000),
        process_start_time_marker: None,
        child_count: 0,
        children_truncated: false,
    };

    let refusal = tree_outcome_from_termination(&confirmed, TerminationOutcome::AlreadyExited);
    assert_eq!(refusal, crate::tree::TreeKillOutcome::RootAlreadyExited);
    #[cfg(windows)]
    assert_eq!(
        crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome(refusal.clone()),
        crate::tree::windows::WindowsTreeKillOutcome::Refused(refusal),
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn locally_incomplete_kill_snapshot() -> NetworkSnapshot {
    use crate::collector::Collector;

    let mut snapshot = crate::collector::FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake snapshot collects");
    snapshot.completeness = SnapshotCompleteness::Complete;
    snapshot.owner_completeness = OwnerCompleteness::Complete;
    snapshot
        .evidence_gaps
        .retain(|gap| gap.impact != EvidenceImpact::SocketSet);
    for socket in &mut snapshot.sockets {
        socket.owner_completeness = OwnerCompleteness::Complete;
    }

    snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has port 3000")
        .owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
            .expect("one reason fits");
    snapshot
}

#[cfg(windows)]
fn confirm_windows_tree_prompt(
    _target: &KillTarget,
    _tree: &crate::tree::ProcessTreeTarget,
    _requirement: super::TreeConfirmation,
) -> std::io::Result<bool> {
    std::io::sink().write_all(&[])?;
    Ok(true)
}

#[cfg(windows)]
fn panic_windows_tree_execute(
    _root: &KillTarget,
    _protected: &[String],
    _authorization: crate::tree::ScopeAuthorization,
) -> crate::tree::windows::WindowsTreeKillOutcome {
    panic!("authoritative refusal must precede Job Object assignment")
}

#[cfg(windows)]
#[test]
fn windows_tree_authority_refusal_precedes_job_assignment() {
    let snapshot = locally_incomplete_kill_snapshot();
    let process_snapshot = vec![crate::tree::TreeProcessInfo {
        pid: 18_422,
        parent_pid: Some(500),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some("node.exe".to_owned()),
        start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
        owner_uid: None,
        process_group: None,
    }];

    let reason = super::run_windows_tree_kill_with(
        &KillArgs {
            pid: Some(18_422),
            port: None,
            force: false,
            yes: false,
            tree: true,
        },
        &Config::default(),
        &entry_views(&[entry(3000)]),
        crate::process::KillMode::Terminate,
        super::WindowsTreeKillIo {
            collect_tree: &mut || Ok(process_snapshot.clone()),
            collect_context: &mut no_context,
            prompt: &mut confirm_windows_tree_prompt,
            collect_kill_ports: &mut || {
                crate::collector::kill_ports_from_snapshot(&snapshot, Some(18_422), None)
            },
            collect_ports: &mut || panic!("refusal must not visibility-poll ports"),
            prepare_root: &mut |_pid| -> Result<u32, TerminationOutcome> {
                panic!("PID mode must preserve its existing preparation path")
            },
            execute: &mut panic_windows_tree_execute,
        },
    );

    assert_eq!(reason, ExitReason::Failure);
}

#[cfg(windows)]
#[test]
fn windows_port_tree_root_exit_during_preparation_is_no_match() {
    let process_snapshot = vec![crate::tree::TreeProcessInfo {
        pid: 18_422,
        parent_pid: Some(500),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some("node".to_owned()),
        start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
        owner_uid: None,
        process_group: None,
    }];
    let events = RefCell::new(Vec::new());

    let reason = super::run_windows_tree_kill_with(
        &KillArgs {
            pid: None,
            port: Some(3000),
            force: false,
            yes: true,
            tree: true,
        },
        &Config::default(),
        &entry_views(&[entry(3000)]),
        crate::process::KillMode::Terminate,
        super::WindowsTreeKillIo {
            collect_tree: &mut || Ok(process_snapshot.clone()),
            collect_context: &mut no_context,
            prompt: &mut confirm_windows_tree_prompt,
            collect_kill_ports: &mut || {
                panic!("root preparation refusal must precede final endpoint collection")
            },
            collect_ports: &mut || {
                events.borrow_mut().push("visibility");
                Ok(Vec::new())
            },
            prepare_root: &mut |pid| -> Result<u32, TerminationOutcome> {
                assert_eq!(pid, 18_422);
                events.borrow_mut().push("prepare");
                Err(TerminationOutcome::AlreadyExited)
            },
            execute: &mut panic_windows_tree_execute,
        },
    );

    assert_eq!(reason, ExitReason::NoMatch);
    assert_eq!(*events.borrow(), ["prepare", "visibility"]);
}

#[cfg(windows)]
#[test]
fn windows_port_owner_move_after_root_prepare_never_commits_job() {
    let process_snapshot = vec![crate::tree::TreeProcessInfo {
        pid: 18_422,
        parent_pid: Some(500),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some("node".to_owned()),
        start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
        owner_uid: None,
        process_group: None,
    }];
    let moved = vec![crate::cli::test_support::entry_with_pid(
        3000,
        Some(29_999),
        Protocol::Tcp,
        "replacement",
    )];
    let events = RefCell::new(Vec::new());
    let context = || crate::model::ProcessContext {
        owner_uid: None,
        process_start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
        children: crate::model::ChildProcessSnapshot::default(),
        docker: None,
    };

    let reason = super::run_windows_tree_kill_with(
        &KillArgs {
            pid: None,
            port: Some(3000),
            force: false,
            yes: true,
            tree: true,
        },
        &Config::default(),
        &entry_views(&[entry(3000)]),
        crate::process::KillMode::Terminate,
        super::WindowsTreeKillIo {
            collect_tree: &mut || Ok(process_snapshot.clone()),
            collect_context: &mut |_pid| context(),
            prompt: &mut confirm_windows_tree_prompt,
            collect_kill_ports: &mut || {
                events.borrow_mut().push("collect");
                Ok(moved.clone())
            },
            collect_ports: &mut || panic!("refusal must not visibility-poll ports"),
            prepare_root: &mut |pid| {
                assert_eq!(pid, 18_422);
                events.borrow_mut().push("prepare");
                Ok::<u32, TerminationOutcome>(pid)
            },
            execute:
                &mut |_root: &KillTarget,
                      _protected: &[String],
                      _authorization: crate::tree::ScopeAuthorization| {
                    events.borrow_mut().push("commit");
                    panic!("moved endpoint must prevent Job Object commit")
                },
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert_eq!(*events.borrow(), ["prepare", "collect"]);
}

#[cfg(windows)]
#[test]
fn windows_post_commit_protected_issue_exits_with_protected_code() {
    let root = KillTarget {
        pid: 100,
        process_name: Some("node.exe".to_owned()),
        platform: Platform::Windows,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
        child_count: 0,
        children_truncated: false,
    };
    let report = crate::tree::windows::WindowsTreeKillReport {
        total: 1,
        job_terminated_pids: vec![100],
        already_exited_pids: Vec::new(),
        not_terminated: vec![101],
        termination_state: WindowsTreeTerminationState::Partial,
        post_commit_issue: Some(
            crate::tree::windows::WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("lsass.exe".to_owned()),
            },
        ),
        secondary_post_commit_issue: Some(
            crate::tree::windows::WindowsTreePostCommitIssue::SnapshotFailed(
                "freezing committed Job Object failed: freeze failed".to_owned(),
            ),
        ),
        cleanup_issue: Some(
            crate::tree::windows::WindowsTreeCleanupIssue::WithheldJobThawFailed(
                "thaw failed".to_owned(),
            ),
        ),
    };
    let mut collect_ports = || Ok(Vec::new());

    let reason = super::map_windows_tree_completed_outcome(&root, &report, &mut collect_ports);

    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
}

#[cfg(windows)]
#[test]
fn windows_post_commit_warning_refusal_is_visible_and_fails() {
    let issue = crate::tree::windows::WindowsTreePostCommitIssue::FreshConfirmationRequired;

    let text = super::windows_post_commit_issue_text(&issue);
    let reason = super::windows_post_commit_issue_exit_reason(&issue);

    assert!(text.contains("gained warnings after --yes"));
    assert_eq!(reason, ExitReason::Failure);
}

#[cfg(windows)]
#[test]
fn windows_post_commit_protected_root_requires_confirmation() {
    let issue = crate::tree::windows::WindowsTreePostCommitIssue::ProtectedRoot {
        pid: 100,
        name: Some("lsass.exe".to_owned()),
    };

    let text = super::windows_post_commit_issue_text(&issue);
    let reason = super::windows_post_commit_issue_exit_reason(&issue);

    assert!(text.contains("root PID 100"));
    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
}

#[cfg(windows)]
#[test]
fn windows_tree_success_polls_post_kill_visibility() {
    let root = KillTarget {
        pid: 100,
        process_name: Some("node.exe".to_owned()),
        platform: Platform::Windows,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: vec![crate::process::KillTargetPort {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".parse().expect("test address"),
            local_port: 3000,
            ipv6_scope: None,
        }],
        owner_uid: None,
        process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
        child_count: 0,
        children_truncated: false,
    };
    let report = crate::tree::windows::WindowsTreeKillReport {
        total: 1,
        job_terminated_pids: vec![100],
        already_exited_pids: Vec::new(),
        not_terminated: Vec::new(),
        termination_state: WindowsTreeTerminationState::Complete,
        post_commit_issue: None,
        secondary_post_commit_issue: None,
        cleanup_issue: None,
    };
    let mut visibility_polls = 0;
    let mut collect_ports = || {
        visibility_polls += 1;
        Ok(Vec::new())
    };

    let reason = super::map_windows_tree_completed_outcome(&root, &report, &mut collect_ports);

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(visibility_polls, 1);
}

#[cfg(windows)]
#[test]
fn windows_partial_report_names_every_outcome_pid() {
    let root = KillTarget {
        pid: 100,
        process_name: Some("node.exe".to_owned()),
        platform: Platform::Windows,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
        child_count: 0,
        children_truncated: false,
    };
    let report = crate::tree::windows::WindowsTreeKillReport {
        total: 3,
        job_terminated_pids: Vec::new(),
        already_exited_pids: vec![102],
        not_terminated: vec![100, 103],
        termination_state: WindowsTreeTerminationState::Withheld,
        post_commit_issue: Some(
            crate::tree::windows::WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 103,
                name: Some("lsass.exe".to_owned()),
            },
        ),
        secondary_post_commit_issue: Some(
            crate::tree::windows::WindowsTreePostCommitIssue::SnapshotFailed(
                "freezing committed Job Object failed: freeze failed".to_owned(),
            ),
        ),
        cleanup_issue: Some(
            crate::tree::windows::WindowsTreeCleanupIssue::WithheldJobThawFailed(
                "thaw failed".to_owned(),
            ),
        ),
    };

    let text = super::windows_tree_partial_report_text(&root, &report);

    assert!(text.contains("job-terminated 0 of 3"), "{text}");
    assert!(text.contains("already exited (PIDs: 102)"), "{text}");
    assert!(
        text.contains("not confirmed terminated: 100, 103"),
        "{text}"
    );
    assert!(
        text.contains("protected descendant PID 103 (lsass.exe)"),
        "{text}"
    );
    assert!(
            text.contains("secondary post-commit issue: enumerating the Windows process tree failed after commit: freezing committed Job Object failed: freeze failed"),
            "{text}"
        );
    assert!(
        text.contains("strict tree closure could not be established"),
        "{text}"
    );
    assert!(
        text.contains("cleanup issue: thawing the withheld Windows Job Object failed: thaw failed"),
        "{text}"
    );
}

#[cfg(windows)]
#[test]
fn failed_windows_job_mapping_prints_partial_report_and_refreshes_ports() {
    let root = KillTarget {
        pid: 100,
        process_name: Some("node.exe".to_owned()),
        platform: Platform::Windows,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: vec![crate::process::KillTargetPort {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".parse().expect("test address"),
            local_port: 3000,
            ipv6_scope: None,
        }],
        owner_uid: None,
        process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
        child_count: 0,
        children_truncated: false,
    };
    let outcome = crate::tree::windows::WindowsTreeKillOutcome::JobTerminateFailed {
        error: "job failed".to_owned(),
        report: Box::new(crate::tree::windows::WindowsTreeKillReport {
            total: 2,
            job_terminated_pids: Vec::new(),
            already_exited_pids: vec![102],
            not_terminated: vec![100],
            termination_state: WindowsTreeTerminationState::Partial,
            post_commit_issue: None,
            secondary_post_commit_issue: None,
            cleanup_issue: Some(
                crate::tree::windows::WindowsTreeCleanupIssue::FailedTerminationThawFailed(
                    "thaw failed".to_owned(),
                ),
            ),
        }),
    };
    let mut refreshes = 0;
    let mut collect_ports = || {
        refreshes += 1;
        Ok(Vec::new())
    };
    let mut stderr = Vec::new();

    let reason =
        super::map_windows_tree_system_failure(&root, &outcome, &mut collect_ports, &mut stderr);
    let text = String::from_utf8(stderr).expect("diagnostic must be UTF-8");

    assert_eq!(reason, ExitReason::Failure);
    assert_eq!(refreshes, 1);
    assert!(
        text.contains("TerminateJobObject failed: job failed"),
        "{text}"
    );
    assert!(text.contains("already exited (PIDs: 102)"), "{text}");
    assert!(text.contains("not confirmed terminated: 100"), "{text}");
    assert!(
            text.contains("cleanup issue: thawing the Windows Job Object after TerminateJobObject failed: thaw failed"),
            "{text}"
        );
    assert!(
        text.contains("confirmed target ports are no longer visible"),
        "{text}"
    );
}

/// Tree ops that allow the preview read but fail the test if the pipeline is
/// ever reached: used to prove refusals happen before any process is touched.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PreviewOnlyTreeOps(Vec<TreeProcessInfo>);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TreeProcessOps for PreviewOnlyTreeOps {
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        Ok(self.0.clone())
    }

    fn stop(&mut self, _pid: u32, _deadline: std::time::Instant) -> crate::tree::TreeStopResult {
        panic!("no process may be stopped for an unresolved root")
    }

    fn cont(&mut self, _pid: u32) -> TreeSignalResult {
        panic!("no process may be continued for an unresolved root")
    }

    fn prepare_delivery(
        &mut self,
        _pid: u32,
        _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
    ) -> TreeSignalResult {
        panic!("no pidfd may be opened for an unresolved root")
    }

    fn deliver(&mut self, _pid: u32, _mode: KillMode) -> TreeSignalResult {
        panic!("no signal may be sent for an unresolved root")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordingTreeEvent {
    Pin(u32),
    CollectPorts,
    Stop(u32),
    Deliver(u32),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct RecordingTreeOps {
    snapshots: Vec<Vec<TreeProcessInfo>>,
    next: usize,
    stops: Vec<u32>,
    events: Rc<RefCell<Vec<RecordingTreeEvent>>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RecordingTreeOps {
    fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
        Self {
            snapshots,
            next: 0,
            stops: Vec::new(),
            events: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TreeProcessOps for RecordingTreeOps {
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        let index = self.next.min(self.snapshots.len().saturating_sub(1));
        self.next += 1;
        Ok(self.snapshots.get(index).cloned().unwrap_or_default())
    }

    fn pin_root_for_revalidation(&mut self, pid: u32) -> TreeSignalResult {
        self.events.borrow_mut().push(RecordingTreeEvent::Pin(pid));
        TreeSignalResult::Delivered
    }

    fn stop(&mut self, pid: u32, _deadline: std::time::Instant) -> crate::tree::TreeStopResult {
        self.stops.push(pid);
        self.events.borrow_mut().push(RecordingTreeEvent::Stop(pid));
        crate::tree::TreeStopResult::Stopped { transitioned: true }
    }

    fn cont(&mut self, _pid: u32) -> TreeSignalResult {
        TreeSignalResult::Delivered
    }

    fn prepare_delivery(
        &mut self,
        _pid: u32,
        _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
    ) -> TreeSignalResult {
        TreeSignalResult::Delivered
    }

    fn deliver(&mut self, pid: u32, _mode: KillMode) -> TreeSignalResult {
        self.events
            .borrow_mut()
            .push(RecordingTreeEvent::Deliver(pid));
        TreeSignalResult::Delivered
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn kill_pid_tree(pid: u32) -> KillArgs {
    KillArgs {
        pid: Some(pid),
        port: None,
        force: false,
        yes: false,
        tree: true,
        group: false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn kill_pid_tree_yes(pid: u32) -> KillArgs {
    KillArgs {
        pid: Some(pid),
        port: None,
        force: false,
        yes: true,
        tree: true,
        group: false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn tree_kill_of_missing_pid_reports_no_match_without_touching_processes() {
    // The PID owns no visible port and is absent from the tree snapshot, so
    // tree kill refuses before freeze, prompt, or signal delivery.
    let reason = run_tree_kill_with(
        &kill_pid_tree(4_242),
        &Config::default(),
        &[],
        KillMode::Terminate,
        &mut PreviewOnlyTreeOps(Vec::new()),
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut |_target: &KillTarget, _tree: &ProcessTreeTarget, _requirement| {
                panic!("unresolved root must not prompt")
            },
            collect_kill_ports: &mut || panic!("unresolved root must not re-collect ports"),
            collect_ports: &mut || panic!("unresolved root must not re-collect ports"),
        },
    );

    assert_eq!(reason, ExitReason::NoMatch);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_info(pid: u32, parent_pid: Option<u32>, name: &str) -> TreeProcessInfo {
    TreeProcessInfo {
        pid,
        parent_pid,
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some(name.to_owned()),
        start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid)).ok(),
        owner_uid: None,
        process_group: None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_info_owned_by_other_uid(pid: u32, parent_pid: Option<u32>, name: &str) -> TreeProcessInfo {
    TreeProcessInfo {
        owner_uid: Some(crate::process::current_user_id().saturating_add(1)),
        ..tree_info(pid, parent_pid, name)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_target(infos: &[TreeProcessInfo], protected_names: &[String]) -> ProcessTreeTarget {
    crate::tree::plan_process_tree(100, infos, protected_names, Platform::Linux, 256)
        .expect("test tree root must be present")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn confirm_tree_prompt(
    _target: &KillTarget,
    _tree: &ProcessTreeTarget,
    _requirement: super::TreeConfirmation,
) -> std::io::Result<bool> {
    std::io::sink().write_all(&[])?;
    Ok(true)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn panic_tree_prompt(
    _target: &KillTarget,
    _tree: &ProcessTreeTarget,
    _requirement: super::TreeConfirmation,
) -> std::io::Result<bool> {
    panic!("tree prompt must not be reached")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn tree_confirmation_gates_yes_and_protected_roots() {
    let clean = tree_target(&[tree_info(100, Some(500), "node")], &[]);
    let clean_root = kill_target_from_tree_info(&tree_info(100, Some(500), "node"), &[]);
    assert_eq!(
        tree_confirmation(&clean_root, &clean, KillMode::Terminate, true),
        TreeConfirmDecision::Skip,
    );
    assert_eq!(
        tree_confirmation(&clean_root, &clean, KillMode::Terminate, false),
        TreeConfirmDecision::PromptWord("tree"),
    );
    assert_eq!(
        tree_confirmation(&clean_root, &clean, KillMode::Force, false),
        TreeConfirmDecision::PromptWord("force"),
    );

    let with_system = tree_target(
        &[
            tree_info(100, Some(500), "node"),
            tree_info(101, Some(100), "systemd"),
        ],
        &[],
    );
    assert_eq!(
        tree_confirmation(&clean_root, &with_system, KillMode::Terminate, true),
        TreeConfirmDecision::PromptWord("tree"),
    );

    let with_other_uid = tree_target(
        &[
            tree_info(100, Some(500), "node"),
            tree_info_owned_by_other_uid(101, Some(100), "worker"),
        ],
        &[],
    );
    assert_eq!(
        tree_confirmation(&clean_root, &with_other_uid, KillMode::Terminate, true),
        TreeConfirmDecision::PromptWord("tree"),
    );

    let protected_root = tree_target(
        &[tree_info(100, Some(500), "postgres")],
        &["postgres".to_owned()],
    );
    let protected_root_target = kill_target_from_tree_info(
        &tree_info(100, Some(500), "postgres"),
        &["postgres".to_owned()],
    );
    assert_eq!(
        tree_confirmation(
            &protected_root_target,
            &protected_root,
            KillMode::Terminate,
            true
        ),
        TreeConfirmDecision::RefuseProtectedYes,
    );
    assert_eq!(
        tree_confirmation(
            &protected_root_target,
            &protected_root,
            KillMode::Terminate,
            false
        ),
        TreeConfirmDecision::PromptProtectedThenWord("tree"),
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn completed_tree_confirmation_returns_exact_authorization() {
    let clean = tree_target(&[tree_info(100, Some(500), "node")], &[]);
    let clean_root = kill_target_from_tree_info(&tree_info(100, Some(500), "node"), &[]);
    assert_eq!(
        confirm_tree_kill(
            &clean_root,
            &clean,
            KillMode::Terminate,
            true,
            &mut panic_tree_prompt,
        )
        .expect("all-clear --yes skips the prompt"),
        crate::tree::ScopeAuthorization::SkippedAllClear,
    );
    assert_eq!(
        confirm_tree_kill(
            &clean_root,
            &clean,
            KillMode::Terminate,
            false,
            &mut confirm_tree_prompt,
        )
        .expect("typed scope word confirms an unprotected tree"),
        crate::tree::ScopeAuthorization::TypedWordConfirmed,
    );

    let protected = tree_target(
        &[tree_info(100, Some(500), "postgres")],
        &["postgres".to_owned()],
    );
    let protected_root = kill_target_from_tree_info(
        &tree_info(100, Some(500), "postgres"),
        &["postgres".to_owned()],
    );
    assert_eq!(
        confirm_tree_kill(
            &protected_root,
            &protected,
            KillMode::Terminate,
            false,
            &mut confirm_tree_prompt,
        )
        .expect("protected identity and scope word confirm the tree"),
        crate::tree::ScopeAuthorization::ProtectedRootAndWordConfirmed,
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn port_selected_tree_pins_old_root_before_endpoint_move_and_sends_no_signal() {
    let rows = vec![entry(3000)];
    let preview = vec![tree_info(18_422, Some(500), "node")];
    let mut ops = RecordingTreeOps::new(vec![preview]);
    let events = Rc::clone(&ops.events);
    let fresh_rows = vec![entry_with_pid(
        3000,
        Some(29_999),
        Protocol::Tcp,
        "replacement",
    )];

    let reason = run_tree_kill_with(
        &KillArgs {
            pid: None,
            port: Some(3000),
            force: false,
            yes: false,
            tree: true,
            group: false,
        },
        &Config::default(),
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut confirm_tree_prompt,
            collect_kill_ports: &mut || {
                events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                Ok(fresh_rows.clone())
            },
            collect_ports: &mut || Ok(Vec::new()),
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert_eq!(
        &*events.borrow(),
        &[
            RecordingTreeEvent::Pin(18_422),
            RecordingTreeEvent::CollectPorts,
        ],
        "the old root handle must be prepared before final endpoint ownership collection",
    );
    assert!(ops.stops.is_empty());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn tree_losing_readable_owner_during_revalidation_exits_permission_denied() {
    let rows = vec![entry(3000)];
    let preview = vec![tree_info(18_422, Some(500), "node")];
    let mut ops = RecordingTreeOps::new(vec![preview]);
    let events = Rc::clone(&ops.events);
    let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

    let reason = run_tree_kill_with(
        &KillArgs {
            pid: Some(18_422),
            port: None,
            force: false,
            yes: false,
            tree: true,
            group: false,
        },
        &Config::default(),
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut confirm_tree_prompt,
            collect_kill_ports: &mut || {
                events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                Ok(fresh_rows.clone())
            },
            collect_ports: &mut || Ok(Vec::new()),
        },
    );

    assert_eq!(reason, ExitReason::PermissionDenied);
    assert_eq!(
        &*events.borrow(),
        &[
            RecordingTreeEvent::Pin(18_422),
            RecordingTreeEvent::CollectPorts,
        ],
    );
    assert!(ops.stops.is_empty(), "refusal must precede any stop");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn tree_authority_refusal_has_zero_stop_or_delivery() {
    let snapshot = locally_incomplete_kill_snapshot();
    let rows = vec![entry(3000)];
    let preview = vec![tree_info(18_422, Some(500), "node")];
    let mut ops = RecordingTreeOps::new(vec![preview]);

    let reason = run_tree_kill_with(
        &kill_pid_tree(18_422),
        &Config::default(),
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut confirm_tree_prompt,
            collect_kill_ports: &mut || {
                crate::collector::kill_ports_from_snapshot(&snapshot, Some(18_422), None)
            },
            collect_ports: &mut || panic!("refusal must not visibility-poll ports"),
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert!(ops.stops.is_empty());
    assert!(
        !ops.events
            .borrow()
            .iter()
            .any(|event| matches!(event, RecordingTreeEvent::Deliver(_)))
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn fresh_tree_warning_after_yes_skip_refuses_before_any_stop() {
    let clean = vec![tree_info(18_422, Some(500), "node")];
    let warned = vec![
        tree_info(18_422, Some(500), "node"),
        TreeProcessInfo {
            pid: 18_423,
            parent_pid: Some(18_422),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: None,
            start_time_marker: crate::observation::ProcessStartMarker::linux(18_423).ok(),
            owner_uid: None,
            process_group: None,
        },
    ];
    let mut ops = RecordingTreeOps::new(vec![clean, warned]);

    let reason = run_tree_kill_with(
        &kill_pid_tree_yes(18_422),
        &Config::default(),
        &[],
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut panic_tree_prompt,
            collect_kill_ports: &mut || panic!("portless tree root must not re-collect ports"),
            collect_ports: &mut || panic!("portless tree root must not re-collect ports"),
        },
    );

    assert_eq!(reason, ExitReason::Failure);
    assert!(ops.stops.is_empty(), "refusal must precede any stop");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn protected_tree_descendant_refuses_before_prompt_or_stop_even_with_yes() {
    let rows = vec![entry(3000)];
    let snapshot = vec![
        tree_info(18_422, Some(500), "node"),
        tree_info(18_423, Some(18_422), "postgres"),
    ];
    let config = Config {
        protected_processes: vec!["postgres".to_owned()],
        ..Config::default()
    };

    let reason = run_tree_kill_with(
        &KillArgs {
            pid: Some(18_422),
            port: None,
            force: false,
            yes: true,
            tree: true,
            group: false,
        },
        &config,
        &entry_views(&rows),
        KillMode::Terminate,
        &mut PreviewOnlyTreeOps(snapshot),
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut panic_tree_prompt,
            collect_kill_ports: &mut || panic!("protected descendant must not re-collect ports"),
            collect_ports: &mut || panic!("protected descendant must not re-collect ports"),
        },
    );

    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
}

/// A port row with no readable process name, so the row policy cannot mark
/// the root protected. Only the tree scan can classify it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn nameless_row(port: u16, pid: u32) -> PortEntry {
    PortEntry {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: port,
        state: SocketState::Listen,
        pid: Some(pid),
        process_name: None,
        executable_path: None,
        command_line: None,
        parent_pid: None,
        parent_process_name: None,
        protected: false,
        platform: Platform::Linux,
        permission: PermissionStatus::Partial,
        process_identity: Some(crate::observation::ProcessIdentity {
            pid,
            start_marker: crate::observation::ProcessStartMarker::linux(55)
                .expect("test marker is nonzero"),
        }),
        ipv6_scope: None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn root_turning_protected_between_confirmation_and_freeze_refuses_with_exit_6() {
    // The confirmed row has no readable name, so identity revalidation
    // cannot compare names. Between confirmation and execution the root
    // execs into a protected name with the same PID and start marker. The fresh
    // root-protection gate must refuse before any stop.
    let rows = vec![nameless_row(3000, 18_422)];
    let confirmation_snapshot = vec![tree_info(18_422, Some(500), "node")];
    let execed_snapshot = vec![TreeProcessInfo {
        pid: 18_422,
        parent_pid: Some(500),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some("postgres".to_owned()),
        start_time_marker: crate::observation::ProcessStartMarker::linux(18_422).ok(),
        owner_uid: None,
        process_group: None,
    }];
    let config = Config {
        protected_processes: vec!["postgres".to_owned()],
        ..Config::default()
    };
    let mut ops = RecordingTreeOps::new(vec![confirmation_snapshot, execed_snapshot]);

    let reason = run_tree_kill_with(
        &KillArgs {
            pid: Some(18_422),
            port: None,
            force: false,
            yes: false,
            tree: true,
            group: false,
        },
        &config,
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut confirm_tree_prompt,
            collect_kill_ports: &mut || Ok(rows.clone()),
            collect_ports: &mut || Ok(rows.clone()),
        },
    );

    assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    assert!(ops.stops.is_empty(), "refusal must precede any stop");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn completed_protected_confirmation_passes_the_root_protection_gate() {
    // The inverse of the guard: a protected root whose two-step
    // confirmation was completed must execute, not be re-refused.
    // `cli::run` marks entries against the protected list before resolving
    // targets, so the test input must arrive marked the same way.
    let mut rows = vec![entry_with_pid(
        3000,
        Some(18_422),
        Protocol::Tcp,
        "postgres",
    )];
    crate::protection::mark_protected(&mut rows, &["postgres".to_owned()]);
    let snapshot = vec![TreeProcessInfo {
        pid: 18_422,
        parent_pid: Some(500),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some("postgres".to_owned()),
        // Matches the confirmed context marker from `no_context`.
        start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
        owner_uid: None,
        process_group: None,
    }];
    let config = Config {
        protected_processes: vec!["postgres".to_owned()],
        ..Config::default()
    };
    let mut ops = RecordingTreeOps::new(vec![snapshot]);
    let mut prompts = 0;
    let mut authority_collections = 0;
    let mut visibility_polls = 0;

    let reason = run_tree_kill_with(
        &KillArgs {
            pid: Some(18_422),
            port: None,
            force: false,
            yes: false,
            tree: true,
            group: false,
        },
        &config,
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut |_target: &KillTarget, _tree: &ProcessTreeTarget, _requirement| {
                prompts += 1;
                Ok(true)
            },
            collect_kill_ports: &mut || {
                authority_collections += 1;
                Ok(rows.clone())
            },
            collect_ports: &mut || {
                visibility_polls += 1;
                Ok(Vec::new())
            },
        },
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(prompts, 2, "protected root asks for PID/name and the word");
    assert_eq!(authority_collections, 1);
    assert_eq!(visibility_polls, 1);
    assert_eq!(ops.stops, vec![18_422]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn grouped_info(pid: u32, parent_pid: Option<u32>, name: &str, group: u32) -> TreeProcessInfo {
    TreeProcessInfo {
        owner_uid: None,
        process_group: Some(group),
        ..tree_info(pid, parent_pid, name)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_target(
    infos: &[TreeProcessInfo],
    root_pid: u32,
    protected_names: &[String],
) -> crate::tree::ProcessGroupTarget {
    crate::tree::plan_process_group(root_pid, infos, protected_names, Platform::Linux, 512)
        .expect("test group root must be present")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn kill_pid_group(pid: u32, yes: bool) -> KillArgs {
    KillArgs {
        pid: Some(pid),
        port: None,
        force: false,
        yes,
        tree: false,
        group: true,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn kill_port_group(port: u16) -> KillArgs {
    KillArgs {
        pid: None,
        port: Some(port),
        force: false,
        yes: false,
        tree: false,
        group: true,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn group_confirmation_gates_yes_by_size_warnings_and_protection() {
    let root = kill_target_from_tree_info(&grouped_info(100, Some(500), "node", 42), &[]);

    let tiny = group_target(&[grouped_info(100, Some(500), "node", 42)], 100, &[]);
    assert_eq!(
        group_confirmation(&root, &tiny, KillMode::Terminate, true),
        TreeConfirmDecision::Skip,
    );
    assert_eq!(
        group_confirmation(&root, &tiny, KillMode::Terminate, false),
        TreeConfirmDecision::PromptWord("group"),
    );
    assert_eq!(
        group_confirmation(&root, &tiny, KillMode::Force, false),
        TreeConfirmDecision::PromptWord("force"),
    );

    let mut big_infos = vec![grouped_info(100, Some(500), "node", 42)];
    for pid in 0..u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32") {
        big_infos.push(grouped_info(9_000 + pid, Some(500), "worker", 42));
    }
    let big = group_target(&big_infos, 100, &[]);
    assert!(big.members().len() > GROUP_YES_SKIP_MAX_PROCESSES);
    assert_eq!(
        group_confirmation(&root, &big, KillMode::Terminate, true),
        TreeConfirmDecision::PromptWord("group"),
    );

    let with_system = group_target(
        &[
            grouped_info(100, Some(500), "node", 42),
            grouped_info(101, Some(1), "systemd", 42),
        ],
        100,
        &[],
    );
    assert_eq!(
        group_confirmation(&root, &with_system, KillMode::Terminate, true),
        TreeConfirmDecision::PromptWord("group"),
    );

    let with_other_uid = group_target(
        &[
            grouped_info(100, Some(500), "node", 42),
            TreeProcessInfo {
                process_group: Some(42),
                ..tree_info_owned_by_other_uid(101, Some(500), "worker")
            },
        ],
        100,
        &[],
    );
    assert_eq!(
        group_confirmation(&root, &with_other_uid, KillMode::Terminate, true),
        TreeConfirmDecision::PromptWord("group"),
    );

    let protected_names = vec!["postgres".to_owned()];
    let protected_root_target = kill_target_from_tree_info(
        &grouped_info(100, Some(500), "postgres", 42),
        &protected_names,
    );
    let protected = group_target(
        &[grouped_info(100, Some(500), "postgres", 42)],
        100,
        &protected_names,
    );
    assert_eq!(
        group_confirmation(
            &protected_root_target,
            &protected,
            KillMode::Terminate,
            true
        ),
        TreeConfirmDecision::RefuseProtectedYes,
    );
    assert_eq!(
        group_confirmation(
            &protected_root_target,
            &protected,
            KillMode::Terminate,
            false
        ),
        TreeConfirmDecision::PromptProtectedThenWord("group"),
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn group_kill_refuses_kernel_domain_roots_without_touching_processes() {
    // The root exists but has no targetable group (pgid 0 maps to None):
    // refuse before any prompt, freeze, or signal.
    let snapshot = vec![tree_info(18_422, Some(500), "node")];

    let reason = run_group_kill_with(
        &kill_pid_group(18_422, false),
        &Config::default(),
        &[],
        KillMode::Terminate,
        &mut PreviewOnlyTreeOps(snapshot),
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut panic_tree_prompt,
            collect_kill_ports: &mut || panic!("untargetable group must not re-collect ports"),
            collect_ports: &mut || panic!("untargetable group must not re-collect ports"),
        },
    );

    assert_eq!(reason, ExitReason::Failure);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn group_losing_readable_owner_during_revalidation_exits_permission_denied() {
    let rows = vec![entry(3000)];
    let preview = vec![grouped_info(18_422, Some(500), "node", 42)];
    let mut ops = RecordingTreeOps::new(vec![preview]);
    let events = Rc::clone(&ops.events);
    let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

    let reason = run_group_kill_with(
        &KillArgs {
            pid: Some(18_422),
            port: None,
            force: false,
            yes: false,
            tree: false,
            group: true,
        },
        &Config::default(),
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut confirm_tree_prompt,
            collect_kill_ports: &mut || {
                events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                Ok(fresh_rows.clone())
            },
            collect_ports: &mut || Ok(Vec::new()),
        },
    );

    assert_eq!(reason, ExitReason::PermissionDenied);
    assert_eq!(
        &*events.borrow(),
        &[
            RecordingTreeEvent::Pin(18_422),
            RecordingTreeEvent::CollectPorts,
        ],
    );
    assert!(ops.stops.is_empty(), "refusal must precede any stop");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn port_selected_group_success_separates_authority_from_visibility_polling() {
    // A port-selected root plus an already-reparented member: one word
    // prompt, then authority is re-collected before delivery and visibility
    // is polled only after successful delivery.
    let rows = vec![entry(3000)];
    let root = TreeProcessInfo {
        start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
        ..grouped_info(18_422, Some(500), "node", 42)
    };
    let snapshot = vec![root, grouped_info(17_000, Some(1), "orphan", 42)];
    let mut ops = RecordingTreeOps::new(vec![snapshot]);
    let mut prompts = 0;
    let mut authority_collections = 0;
    let mut visibility_polls = 0;

    let reason = run_group_kill_with(
        &kill_port_group(3000),
        &Config::default(),
        &entry_views(&rows),
        KillMode::Terminate,
        &mut ops,
        TreeKillIo {
            collect_context: &mut no_context,
            prompt: &mut |_target: &KillTarget, members: &ProcessTreeTarget, _requirement| {
                prompts += 1;
                assert_eq!(members.len(), 2, "the prompt must name the full count");
                Ok(true)
            },
            collect_kill_ports: &mut || {
                authority_collections += 1;
                Ok(rows.clone())
            },
            collect_ports: &mut || {
                visibility_polls += 1;
                Ok(Vec::new())
            },
        },
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(prompts, 1, "an unprotected group asks for the word once");
    assert_eq!(authority_collections, 1);
    assert_eq!(visibility_polls, 1);
    assert_eq!(
        ops.stops,
        vec![18_422, 17_000],
        "the confirmed root freezes before the members",
    );
}
