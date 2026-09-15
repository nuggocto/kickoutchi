use crate::model::PortEntryView;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::{
    FrozenNode, GROUP_YES_SKIP_MAX_PROCESSES, GroupPlanError, MAX_GROUP_PROCESSES,
    MAX_TREE_PROCESSES, PROCESS_TREE_INDEX_MAX, ProcessTreeIndex, ScopeAuthorization,
    TreeKillOutcome, TreePlanError, TreeProcessInfo, TreeProcessOps, TreeRefusalClass,
    TreeSignalResult, TreeStopError, TreeStopResult, execute_group_kill, execute_tree_kill,
    plan_process_group, plan_process_tree, stop_deadline_expired, verify_frozen_identities,
};
use crate::model::{PermissionStatus, Platform, PortEntry, ProcessContext, Protocol, SocketState};
use crate::process::{KillMode, KillTarget, UnsafePidReason};
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Stop(u32),
    Cont(u32),
    Deliver(u32, KillMode),
}

#[test]
fn refusal_semantics_have_one_stable_class_and_cause() {
    let cases = [
        (
            TreeKillOutcome::RootAlreadyExited,
            TreeRefusalClass::NoMatch,
            "the root process already exited",
        ),
        (
            TreeKillOutcome::PermissionDenied { pid: 101 },
            TreeRefusalClass::PermissionDenied,
            "permission denied for PID 101",
        ),
        (
            TreeKillOutcome::TargetChanged { pid: 102 },
            TreeRefusalClass::Failure,
            "process identity changed at PID 102",
        ),
        (
            TreeKillOutcome::Truncated { limit: 256 },
            TreeRefusalClass::Failure,
            "the process scope exceeded 256 members",
        ),
        (
            TreeKillOutcome::SweepPassLimit { limit: 8 },
            TreeRefusalClass::Failure,
            "the process scope did not converge after 8 freeze passes",
        ),
        (
            TreeKillOutcome::UnsafePid {
                pid: 103,
                reason: UnsafePidReason::CurrentProcess,
            },
            TreeRefusalClass::Failure,
            "unsafe PID 103: Kickoutchi cannot terminate itself",
        ),
        (
            TreeKillOutcome::ProtectedDescendant {
                pid: 104,
                name: Some("postgres".to_owned()),
            },
            TreeRefusalClass::ProtectedNeedsConfirmation,
            "protected process PID 104 (postgres) entered the scope",
        ),
        (
            TreeKillOutcome::ProtectedRoot {
                pid: 105,
                name: Some("sshd".to_owned()),
            },
            TreeRefusalClass::ProtectedNeedsConfirmation,
            "protected root PID 105 (sshd)",
        ),
        (
            TreeKillOutcome::FreshConfirmationRequired,
            TreeRefusalClass::Failure,
            "the process scope changed after confirmation",
        ),
        (
            TreeKillOutcome::OwnershipUnavailable { pid: 106 },
            TreeRefusalClass::PermissionDenied,
            "ownership for PID 106 became unavailable",
        ),
        (
            TreeKillOutcome::PartialMetadata { pid: 107 },
            TreeRefusalClass::Failure,
            "process metadata for PID 107 was incomplete",
        ),
        (
            TreeKillOutcome::SnapshotFailed("snapshot unavailable".to_owned()),
            TreeRefusalClass::Failure,
            "snapshot unavailable",
        ),
    ];

    for (outcome, class, cause) in cases {
        assert_eq!(outcome.refusal_class(), Some(class));
        assert_eq!(outcome.failure_cause_text(), cause);
    }
}

/// A scripted process table plus a recorded call log.
///
/// `snapshots` are returned in order; the last one repeats for any further
/// reads, so a test only lists as many distinct tables as its scenario needs.
struct FakeOps {
    snapshots: Vec<Vec<TreeProcessInfo>>,
    next: usize,
    events: Vec<Event>,
    deny_stop: Vec<u32>,
    pre_stopped: Vec<u32>,
    uncertain_stop: Vec<u32>,
    stop_clock: std::time::Instant,
    stop_elapsed: std::time::Duration,
    stop_deadlines: Vec<std::time::Instant>,
    missing_stop: Vec<u32>,
    missing_deliver: Vec<u32>,
    deny_deliver: Vec<u32>,
    deny_cont: Vec<u32>,
    missing_cont: Vec<u32>,
    rollback_markers_after_stop: HashMap<u32, Option<crate::observation::ProcessStartMarker>>,
    prepared_thaws: HashMap<u32, Option<crate::observation::ProcessStartMarker>>,
    fresh_evidence: HashMap<u32, Result<FreshProcessEvidence, ProcessEvidenceError>>,
}

impl FakeOps {
    fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
        Self {
            snapshots,
            next: 0,
            events: Vec::new(),
            deny_stop: Vec::new(),
            pre_stopped: Vec::new(),
            uncertain_stop: Vec::new(),
            stop_clock: std::time::Instant::now(),
            stop_elapsed: std::time::Duration::ZERO,
            stop_deadlines: Vec::new(),
            missing_stop: Vec::new(),
            missing_deliver: Vec::new(),
            deny_deliver: Vec::new(),
            deny_cont: Vec::new(),
            missing_cont: Vec::new(),
            rollback_markers_after_stop: HashMap::new(),
            prepared_thaws: HashMap::new(),
            fresh_evidence: HashMap::new(),
        }
    }

    fn delivered_pids(&self) -> Vec<u32> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Deliver(pid, _) => Some(*pid),
                _ => None,
            })
            .collect()
    }
}

impl TreeProcessOps for FakeOps {
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        let index = self.next.min(self.snapshots.len().saturating_sub(1));
        self.next += 1;
        Ok(self.snapshots.get(index).cloned().unwrap_or_default())
    }

    fn stop(&mut self, pid: u32, deadline: std::time::Instant) -> TreeStopResult {
        self.stop_deadlines.push(deadline);
        self.stop_clock += self.stop_elapsed;
        if self.stop_clock >= deadline {
            return stop_deadline_expired();
        }
        self.events.push(Event::Stop(pid));
        if self.deny_stop.contains(&pid) {
            return TreeStopResult::Failed {
                cleanup_required: false,
                rollback_start_time_marker: None,
                error: TreeStopError::PermissionDenied,
            };
        }
        if self.missing_stop.contains(&pid) {
            return TreeStopResult::NotFound;
        }
        if self.uncertain_stop.contains(&pid) {
            return TreeStopResult::Failed {
                cleanup_required: true,
                rollback_start_time_marker: self
                    .rollback_markers_after_stop
                    .get(&pid)
                    .copied()
                    .flatten(),
                error: TreeStopError::ObservationFailed(
                    "stopped-state observation failed".to_owned(),
                ),
            };
        }
        TreeStopResult::Stopped {
            transitioned: !self.pre_stopped.contains(&pid),
        }
    }

    fn stop_acknowledgement_now(&self) -> std::time::Instant {
        self.stop_clock
    }

    fn rollback_identity_after_stop(
        &mut self,
        pid: u32,
        prior_marker: Option<crate::observation::ProcessStartMarker>,
    ) -> Option<crate::observation::ProcessStartMarker> {
        self.rollback_markers_after_stop
            .get(&pid)
            .copied()
            .unwrap_or(prior_marker)
    }

    fn cont(&mut self, pid: u32) -> TreeSignalResult {
        self.events.push(Event::Cont(pid));
        if self.deny_cont.contains(&pid) {
            TreeSignalResult::Denied
        } else if self.missing_cont.contains(&pid) {
            TreeSignalResult::NotFound
        } else {
            TreeSignalResult::Delivered
        }
    }

    fn prepare_thaw(&mut self, pid: u32, marker: Option<crate::observation::ProcessStartMarker>) {
        self.prepared_thaws.insert(pid, marker);
    }

    fn prepare_delivery(
        &mut self,
        _pid: u32,
        _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
    ) -> TreeSignalResult {
        TreeSignalResult::Delivered
    }

    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        if let Some(evidence) = self.fresh_evidence.get(&pid) {
            return evidence.clone();
        }
        let snapshot = self
            .snapshot()
            .map_err(|_| ProcessEvidenceError::Missing { pid })?;
        let info = snapshot
            .iter()
            .find(|info| info.pid == pid)
            .ok_or(ProcessEvidenceError::Missing { pid })?;
        Ok(FreshProcessEvidence {
            pid,
            start_marker: info
                .start_time_marker
                .ok_or(ProcessEvidenceError::Missing { pid })?,
            name: info
                .process_name
                .clone()
                .ok_or(ProcessEvidenceError::NameMissing { pid })?,
        })
    }

    fn deliver(&mut self, pid: u32, mode: KillMode) -> TreeSignalResult {
        self.events.push(Event::Deliver(pid, mode));
        if self.missing_deliver.contains(&pid) {
            return TreeSignalResult::NotFound;
        }
        if self.deny_deliver.contains(&pid) {
            return TreeSignalResult::Denied;
        }
        TreeSignalResult::Delivered
    }
}

#[test]
fn refusal_prepares_verified_identity_before_each_thaw() {
    let marker = crate::observation::ProcessStartMarker::linux(55).ok();
    let frozen = [FrozenNode {
        pid: 42,
        parent_pid: None,
        parent_process_name: None,
        process_name: Some("node".to_owned()),
        owner_uid: None,
        start_time_marker: marker,
        rollback_start_time_marker: marker,
        resume_on_cleanup: true,
        depth: 0,
    }];
    let mut ops = FakeOps::new(Vec::new());

    assert!(super::thaw_all(&frozen, &mut ops).is_empty());
    assert_eq!(ops.prepared_thaws.get(&42), Some(&marker));
    assert_eq!(ops.events, [Event::Cont(42)]);
}

/// A member that vanished under the freeze leaves nothing stopped, so it
/// must not be named as a thaw failure because that PID no longer exists.
/// Only a refused `SIGCONT` is a real failure.
/// This pins the same `Denied`-only rule the delivery paths and the
/// single-process `outcome_after_thaw` already use.
#[test]
fn refusal_reports_only_denied_continuations_as_thaw_failures() {
    let marker = crate::observation::ProcessStartMarker::linux(55).ok();
    let node = |pid| FrozenNode {
        pid,
        parent_pid: None,
        parent_process_name: None,
        process_name: Some("node".to_owned()),
        owner_uid: None,
        start_time_marker: marker,
        rollback_start_time_marker: marker,
        resume_on_cleanup: true,
        depth: 0,
    };
    let frozen = [node(42), node(43)];
    let mut ops = FakeOps::new(Vec::new());
    ops.missing_cont.push(42);
    ops.deny_cont.push(43);

    assert_eq!(super::thaw_all(&frozen, &mut ops), [43]);
    assert_eq!(ops.prepared_thaws.get(&42), Some(&marker));
    assert_eq!(ops.prepared_thaws.get(&43), Some(&marker));
    // Both members are still attempted, deepest-first, even though only one
    // is reported.
    assert_eq!(ops.events, [Event::Cont(43), Event::Cont(42)]);
}

#[test]
fn refusal_does_not_resume_members_that_were_already_stopped() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "postgres", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
    ops.pre_stopped.push(101);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(
        outcome,
        TreeKillOutcome::ProtectedDescendant { pid: 101, .. }
    ));
    assert!(ops.events.contains(&Event::Cont(100)));
    assert!(!ops.events.contains(&Event::Cont(101)));
}

#[test]
fn later_refusal_does_not_resume_a_root_that_was_already_stopped() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "postgres", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
    ops.pre_stopped.push(100);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(
        outcome,
        TreeKillOutcome::ProtectedDescendant { pid: 101, .. }
    ));
    assert!(ops.events.contains(&Event::Cont(101)));
    assert!(!ops.events.contains(&Event::Cont(100)));
}

#[test]
fn successful_terminate_resumes_a_previously_stopped_member_after_delivery() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
    ops.pre_stopped.push(101);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
    let delivered = ops
        .events
        .iter()
        .position(|event| *event == Event::Deliver(101, KillMode::Terminate))
        .expect("child receives SIGTERM");
    let continued = ops
        .events
        .iter()
        .position(|event| *event == Event::Cont(101))
        .expect("child is resumed so pending SIGTERM can run");
    assert!(delivered < continued);
}

#[test]
fn failed_stopped_state_observation_still_rolls_back_submitted_stop() {
    let root = root_target(100, "root", 10);
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "root", 10)]]);
    ops.uncertain_stop.push(100);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::SnapshotFailed("stopped-state observation failed".to_owned())
    );
    assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
    assert!(ops.delivered_pids().is_empty());
}

#[test]
fn identity_change_after_stop_retains_cleanup_for_the_observed_replacement() {
    let root = root_target(100, "root", 10);
    let replacement = crate::observation::ProcessStartMarker::linux(999).ok();
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "root", 10)]]);
    ops.uncertain_stop.push(100);
    ops.rollback_markers_after_stop.insert(100, replacement);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Macos,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::SnapshotFailed("stopped-state observation failed".to_owned())
    );
    assert_eq!(ops.prepared_thaws.get(&100), Some(&replacement));
    assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
}

#[test]
fn stop_acknowledgements_share_one_operation_deadline() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "first", 11),
        info(102, Some(100), "second", 12),
    ];
    let mut ops = FakeOps::new(vec![snapshot]);
    ops.stop_elapsed = std::time::Duration::from_millis(100);
    let expected_deadline = ops.stop_clock + crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;

    let outcome = execute_tree_kill(
        &root,
        KillMode::Force,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
    assert_eq!(
        ops.stop_deadlines,
        [expected_deadline, expected_deadline, expected_deadline]
    );
}

#[test]
fn pre_signal_delay_past_shared_deadline_sends_no_stop() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![info(100, Some(1), "root", 10)];
    let mut ops = FakeOps::new(vec![snapshot]);
    ops.stop_elapsed = crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;
    let expected_deadline = ops.stop_clock + crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::SnapshotFailed(
            "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned()
        )
    );
    assert!(
        ops.events.is_empty(),
        "SIGSTOP must not be sent at the deadline"
    );
    assert_eq!(ops.stop_deadlines, [expected_deadline]);
}

#[test]
fn root_delay_consumes_shared_deadline_before_descendant_stop() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot]);
    ops.stop_elapsed = std::time::Duration::from_millis(250);
    let expected_deadline = ops.stop_clock + crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::SnapshotFailed(
            "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned()
        )
    );
    assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
    assert_eq!(ops.stop_deadlines, [expected_deadline, expected_deadline]);
}

#[test]
fn scoped_thaw_failure_text_retains_the_primary_failure() {
    let outcome = TreeKillOutcome::ThawFailed {
        pids: vec![100],
        cause: Box::new(TreeKillOutcome::PermissionDenied { pid: 101 }),
    };

    assert_eq!(
        outcome.failure_cause_text(),
        "permission denied for PID 101; cleanup could not continue PID(s) 100"
    );
}

#[test]
fn stopped_replacement_uses_immediate_identity_when_later_member_refuses() {
    let root = root_target(100, "root", 10);
    let root_snapshot = vec![info(100, None, "root", 10)];
    let mut partial = info(102, Some(100), "partial", 12);
    partial.start_time_marker = None;
    let sweep_snapshot = vec![
        info(100, None, "root", 10),
        info(101, Some(100), "child", 11),
        partial,
    ];
    let replacement_marker = crate::observation::ProcessStartMarker::linux(777).ok();
    let mut ops = FakeOps::new(vec![root_snapshot, sweep_snapshot]);
    ops.rollback_markers_after_stop
        .insert(101, replacement_marker);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::PartialMetadata { pid: 102 });
    assert_eq!(ops.prepared_thaws.get(&101), Some(&replacement_marker));
    assert_eq!(
        ops.events,
        [
            Event::Stop(100),
            Event::Stop(101),
            Event::Cont(101),
            Event::Cont(100),
        ]
    );
    assert!(ops.delivered_pids().is_empty());
}

fn info(pid: u32, parent: Option<u32>, name: &str, marker: u64) -> TreeProcessInfo {
    TreeProcessInfo {
        pid,
        parent_pid: parent,
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some(name.into()),
        start_time_marker: crate::observation::ProcessStartMarker::linux(marker).ok(),
        owner_uid: None,
        process_group: None,
    }
}

#[test]
fn process_tree_index_accepts_exact_limit_and_rejects_max_plus_one() {
    let exact = vec![
        info(3, Some(1), "three", 3),
        info(1, None, "one", 1),
        info(2, Some(1), "two", 2),
    ];
    let index = ProcessTreeIndex::new(&exact, 3).expect("exact index limit is accepted");
    assert_eq!(index.process(2).map(|process| process.pid), Some(2));
    assert_eq!(
        index
            .children(1)
            .iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>(),
        [2, 3]
    );

    let error = ProcessTreeIndex::new(&exact, 2).expect_err("max plus one is rejected");
    assert_eq!(error, TreePlanError::SnapshotLimitExceeded { limit: 2 });
}

#[test]
fn production_index_bound_is_wired_through_planning_and_final_verification() {
    let mut exact = Vec::with_capacity(PROCESS_TREE_INDEX_MAX + 1);
    exact.push(info(2, None, "root", 2));
    for offset in 1..PROCESS_TREE_INDEX_MAX {
        let pid = u32::try_from(offset + 2).expect("production index bound fits u32");
        exact.push(TreeProcessInfo {
            pid,
            parent_pid: None,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: None,
            start_time_marker: None,
            owner_uid: None,
            process_group: None,
        });
    }

    let preview = plan_process_tree(2, &exact, &[], Platform::Linux, MAX_TREE_PROCESSES)
        .expect("exact production index maximum plans");
    assert_eq!(preview.len(), 1);
    assert!(!preview.truncated());

    let root = FrozenNode::from_info(&exact[0], 0);
    let mut frozen = [root];
    verify_frozen_identities(&mut frozen, super::SweepScope::Tree, &exact)
        .expect("exact production index maximum verifies");

    exact.push(TreeProcessInfo {
        pid: u32::MAX,
        parent_pid: None,
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: None,
        start_time_marker: None,
        owner_uid: None,
        process_group: None,
    });
    assert_eq!(
        plan_process_tree(2, &exact, &[], Platform::Linux, MAX_TREE_PROCESSES),
        Err(TreePlanError::SnapshotLimitExceeded {
            limit: PROCESS_TREE_INDEX_MAX
        })
    );
    assert!(matches!(
        verify_frozen_identities(&mut frozen, super::SweepScope::Tree, &exact),
        Err(TreeKillOutcome::SnapshotFailed(message))
            if message.contains("process index construction failed")
    ));
}

/// Authorization for the common test case: no protected-root confirmation
/// completed, and the typed-word prompt actually answered (not skipped).
fn auth() -> ScopeAuthorization {
    ScopeAuthorization::TypedWordConfirmed
}

fn root_target(pid: u32, name: &str, marker: u64) -> KillTarget {
    let entry = PortEntry {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        pid: Some(pid),
        process_name: Some(name.into()),
        executable_path: None,
        command_line: None,
        parent_pid: None,
        parent_process_name: None,
        protected: false,
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        process_identity: Some(crate::observation::ProcessIdentity {
            pid,
            start_marker: crate::observation::ProcessStartMarker::linux(marker)
                .expect("test marker is nonzero"),
        }),
        ipv6_scope: None,
    };
    let context = ProcessContext {
        process_start_time_marker: crate::observation::ProcessStartMarker::linux(marker).ok(),
        ..ProcessContext::default()
    };
    KillTarget::from_entries(pid, [PortEntryView::from(&entry)], Some(&context))
}

#[test]
fn preview_builds_depth_ordered_tree_and_flags_policy() {
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "worker", 11),
        info(102, Some(101), "postgres", 12),
    ];

    let tree = plan_process_tree(
        100,
        &snapshot,
        &["postgres".to_owned()],
        Platform::Linux,
        256,
    )
    .expect("root is present");

    assert_eq!(tree.len(), 3);
    assert_eq!(tree.root().map(|node| node.pid), Some(100));
    // The protected descendant is discoverable for the pre-flight refusal.
    assert_eq!(
        tree.protected_descendants().map(|node| node.pid).next(),
        Some(102),
    );
    assert!(!tree.truncated());
}

#[test]
fn root_protection_gate_requires_completed_confirmation() {
    use super::root_protection_outcome;

    let protected_root = plan_process_tree(
        100,
        &[info(100, Some(500), "postgres", 10)],
        &["postgres".to_owned()],
        Platform::Linux,
        256,
    )
    .expect("root present");
    // Without the completed protected confirmation, a protected root
    // refuses and names itself; with it, the same tree proceeds.
    assert_eq!(
        root_protection_outcome(&protected_root, false),
        Err(TreeKillOutcome::ProtectedRoot {
            pid: 100,
            name: Some("postgres".to_owned()),
        }),
    );
    assert_eq!(root_protection_outcome(&protected_root, true), Ok(()));

    let plain_root = plan_process_tree(
        100,
        &[info(100, Some(500), "node", 10)],
        &["postgres".to_owned()],
        Platform::Linux,
        256,
    )
    .expect("root present");
    assert_eq!(root_protection_outcome(&plain_root, false), Ok(()));
}

#[test]
fn preview_truncates_at_the_limit_without_erroring() {
    let mut snapshot = vec![info(100, Some(1), "root", 10)];
    for pid in 200..210 {
        snapshot.push(info(pid, Some(100), "child", u64::from(pid)));
    }

    let tree = plan_process_tree(100, &snapshot, &[], Platform::Linux, 4).expect("root is present");

    assert_eq!(tree.len(), 4);
    assert!(tree.truncated());
}

#[test]
fn single_root_terminates_with_term_then_cont() {
    let root = root_target(100, "node", 10);
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 1);
    assert_eq!(report.delivered, 1);
    assert_eq!(
        ops.events,
        vec![
            Event::Stop(100),
            Event::Deliver(100, KillMode::Terminate),
            Event::Cont(100),
        ],
    );
}

#[test]
fn spawner_converges_and_kills_leaves_first() {
    let root = root_target(100, "root", 10);
    // The child (101) spawns a grandchild (102) that only appears in a later
    // sweep. The fixed point must still catch it.
    let base = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
    ];
    let grown = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
        info(102, Some(101), "grandchild", 12),
    ];
    let mut ops = FakeOps::new(vec![
        base.clone(),  // verify root
        base,          // sweep pass 1: discovers 101
        grown.clone(), // sweep pass 2: discovers 102
        grown.clone(), // sweep pass 3: no new -> converged
        grown,         // final identity verify
    ]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 3);
    assert_eq!(ops.delivered_pids(), vec![102, 101, 100]);
}

#[test]
fn force_mode_kills_without_continue() {
    let root = root_target(100, "node", 10);
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Force,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
    assert_eq!(
        ops.events,
        vec![Event::Stop(100), Event::Deliver(100, KillMode::Force)],
    );
}

#[test]
fn stopped_root_replacement_is_refused_but_prepared_for_rollback() {
    let root = root_target(100, "node", 10);
    // Same PID, different start marker: a reused PID. Refuse, and thaw.
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 999)]]);
    ops.rollback_markers_after_stop
        .insert(100, crate::observation::ProcessStartMarker::linux(999).ok());

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 100 });
    assert_eq!(ops.events, vec![Event::Stop(100), Event::Cont(100)]);
    assert_eq!(
        ops.prepared_thaws.get(&100),
        Some(&crate::observation::ProcessStartMarker::linux(999).ok())
    );
    assert!(ops.delivered_pids().is_empty());
}

#[test]
fn all_stopped_descendant_replacements_are_prepared_before_first_refusal() {
    let root = root_target(100, "root", 10);
    let stable = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "first-child", 11),
        info(102, Some(100), "second-child", 12),
    ];
    // Both stops landed on replacements. Validation fails on 101 first,
    // but rollback must already retain both immediately observed identities.
    let drifted = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "first-child", 777),
        info(102, Some(100), "second-child", 888),
    ];
    let mut ops = FakeOps::new(vec![
        stable.clone(), // verify root
        stable,         // sweep pass 1: discovers both children
        drifted,        // sweep pass 2: converged and verifies drift
    ]);
    ops.rollback_markers_after_stop
        .insert(101, crate::observation::ProcessStartMarker::linux(777).ok());
    ops.rollback_markers_after_stop
        .insert(102, crate::observation::ProcessStartMarker::linux(888).ok());

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 101 });
    assert!(ops.delivered_pids().is_empty());
    assert_eq!(
        ops.prepared_thaws,
        HashMap::from([
            (100, crate::observation::ProcessStartMarker::linux(10).ok()),
            (101, crate::observation::ProcessStartMarker::linux(777).ok()),
            (102, crate::observation::ProcessStartMarker::linux(888).ok()),
        ])
    );
    assert_eq!(
        ops.events,
        vec![
            Event::Stop(100),
            Event::Stop(101),
            Event::Stop(102),
            Event::Cont(102),
            Event::Cont(101),
            Event::Cont(100)
        ],
    );
}

#[test]
fn protected_descendant_thaws_and_refuses() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "postgres", 11),
    ];
    let mut ops = FakeOps::new(vec![
        snapshot.clone(),
        snapshot.clone(),
        snapshot.clone(),
        snapshot,
    ]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::ProtectedDescendant {
            pid: 101,
            name: Some("postgres".to_owned()),
        },
    );
    assert!(ops.delivered_pids().is_empty());
    assert_eq!(
        ops.events,
        vec![
            Event::Stop(100),
            Event::Stop(101),
            Event::Cont(101),
            Event::Cont(100)
        ],
    );
}

#[test]
fn tree_thaw_failure_attempts_every_member_and_reports_survivors() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "postgres", 11),
    ];
    let mut ops = FakeOps::new(vec![
        snapshot.clone(),
        snapshot.clone(),
        snapshot.clone(),
        snapshot,
    ]);
    ops.deny_cont.extend([100, 101]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(
        outcome,
        TreeKillOutcome::ThawFailed { ref pids, .. } if pids == &[100, 101]
    ));
    assert!(ops.events.contains(&Event::Cont(100)));
    assert!(ops.events.contains(&Event::Cont(101)));
    assert!(ops.delivered_pids().is_empty());
}

#[test]
fn group_thaw_failure_is_typed_and_visible() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        ginfo(100, Some(1), "root", 10, 77),
        ginfo(101, Some(1), "postgres", 11, 77),
    ];
    let mut ops = FakeOps::new(vec![
        snapshot.clone(),
        snapshot.clone(),
        snapshot.clone(),
        snapshot,
    ]);
    ops.deny_cont.push(101);

    let outcome = execute_group_kill(
        &root,
        77,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(
        outcome,
        TreeKillOutcome::ThawFailed { ref pids, .. } if pids == &[101]
    ));
    assert!(ops.events.contains(&Event::Cont(100)));
    assert!(ops.events.contains(&Event::Cont(101)));
}

#[test]
fn cap_exceeded_during_freeze_thaws_and_refuses() {
    let root = root_target(100, "root", 10);
    let mut snapshot = vec![info(100, Some(1), "root", 10)];
    let child_pid_start = std::process::id()
        .checked_add(1_000)
        .expect("test PID range must fit u32");
    let child_pid_end = child_pid_start
        .checked_add(u32::try_from(MAX_TREE_PROCESSES).unwrap() + 5)
        .expect("bounded test PID range must fit u32");
    for pid in child_pid_start..child_pid_end {
        snapshot.push(info(pid, Some(100), "child", u64::from(pid)));
    }
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::Truncated {
            limit: MAX_TREE_PROCESSES,
        },
    );
    assert!(ops.delivered_pids().is_empty());
    // Everything stopped so far was thawed. Check the same PIDs, not just the
    // same number of signals.
    let mut stopped: Vec<u32> = ops
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Stop(pid) => Some(*pid),
            _ => None,
        })
        .collect();
    let mut continued: Vec<u32> = ops
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Cont(pid) => Some(*pid),
            _ => None,
        })
        .collect();
    stopped.sort_unstable();
    continued.sort_unstable();
    assert!(
        !stopped.is_empty(),
        "the freeze must stop members before refusing"
    );
    assert_eq!(stopped, continued);
}

#[test]
fn unsafe_descendant_refuses_before_stop_and_thaws_root() {
    let root = root_target(100, "root", 10);
    let unsafe_pid = std::process::id();
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(unsafe_pid, Some(100), "kickoutchi", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(outcome, TreeKillOutcome::UnsafePid { pid, .. } if pid == unsafe_pid));
    assert_eq!(ops.events, vec![Event::Stop(100), Event::Cont(100)]);
}

#[test]
fn missing_descendant_start_marker_thaws_and_refuses() {
    let root = root_target(100, "root", 10);
    let mut child = info(101, Some(100), "child", 11);
    child.start_time_marker = None;
    let snapshot = vec![info(100, Some(1), "root", 10), child];
    let mut ops = FakeOps::new(vec![
        snapshot.clone(),
        snapshot.clone(),
        snapshot.clone(),
        snapshot,
    ]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::PartialMetadata { pid: 101 });
    assert!(ops.delivered_pids().is_empty());
    assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
}

#[test]
fn markerless_descendant_refuses_before_stop_and_thaws_prior_members() {
    let root = root_target(100, "root", 10);
    let mut markerless = info(102, Some(101), "grandchild", 12);
    markerless.start_time_marker = None;
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
        markerless,
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::PartialMetadata { pid: 102 });
    assert_eq!(
        ops.events,
        [
            Event::Stop(100),
            Event::Stop(101),
            Event::Cont(101),
            Event::Cont(100),
        ]
    );
    assert_eq!(
        ops.prepared_thaws,
        HashMap::from([
            (100, crate::observation::ProcessStartMarker::linux(10).ok()),
            (101, crate::observation::ProcessStartMarker::linux(11).ok()),
        ])
    );
}

#[test]
fn force_delivery_denial_thaws_the_denied_member() {
    let root = root_target(100, "node", 10);
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);
    ops.deny_deliver.push(100);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Force,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion report, got {outcome:?}");
    };
    assert_eq!(report.denied, vec![100]);
    assert_eq!(
        ops.events,
        vec![
            Event::Stop(100),
            Event::Deliver(100, KillMode::Force),
            Event::Cont(100)
        ],
    );
}

#[test]
fn post_delivery_thaw_failure_is_retained_in_the_completion_report() {
    let root = root_target(100, "node", 10);
    let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);
    ops.deny_cont.push(100);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("delivery completed and cleanup failure must remain reportable");
    };
    assert_eq!(report.delivered, 1);
    assert!(report.denied.is_empty());
    assert_eq!(report.thaw_failed, vec![100]);
    assert_eq!(
        ops.events,
        vec![
            Event::Stop(100),
            Event::Deliver(100, KillMode::Terminate),
            Event::Cont(100)
        ]
    );
}

#[test]
fn final_delivery_not_found_is_reported_separately_from_sent_signals() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot]);
    ops.missing_deliver.push(101);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion report, got {outcome:?}");
    };
    assert_eq!(report.total, 2);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.already_exited, 1);
    assert!(report.denied.is_empty());
}

#[test]
fn root_already_exited_sends_nothing() {
    let root = root_target(100, "node", 10);
    let mut ops = FakeOps::new(vec![vec![]]);
    ops.missing_stop.push(100);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::RootAlreadyExited);
    assert_eq!(ops.events, vec![Event::Stop(100)]);
}

#[test]
fn denied_descendant_stop_thaws_root_and_refuses() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
    ops.deny_stop.push(101);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::PermissionDenied { pid: 101 });
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.contains(&Event::Cont(100)));
}

/// `info` with a real process group, for group-scope scenarios.
fn ginfo(pid: u32, parent: Option<u32>, name: &str, marker: u64, group: u32) -> TreeProcessInfo {
    TreeProcessInfo {
        process_group: Some(group),
        ..info(pid, parent, name, marker)
    }
}

#[test]
fn group_plan_is_a_flat_member_set_with_the_root_first() {
    let snapshot = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(1), "orphan", 11, 42),
        ginfo(90, Some(1), "worker", 12, 42),
        ginfo(300, Some(1), "outsider", 13, 77),
        info(2, None, "kthreadd", 14),
    ];

    let group = plan_process_group(100, &snapshot, &[], Platform::Linux, 512)
        .expect("root is present with a group");

    assert_eq!(group.pgid(), 42);
    assert_eq!(group.members().len(), 3);
    assert_eq!(group.members().root().map(|node| node.pid), Some(100));
    let order: Vec<u32> = group
        .members()
        .preview_nodes(usize::MAX)
        .iter()
        .map(|node| node.pid)
        .collect();
    assert_eq!(order, vec![100, 90, 150]);
    assert!(!group.members().truncated());
}

#[test]
fn group_plan_refuses_missing_roots_and_untargetable_groups() {
    let kernel_rooted = vec![info(100, None, "kthread", 10)];
    assert_eq!(
        plan_process_group(100, &kernel_rooted, &[], Platform::Linux, 512),
        Err(GroupPlanError::GroupUnavailable),
    );
    assert_eq!(
        plan_process_group(4242, &kernel_rooted, &[], Platform::Linux, 512),
        Err(GroupPlanError::RootMissing),
    );
}

#[test]
fn group_plan_truncates_at_its_own_limit_and_preflight_names_it() {
    let mut snapshot = vec![ginfo(100, Some(1), "root", 10, 42)];
    for pid in 200..210 {
        snapshot.push(ginfo(pid, Some(1), "member", u64::from(pid), 42));
    }

    let group = plan_process_group(100, &snapshot, &[], Platform::Linux, 4)
        .expect("root is present with a group");

    assert_eq!(group.members().len(), 4);
    assert!(group.members().truncated());
    // The refusal must carry the cap the builder actually used, not the
    // tree cap: the two scopes have different limits.
    assert_eq!(
        super::preflight_outcome(group.members()),
        Err(TreeKillOutcome::Truncated { limit: 4 }),
    );
}

#[test]
fn group_kill_reaches_a_reparented_member_and_signals_the_root_last() {
    let root = root_target(100, "root", 10);
    // The orphan double-forked away long ago: parent 1, same group. A tree
    // kill from 100 could never reach it; the group kill must.
    let snapshot = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(1), "orphan", 11, 42),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot.clone(), snapshot]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 2);
    assert_eq!(report.delivered, 2);
    assert_eq!(ops.delivered_pids(), vec![150, 100]);
    assert!(ops.events.contains(&Event::Cont(150)));
    assert!(ops.events.contains(&Event::Cont(100)));
}

#[test]
fn group_terminate_queues_every_term_before_any_continue() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(100), "parent-like", 11, 42),
        ginfo(151, Some(150), "child-like", 12, 42),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot.clone(), snapshot]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 3);
    assert_eq!(ops.delivered_pids(), vec![150, 151, 100]);

    let first_continue = ops
        .events
        .iter()
        .position(|event| matches!(event, Event::Cont(_)))
        .expect("terminate mode must continue stopped members");
    let last_delivery = ops
        .events
        .iter()
        .rposition(|event| matches!(event, Event::Deliver(_, KillMode::Terminate)))
        .expect("terminate mode must deliver SIGTERM");
    assert!(
        last_delivery < first_continue,
        "group members must not resume until every SIGTERM is queued: {:?}",
        ops.events,
    );
}

#[test]
fn group_final_verification_reuses_the_convergence_snapshot() {
    let root = root_target(100, "root", 10);
    let base = vec![ginfo(100, Some(1), "root", 10, 42)];
    let grown = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(100), "late", 11, 42),
    ];
    let mut ops = FakeOps::new(vec![
        base.clone(), // verify root
        base,         // sweep pass 1: nothing new yet
        grown,
    ]);
    ops.fresh_evidence.insert(
        100,
        Ok(FreshProcessEvidence {
            pid: 100,
            start_marker: crate::observation::ProcessStartMarker::linux(10)
                .expect("test marker is valid"),
            name: "root".to_owned(),
        }),
    );

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 1);
    assert_eq!(ops.delivered_pids(), vec![100]);
    assert_eq!(
        ops.next, 2,
        "no later snapshot may replace convergence evidence"
    );
}

#[test]
fn group_member_reparenting_mid_kill_is_not_identity_drift() {
    let root = root_target(100, "root", 10);
    let before = vec![
        ginfo(100, Some(1), "root", 10, 42),
        // Its parent (250, outside the group) is alive at sweep time...
        ginfo(150, Some(250), "worker", 11, 42),
    ];
    // ...and exits before the final verify: the worker reparents, keeping
    // its group. Group identity is the group, not the parent. This must
    // proceed where the tree rules would refuse.
    let reparented = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(1), "worker", 11, 42),
    ];
    let mut ops = FakeOps::new(vec![
        before.clone(), // verify root
        before.clone(), // sweep pass 1: discovers 150
        reparented,     // sweep pass 2: converged after reparenting
    ]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 2);
    assert_eq!(ops.delivered_pids(), vec![150, 100]);
}

#[test]
fn group_member_leaving_the_group_post_stop_thaws_everything() {
    let root = root_target(100, "root", 10);
    let before = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(1), "worker", 11, 42),
    ];
    // The worker's group changed under the freeze (a setpgid from outside):
    // membership no longer provable, so the whole kill refuses and thaws.
    let moved = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(1), "worker", 11, 77),
    ];
    let mut ops = FakeOps::new(vec![before.clone(), before, moved]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 150 });
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.ends_with(&[Event::Cont(150), Event::Cont(100)]));
}

#[test]
fn group_root_that_moved_groups_thaws_and_refuses() {
    let root = root_target(100, "root", 10);
    // The user confirmed group 42, but by freeze time the root sits in 77:
    // sweeping 77 would kill a set the user never saw.
    let snapshot = vec![ginfo(100, Some(1), "root", 10, 77)];
    let mut ops = FakeOps::new(vec![snapshot]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 100 });
    assert_eq!(ops.events, vec![Event::Stop(100), Event::Cont(100)]);
}

#[test]
fn group_cap_exceeded_during_freeze_thaws_and_refuses() {
    let root = root_target(100, "root", 10);
    let mut snapshot = vec![ginfo(100, Some(1), "root", 10, 42)];
    let current_pid = std::process::id();
    let member_count = MAX_GROUP_PROCESSES + 5;
    for pid in (2..)
        .filter(|pid| *pid != root.pid && *pid != current_pid)
        .take(member_count)
    {
        snapshot.push(ginfo(pid, Some(1), "member", u64::from(pid), 42));
    }
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::Truncated {
            limit: MAX_GROUP_PROCESSES,
        },
    );
    assert!(ops.delivered_pids().is_empty());
    // Everything stopped so far was thawed. Check the same PIDs, not just the
    // same number of signals.
    let mut stopped: Vec<u32> = ops
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Stop(pid) => Some(*pid),
            _ => None,
        })
        .collect();
    let mut continued: Vec<u32> = ops
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Cont(pid) => Some(*pid),
            _ => None,
        })
        .collect();
    stopped.sort_unstable();
    continued.sort_unstable();
    assert!(
        !stopped.is_empty(),
        "the freeze must stop members before refusing"
    );
    assert_eq!(stopped, continued);
}

#[test]
fn protected_group_member_thaws_and_refuses() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(150, Some(1), "postgres", 11, 42),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot.clone(), snapshot]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::ProtectedDescendant {
            pid: 150,
            name: Some("postgres".to_owned()),
        },
    );
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.ends_with(&[Event::Cont(150), Event::Cont(100)]));
}

#[test]
fn kickoutchi_inside_the_target_group_refuses_before_it_is_stopped() {
    // The script case: `server & kick kill --pid $! --group` in a plain
    // `sh -c` script puts kick itself in the target group. The sweep must
    // refuse on kick's own PID, never stop it.
    let root = root_target(100, "root", 10);
    let self_pid = std::process::id();
    let snapshot = vec![
        ginfo(100, Some(1), "root", 10, 42),
        ginfo(self_pid, Some(1), "kickoutchi", 11, 42),
    ];
    let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert!(matches!(outcome, TreeKillOutcome::UnsafePid { pid, .. } if pid == self_pid));
    assert!(!ops.events.contains(&Event::Stop(self_pid)));
    assert!(ops.events.contains(&Event::Cont(100)));
}

/// A static parent chain deeper than the pass limit must freeze in a single
/// snapshot pass: every generation is already visible in that snapshot, so
/// depth must never consume passes. Guards against the sweep advancing only
/// one generation per snapshot and refusing legitimate deep trees.
#[test]
fn deep_static_chain_freezes_in_one_pass_and_kills_leaves_first() {
    let root = root_target(100, "link", 10);
    // A 10-process chain: 100 -> 101 -> ... -> 109.
    let chain: Vec<TreeProcessInfo> = (0..10_u32)
        .map(|index| {
            let pid = 100 + index;
            let parent = if index == 0 { 1 } else { pid - 1 };
            info(pid, Some(parent), "link", 10 + u64::from(index))
        })
        .collect();
    // One static snapshot serves root verification, both sweep passes, and
    // fresh delivery evidence because the fake repeats its last snapshot.
    let mut ops = FakeOps::new(vec![chain]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 10);
    assert_eq!(report.delivered, 10);
    let expected: Vec<u32> = (100..110).rev().collect();
    assert_eq!(ops.delivered_pids(), expected);
}

/// Only a member set that keeps growing across fresh snapshots may exhaust
/// the pass limit; the refusal must thaw exactly the PIDs it stopped.
#[test]
fn sweep_pass_limit_refuses_a_set_that_grows_every_snapshot_and_thaws_all() {
    let root = root_target(100, "root", 10);
    let base = vec![info(100, Some(1), "root", 10)];
    // Snapshot for pass k shows k children of the root: every fresh read
    // discovers one process the previous pass could not have seen.
    let mut snapshots = vec![base.clone()];
    for pass in 1..=8_u32 {
        let mut grown = base.clone();
        for child in 0..pass {
            let pid = 200 + child;
            grown.push(info(pid, Some(100), "spawned", u64::from(pid)));
        }
        snapshots.push(grown);
    }
    let mut ops = FakeOps::new(snapshots);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::SweepPassLimit { limit: 8 });
    assert!(ops.delivered_pids().is_empty());
    let mut stopped: Vec<u32> = ops
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Stop(pid) => Some(*pid),
            _ => None,
        })
        .collect();
    let mut continued: Vec<u32> = ops
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Cont(pid) => Some(*pid),
            _ => None,
        })
        .collect();
    stopped.sort_unstable();
    continued.sort_unstable();
    assert!(
        !stopped.is_empty(),
        "the freeze must stop members before refusing"
    );
    assert_eq!(stopped, continued, "every stopped PID must be thawed");
}

/// Post-stop verification must reject a frozen tree member whose parent
/// PID changed, not only one whose start marker changed: the parent link
/// is what proved tree membership.
#[test]
fn frozen_tree_member_reparenting_thaws_everything_and_refuses() {
    let root = root_target(100, "root", 10);
    let stable = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(100), "child", 11),
    ];
    // Same marker, different parent: membership is no longer provable.
    let reparented = vec![
        info(100, Some(1), "root", 10),
        info(101, Some(1), "child", 11),
    ];
    let mut ops = FakeOps::new(vec![
        stable.clone(), // verify root
        stable,         // sweep pass 1: discovers and freezes 101
        reparented,     // sweep pass 2: converged and verifies relation
    ]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 101 });
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.ends_with(&[Event::Cont(101), Event::Cont(100)]));
}

/// The confirmed root's parent is outside the frozen set, so it can exit and
/// reparent the root without changing the root's identity or tree scope.
#[test]
fn frozen_tree_root_reparenting_is_not_identity_drift() {
    let root = root_target(100, "root", 10);
    let before = vec![info(100, Some(250), "root", 10)];
    let reparented = vec![info(100, Some(1), "root", 10)];
    let mut ops = FakeOps::new(vec![
        before,     // verify root
        reparented, // converged with only the root's parent changed
    ]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    let TreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(report.total, 1);
    assert_eq!(ops.delivered_pids(), vec![100]);
}

/// A root confirmed without a readable name can `exec` into a protected
/// name while keeping its PID, parent, and start marker. The final
/// frozen-set policy must refuse it unless the protected-root typed
/// confirmation was actually completed.
#[test]
fn root_exec_into_protected_name_refuses_without_protected_confirmation() {
    let mut confirmed = root_target(100, "postgres", 10);
    confirmed.process_name = None;
    let snapshot = vec![info(100, Some(500), "postgres", 10)];
    let protected = vec!["postgres".to_owned()];

    let mut ops = FakeOps::new(vec![snapshot.clone()]);
    let outcome = execute_tree_kill(
        &confirmed,
        KillMode::Terminate,
        &protected,
        Platform::Linux,
        auth(),
        &mut ops,
    );
    assert_eq!(
        outcome,
        TreeKillOutcome::ProtectedRoot {
            pid: 100,
            name: Some("postgres".to_owned()),
        },
    );
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.ends_with(&[Event::Cont(100)]));

    // The same tree proceeds once the protected-root confirmation is real.
    let mut ops = FakeOps::new(vec![snapshot]);
    let outcome = execute_tree_kill(
        &confirmed,
        KillMode::Terminate,
        &protected,
        Platform::Linux,
        ScopeAuthorization::ProtectedRootAndWordConfirmed,
        &mut ops,
    );
    assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
}

/// A skipped `--yes` prompt was justified by an all-clear preview; a
/// system/service member appearing in the frozen set afterwards must void
/// the skip and refuse, thawing everything.
#[test]
fn yes_skip_refuses_when_a_system_member_appears_mid_freeze() {
    let root = root_target(100, "root", 10);
    let base = vec![info(100, Some(500), "root", 10)];
    let grown = vec![
        info(100, Some(500), "root", 10),
        info(101, Some(100), "systemd", 11),
    ];
    let skipped = ScopeAuthorization::SkippedAllClear;
    let mut ops = FakeOps::new(vec![base, grown]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        skipped,
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::FreshConfirmationRequired);
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.ends_with(&[Event::Cont(101), Event::Cont(100)]));
}

/// A skipped `--yes` prompt is also voided if a different-uid member appears
/// after the all-clear preview. The final frozen set is authoritative for
/// the same warning gates the preview used.
#[test]
fn yes_skip_refuses_when_an_owner_mismatch_appears_mid_freeze() {
    let root = root_target(100, "root", 10);
    let base = vec![info(100, Some(500), "root", 10)];
    let grown = vec![
        info(100, Some(500), "root", 10),
        TreeProcessInfo {
            owner_uid: Some(crate::process::current_user_id().saturating_add(1)),
            ..info(101, Some(100), "worker", 11)
        },
    ];
    let skipped = ScopeAuthorization::SkippedAllClear;
    let mut ops = FakeOps::new(vec![base, grown]);

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        skipped,
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::FreshConfirmationRequired);
    assert!(ops.delivered_pids().is_empty());
    assert!(ops.events.ends_with(&[Event::Cont(101), Event::Cont(100)]));
}

/// A group that outgrows [`GROUP_YES_SKIP_MAX_PROCESSES`] between the
/// `--yes` skip and the end of the freeze no longer matches what the skip
/// authorized: refuse, thaw, and ask for a prompted rerun.
#[test]
fn yes_skip_refuses_when_the_group_outgrows_the_skip_cap_mid_freeze() {
    let root = root_target(100, "root", 10);
    // Parent 500 keeps every member out of the system-process policy, so
    // this test isolates the size gate rather than the warning gate.
    let small = vec![
        ginfo(100, Some(500), "root", 10, 42),
        ginfo(150, Some(500), "worker", 11, 42),
    ];
    let mut grown = small.clone();
    for pid in 200..(200 + u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32")) {
        grown.push(ginfo(pid, Some(500), "joiner", u64::from(pid), 42));
    }
    assert!(grown.len() > GROUP_YES_SKIP_MAX_PROCESSES);
    let skipped = ScopeAuthorization::SkippedAllClear;
    let mut ops = FakeOps::new(vec![small, grown]);

    let outcome = execute_group_kill(
        &root,
        42,
        KillMode::Terminate,
        &[],
        Platform::Linux,
        skipped,
        &mut ops,
    );

    assert_eq!(outcome, TreeKillOutcome::FreshConfirmationRequired);
    assert!(ops.delivered_pids().is_empty());
    let stops = ops
        .events
        .iter()
        .filter(|event| matches!(event, Event::Stop(_)))
        .count();
    let conts = ops
        .events
        .iter()
        .filter(|event| matches!(event, Event::Cont(_)))
        .count();
    assert!(stops > 0, "the freeze must stop members before refusing");
    assert_eq!(stops, conts, "every stopped member must be thawed");
}

#[test]
fn final_evidence_missing_denied_oversized_and_identity_changed_deliver_nothing() {
    let cases = [
        (
            ProcessEvidenceError::Missing { pid: 100 },
            TreeKillOutcome::TargetChanged { pid: 100 },
        ),
        (
            ProcessEvidenceError::PermissionDenied { pid: 100 },
            TreeKillOutcome::PermissionDenied { pid: 100 },
        ),
        (
            ProcessEvidenceError::NameOversized {
                pid: 100,
                bytes: crate::observation::PROTECTION_NAME_MAX_BYTES + 1,
            },
            TreeKillOutcome::PartialMetadata { pid: 100 },
        ),
        (
            ProcessEvidenceError::IdentityChanged { pid: 100 },
            TreeKillOutcome::TargetChanged { pid: 100 },
        ),
    ];
    for (error, expected_outcome) in cases {
        let root = root_target(100, "root", 10);
        let snapshot = vec![info(100, Some(500), "root", 10)];
        let mut ops = FakeOps::new(vec![snapshot]);
        ops.fresh_evidence.insert(100, Err(error));

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, expected_outcome);
        assert!(ops.delivered_pids().is_empty());
        assert_eq!(
            ops.events
                .iter()
                .filter(|event| matches!(event, Event::Stop(_)))
                .count(),
            ops.events
                .iter()
                .filter(|event| matches!(event, Event::Cont(_)))
                .count(),
        );
    }
}

#[test]
fn newly_protected_final_evidence_refuses_before_any_delivery() {
    let root = root_target(100, "root", 10);
    let snapshot = vec![
        info(100, Some(500), "root", 10),
        info(101, Some(100), "worker", 11),
    ];
    let mut ops = FakeOps::new(vec![snapshot]);
    ops.fresh_evidence.insert(
        101,
        Ok(FreshProcessEvidence {
            pid: 101,
            start_marker: crate::observation::ProcessStartMarker::linux(11)
                .expect("nonzero marker"),
            name: "postgres".to_owned(),
        }),
    );

    let outcome = execute_tree_kill(
        &root,
        KillMode::Terminate,
        &["postgres".to_owned()],
        Platform::Linux,
        auth(),
        &mut ops,
    );

    assert_eq!(
        outcome,
        TreeKillOutcome::ProtectedDescendant {
            pid: 101,
            name: Some("postgres".to_owned()),
        }
    );
    assert!(ops.delivered_pids().is_empty());
    assert!(
        !ops.events
            .iter()
            .any(|event| matches!(event, Event::Deliver(_, _)))
    );
}
