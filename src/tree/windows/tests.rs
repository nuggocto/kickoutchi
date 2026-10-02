use super::{
    JobMembershipError, RealWindowsTreeApi, WindowsApiError, WindowsTreeApi,
    WindowsTreeCleanupIssue, WindowsTreeKillOutcome, WindowsTreePostCommitIssue,
    WindowsTreeTerminationState, WindowsWaitResult, execute_tree_kill_with,
};
use crate::model::{PermissionStatus, Platform};
use crate::process::KillTarget;
use crate::tree::{ScopeAuthorization, TreeKillOutcome as TreeRefusal, TreeProcessInfo};
use std::collections::{HashMap, HashSet, VecDeque};

const fn auth() -> ScopeAuthorization {
    ScopeAuthorization::TypedWordConfirmed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    PreflightFreezeCapability,
    CreateJob,
    Assign(u32),
    FreezeJob(bool),
    TerminateJob,
    Wait(u32, u32),
    SpawnedDescendant { parent_pid: u32, child_pid: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FakeProcessHandle {
    pid: u32,
    start_marker: crate::observation::ProcessStartMarker,
}

#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool scripts one independent fake-API failure mode"
)]
struct FakeApi {
    snapshots: Vec<Vec<TreeProcessInfo>>,
    snapshot_errors: HashMap<usize, String>,
    next_snapshot: usize,
    current_markers: HashMap<u32, crate::observation::ProcessStartMarker>,
    marker_overrides: HashMap<u32, crate::observation::ProcessStartMarker>,
    names: HashMap<FakeProcessHandle, String>,
    name_results: HashMap<FakeProcessHandle, VecDeque<Result<Option<String>, WindowsApiError>>>,
    deny_name: HashSet<u32>,
    events: Vec<Event>,
    deny_assign: HashSet<u32>,
    fail_root_assign: bool,
    preflight_error: Option<String>,
    fail_terminate_job: bool,
    fail_freeze_job: bool,
    fail_thaw_job: bool,
    already_in_job: HashSet<FakeProcessHandle>,
    membership_results: VecDeque<Result<Vec<u32>, JobMembershipError>>,
    force_not_in_job: HashSet<u32>,
    fail_in_job: HashSet<u32>,
    wait_results: HashMap<u32, VecDeque<WindowsWaitResult>>,
    wait_elapsed_ms: HashMap<u32, VecDeque<u32>>,
    wait_counts: HashMap<u32, usize>,
    spawn_on_wait: Option<(u32, usize, u32)>,
    now_ms: u64,
    job_terminated: bool,
}

impl FakeApi {
    fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
        let names = snapshots
            .iter()
            .flat_map(|snapshot| snapshot.iter())
            .filter_map(|info| {
                Some((
                    FakeProcessHandle {
                        pid: info.pid,
                        start_marker: info.start_time_marker?,
                    },
                    info.process_name.clone()?,
                ))
            })
            .collect();
        Self {
            snapshots,
            names,
            ..Self::default()
        }
    }

    fn handle(pid: u32, marker: u64) -> FakeProcessHandle {
        FakeProcessHandle {
            pid,
            start_marker: crate::observation::ProcessStartMarker::windows(marker).unwrap(),
        }
    }

    fn contain(&mut self, pid: u32, marker: u64) {
        self.already_in_job.insert(Self::handle(pid, marker));
    }

    fn set_name(&mut self, pid: u32, marker: u64, name: impl Into<String>) {
        self.names.insert(Self::handle(pid, marker), name.into());
    }

    fn remove_name(&mut self, pid: u32, marker: u64) {
        self.names.remove(&Self::handle(pid, marker));
    }
}

impl WindowsTreeApi for FakeApi {
    type ProcessHandle = FakeProcessHandle;
    type JobHandle = ();

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        if let Some(error) = self.snapshot_errors.get(&self.next_snapshot).cloned() {
            self.next_snapshot += 1;
            return Err(error);
        }
        let index = self
            .next_snapshot
            .min(self.snapshots.len().saturating_sub(1));
        self.next_snapshot += 1;
        let snapshot = self.snapshots.get(index).cloned().unwrap_or_default();
        self.current_markers = snapshot
            .iter()
            .filter_map(|info| Some((info.pid, info.start_time_marker?)))
            .collect();
        Ok(snapshot)
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError> {
        self.marker_overrides
            .get(&pid)
            .or_else(|| self.current_markers.get(&pid))
            .copied()
            .map(|start_marker| FakeProcessHandle { pid, start_marker })
            .ok_or(WindowsApiError::NotFound)
    }

    fn process_start_marker(
        &mut self,
        handle: &Self::ProcessHandle,
    ) -> Option<crate::observation::ProcessStartMarker> {
        Some(handle.start_marker)
    }

    fn process_name(
        &mut self,
        handle: &Self::ProcessHandle,
    ) -> Result<Option<String>, WindowsApiError> {
        if self.deny_name.contains(&handle.pid) {
            return Err(WindowsApiError::PermissionDenied);
        }
        if let Some(results) = self.name_results.get_mut(handle)
            && let Some(result) = results.pop_front()
        {
            return result;
        }
        Ok(self.names.get(handle).cloned())
    }

    fn preflight_job_freeze_thaw(&mut self) -> Result<(), String> {
        self.events.push(Event::PreflightFreezeCapability);
        match &self.preflight_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn create_job(&mut self) -> Result<Self::JobHandle, String> {
        self.events.push(Event::CreateJob);
        Ok(())
    }

    fn process_in_job(
        &mut self,
        _job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<bool, WindowsApiError> {
        if self.fail_in_job.contains(&process.pid) {
            return Err(WindowsApiError::Other(
                "containment query failed".to_owned(),
            ));
        }
        if self.force_not_in_job.contains(&process.pid) {
            return Ok(false);
        }
        Ok(self.already_in_job.contains(process))
    }

    fn assign_process(
        &mut self,
        _job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<(), WindowsApiError> {
        self.events.push(Event::Assign(process.pid));
        if process.pid == 100 && self.fail_root_assign {
            return Err(WindowsApiError::Other("root cannot join job".to_owned()));
        }
        if self.deny_assign.contains(&process.pid) {
            return Err(WindowsApiError::Other("member cannot join job".to_owned()));
        }
        self.already_in_job.insert(*process);
        Ok(())
    }

    fn job_process_ids(&mut self, _job: &Self::JobHandle) -> Result<Vec<u32>, JobMembershipError> {
        if let Some(result) = self.membership_results.pop_front() {
            return result;
        }
        let mut pids = self
            .already_in_job
            .iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    fn terminate_job(&mut self, _job: &Self::JobHandle) -> Result<(), String> {
        self.events.push(Event::TerminateJob);
        if self.fail_terminate_job {
            return Err("job termination failed".to_owned());
        }
        self.job_terminated = true;
        Ok(())
    }

    fn set_job_frozen(&mut self, _job: &Self::JobHandle, frozen: bool) -> Result<(), String> {
        self.events.push(Event::FreezeJob(frozen));
        if (frozen && self.fail_freeze_job) || (!frozen && self.fail_thaw_job) {
            return Err("job freeze transition failed".to_owned());
        }
        Ok(())
    }

    fn wait_process_exit(
        &mut self,
        process: &Self::ProcessHandle,
        timeout_ms: u32,
    ) -> WindowsWaitResult {
        self.events.push(Event::Wait(process.pid, timeout_ms));
        let wait_count = self.wait_counts.entry(process.pid).or_default();
        *wait_count += 1;
        if let Some((parent_pid, spawn_wait, child_pid)) = self.spawn_on_wait
            && (parent_pid, spawn_wait) == (process.pid, *wait_count)
        {
            self.events.push(Event::SpawnedDescendant {
                parent_pid,
                child_pid,
            });
        }
        let elapsed_ms = self
            .wait_elapsed_ms
            .get_mut(&process.pid)
            .and_then(VecDeque::pop_front)
            .unwrap_or(0)
            .min(timeout_ms);
        self.now_ms = self.now_ms.saturating_add(u64::from(elapsed_ms));
        if let Some(results) = self.wait_results.get_mut(&process.pid)
            && let Some(result) = results.pop_front()
        {
            return result;
        }
        if self.job_terminated {
            WindowsWaitResult::Exited
        } else {
            WindowsWaitResult::StillRunning
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.now_ms
    }
}

fn info(pid: u32, parent_pid: Option<u32>, marker: u64) -> TreeProcessInfo {
    TreeProcessInfo {
        pid,
        parent_pid,
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some(format!("p{pid}")),
        start_time_marker: crate::observation::ProcessStartMarker::windows(marker).ok(),
        owner_uid: None,
        process_group: None,
        executable_name: None,
    }
}

fn root() -> KillTarget {
    KillTarget {
        pid: 100,
        process_name: Some("p100".to_owned()),
        platform: Platform::Windows,
        permission: PermissionStatus::Full,
        protected: false,
        system_process: false,
        ports: Vec::new(),
        owner_uid: None,
        process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
        child_count: 0,
        children_truncated: false,
    }
}

#[test]
fn root_assignment_is_the_commit_boundary() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.fail_root_assign = true;

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert!(matches!(
        outcome,
        WindowsTreeKillOutcome::CommitFailed { .. }
    ));
    assert_eq!(
        api.events,
        vec![
            Event::PreflightFreezeCapability,
            Event::CreateJob,
            Event::Assign(100)
        ]
    );
}

#[test]
fn native_private_job_freeze_calls_are_accepted_on_an_empty_job() {
    let mut api = RealWindowsTreeApi::new();
    let job = api
        .create_job()
        .expect("this Windows host must create a disposable Job Object");

    api.set_job_frozen(&job, true)
        .expect("this Windows host must accept the private freeze call");
    api.set_job_frozen(&job, false)
        .expect("this Windows host must accept the private thaw call");
}

#[test]
fn freeze_capability_preflight_failure_refuses_before_root_assignment() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.preflight_error = Some("class 18 is unavailable".to_owned());

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::FreezeCapabilityUnavailable {
            error: "class 18 is unavailable".to_owned(),
        }
    );
    assert_eq!(api.events, vec![Event::PreflightFreezeCapability]);
    assert!(!api.job_terminated);
}

#[test]
fn root_snapshot_identity_drift_refuses_before_job_creation() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 200), info(101, Some(100), 201)]]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::TargetChanged { pid: 100 })
    );
    assert!(api.events.is_empty());
}

#[test]
fn root_handle_identity_drift_refuses_before_job_creation() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.marker_overrides.insert(
        100,
        crate::observation::ProcessStartMarker::windows(200).unwrap(),
    );

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::TargetChanged { pid: 100 })
    );
    assert!(api.events.is_empty());
}

#[test]
fn missing_fresh_name_refuses_with_zero_delivery_or_job_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.remove_name(101, 101);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::PartialMetadata { pid: 101 })
    );
    assert!(api.events.is_empty());
    assert!(!api.job_terminated);
}

#[test]
fn denied_fresh_name_refuses_distinctly_with_zero_delivery_or_job_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.deny_name.insert(101);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::PermissionDenied { pid: 101 })
    );
    assert!(api.events.is_empty());
    assert!(!api.job_terminated);
}

#[test]
fn oversized_fresh_name_refuses_with_zero_delivery_or_job_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.set_name(
        101,
        101,
        "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES + 1),
    );

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::PartialMetadata { pid: 101 })
    );
    assert!(api.events.is_empty());
    assert!(!api.job_terminated);
}

#[test]
fn live_assignment_failure_prevents_descendant_spawning_during_fallback() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.deny_assign.insert(101);
    api.wait_results.insert(
        101,
        VecDeque::from([
            WindowsWaitResult::StillRunning,
            WindowsWaitResult::StillRunning,
        ]),
    );
    api.spawn_on_wait = Some((101, 2, 102));

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert_eq!(
        report.termination_state,
        WindowsTreeTerminationState::Withheld
    );
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert!(!api.events.contains(&Event::TerminateJob));
    assert!(!api.events.contains(&Event::FreezeJob(true)));
    assert!(!api.events.contains(&Event::SpawnedDescendant {
        parent_pid: 101,
        child_pid: 102,
    }));
    assert_eq!(api.wait_counts.get(&101), Some(&1));
}

#[test]
fn frozen_final_window_refuses_late_protected_child() {
    let initial = vec![info(100, None, 100), info(101, Some(100), 101)];
    let late = vec![
        info(100, None, 100),
        info(101, Some(100), 101),
        info(102, Some(100), 102),
    ];
    let mut api = FakeApi::new(vec![initial.clone(), initial.clone(), initial, late]);
    api.contain(102, 102);

    let outcome = execute_tree_kill_with(&root(), &["p102".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-commit protection refusal returns a report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(report.not_terminated.contains(&100));
    assert!(report.not_terminated.contains(&101));
    assert!(report.not_terminated.contains(&102));
    assert!(!api.events.contains(&Event::TerminateJob));
    let freeze = api
        .events
        .iter()
        .position(|event| *event == Event::FreezeJob(true))
        .expect("job is frozen before the final window");
    let thaw = api
        .events
        .iter()
        .position(|event| *event == Event::FreezeJob(false))
        .expect("withheld job is thawed");
    assert!(freeze < thaw);
}

#[test]
fn yes_skip_withholds_all_termination_when_a_late_child_adds_a_warning() {
    let initial = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut late_system_child = info(102, Some(100), 102);
    late_system_child.process_name = Some("spoolsv.exe".to_owned());
    let late = vec![
        info(100, None, 100),
        info(101, Some(100), 101),
        late_system_child,
    ];
    let mut api = FakeApi::new(vec![initial, late]);
    api.deny_assign.insert(101);

    let outcome =
        execute_tree_kill_with(&root(), &[], ScopeAuthorization::SkippedAllClear, &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-commit warning refusal returns a report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::FreshConfirmationRequired)
    );
    assert!(report.not_terminated.contains(&101));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn real_job_freeze_failure_withholds_job_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.fail_freeze_job = true;
    api.fail_thaw_job = true;

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-commit freeze failure returns a report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert!(!api.events.contains(&Event::TerminateJob));
    assert!(matches!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
            if error.contains("freezing committed Job Object failed")
    ));
    assert_eq!(report.secondary_post_commit_issue, None);
    assert!(matches!(
        report.cleanup_issue,
        Some(WindowsTreeCleanupIssue::WithheldJobThawFailed(ref error))
            if error == "job freeze transition failed"
    ));
    assert_eq!(
        api.events
            .iter()
            .filter(|event| **event == Event::FreezeJob(false))
            .count(),
        1,
        "a failed private freeze transition must trigger exactly one best-effort thaw"
    );
}

#[test]
fn freeze_failure_after_primary_issue_is_retained_as_secondary() {
    let first = vec![info(100, None, 100)];
    let with_protected = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, with_protected]);
    api.fail_freeze_job = true;

    let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-commit issues return a report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant {
            pid: 101,
            name: Some("p101".to_owned()),
        })
    );
    assert!(matches!(
        report.secondary_post_commit_issue,
        Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
            if error.contains("freezing committed Job Object failed")
    ));
    assert!(api.events.contains(&Event::FreezeJob(false)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn frozen_sweep_failure_after_primary_issue_is_retained_as_secondary() {
    let first = vec![info(100, None, 100)];
    let with_protected = vec![info(100, None, 100), info(101, Some(100), 101)];
    let with_unknown = vec![info(100, None, 100), info(102, Some(100), 102)];
    let mut api = FakeApi::new(vec![first, with_protected, with_unknown]);
    api.remove_name(102, 102);

    let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-commit issues return a report");
    };
    assert!(matches!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant { pid: 101, .. })
    ));
    assert_eq!(
        report.secondary_post_commit_issue,
        Some(WindowsTreePostCommitIssue::PartialMetadata { pid: 102 })
    );
    assert!(api.events.contains(&Event::FreezeJob(true)));
    assert!(api.events.contains(&Event::FreezeJob(false)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn withheld_thaw_failure_preserves_primary_issue_and_avoids_job_termination() {
    let first = vec![info(100, None, 100)];
    let late = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first.clone(), first.clone(), first, late]);
    api.contain(101, 101);
    api.fail_thaw_job = true;

    let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("withheld termination returns a report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant {
            pid: 101,
            name: Some("p101".to_owned()),
        })
    );
    assert!(matches!(
        report.cleanup_issue,
        Some(WindowsTreeCleanupIssue::WithheldJobThawFailed(ref error))
            if error == "job freeze transition failed"
    ));
    assert!(api.events.contains(&Event::FreezeJob(true)));
    assert!(api.events.contains(&Event::FreezeJob(false)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn failed_job_termination_thaw_failure_is_reported_separately() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.fail_terminate_job = true;
    api.fail_thaw_job = true;

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::JobTerminateFailed { error, report } = outcome else {
        panic!("expected failed job termination");
    };
    assert_eq!(error, "job termination failed");
    assert_eq!(report.post_commit_issue, None);
    assert!(matches!(
        report.cleanup_issue,
        Some(WindowsTreeCleanupIssue::FailedTerminationThawFailed(ref thaw_error))
            if thaw_error == "job freeze transition failed"
    ));
    assert_eq!(
        api.events
            .iter()
            .filter(|event| **event == Event::TerminateJob)
            .count(),
        1
    );
    assert!(!api.job_terminated);
}

#[test]
fn failed_job_termination_preserves_assigned_and_already_exited_members() {
    let snapshot = vec![
        info(100, None, 100),
        info(101, Some(100), 101),
        info(102, Some(100), 102),
    ];
    let after_exit = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![snapshot, after_exit]);
    api.deny_assign.insert(102);
    api.wait_results
        .insert(102, VecDeque::from([WindowsWaitResult::Exited]));
    api.fail_terminate_job = true;

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::JobTerminateFailed { error, report } = outcome else {
        panic!("expected failed job termination");
    };
    assert_eq!(error, "job termination failed");
    assert_eq!(report.total, 3);
    assert!(report.job_terminated_pids.is_empty());
    assert_eq!(report.already_exited_pids, vec![102]);
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert!(!report.termination_state.is_complete());
    assert!(api.events.contains(&Event::TerminateJob));
}

#[test]
fn report_waits_share_one_total_deadline() {
    let snapshot = vec![
        info(100, None, 100),
        info(101, Some(100), 101),
        info(102, Some(100), 102),
    ];
    let mut api = FakeApi::new(vec![snapshot]);
    api.wait_results
        .insert(100, VecDeque::from([WindowsWaitResult::Exited]));
    api.wait_results
        .insert(101, VecDeque::from([WindowsWaitResult::Exited]));
    api.wait_results
        .insert(102, VecDeque::from([WindowsWaitResult::StillRunning]));
    api.wait_elapsed_ms.insert(100, VecDeque::from([2_000]));
    api.wait_elapsed_ms.insert(101, VecDeque::from([3_000]));

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert_eq!(report.job_terminated_pids, vec![100, 101]);
    assert_eq!(report.not_terminated, vec![102]);
    assert!(!report.termination_state.is_complete());
    assert!(api.events.contains(&Event::Wait(100, 5_000)));
    assert!(api.events.contains(&Event::Wait(101, 3_000)));
    assert!(api.events.contains(&Event::Wait(102, 0)));
}

#[test]
fn exited_member_after_assign_failure_is_not_reported_alive() {
    let mut api = FakeApi::new(vec![
        vec![info(100, None, 100), info(101, Some(100), 101)],
        vec![info(100, None, 100)],
    ]);
    api.deny_assign.insert(101);
    api.wait_results
        .insert(101, VecDeque::from([WindowsWaitResult::Exited]));

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert_eq!(report.already_exited_pids, vec![101]);
    assert!(report.not_terminated.is_empty());
    assert!(report.termination_state.is_complete());
    assert!(api.events.contains(&Event::Wait(101, 0)));
}

#[test]
fn live_uncontained_member_is_not_retried_even_if_it_would_exit_later() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
    api.deny_assign.insert(101);
    api.wait_results.insert(
        101,
        VecDeque::from([WindowsWaitResult::StillRunning, WindowsWaitResult::Exited]),
    );

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert!(report.already_exited_pids.is_empty());
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert_eq!(
        report.termination_state,
        WindowsTreeTerminationState::Withheld
    );
    assert!(!api.events.contains(&Event::TerminateJob));
    assert_eq!(api.wait_counts.get(&101), Some(&1));
}

#[test]
fn already_contained_late_child_terminates_with_the_job() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);
    api.contain(101, 101);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert_eq!(report.job_terminated_pids, vec![100, 101]);
    assert!(api.events.contains(&Event::TerminateJob));
}

#[test]
fn protected_late_child_withholds_final_job_termination() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);

    let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert_eq!(
        report.termination_state,
        WindowsTreeTerminationState::Withheld
    );
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant {
            pid: 101,
            name: Some("p101".to_owned()),
        })
    );
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn protected_late_child_already_in_job_is_not_reported_alive() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);
    api.contain(101, 101);

    let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert!(!report.termination_state.is_complete());
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert!(report.job_terminated_pids.is_empty());
    assert!(report.termination_state.is_withheld());
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant {
            pid: 101,
            name: Some("p101".to_owned()),
        })
    );
    assert!(!api.events.contains(&Event::TerminateJob));
    assert!(!api.job_terminated);
}

#[test]
fn newly_protected_late_child_uses_fresh_name_and_withholds_termination() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);
    api.set_name(101, 101, "lsass.exe");
    api.contain(101, 101);

    let outcome = execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected truthful contained partial report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant {
            pid: 101,
            name: Some("lsass.exe".to_owned()),
        })
    );
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn unknown_late_contained_child_withholds_all_termination() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);
    api.remove_name(101, 101);
    api.contain(101, 101);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected truthful contained partial report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::PartialMetadata { pid: 101 })
    );
    assert!(!api.events.contains(&Event::TerminateJob));
    assert!(!api.job_terminated);
}

#[test]
fn protected_late_child_with_unknown_job_state_withholds_all_termination() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);
    api.set_name(101, 101, "lsass.exe");
    api.fail_in_job.insert(101);

    let outcome = execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], auth(), &mut api);
    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected fail-closed partial report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn unknown_late_child_with_unknown_job_state_withholds_all_termination() {
    let first = vec![info(100, None, 100)];
    let second = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second]);
    api.remove_name(101, 101);
    api.fail_in_job.insert(101);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);
    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected fail-closed partial report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn post_commit_snapshot_error_withholds_job_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.snapshot_errors
        .insert(1, "injected sweep snapshot failure".to_owned());

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);
    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected post-commit report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(matches!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SnapshotFailed(_))
    ));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn sweep_pass_exhaustion_withholds_job_termination() {
    let mut snapshots = vec![vec![info(100, None, 100)]];
    let mut current = snapshots[0].clone();
    for offset in 0..super::WINDOWS_TREE_SWEEP_PASSES {
        let pid = 101 + u32::try_from(offset).expect("test offset fits u32");
        current.push(info(pid, Some(100), u64::from(pid)));
        snapshots.push(current.clone());
    }
    let mut api = FakeApi::new(snapshots);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);
    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected post-commit report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SweepPassLimit {
            limit: super::WINDOWS_TREE_SWEEP_PASSES,
        })
    );
    assert_eq!(
        api.next_snapshot,
        1 + super::WINDOWS_TREE_SWEEP_PASSES,
        "the pre-commit snapshot plus exactly eight sweep snapshots are allowed"
    );
    assert!(!api.events.contains(&Event::FreezeJob(true)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn pre_freeze_and_frozen_sweeps_share_exact_total_pass_budget() {
    let root_only = vec![info(100, None, 100)];
    let mut snapshots = vec![root_only.clone(), root_only.clone(), root_only];
    let mut grown = snapshots[2].clone();
    for offset in 0..(super::WINDOWS_TREE_SWEEP_PASSES - 2) {
        let pid = 101 + u32::try_from(offset).expect("test offset fits u32");
        grown.push(info(pid, Some(100), u64::from(pid)));
        snapshots.push(grown.clone());
    }
    let mut api = FakeApi::new(snapshots);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("budget exhaustion returns a post-commit report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SweepPassLimit {
            limit: super::WINDOWS_TREE_SWEEP_PASSES,
        })
    );
    assert_eq!(
        api.next_snapshot,
        1 + super::WINDOWS_TREE_SWEEP_PASSES,
        "the invocation must never start sweep snapshot nine"
    );
    assert!(api.events.contains(&Event::FreezeJob(true)));
    assert!(api.events.contains(&Event::FreezeJob(false)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn final_window_snapshot_catches_late_protected_child() {
    let first = vec![info(100, None, 100)];
    let second = first.clone();
    let third = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![first, second, third]);
    api.contain(101, 101);

    let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], auth(), &mut api);
    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected post-commit report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(report.not_terminated, vec![100, 101]);
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn final_reconciliation_keeps_a_descendant_whose_intermediate_parent_exited() {
    let initial = vec![
        info(100, None, 100),
        info(101, Some(100), 101),
        info(102, Some(101), 102),
    ];
    let reparented = vec![info(100, None, 100), info(102, Some(1), 102)];
    let mut api = FakeApi::new(vec![
        initial.clone(),
        initial.clone(),
        initial.clone(),
        initial.clone(),
        initial,
        reparented,
    ]);
    api.wait_results
        .insert(101, VecDeque::from([WindowsWaitResult::Exited]));
    api.membership_results = VecDeque::from([Ok(vec![100, 102]), Ok(vec![100, 102])]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("expected completed report");
    };
    assert!(api.events.contains(&Event::TerminateJob));
    assert_eq!(report.already_exited_pids, vec![101]);
    assert_eq!(report.job_terminated_pids, vec![100, 102]);
}

#[test]
fn exact_membership_finds_unseen_inherited_protected_child() {
    let root_only = vec![info(100, None, 100)];
    let final_snapshot = vec![info(100, None, 100), info(102, Some(101), 102)];
    let mut api = FakeApi::new(vec![
        root_only.clone(),
        root_only.clone(),
        root_only.clone(),
        root_only.clone(),
        root_only,
        final_snapshot,
    ]);
    api.contain(102, 102);

    let outcome = execute_tree_kill_with(&root(), &["p102".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("protected inherited member returns a withheld report");
    };
    assert!(report.termination_state.is_withheld());
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedDescendant {
            pid: 102,
            name: Some("p102".to_owned()),
        })
    );
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn final_graph_never_traverses_a_reused_root_pid() {
    let original = vec![info(100, None, 100)];
    let mut replacement_root = info(100, None, 200);
    replacement_root.process_name = Some("lsass.exe".to_owned());
    let replacement = vec![replacement_root, info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![
        original.clone(),
        original.clone(),
        original.clone(),
        original.clone(),
        original,
        replacement,
    ]);

    let outcome = execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("PID reuse after commit returns a withheld report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::TargetChanged { pid: 100 })
    );
    assert!(!api.events.contains(&Event::Assign(101)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn final_graph_never_traverses_a_reused_intermediate_pid() {
    let original = vec![info(100, None, 100), info(101, Some(100), 101)];
    let replacement = vec![
        info(100, None, 100),
        info(101, Some(100), 201),
        info(102, Some(101), 102),
    ];
    let mut api = FakeApi::new(vec![
        original.clone(),
        original.clone(),
        original.clone(),
        original.clone(),
        original,
        replacement,
    ]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("intermediate PID reuse returns a withheld report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::TargetChanged { pid: 101 })
    );
    assert!(!api.events.contains(&Event::Assign(102)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn exact_membership_mismatch_withholds_termination() {
    let snapshot = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![snapshot]);
    api.membership_results = VecDeque::from([Ok(vec![100])]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("membership mismatch returns a withheld report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(matches!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
            if error.contains("PID 101 was absent from exact frozen Job membership")
    ));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn oversized_exact_membership_withholds_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.membership_results = VecDeque::from([Err(JobMembershipError::Oversized {
        limit: crate::tree::MAX_TREE_PROCESSES,
    })]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("oversized membership returns a withheld report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::Truncated {
            limit: crate::tree::MAX_TREE_PROCESSES,
        })
    );
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn changing_exact_membership_during_validation_withholds_termination() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.membership_results = VecDeque::from([Ok(vec![100]), Ok(Vec::new())]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("raced membership returns a withheld report");
    };
    assert!(matches!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
            if error.contains("membership changed during final reconciliation")
    ));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn survivor_after_successful_job_termination_is_thawed_and_reported() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.wait_results
        .insert(100, VecDeque::from([WindowsWaitResult::StillRunning]));

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("successful job termination returns a report");
    };
    assert_eq!(
        report.cleanup_issue,
        Some(WindowsTreeCleanupIssue::PostTerminationSurvivorsThawed {
            pids: vec![100],
            wait_errors: Vec::new(),
        })
    );
    assert!(api.events.contains(&Event::TerminateJob));
    assert!(api.events.contains(&Event::FreezeJob(false)));
}

#[test]
fn survivor_thaw_failure_after_successful_job_termination_is_distinct() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.wait_results.insert(
        100,
        VecDeque::from([WindowsWaitResult::Failed("wait failed".to_owned())]),
    );
    api.fail_thaw_job = true;

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("successful job termination returns a report");
    };
    assert_eq!(
        report.cleanup_issue,
        Some(WindowsTreeCleanupIssue::PostTerminationSurvivorThawFailed {
            pids: vec![100],
            wait_errors: vec![(100, "wait failed".to_owned())],
            error: "job freeze transition failed".to_owned(),
        })
    );
}

#[test]
fn protected_root_change_after_commit_keeps_typed_confirmation_result() {
    let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
    api.name_results.insert(
        FakeApi::handle(100, 100),
        VecDeque::from([
            Ok(Some("p100".to_owned())),
            Ok(Some("lsass.exe".to_owned())),
        ]),
    );

    let outcome = execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-commit protected root returns a withheld report");
    };
    assert_eq!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::ProtectedRoot {
            pid: 100,
            name: Some("lsass.exe".to_owned()),
        })
    );
    assert!(report.termination_state.is_withheld());
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn final_reconciliation_refuses_unproven_live_membership_and_thaws() {
    let snapshot = vec![info(100, None, 100), info(101, Some(100), 101)];
    let mut api = FakeApi::new(vec![snapshot]);
    api.force_not_in_job.insert(101);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("containment refusal returns a report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(!api.events.contains(&Event::TerminateJob));
    let freeze = api
        .events
        .iter()
        .position(|event| *event == Event::FreezeJob(true))
        .expect("job was frozen");
    let thaw = api
        .events
        .iter()
        .position(|event| *event == Event::FreezeJob(false))
        .expect("refusal thawed the job");
    assert!(freeze < thaw);
}

#[test]
fn final_reconciliation_snapshot_error_always_thaws_the_job() {
    let snapshot = vec![info(100, None, 100)];
    let mut api = FakeApi::new(vec![snapshot]);
    api.snapshot_errors
        .insert(5, "final reconciliation failed".to_owned());

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    let WindowsTreeKillOutcome::Completed(report) = outcome else {
        panic!("post-freeze error returns a report");
    };
    assert!(report.termination_state.is_withheld());
    assert!(matches!(
        report.post_commit_issue,
        Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
            if error == "final reconciliation failed"
    ));
    assert!(api.events.contains(&Event::FreezeJob(true)));
    assert!(api.events.contains(&Event::FreezeJob(false)));
    assert!(!api.events.contains(&Event::TerminateJob));
}

#[test]
fn partial_metadata_refuses_before_job_creation() {
    let mut partial = info(101, Some(100), 101);
    partial.start_time_marker = None;
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), partial]]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::PartialMetadata { pid: 101 })
    );
    assert!(api.events.is_empty());
}

#[test]
fn unverified_parent_edge_into_preview_refuses_before_job_creation() {
    let mut partial_child = info(101, None, 101);
    partial_child.start_time_marker = None;
    partial_child.unverified_parent_pid = Some(100);
    let mut api = FakeApi::new(vec![vec![info(100, None, 100), partial_child]]);

    let outcome = execute_tree_kill_with(&root(), &[], auth(), &mut api);

    assert_eq!(
        outcome,
        WindowsTreeKillOutcome::Refused(TreeRefusal::PartialMetadata { pid: 101 })
    );
    assert!(api.events.is_empty());
}
