//! Unix freeze-first tree and process-group execution.
//!
//! The safety ordering stays together here: pin and stop the root, converge on
//! the scope, verify every frozen identity and policy gate, deliver terminating
//! signals, and thaw only the members whose cleanup ownership is proven.

use crate::process::UnsafePidReason;
use crate::process_evidence::ProcessEvidenceError;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::model::Platform;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::observation::ProcessStartMarker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::cancellation::KillCancellationGuard;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::{
    KillMode, KillTarget, UNIX_STOP_ACKNOWLEDGEMENT_MAX, current_user_id, unsafe_pid_reason,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process_evidence::{ExpectedProcessEvidence, ProcessEvidenceScope};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::protection::is_protected_process_name;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::{HashMap, HashSet};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::plan::{format_pid_list, is_system};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::{
    GROUP_YES_SKIP_MAX_PROCESSES, MAX_GROUP_PROCESSES, MAX_TREE_PROCESSES, PROCESS_TREE_INDEX_MAX,
    ProcessTreeIndex, ScopeAuthorization, TreePlanError, TreeProcessInfo, TreeProcessOps,
    TreeSignalResult, TreeSnapshotScope, TreeStopError, TreeStopResult, stop_deadline_expired,
};

/// Cap on freeze-sweep passes. Every pass drains one snapshot completely, so a
/// static scope normally converges immediately. Exhaustion refuses the kill.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_FREEZE_PASSES: usize = 8;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn pin_root_before_revalidation<Ops: TreeProcessOps>(
    root_pid: u32,
    ops: &mut Ops,
) -> Result<(), TreeKillOutcome> {
    match ops.pin_root_for_revalidation(root_pid) {
        TreeSignalResult::Delivered => Ok(()),
        TreeSignalResult::NotFound => Err(TreeKillOutcome::RootAlreadyExited),
        TreeSignalResult::Denied => Err(TreeKillOutcome::PermissionDenied { pid: root_pid }),
    }
}

/// A process the pipeline has stopped and recorded, so it can verify identity
/// later and thaw it on abort.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FrozenNode {
    pub(super) pid: u32,
    pub(super) parent_pid: Option<u32>,
    pub(super) parent_process_name: Option<String>,
    pub(super) process_name: Option<String>,
    pub(super) owner_uid: Option<u32>,
    /// Identity authorized for termination. This never changes after discovery.
    pub(super) start_time_marker: Option<ProcessStartMarker>,
    /// Identity observed immediately after this PID accepted `SIGSTOP`, used
    /// only to guard rollback when termination authorization fails.
    pub(super) rollback_start_time_marker: Option<ProcessStartMarker>,
    /// Whether Kickoutchi observed this process running before its successful
    /// stop submission. Only these members may receive cleanup `SIGCONT`.
    pub(super) resume_on_cleanup: bool,
    pub(super) depth: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl FrozenNode {
    pub(super) fn from_info(info: &TreeProcessInfo, depth: usize) -> Self {
        Self {
            pid: info.pid,
            parent_pid: info.parent_pid,
            parent_process_name: info.parent_process_name.clone(),
            process_name: info.process_name.clone(),
            owner_uid: info.owner_uid,
            start_time_marker: info.start_time_marker,
            rollback_start_time_marker: info.start_time_marker,
            resume_on_cleanup: true,
            depth,
        }
    }
}

/// The scope-specific half of the shared freeze pipeline.
///
/// Tree and group kills share one pipeline: stop the root, sweep to a fixed
/// point, verify frozen identities, apply policy, then signal. Scope determines
/// membership and the relation checked after stopping.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SweepScope {
    /// Members are descendants of the frozen set, discovered over parent
    /// links; identity holds while the parent PID is unchanged.
    Tree,
    /// Members share the target process group; identity holds while the group
    /// is unchanged. The parent PID is deliberately not checked: a member's
    /// parent (outside the group, so never frozen) can exit mid-kill and
    /// reparent the member without affecting its membership.
    Group { pgid: u32 },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl SweepScope {
    fn member_cap(self) -> usize {
        match self {
            Self::Tree => MAX_TREE_PROCESSES,
            Self::Group { .. } => MAX_GROUP_PROCESSES,
        }
    }

    /// Not-yet-frozen members visible in this snapshot, in deterministic (PID)
    /// order.
    fn unfrozen_members(
        self,
        snapshot: &[TreeProcessInfo],
        index: &ProcessTreeIndex<'_>,
        frozen: &[FrozenNode],
    ) -> Vec<FrozenNode> {
        match self {
            Self::Tree => unfrozen_children(index, frozen),
            Self::Group { pgid } => unfrozen_group_members(snapshot, frozen, pgid),
        }
    }

    /// Whether the fresh read still proves the frozen node's membership.
    fn relation_holds(self, node: &FrozenNode, info: &TreeProcessInfo) -> bool {
        match self {
            Self::Tree => node.depth == 0 || info.parent_pid == node.parent_pid,
            Self::Group { pgid } => info.process_group == Some(pgid),
        }
    }
}

/// What a report line needs after a completed tree kill.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeKillReport {
    pub(crate) total: usize,
    /// Processes that accepted the terminating signal.
    pub(crate) delivered: usize,
    /// Processes that were already gone or PID-recycled before final delivery.
    pub(crate) already_exited: usize,
    /// PIDs the OS refused to signal (permission).
    pub(crate) denied: Vec<u32>,
    pub(crate) thaw_failed: Vec<u32>,
}

/// The outcome of the whole freeze-first execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreeKillOutcome {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Completed(TreeKillReport),
    RootAlreadyExited,
    PermissionDenied {
        pid: u32,
    },
    TargetChanged {
        pid: u32,
    },
    Truncated {
        limit: usize,
    },
    SweepPassLimit {
        limit: usize,
    },
    UnsafePid {
        pid: u32,
        reason: UnsafePidReason,
    },
    ProtectedDescendant {
        pid: u32,
        name: Option<String>,
    },
    ProtectedRoot {
        pid: u32,
        name: Option<String>,
    },
    FreshConfirmationRequired,
    OwnershipUnavailable {
        pid: u32,
    },
    PartialMetadata {
        pid: u32,
    },
    SnapshotFailed(String),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ThawFailed {
        pids: Vec<u32>,
        cause: Box<TreeKillOutcome>,
    },
}

/// Presentation-neutral exit class for a refusal.
///
/// CLI and TUI renderers add their own scope and phase context, but the
/// semantic class lives here so a refusal cannot silently acquire a different
/// exit meaning on another interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeRefusalClass {
    NoMatch,
    PermissionDenied,
    ProtectedNeedsConfirmation,
    Failure,
}

impl TreeKillOutcome {
    // Windows compiles out the two non-refusal Unix variants, but keeping one
    // cross-platform signature lets every renderer consume the same semantic
    // classification without a platform-specific adapter.
    #[cfg_attr(
        windows,
        allow(
            clippy::unnecessary_wraps,
            reason = "the cross-platform semantic classifier must retain one signature"
        )
    )]
    pub(crate) const fn refusal_class(&self) -> Option<TreeRefusalClass> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Completed(_) | Self::ThawFailed { .. } => None,
            Self::RootAlreadyExited => Some(TreeRefusalClass::NoMatch),
            Self::PermissionDenied { .. } | Self::OwnershipUnavailable { .. } => {
                Some(TreeRefusalClass::PermissionDenied)
            }
            Self::ProtectedDescendant { .. } | Self::ProtectedRoot { .. } => {
                Some(TreeRefusalClass::ProtectedNeedsConfirmation)
            }
            Self::TargetChanged { .. }
            | Self::Truncated { .. }
            | Self::SweepPassLimit { .. }
            | Self::UnsafePid { .. }
            | Self::FreshConfirmationRequired
            | Self::PartialMetadata { .. }
            | Self::SnapshotFailed(_) => Some(TreeRefusalClass::Failure),
        }
    }

    pub(crate) fn failure_cause_text(&self) -> String {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Completed(_) => "scoped signal delivery was incomplete".to_owned(),
            Self::RootAlreadyExited => "the root process already exited".to_owned(),
            Self::PermissionDenied { pid } => format!("permission denied for PID {pid}"),
            Self::TargetChanged { pid } => format!("process identity changed at PID {pid}"),
            Self::Truncated { limit } => format!("the process scope exceeded {limit} members"),
            Self::SweepPassLimit { limit } => {
                format!("the process scope did not converge after {limit} freeze passes")
            }
            Self::UnsafePid { pid, reason } => {
                format!("unsafe PID {pid}: {}", reason.message())
            }
            Self::ProtectedDescendant { pid, name } => format!(
                "protected process PID {pid} ({}) entered the scope",
                name.as_deref().unwrap_or("<unknown>")
            ),
            Self::ProtectedRoot { pid, name } => format!(
                "protected root PID {pid} ({})",
                name.as_deref().unwrap_or("<unknown>")
            ),
            Self::FreshConfirmationRequired => {
                "the process scope changed after confirmation".to_owned()
            }
            Self::OwnershipUnavailable { pid } => {
                format!("ownership for PID {pid} became unavailable")
            }
            Self::PartialMetadata { pid } => {
                format!("process metadata for PID {pid} was incomplete")
            }
            Self::SnapshotFailed(error) => error.clone(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::ThawFailed { pids, cause } => format!(
                "{}; cleanup could not continue PID(s) {}",
                cause.failure_cause_text(),
                format_pid_list(pids)
            ),
        }
    }
}

/// Freeze the tree, verify it, and terminate it. Stop the root first and signal
/// it last.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn execute_tree_kill<Ops: TreeProcessOps>(
    root: &KillTarget,
    mode: KillMode,
    protected_names: &[String],
    platform: Platform,
    authorization: ScopeAuthorization,
    ops: &mut Ops,
) -> TreeKillOutcome {
    execute_freeze_kill(
        root,
        SweepScope::Tree,
        mode,
        protected_names,
        platform,
        authorization,
        ops,
    )
}

/// Freeze the process group `pgid`, verify it, and terminate it. Stop the
/// confirmed root first and signal it last. `pgid` is the confirmed group;
/// the pipeline re-proves after every stop that each member (root included)
/// still belongs to it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn execute_group_kill<Ops: TreeProcessOps>(
    root: &KillTarget,
    pgid: u32,
    mode: KillMode,
    protected_names: &[String],
    platform: Platform,
    authorization: ScopeAuthorization,
    ops: &mut Ops,
) -> TreeKillOutcome {
    execute_freeze_kill(
        root,
        SweepScope::Group { pgid },
        mode,
        protected_names,
        platform,
        authorization,
        ops,
    )
}

/// The shared freeze-first execution, for both scopes.
///
/// The ordering is the safety contract: `SIGSTOP` the root before enumerating to
/// prevent ordinary forks; sweep the remaining members to a fixed point; verify
/// every frozen identity through pinned or marker-guarded delivery; refuse
/// (thawing) on any uncertainty; then signal tree members
/// deepest-first/root-last, or group members with every terminating signal
/// queued before any continue.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[expect(
    clippy::too_many_lines,
    reason = "keep freeze, cancellation, verification, delivery, and rollback ordering together"
)]
fn execute_freeze_kill<Ops: TreeProcessOps>(
    root: &KillTarget,
    scope: SweepScope,
    mode: KillMode,
    protected_names: &[String],
    platform: Platform,
    authorization: ScopeAuthorization,
    ops: &mut Ops,
) -> TreeKillOutcome {
    if let Some(reason) = unsafe_pid_reason(root.pid) {
        return TreeKillOutcome::UnsafePid {
            pid: root.pid,
            reason,
        };
    }

    ops.set_snapshot_scope(match scope {
        SweepScope::Tree => TreeSnapshotScope::Tree { root_pid: root.pid },
        SweepScope::Group { pgid } => TreeSnapshotScope::Group {
            root_pid: root.pid,
            pgid,
        },
    });

    let stop_deadline = ops.stop_acknowledgement_now() + UNIX_STOP_ACKNOWLEDGEMENT_MAX;
    let cancellation = match KillCancellationGuard::block() {
        Ok(guard) => guard,
        Err(error) => return TreeKillOutcome::SnapshotFailed(error.to_string()),
    };

    // Stop the root before anything else: while it remains stopped it cannot
    // fork on its own, normally freezing growth before we inspect membership.
    let (rollback_start_time_marker, root_transitioned) =
        match stop_before_deadline(root.pid, stop_deadline, ops) {
            TreeStopResult::Stopped { transitioned } => (
                ops.rollback_identity_after_stop(root.pid, root.process_start_time_marker),
                transitioned,
            ),
            TreeStopResult::NotFound => return TreeKillOutcome::RootAlreadyExited,
            TreeStopResult::Failed {
                cleanup_required: false,
                rollback_start_time_marker: _,
                error,
            } => return tree_stop_error_outcome(root.pid, error),
            TreeStopResult::Failed {
                cleanup_required: true,
                rollback_start_time_marker,
                error,
            } => {
                let rollback_start_time_marker = rollback_start_time_marker.or_else(|| {
                    ops.rollback_identity_after_stop(root.pid, root.process_start_time_marker)
                });
                let root_node = FrozenNode {
                    pid: root.pid,
                    parent_pid: None,
                    parent_process_name: None,
                    process_name: root.process_name.clone(),
                    owner_uid: root.owner_uid,
                    start_time_marker: root.process_start_time_marker,
                    rollback_start_time_marker,
                    resume_on_cleanup: true,
                    depth: 0,
                };
                return refuse_after_thaw(
                    tree_stop_error_outcome(root.pid, error),
                    &[root_node],
                    ops,
                );
            }
        };

    let mut frozen = match verify_root_after_stop(root, scope, rollback_start_time_marker, ops) {
        Ok(mut node) => {
            node.resume_on_cleanup = root_transitioned;
            vec![node]
        }
        Err((outcome, observed_root)) => {
            // Only the root is stopped at this point.
            let root_node = observed_root.map_or_else(
                || FrozenNode {
                    pid: root.pid,
                    parent_pid: None,
                    parent_process_name: None,
                    process_name: root.process_name.clone(),
                    owner_uid: root.owner_uid,
                    start_time_marker: root.process_start_time_marker,
                    rollback_start_time_marker,
                    resume_on_cleanup: root_transitioned,
                    depth: 0,
                },
                |node| {
                    let mut node = *node;
                    node.resume_on_cleanup = root_transitioned;
                    node
                },
            );
            return refuse_after_thaw(outcome, &[root_node], ops);
        }
    };

    let convergence_snapshot =
        match freeze_sweep(&mut frozen, scope, stop_deadline, &cancellation, ops) {
            Ok(snapshot) => snapshot,
            Err(outcome) => return refuse_after_thaw(outcome, &frozen, ops),
        };
    if let Err(outcome) = verify_frozen_identities(&mut frozen, scope, &convergence_snapshot) {
        return refuse_after_thaw(outcome, &frozen, ops);
    }
    if let Err(outcome) = prepare_delivery_handles(&frozen, ops) {
        return refuse_after_thaw(outcome, &frozen, ops);
    }
    if let Err(outcome) = verify_fresh_delivery_evidence(&mut frozen, ops) {
        return refuse_after_thaw(outcome, &frozen, ops);
    }
    if let Err(outcome) =
        check_tree_policy(&frozen, scope, authorization, protected_names, platform)
    {
        return refuse_after_thaw(outcome, &frozen, ops);
    }

    if let Err(error) = cancellation.check() {
        return refuse_after_thaw(
            TreeKillOutcome::SnapshotFailed(error.to_string()),
            &frozen,
            ops,
        );
    }

    // Once delivery starts, finish the bounded batch and its cleanup before
    // unblocking signals. In particular, a group must queue all terminating
    // signals before any member resumes.
    TreeKillOutcome::Completed(signal_tree(&mut frozen, scope, mode, ops))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_before_deadline<Ops: TreeProcessOps>(
    pid: u32,
    deadline: std::time::Instant,
    ops: &mut Ops,
) -> TreeStopResult {
    if ops.stop_acknowledgement_now() >= deadline {
        return stop_deadline_expired();
    }
    ops.stop(pid, deadline)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_root_after_stop<Ops: TreeProcessOps>(
    root: &KillTarget,
    scope: SweepScope,
    rollback_start_time_marker: Option<ProcessStartMarker>,
    ops: &mut Ops,
) -> Result<FrozenNode, (TreeKillOutcome, Option<Box<FrozenNode>>)> {
    let snapshot = ops
        .snapshot()
        .map_err(|error| (TreeKillOutcome::SnapshotFailed(error), None))?;
    let Some(info) = snapshot.iter().find(|info| info.pid == root.pid) else {
        return Err((TreeKillOutcome::RootAlreadyExited, None));
    };
    let mut observed = FrozenNode::from_info(info, 0);
    // The post-stop marker is rollback evidence only. Keep the marker that the
    // user authorized as the termination identity even on this refusal path.
    observed.start_time_marker = root.process_start_time_marker;
    observed.rollback_start_time_marker = rollback_start_time_marker;
    if !root_identity_matches(root, info) {
        return Err((
            TreeKillOutcome::TargetChanged { pid: root.pid },
            Some(Box::new(observed)),
        ));
    }
    // For group scope the confirmed group is part of the root's identity: the
    // sweep derives every other member from it, so a root that moved groups
    // between confirmation and freeze would silently retarget the whole kill.
    if let SweepScope::Group { pgid } = scope
        && info.process_group != Some(pgid)
    {
        return Err((
            TreeKillOutcome::TargetChanged { pid: root.pid },
            Some(Box::new(observed)),
        ));
    }
    Ok(observed)
}

/// Strict root identity: both start markers present and equal, and the confirmed
/// name (when known) unchanged. Mirrors the single-kill revalidation so a reused
/// or exec'd PID is refused, not signalled.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_identity_matches(root: &KillTarget, info: &TreeProcessInfo) -> bool {
    match (root.process_start_time_marker, info.start_time_marker) {
        (Some(confirmed), Some(fresh)) if confirmed == fresh => {}
        _ => return false,
    }
    if let Some(expected) = root.process_name.as_deref() {
        match info.process_name.as_deref() {
            Some(actual) if actual == expected => {}
            _ => return false,
        }
    }
    true
}

/// Sweep until a fresh snapshot contains no unfrozen members. Each pass drains
/// the complete snapshot, so a static tree freezes in one pass regardless of
/// depth. The pass limit bounds new forks and process-group joins between
/// snapshots. External continuation can still race the sweep.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn freeze_sweep<Ops: TreeProcessOps>(
    frozen: &mut Vec<FrozenNode>,
    scope: SweepScope,
    stop_deadline: std::time::Instant,
    cancellation: &KillCancellationGuard,
    ops: &mut Ops,
) -> Result<Vec<TreeProcessInfo>, TreeKillOutcome> {
    let member_cap = scope.member_cap();
    for _ in 0..MAX_FREEZE_PASSES {
        cancellation
            .check()
            .map_err(|error| TreeKillOutcome::SnapshotFailed(error.to_string()))?;
        let snapshot = ops.snapshot().map_err(TreeKillOutcome::SnapshotFailed)?;
        let index =
            ProcessTreeIndex::new(&snapshot, PROCESS_TREE_INDEX_MAX).map_err(
                |error| match error {
                    TreePlanError::SnapshotLimitExceeded { limit } => {
                        TreeKillOutcome::Truncated { limit }
                    }
                    TreePlanError::RootMissing => {
                        unreachable!("index construction does not resolve roots")
                    }
                },
            )?;
        // Members that exited between this snapshot and our stop attempt. They
        // must be excluded from re-discovery in the same (now stale) snapshot,
        // or the drain below would spin on them; whatever they left behind is
        // picked up by the next pass's fresh snapshot if it still qualifies.
        let mut vanished: HashSet<u32> = HashSet::new();
        let mut discovered_in_pass = false;
        loop {
            let discovered: Vec<FrozenNode> = scope
                .unfrozen_members(&snapshot, &index, frozen)
                .into_iter()
                .filter(|member| !vanished.contains(&member.pid))
                .collect();
            if discovered.is_empty() {
                break;
            }
            discovered_in_pass = true;
            for member in discovered {
                cancellation
                    .check()
                    .map_err(|error| TreeKillOutcome::SnapshotFailed(error.to_string()))?;
                if frozen.len() >= member_cap {
                    return Err(TreeKillOutcome::Truncated { limit: member_cap });
                }
                if let Some(reason) = unsafe_pid_reason(member.pid) {
                    return Err(TreeKillOutcome::UnsafePid {
                        pid: member.pid,
                        reason,
                    });
                }
                if member.start_time_marker.is_none() {
                    return Err(TreeKillOutcome::PartialMetadata { pid: member.pid });
                }
                match stop_before_deadline(member.pid, stop_deadline, ops) {
                    TreeStopResult::Stopped { transitioned } => {
                        let mut member = member;
                        member.rollback_start_time_marker =
                            ops.rollback_identity_after_stop(member.pid, member.start_time_marker);
                        member.resume_on_cleanup = transitioned;
                        frozen.push(member);
                    }
                    TreeStopResult::NotFound => {
                        vanished.insert(member.pid);
                    }
                    TreeStopResult::Failed {
                        cleanup_required: false,
                        rollback_start_time_marker: _,
                        error,
                    } => {
                        return Err(tree_stop_error_outcome(member.pid, error));
                    }
                    TreeStopResult::Failed {
                        cleanup_required: true,
                        rollback_start_time_marker,
                        error,
                    } => {
                        let mut member = member;
                        let pid = member.pid;
                        member.rollback_start_time_marker =
                            rollback_start_time_marker.or_else(|| {
                                ops.rollback_identity_after_stop(
                                    member.pid,
                                    member.start_time_marker,
                                )
                            });
                        member.resume_on_cleanup = true;
                        frozen.push(member);
                        return Err(tree_stop_error_outcome(pid, error));
                    }
                }
            }
        }
        if !discovered_in_pass {
            return Ok(snapshot);
        }
    }
    // Never reached a clean empty pass: the member set kept changing, so we
    // cannot claim to have enumerated it completely.
    Err(TreeKillOutcome::SweepPassLimit {
        limit: MAX_FREEZE_PASSES,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_stop_error_outcome(pid: u32, error: TreeStopError) -> TreeKillOutcome {
    match error {
        TreeStopError::PermissionDenied => TreeKillOutcome::PermissionDenied { pid },
        TreeStopError::ObservationFailed(error) => TreeKillOutcome::SnapshotFailed(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unfrozen_children(index: &ProcessTreeIndex<'_>, frozen: &[FrozenNode]) -> Vec<FrozenNode> {
    let frozen_depths: HashMap<u32, usize> =
        frozen.iter().map(|node| (node.pid, node.depth)).collect();
    let mut discovered = Vec::new();
    let mut seen = frozen_depths.keys().copied().collect::<HashSet<_>>();
    let mut frontier = frozen
        .iter()
        .map(|node| (node.pid, node.depth))
        .collect::<Vec<_>>();
    while let Some((parent_pid, parent_depth)) = frontier.pop() {
        for &info in index.children(parent_pid) {
            if !seen.insert(info.pid) {
                continue;
            }
            let depth = parent_depth + 1;
            discovered.push(FrozenNode::from_info(info, depth));
            frontier.push((info.pid, depth));
        }
    }
    discovered.sort_by_key(|node| node.pid);
    discovered
}

/// Group members are a flat filter on the group ID; depth 1 keeps them grouped
/// before the confirmed root in display and delivery order. The group-specific
/// final signal step queues every terminating signal before any `SIGCONT`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unfrozen_group_members(
    snapshot: &[TreeProcessInfo],
    frozen: &[FrozenNode],
    pgid: u32,
) -> Vec<FrozenNode> {
    let frozen_pids: HashSet<u32> = frozen.iter().map(|node| node.pid).collect();
    let mut discovered: Vec<FrozenNode> = snapshot
        .iter()
        .filter(|info| info.process_group == Some(pgid) && !frozen_pids.contains(&info.pid))
        .map(|info| FrozenNode::from_info(info, 1))
        .collect();
    discovered.sort_by_key(|node| node.pid);
    discovered
}

/// Use the snapshot that proved sweep convergence to verify every frozen node.
/// A process that remains stopped cannot exec or exit on its own, so its start
/// marker and scope relation (parent PID for trees, group ID for groups) must be
/// unchanged. External signals can break that assumption; any mismatch refuses.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn verify_frozen_identities(
    frozen: &mut [FrozenNode],
    scope: SweepScope,
    snapshot: &[TreeProcessInfo],
) -> Result<(), TreeKillOutcome> {
    let index = ProcessTreeIndex::new(snapshot, PROCESS_TREE_INDEX_MAX).map_err(|error| {
        TreeKillOutcome::SnapshotFailed(format!("process index construction failed: {error:?}"))
    })?;
    for node in frozen.iter_mut() {
        let Some(info) = index.process(node.pid) else {
            return Err(TreeKillOutcome::TargetChanged { pid: node.pid });
        };
        if info.start_time_marker.is_none() || info.process_name.is_none() {
            return Err(TreeKillOutcome::PartialMetadata { pid: node.pid });
        }
        if !scope.relation_holds(node, info) || info.start_time_marker != node.start_time_marker {
            return Err(TreeKillOutcome::TargetChanged { pid: node.pid });
        }
        node.process_name.clone_from(&info.process_name);
        node.owner_uid = info.owner_uid;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_delivery_handles<Ops: TreeProcessOps>(
    frozen: &[FrozenNode],
    ops: &mut Ops,
) -> Result<(), TreeKillOutcome> {
    for node in frozen {
        match ops.prepare_delivery(node.pid, node.start_time_marker) {
            TreeSignalResult::Delivered => {}
            TreeSignalResult::NotFound => {
                return Err(TreeKillOutcome::TargetChanged { pid: node.pid });
            }
            TreeSignalResult::Denied => {
                return Err(TreeKillOutcome::PermissionDenied { pid: node.pid });
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_fresh_delivery_evidence<Ops: TreeProcessOps>(
    frozen: &mut [FrozenNode],
    ops: &mut Ops,
) -> Result<(), TreeKillOutcome> {
    let mut scope = ProcessEvidenceScope::new(frozen.len()).map_err(evidence_tree_outcome)?;
    for node in frozen {
        let expected = ExpectedProcessEvidence {
            pid: node.pid,
            start_marker: node
                .start_time_marker
                .ok_or(TreeKillOutcome::PartialMetadata { pid: node.pid })?,
            name: None,
        };
        let fresh = scope
            .observe(&expected, ops.fresh_process_evidence(node.pid))
            .map_err(evidence_tree_outcome)?;
        node.process_name = Some(fresh.name);
    }
    scope.finish().map_err(evidence_tree_outcome)
}

pub(crate) fn evidence_tree_outcome(error: ProcessEvidenceError) -> TreeKillOutcome {
    match error {
        ProcessEvidenceError::PermissionDenied { pid } => TreeKillOutcome::PermissionDenied { pid },
        ProcessEvidenceError::IdentityChanged { pid }
        | ProcessEvidenceError::NameChanged { pid }
        | ProcessEvidenceError::Missing { pid } => TreeKillOutcome::TargetChanged { pid },
        ProcessEvidenceError::NameMissing { pid }
        | ProcessEvidenceError::NameOversized { pid, .. } => {
            TreeKillOutcome::PartialMetadata { pid }
        }
        ProcessEvidenceError::IncompleteScope { .. }
        | ProcessEvidenceError::MemberLimitExceeded { .. }
        | ProcessEvidenceError::ByteLimitExceeded { .. } => TreeKillOutcome::SnapshotFailed(
            "fresh process evidence exceeded its bounded scope".to_owned(),
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_tree_policy(
    frozen: &[FrozenNode],
    scope: SweepScope,
    authorization: ScopeAuthorization,
    protected_names: &[String],
    platform: Platform,
) -> Result<(), TreeKillOutcome> {
    for node in frozen {
        if let Some(reason) = unsafe_pid_reason(node.pid) {
            return Err(TreeKillOutcome::UnsafePid {
                pid: node.pid,
                reason,
            });
        }
        if node.process_name.is_none() {
            return Err(TreeKillOutcome::PartialMetadata { pid: node.pid });
        }
    }
    // A protected descendant refuses the whole tree in v1.
    for node in frozen.iter().filter(|node| node.depth > 0) {
        if let Some(name) = node.process_name.as_deref()
            && is_protected_process_name(platform, name, protected_names)
        {
            return Err(TreeKillOutcome::ProtectedDescendant {
                pid: node.pid,
                name: Some(name.to_owned()),
            });
        }
    }
    // The root's protection is re-checked against its fresh post-stop name.
    // The confirmation-stage verdict used whatever name was readable then, but
    // `exec` swaps the name without changing the PID, parent, or start marker
    // while an unknown confirmed name makes the identity check name-blind. A
    // newly protected root requires completed protected-root confirmation.
    if !authorization.protected_root_confirmed()
        && let Some(root) = frozen.iter().find(|node| node.depth == 0)
        && let Some(name) = root.process_name.as_deref()
        && is_protected_process_name(platform, name, protected_names)
    {
        return Err(TreeKillOutcome::ProtectedRoot {
            pid: root.pid,
            name: Some(name.to_owned()),
        });
    }
    // Refuse a skipped prompt if the final frozen set no longer satisfies the
    // preview's all-clear policy.
    if authorization.prompt_skipped() {
        let system_member_appeared = frozen.iter().any(|node| {
            is_system(
                node.pid,
                node.parent_pid,
                node.parent_process_name.as_deref(),
                node.process_name.as_deref(),
                platform,
            )
        });
        let current_uid = current_user_id();
        let owner_mismatch_member_appeared = frozen.iter().any(|node| {
            node.owner_uid
                .is_some_and(|owner_uid| owner_uid != current_uid)
        });
        let group_outgrew_skip = matches!(scope, SweepScope::Group { .. })
            && frozen.len() > GROUP_YES_SKIP_MAX_PROCESSES;
        if system_member_appeared || owner_mismatch_member_appeared || group_outgrew_skip {
            return Err(TreeKillOutcome::FreshConfirmationRequired);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn signal_tree<Ops: TreeProcessOps>(
    frozen: &mut [FrozenNode],
    scope: SweepScope,
    mode: KillMode,
    ops: &mut Ops,
) -> TreeKillReport {
    // Leaves first: deepest depth first, root (depth 0) last, PID as a stable
    // tiebreak so the order is deterministic across runs and tests.
    frozen.sort_by(|left, right| right.depth.cmp(&left.depth).then(left.pid.cmp(&right.pid)));

    if matches!(scope, SweepScope::Group { .. }) {
        return signal_group(frozen, mode, ops);
    }

    let total = frozen.len();
    let mut delivered = 0;
    let mut already_exited = 0;
    let mut denied = Vec::new();
    let mut thaw_failed = Vec::new();
    for node in frozen.iter() {
        let result = ops.deliver(node.pid, mode);
        match result {
            TreeSignalResult::Delivered => {
                delivered += 1;
                if mode == KillMode::Terminate && ops.cont(node.pid) == TreeSignalResult::Denied {
                    // SIGTERM remains pending for any stopped process, including
                    // one stopped before Kickoutchi observed it.
                    thaw_failed.push(node.pid);
                }
            }
            TreeSignalResult::NotFound => already_exited += 1,
            TreeSignalResult::Denied => {
                if node.resume_on_cleanup {
                    // A denied signal leaves a process we stopped in need of
                    // cleanup. A process that was already stopped stays stopped.
                    if ops.cont(node.pid) == TreeSignalResult::Denied {
                        thaw_failed.push(node.pid);
                    }
                }
                denied.push(node.pid);
            }
        }
    }

    TreeKillReport {
        total,
        delivered,
        already_exited,
        denied,
        thaw_failed,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn signal_group<Ops: TreeProcessOps>(
    frozen: &[FrozenNode],
    mode: KillMode,
    ops: &mut Ops,
) -> TreeKillReport {
    let total = frozen.len();
    let mut delivered = 0;
    let mut already_exited = 0;
    let mut denied = Vec::new();
    let mut thaw_failed = Vec::new();
    let mut continue_after_delivery = Vec::new();

    for node in frozen {
        match ops.deliver(node.pid, mode) {
            TreeSignalResult::Delivered => {
                delivered += 1;
                if mode == KillMode::Terminate {
                    continue_after_delivery.push(node.pid);
                }
            }
            TreeSignalResult::NotFound => already_exited += 1,
            TreeSignalResult::Denied => {
                denied.push(node.pid);
                if node.resume_on_cleanup {
                    continue_after_delivery.push(node.pid);
                }
            }
        }
    }

    // Group members can have parent/child relationships even though membership
    // is flat. Queue every terminating signal before any member resumes, so a
    // parent cannot wake up and spawn survivors while children are still merely
    // frozen.
    for pid in continue_after_delivery {
        if ops.cont(pid) == TreeSignalResult::Denied {
            thaw_failed.push(pid);
        }
    }

    TreeKillReport {
        total,
        delivered,
        already_exited,
        denied,
        thaw_failed,
    }
}

/// Thaw every member Kickoutchi transitioned and report the ones that may still
/// be stopped. Members observed already stopped are left unchanged.
///
/// Only `Denied` counts as a cleanup failure, matching `signal_tree`,
/// `signal_group`, and the single-process `outcome_after_thaw`. `NotFound`
/// means the member is gone because an external `SIGKILL` removed it or macOS
/// observed a changed start marker. It cannot leave a stopped survivor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn thaw_all<Ops: TreeProcessOps>(frozen: &[FrozenNode], ops: &mut Ops) -> Vec<u32> {
    let mut failed = Vec::new();
    for node in frozen.iter().rev().filter(|node| node.resume_on_cleanup) {
        ops.prepare_thaw(node.pid, node.rollback_start_time_marker);
        if ops.cont(node.pid) == TreeSignalResult::Denied {
            failed.push(node.pid);
        }
    }
    failed.sort_unstable();
    failed
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn refuse_after_thaw<Ops: TreeProcessOps>(
    cause: TreeKillOutcome,
    frozen: &[FrozenNode],
    ops: &mut Ops,
) -> TreeKillOutcome {
    let pids = thaw_all(frozen, ops);
    if pids.is_empty() {
        cause
    } else {
        TreeKillOutcome::ThawFailed {
            pids,
            cause: Box::new(cause),
        }
    }
}
