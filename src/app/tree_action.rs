//! Tree-kill planning and status presentation for the TUI.

use crate::model::Platform;
use crate::process::{KillMode, KillTarget};
use crate::tree::{self, TreeProcessOps};

use super::{TreeKillConfirmation, TreePreviewResult};

/// Result of one Enter press, computed before mutating confirmation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TreeSubmitVerdict {
    Execute,
    AdvanceToWord,
    Reject(String),
}

/// Build the platform's real tree ops. One place, so the worker thread and the
/// execution path can never disagree about which implementation the host uses.
#[cfg(target_os = "linux")]
pub(super) fn host_tree_ops() -> crate::platform::linux::LinuxTreeOps {
    crate::platform::linux::LinuxTreeOps::new()
}

#[cfg(target_os = "macos")]
pub(super) fn host_tree_ops() -> crate::platform::macos::MacosTreeOps {
    crate::platform::macos::MacosTreeOps::new()
}

/// One preview enumeration, run on the worker thread.
pub(super) fn collect_tree_preview(
    root_pid: u32,
    protected_names: &[String],
    platform: Platform,
) -> TreePreviewResult {
    let mut ops = host_tree_ops();
    ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree { root_pid });
    let snapshot = ops.snapshot()?;
    tree::plan_process_tree(
        root_pid,
        &snapshot,
        protected_names,
        platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(|error| match error {
        tree::TreePlanError::RootMissing => {
            "root process is no longer running; nothing to terminate".to_owned()
        }
        tree::TreePlanError::SnapshotLimitExceeded { limit } => {
            format!("process snapshot exceeds the bounded {limit}-PID index")
        }
    })
}

/// Fresh pre-freeze gates for the TUI execution path: rebuild the tree from a
/// fresh snapshot and re-run the preflight and root-protection rules, mapped
/// into the shared outcome vocabulary.
///
/// `confirmation.target.protected` is true only when the protected-root stage
/// was actually walked (set at request time or upgraded by the preview); a
/// root the fresh scan newly classifies as protected, such as one that exec'd
/// into a protected name with the same PID and start marker, must be refused
/// unless protected-root confirmation was completed.
pub(super) fn fresh_tree_gates<Ops: TreeProcessOps>(
    fresh_root: &KillTarget,
    protected_processes: &[String],
    confirmation: &TreeKillConfirmation,
    ops: &mut Ops,
) -> Result<(), tree::TreeKillOutcome> {
    ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree {
        root_pid: fresh_root.pid,
    });
    let snapshot = ops
        .snapshot()
        .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
    let fresh_preview = tree::plan_process_tree(
        fresh_root.pid,
        &snapshot,
        protected_processes,
        fresh_root.platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(tree::plan_error_outcome)?;
    tree::preflight_outcome(&fresh_preview)?;
    tree::root_protection_outcome(&fresh_preview, confirmation.target.protected)?;
    Ok(())
}

/// Status-bar wording for tree outcomes. It reports the same facts as the
/// CLI's stderr wording; recovery instructions precede PID lists so a long
/// list cannot push them out of the bounded status area.
pub(super) fn tree_kill_status_line(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
) -> String {
    use crate::display::sanitize;
    use crate::tree::TreeKillOutcome;

    let delivery = mode.delivery_label(root.platform);
    match outcome {
        TreeKillOutcome::ThawFailed { pids, cause } => format!(
            "{}; cleanup failed, so these PID(s) may remain stopped and require SIGCONT: {}",
            sanitize(&cause.failure_cause_text()),
            tree::format_pid_list(pids),
        ),
        TreeKillOutcome::Completed(report) if !report.thaw_failed.is_empty() => format!(
            "sent {delivery}, but SIGCONT failed, so these PID(s) may remain stopped: {}",
            tree::format_pid_list(&report.thaw_failed),
        ),
        TreeKillOutcome::Completed(report)
            if report.denied.is_empty() && report.already_exited == 0 =>
        {
            format!(
                "sent {delivery} to {} process(es) in the tree rooted at {}",
                report.delivered,
                root.identity(),
            )
        }
        TreeKillOutcome::Completed(report) if report.denied.is_empty() => format!(
            "sent {delivery} to {} of {} tree process(es); {} already exited before final delivery",
            report.delivered, report.total, report.already_exited,
        ),
        TreeKillOutcome::Completed(report) => {
            let exited_suffix = if report.already_exited == 0 {
                String::new()
            } else {
                format!(
                    "; {} already exited before final delivery",
                    report.already_exited
                )
            };
            format!(
                "sent {delivery} to {} of {} tree process(es){exited_suffix}; permission denied for PID(s): {}",
                report.delivered,
                report.total,
                tree::format_pid_list(&report.denied),
            )
        }
        TreeKillOutcome::RootAlreadyExited => format!(
            "{} already exited before termination was sent",
            root.identity(),
        ),
        TreeKillOutcome::PermissionDenied { .. }
        | TreeKillOutcome::TargetChanged { .. }
        | TreeKillOutcome::SweepPassLimit { .. } => format!(
            "{}; the tree was thawed and no termination was sent",
            sanitize(&outcome.failure_cause_text()),
        ),
        TreeKillOutcome::Truncated { .. } => format!(
            "{}; refusing to kill a partial tree",
            sanitize(&outcome.failure_cause_text()),
        ),
        TreeKillOutcome::UnsafePid { .. }
        | TreeKillOutcome::ProtectedDescendant { .. }
        | TreeKillOutcome::FreshConfirmationRequired => format!(
            "{}; no termination was sent",
            sanitize(&outcome.failure_cause_text()),
        ),
        TreeKillOutcome::ProtectedRoot { .. } => format!(
            "{} and requires PID/name confirmation; no termination was sent",
            sanitize(&outcome.failure_cause_text()),
        ),
        TreeKillOutcome::OwnershipUnavailable { .. } => format!(
            "{} before {delivery}; no termination was sent",
            sanitize(&outcome.failure_cause_text()),
        ),
        TreeKillOutcome::PartialMetadata { .. } => format!(
            "{} during tree verification; the tree was thawed and no termination was sent",
            sanitize(&outcome.failure_cause_text()),
        ),
        TreeKillOutcome::SnapshotFailed(_) => format!(
            "enumerating the process tree during termination failed: {}; no termination was sent",
            sanitize(&outcome.failure_cause_text()),
        ),
    }
}
