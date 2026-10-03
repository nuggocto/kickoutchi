//! Exit-code mapping and user-facing reports for scoped kills.

#[cfg(windows)]
use std::io::{self, Write};

use crate::collector;
use crate::display::sanitize;
use crate::model::PortEntry;
use crate::process::{self, KillMode, KillTarget};
use crate::tree;
#[cfg(windows)]
use crate::tree::TreeKillOutcome as TreeRefusal;

use crate::cli::ExitReason;
use crate::cli::kill::print_post_kill_refresh_status;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::cli::settle;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn map_tree_outcome(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    post_kill: &mut PostKillIo<'_>,
) -> ExitReason {
    let scope_of_target = format!("the tree rooted at {}", root.identity());
    map_scoped_outcome(root, mode, outcome, "tree", &scope_of_target, post_kill)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn map_group_outcome(
    root: &KillTarget,
    pgid: u32,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    post_kill: &mut PostKillIo<'_>,
) -> ExitReason {
    let scope_of_target = format!("process group {pgid} of {}", root.identity());
    map_scoped_outcome(root, mode, outcome, "group", &scope_of_target, post_kill)
}

/// The reads a Unix scoped kill performs after delivery.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct PostKillIo<'a> {
    pub(super) collect_ports:
        &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    pub(super) observe_exit:
        &'a mut dyn FnMut(crate::observation::ProcessIdentity) -> process::ExitObservation,
}

/// Wait for delivered members to exit and, when asked, the root's confirmed
/// ports to clear, then print both facts.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_scoped_settle_report(
    root: &KillTarget,
    mode: KillMode,
    report: &tree::TreeKillReport,
    check_ports: bool,
    post_kill: &mut PostKillIo<'_>,
) {
    let ports: &[process::KillTargetPort] = if check_ports { &root.ports } else { &[] };
    let settled = settle::settle(
        &report.delivered_identities,
        ports,
        &mut settle::SettleProbe {
            collect_ports: post_kill.collect_ports,
            observe_exit: post_kill.observe_exit,
            sleep: &mut std::thread::sleep,
        },
    );
    for line in settle::scoped_report_lines(root, mode, report.delivered, &settled) {
        eprintln!("{line}");
    }
}

#[cfg(windows)]
pub(super) fn map_windows_tree_outcome<CollectPorts>(
    root: &KillTarget,
    _mode: KillMode,
    outcome: &crate::tree::windows::WindowsTreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    use crate::tree::windows::WindowsTreeKillOutcome;

    match outcome {
        WindowsTreeKillOutcome::Completed(report) => {
            map_windows_tree_completed_outcome(root, report, collect_ports)
        }
        _ => map_windows_tree_refusal_outcome(root, outcome, collect_ports),
    }
}

#[cfg(windows)]
pub(super) fn map_windows_tree_completed_outcome<CollectPorts>(
    root: &KillTarget,
    report: &crate::tree::windows::WindowsTreeKillReport,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    if report.termination_state.is_complete() && report.not_terminated.is_empty() {
        eprintln!(
            "terminated {} process(es) in the Windows Job Object for the tree rooted at {}",
            report.job_terminated_pids.len(),
            root.identity(),
        );
        print_post_kill_refresh_status(root, collect_ports);
        return ExitReason::Success;
    }

    eprintln!("{}", windows_tree_partial_report_text(root, report));
    if let Some(issue) = &report.post_commit_issue {
        return windows_post_commit_issue_exit_reason(issue);
    }
    if report.cleanup_issue.is_some() {
        return ExitReason::Failure;
    }
    if report.not_terminated.is_empty() {
        ExitReason::Failure
    } else {
        ExitReason::PermissionDenied
    }
}

#[cfg(windows)]
pub(super) fn windows_tree_partial_report_text(
    root: &KillTarget,
    report: &crate::tree::windows::WindowsTreeKillReport,
) -> String {
    let job = if report.job_terminated_pids.is_empty() {
        format!("job-terminated 0 of {} observed process(es)", report.total)
    } else {
        format!(
            "job-terminated {} of {} observed process(es) (PIDs: {})",
            report.job_terminated_pids.len(),
            report.total,
            tree::format_pid_list(&report.job_terminated_pids),
        )
    };
    let already_exited = if report.already_exited_pids.is_empty() {
        String::new()
    } else {
        format!(
            "; {} process(es) already exited (PIDs: {})",
            report.already_exited_pids.len(),
            tree::format_pid_list(&report.already_exited_pids),
        )
    };
    let missing = if report.not_terminated.is_empty() {
        String::new()
    } else {
        format!(
            "; PID(s) not confirmed terminated: {}",
            tree::format_pid_list(&report.not_terminated)
        )
    };
    let withheld = if report.termination_state.is_withheld() {
        "; job termination was withheld because strict tree closure could not be established for every observed descendant"
    } else {
        ""
    };
    let post_commit_issue = report
        .post_commit_issue
        .as_ref()
        .map_or_else(String::new, |issue| {
            format!(
                "; post-commit issue: {}",
                windows_post_commit_issue_text(issue)
            )
        });
    let secondary_post_commit_issue =
        report
            .secondary_post_commit_issue
            .as_ref()
            .map_or_else(String::new, |issue| {
                format!(
                    "; secondary post-commit issue: {}",
                    windows_post_commit_issue_text(issue)
                )
            });
    let cleanup_issue = report
        .cleanup_issue
        .as_ref()
        .map_or_else(String::new, |issue| {
            format!("; cleanup issue: {}", windows_cleanup_issue_text(issue))
        });
    format!(
        "warning: Windows tree containment was partial for {}; {job}{already_exited}{missing}{withheld}{post_commit_issue}{secondary_post_commit_issue}{cleanup_issue}",
        root.identity(),
    )
}

#[cfg(windows)]
fn windows_cleanup_issue_text(issue: &crate::tree::windows::WindowsTreeCleanupIssue) -> String {
    use crate::tree::windows::WindowsTreeCleanupIssue;

    match issue {
        WindowsTreeCleanupIssue::WithheldJobThawFailed(error) => format!(
            "thawing the withheld Windows Job Object failed: {}",
            sanitize(error)
        ),
        WindowsTreeCleanupIssue::FailedTerminationThawFailed(error) => format!(
            "thawing the Windows Job Object after TerminateJobObject failed: {}",
            sanitize(error)
        ),
        WindowsTreeCleanupIssue::PostTerminationSurvivorsThawed { pids, wait_errors } => format!(
            "TerminateJobObject returned success but PID(s) {} were not confirmed exited; the job was thawed{}",
            tree::format_pid_list(pids),
            windows_wait_error_suffix(wait_errors),
        ),
        WindowsTreeCleanupIssue::PostTerminationSurvivorThawFailed {
            pids,
            wait_errors,
            error,
        } => format!(
            "TerminateJobObject returned success but PID(s) {} were not confirmed exited, and thawing the job failed: {}{}",
            tree::format_pid_list(pids),
            sanitize(error),
            windows_wait_error_suffix(wait_errors),
        ),
    }
}

#[cfg(windows)]
fn windows_wait_error_suffix(wait_errors: &[(u32, String)]) -> String {
    if wait_errors.is_empty() {
        return String::new();
    }
    let details = wait_errors
        .iter()
        .map(|(pid, error)| format!("PID {pid}: {}", sanitize(error)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("; wait error(s): {details}")
}

#[cfg(windows)]
pub(super) fn windows_post_commit_issue_text(
    issue: &crate::tree::windows::WindowsTreePostCommitIssue,
) -> String {
    use crate::tree::windows::WindowsTreePostCommitIssue;

    match issue {
        WindowsTreePostCommitIssue::RootAlreadyExited => {
            "root exited during the containment sweep".to_owned()
        }
        WindowsTreePostCommitIssue::PermissionDenied { pid } => {
            format!("permission denied for PID {pid} during the containment sweep")
        }
        WindowsTreePostCommitIssue::TargetChanged { pid } => {
            format!("process identity changed at PID {pid} during the containment sweep")
        }
        WindowsTreePostCommitIssue::Truncated { limit } => {
            format!("tree exceeded {limit} processes after containment was committed")
        }
        WindowsTreePostCommitIssue::SweepPassLimit { limit } => {
            format!("tree did not converge after {limit} containment sweeps")
        }
        WindowsTreePostCommitIssue::UnsafePid { pid, reason } => {
            format!(
                "unsafe PID {pid} appeared after commit: {}",
                reason.message()
            )
        }
        WindowsTreePostCommitIssue::ProtectedDescendant { pid, name } => format!(
            "protected descendant PID {pid} ({}) appeared after commit",
            sanitize(name.as_deref().unwrap_or("<unknown>"))
        ),
        WindowsTreePostCommitIssue::ProtectedRoot { pid, name } => format!(
            "root PID {pid} ({}) became protected after commit and requires fresh confirmation",
            sanitize(name.as_deref().unwrap_or("<unknown>"))
        ),
        WindowsTreePostCommitIssue::FreshConfirmationRequired => {
            "tree gained warnings after --yes; rerun without --yes to review them".to_owned()
        }
        WindowsTreePostCommitIssue::OwnershipUnavailable { pid } => {
            format!("ownership for PID {pid} became unavailable after containment was committed")
        }
        WindowsTreePostCommitIssue::PartialMetadata { pid } => {
            format!("process metadata for PID {pid} became incomplete during the containment sweep")
        }
        WindowsTreePostCommitIssue::SnapshotFailed(error) => format!(
            "enumerating the Windows process tree failed after commit: {}",
            sanitize(error)
        ),
    }
}

#[cfg(windows)]
pub(super) fn windows_post_commit_issue_exit_reason(
    issue: &crate::tree::windows::WindowsTreePostCommitIssue,
) -> ExitReason {
    use crate::tree::windows::WindowsTreePostCommitIssue;

    match issue {
        WindowsTreePostCommitIssue::ProtectedDescendant { .. }
        | WindowsTreePostCommitIssue::ProtectedRoot { .. } => {
            ExitReason::ProtectedNeedsConfirmation
        }
        WindowsTreePostCommitIssue::PermissionDenied { .. }
        | WindowsTreePostCommitIssue::OwnershipUnavailable { .. } => ExitReason::PermissionDenied,
        WindowsTreePostCommitIssue::RootAlreadyExited
        | WindowsTreePostCommitIssue::TargetChanged { .. }
        | WindowsTreePostCommitIssue::Truncated { .. }
        | WindowsTreePostCommitIssue::SweepPassLimit { .. }
        | WindowsTreePostCommitIssue::UnsafePid { .. }
        | WindowsTreePostCommitIssue::FreshConfirmationRequired
        | WindowsTreePostCommitIssue::PartialMetadata { .. }
        | WindowsTreePostCommitIssue::SnapshotFailed(_) => ExitReason::Failure,
    }
}

#[cfg(windows)]
fn map_windows_tree_refusal_outcome<CollectPorts>(
    root: &KillTarget,
    outcome: &crate::tree::windows::WindowsTreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    use crate::tree::windows::WindowsTreeKillOutcome;

    match outcome {
        WindowsTreeKillOutcome::Completed(_) => unreachable!("completed outcome handled above"),
        WindowsTreeKillOutcome::Refused(refusal) => {
            map_windows_tree_refusal(root, refusal, collect_ports)
        }
        WindowsTreeKillOutcome::CommitFailed { .. }
        | WindowsTreeKillOutcome::FreezeCapabilityUnavailable { .. }
        | WindowsTreeKillOutcome::JobTerminateFailed { .. } => {
            let mut stderr = io::stderr().lock();
            map_windows_tree_system_failure(root, outcome, collect_ports, &mut stderr)
        }
    }
}

#[cfg(windows)]
fn map_windows_tree_refusal(
    root: &KillTarget,
    refusal: &TreeRefusal,
    collect_ports: &mut impl FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
) -> ExitReason {
    let cause = sanitize(&refusal.failure_cause_text());
    match refusal {
        TreeRefusal::RootAlreadyExited => {
            eprintln!(
                "{} already exited before containment was committed",
                root.identity(),
            );
            print_post_kill_refresh_status(root, collect_ports);
        }
        TreeRefusal::PermissionDenied { .. } => {
            eprintln!(
                "error: {cause}; no Windows Job Object containment was committed; {}",
                process::permission_denied_hint(root.platform),
            );
        }
        TreeRefusal::TargetChanged { .. }
        | TreeRefusal::SweepPassLimit { .. }
        | TreeRefusal::UnsafePid { .. }
        | TreeRefusal::ProtectedDescendant { .. } => {
            eprintln!("error: {cause}; no Windows Job Object containment was committed");
        }
        TreeRefusal::Truncated { .. } => {
            eprintln!("error: {cause}; refusing to commit a partial Windows process tree");
        }
        TreeRefusal::ProtectedRoot { .. } => {
            eprintln!(
                "error: {cause} and requires PID/name confirmation before Windows containment",
            );
        }
        TreeRefusal::FreshConfirmationRequired => {
            eprintln!(
                "error: {cause}; rerun without --yes to review fresh warnings; no containment was committed",
            );
        }
        TreeRefusal::OwnershipUnavailable { .. } | TreeRefusal::PartialMetadata { .. } => {
            eprintln!("error: {cause} before Windows containment; no termination was sent");
        }
        TreeRefusal::SnapshotFailed(_) => {
            eprintln!(
                "error: enumerating the Windows process tree failed: {cause}; no termination was sent",
            );
        }
    }

    tree_refusal_exit_reason(refusal)
}

#[cfg(windows)]
pub(super) fn map_windows_tree_system_failure(
    root: &KillTarget,
    outcome: &crate::tree::windows::WindowsTreeKillOutcome,
    collect_ports: &mut impl FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    stderr: &mut impl Write,
) -> ExitReason {
    use crate::tree::windows::WindowsTreeKillOutcome;

    match outcome {
        WindowsTreeKillOutcome::CommitFailed { pid, error } => {
            let _ = writeln!(
                stderr,
                "error: assigning root PID {pid} to the Windows Job Object failed before commit: {}; no termination was sent",
                sanitize(error),
            );
            ExitReason::Failure
        }
        WindowsTreeKillOutcome::FreezeCapabilityUnavailable { error } => {
            let _ = writeln!(
                stderr,
                "error: Windows Job Object freeze/thaw capability is unavailable: {}; no containment was committed and no termination was sent",
                sanitize(error),
            );
            ExitReason::Failure
        }
        WindowsTreeKillOutcome::JobTerminateFailed { error, report } => {
            let _ = writeln!(
                stderr,
                "error: Windows Job Object containment was committed but TerminateJobObject failed: {}",
                sanitize(error),
            );
            let _ = writeln!(stderr, "{}", windows_tree_partial_report_text(root, report));
            if let Some(message) =
                crate::cli::settle::ports_only_status_message(root, collect_ports)
            {
                let _ = writeln!(stderr, "{message}");
            }
            ExitReason::Failure
        }
        WindowsTreeKillOutcome::Completed(_) | WindowsTreeKillOutcome::Refused(_) => {
            unreachable!("non-system Windows tree outcome handled above")
        }
    }
}

/// Shared success/partial-success wording for tree and group delivery reports.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scoped_delivery_summary(
    delivery: &str,
    scope_noun: &str,
    scope_of_target: &str,
    report: &tree::TreeKillReport,
) -> String {
    if report.denied.is_empty() && report.already_exited == 0 {
        return format!(
            "sent {delivery} to {} process(es) in {scope_of_target}",
            report.delivered,
        );
    }

    let exited_suffix = if report.already_exited == 0 {
        String::new()
    } else {
        format!(
            "; {} already exited before final delivery",
            report.already_exited
        )
    };
    let denied_suffix = if report.denied.is_empty() {
        String::new()
    } else {
        format!(
            "; permission denied for PID(s): {}",
            tree::format_pid_list(&report.denied)
        )
    };
    format!(
        "sent {delivery} to {} of {} {scope_noun} process(es){exited_suffix}{denied_suffix}",
        report.delivered, report.total,
    )
}

/// Print the outcome of a scoped (tree or group) kill and map it to the exit
/// contract. One function for both scopes so a refusal can never exit with
/// different codes depending on how the same processes were targeted;
/// `scope_noun` and `scope_of_target` only shape the wording.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive typed scoped-outcome mapping is intentionally centralized"
)]
fn map_scoped_outcome(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    scope_noun: &str,
    scope_of_target: &str,
    post_kill: &mut PostKillIo<'_>,
) -> ExitReason {
    use crate::tree::TreeKillOutcome;

    let delivery = mode.delivery_label(root.platform);
    match outcome {
        TreeKillOutcome::ThawFailed { pids, cause } => {
            eprintln!(
                "error: {}; cleanup could not continue PID(s) {}; they may remain stopped and require SIGCONT",
                sanitize(&cause.failure_cause_text()),
                tree::format_pid_list(pids),
            );
            ExitReason::Failure
        }
        TreeKillOutcome::Completed(report)
            if report.denied.is_empty() && report.thaw_failed.is_empty() =>
        {
            eprintln!(
                "{}",
                scoped_delivery_summary(delivery, scope_noun, scope_of_target, report)
            );
            print_scoped_settle_report(root, mode, report, true, post_kill);
            ExitReason::Success
        }
        TreeKillOutcome::Completed(report) => {
            eprintln!(
                "{}",
                scoped_delivery_summary(delivery, scope_noun, scope_of_target, report)
            );
            // Denied or stopped members can keep ports open, so only exits of
            // the delivered members are worth reporting here.
            print_scoped_settle_report(root, mode, report, false, post_kill);
            if report.thaw_failed.is_empty() {
                ExitReason::PermissionDenied
            } else {
                eprintln!(
                    "error: PID(s) {} may remain stopped because SIGCONT failed",
                    tree::format_pid_list(&report.thaw_failed),
                );
                ExitReason::Failure
            }
        }
        TreeKillOutcome::RootAlreadyExited => {
            eprintln!(
                "{} already exited before termination was sent",
                root.identity(),
            );
            print_post_kill_refresh_status(root, post_kill.collect_ports);
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::PermissionDenied { .. } => {
            eprintln!(
                "error: {}; any frozen process was thawed and no termination was sent; {}",
                sanitize(&outcome.failure_cause_text()),
                process::permission_denied_hint(root.platform),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::TargetChanged { .. } | TreeKillOutcome::SweepPassLimit { .. } => {
            eprintln!(
                "error: {}; the process {scope_noun} was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::Truncated { .. } | TreeKillOutcome::ProtectedDescendant { .. } => {
            eprintln!(
                "error: {}; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::UnsafePid { .. } => {
            eprintln!(
                "error: {} in {scope_noun}; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::ProtectedRoot { .. } => {
            eprintln!(
                "error: {} and requires PID/name confirmation; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::FreshConfirmationRequired => {
            eprintln!(
                "error: {}; rerun without --yes to review fresh warnings; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::OwnershipUnavailable { .. } => {
            eprintln!(
                "error: {} before {delivery}; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::PartialMetadata { .. } => {
            eprintln!(
                "error: {} during {scope_noun} verification; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::SnapshotFailed(_) => {
            eprintln!(
                "error: enumerating the process {scope_noun} during termination failed: {}; no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
    }
}

fn tree_refusal_exit_reason(outcome: &tree::TreeKillOutcome) -> ExitReason {
    match outcome.refusal_class() {
        Some(tree::TreeRefusalClass::NoMatch) => ExitReason::NoMatch,
        Some(tree::TreeRefusalClass::PermissionDenied) => ExitReason::PermissionDenied,
        Some(tree::TreeRefusalClass::ProtectedNeedsConfirmation) => {
            ExitReason::ProtectedNeedsConfirmation
        }
        Some(tree::TreeRefusalClass::Failure) => ExitReason::Failure,
        None => unreachable!("completed or cleanup outcomes are not refusals"),
    }
}
