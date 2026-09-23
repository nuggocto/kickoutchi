//! Scoped `--tree` and `--group` kills.
//!
//! One confirmed root authorizes a bounded process set. Unix uses freeze-first
//! execution; Windows uses Job Object containment.

use std::io::Write;

use crate::collector;
use crate::config::Config;
use crate::display::sanitize;
use crate::model::{
    PermissionStatus, Platform, PortEntry, PortEntryView, ProcessContext, SystemProcessCheck,
};
use crate::observation::MetadataProfile;
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome,
};
use crate::tree;
#[cfg(windows)]
use crate::tree::TreeKillOutcome as TreeRefusal;

use super::kill::{
    KillTargetError, print_target_error, read_confirmation_line, resolve_kill_target,
    revalidate_cli_target,
};
use super::{ExitReason, KillArgs, TREE_HOST_PLATFORM};

/// Longest child preview printed in the tree confirmation banner.
const TREE_PREVIEW_MAX: usize = 12;

/// What the user must do to authorize a tree kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeConfirmation {
    /// Type a literal word (`tree` for terminate, `force` for force).
    TypedWord(&'static str),
    /// The root is protected: type its PID or process name, as with a
    /// single-process protected kill.
    ProtectedRoot,
}

/// The confirmation gate for a tree kill, decided before the prompt is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeConfirmDecision {
    /// `--yes` on an all-clear tree: proceed without a prompt.
    Skip,
    /// Ask the user to satisfy this requirement.
    PromptWord(&'static str),
    /// Protected root requires the protected confirmation and then the tree word.
    PromptProtectedThenWord(&'static str),
    /// `--yes` cannot authorize a protected root: refuse.
    RefuseProtectedYes,
}

/// Collection and confirmation operations shared by tree and group commands.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TreeKillIo<'a> {
    collect_context: &'a mut dyn FnMut(u32) -> ProcessContext,
    prompt: &'a mut dyn FnMut(
        &KillTarget,
        &tree::ProcessTreeTarget,
        TreeConfirmation,
    ) -> std::io::Result<bool>,
    collect_kill_ports: &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    collect_ports: &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn run_tree_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    run_tree_kill_with(
        args,
        config,
        entries,
        mode,
        &mut ops,
        TreeKillIo {
            collect_context: &mut platform::collect_process_context,
            prompt: &mut prompt_tree_confirmation,
            collect_kill_ports: &mut || collector::collect_kill_ports(args.pid, args.port),
            collect_ports: &mut || {
                collector::collect_ports_with_profile(MetadataProfile::IdentityOnly)
            },
        },
    )
}

#[cfg(windows)]
pub(super) fn run_tree_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    run_windows_tree_kill(args, config, entries, mode)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_tree_kill_with<Ops>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
    ops: &mut Ops,
    mut io: TreeKillIo<'_>,
) -> ExitReason
where
    Ops: tree::TreeProcessOps,
{
    // The preview drives the banner and side-effect-free preflight checks.
    // Execution enumerates again after freezing.
    let snapshot = match ops.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process tree failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    let root =
        match resolve_scoped_kill_root(args, config, entries, &snapshot, &mut io.collect_context) {
            Ok(target) => target,
            Err(reason) => return reason,
        };
    let preview = match plan_tree_preview(&root, &snapshot, &config.protected_processes) {
        Ok(preview) => preview,
        Err(reason) => return reason,
    };

    if let Some(reason) = scoped_preflight_refusal(&preview, "tree") {
        return reason;
    }

    let confirmation = match confirm_tree_kill(&root, &preview, mode, args.yes, &mut io.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    if let Err(outcome) = tree::pin_root_before_revalidation(root.pid, ops) {
        return map_tree_outcome(&root, mode, &outcome, &mut io.collect_ports);
    }

    let fresh_root = match revalidate_tree_root_before_freeze(
        args,
        config,
        &root,
        confirmation,
        &mut io.collect_context,
        &mut io.collect_kill_ports,
        ops,
    ) {
        Ok(root) => root,
        Err(outcome) => return map_tree_outcome(&root, mode, &outcome, &mut io.collect_ports),
    };

    let outcome = tree::execute_tree_kill(
        &fresh_root,
        mode,
        &config.protected_processes,
        fresh_root.platform,
        confirmation,
        ops,
    );
    map_tree_outcome(&fresh_root, mode, &outcome, &mut io.collect_ports)
}

#[cfg(windows)]
fn run_windows_tree_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
) -> ExitReason {
    run_windows_tree_kill_with(
        args,
        config,
        entries,
        mode,
        WindowsTreeKillIo {
            collect_tree: &mut crate::platform::windows::collect_tree_process_infos,
            collect_context: &mut platform::collect_process_context,
            prompt: &mut prompt_tree_confirmation,
            collect_kill_ports: &mut || collector::collect_kill_ports(args.pid, args.port),
            collect_ports: &mut || {
                collector::collect_ports_with_profile(MetadataProfile::IdentityOnly)
            },
            prepare_root: &mut process::prepare_termination,
            execute: &mut crate::tree::windows::execute_tree_kill,
        },
    )
}

#[cfg(windows)]
struct WindowsTreeKillIo<'a, RootHandle> {
    collect_tree:
        &'a mut dyn FnMut() -> Result<Vec<tree::TreeProcessInfo>, collector::CollectorError>,
    collect_context: &'a mut dyn FnMut(u32) -> ProcessContext,
    prompt: &'a mut dyn FnMut(
        &KillTarget,
        &tree::ProcessTreeTarget,
        TreeConfirmation,
    ) -> std::io::Result<bool>,
    collect_kill_ports: &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    collect_ports: &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    prepare_root: &'a mut dyn FnMut(u32) -> Result<RootHandle, TerminationOutcome>,
    execute: &'a mut dyn FnMut(
        &KillTarget,
        &[String],
        tree::ScopeAuthorization,
    ) -> crate::tree::windows::WindowsTreeKillOutcome,
}

#[cfg(windows)]
fn run_windows_tree_kill_with<RootHandle>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
    mut io: WindowsTreeKillIo<'_, RootHandle>,
) -> ExitReason {
    let snapshot = match (io.collect_tree)() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("error: enumerating the process table failed: {error}");
            return ExitReason::Failure;
        }
    };
    let root =
        match resolve_scoped_kill_root(args, config, entries, &snapshot, &mut io.collect_context) {
            Ok(target) => target,
            Err(reason) => return reason,
        };
    let preview = match plan_tree_preview(&root, &snapshot, &config.protected_processes) {
        Ok(preview) => preview,
        Err(reason) => return reason,
    };

    if let Some(reason) = scoped_preflight_refusal(&preview, "tree") {
        return reason;
    }

    let confirmation = match confirm_tree_kill(&root, &preview, mode, args.yes, &mut io.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    // A port-selected root must be retained before the final authoritative
    // endpoint collection. PID mode keeps its existing path.
    let prepared_root = if args.port.is_some() {
        match (io.prepare_root)(root.pid) {
            Ok(handle) => Some(handle),
            Err(outcome) => {
                let outcome = crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome(
                    tree_outcome_from_termination(&root, outcome),
                );
                return map_windows_tree_outcome(&root, mode, &outcome, &mut io.collect_ports);
            }
        }
    } else {
        None
    };

    let fresh_root = match revalidate_windows_tree_root_before_commit(
        args,
        config,
        &root,
        confirmation,
        &mut io.collect_tree,
        &mut io.collect_context,
        &mut io.collect_kill_ports,
    ) {
        Ok(root) => root,
        Err(outcome) => {
            return map_windows_tree_outcome(&root, mode, &outcome, &mut io.collect_ports);
        }
    };

    let outcome = (io.execute)(&fresh_root, &config.protected_processes, confirmation);
    drop(prepared_root);
    map_windows_tree_outcome(&fresh_root, mode, &outcome, &mut io.collect_ports)
}

#[cfg(windows)]
fn revalidate_windows_tree_root_before_commit<CollectTree, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmation: tree::ScopeAuthorization,
    collect_tree: &mut CollectTree,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
) -> Result<KillTarget, crate::tree::windows::WindowsTreeKillOutcome>
where
    CollectTree: FnMut() -> Result<Vec<tree::TreeProcessInfo>, collector::CollectorError>,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        let snapshot = collect_tree().map_err(|error| {
            crate::tree::windows::WindowsTreeKillOutcome::snapshot_failed(error.to_string())
        })?;
        let root = revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)
            .map_err(crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome)?;
        windows_fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| {
            let outcome = tree_outcome_from_termination(confirmed, outcome);
            crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome(outcome)
        })?;
        let snapshot = collect_tree().map_err(|error| {
            crate::tree::windows::WindowsTreeKillOutcome::snapshot_failed(error.to_string())
        })?;
        windows_fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    };
    Ok(fresh_root)
}

#[cfg(windows)]
fn windows_fresh_tree_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmation: tree::ScopeAuthorization,
) -> Result<(), crate::tree::windows::WindowsTreeKillOutcome> {
    let preview = tree::plan_process_tree(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(tree::plan_error_outcome)
    .map_err(crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome)?;
    tree::preflight_outcome(&preview)
        .map_err(crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome)?;
    tree::root_protection_outcome(&preview, confirmation.protected_root_confirmed())
        .map_err(crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome)?;
    fresh_tree_yes_outcome(root, &preview, confirmation)
        .map_err(crate::tree::windows::WindowsTreeKillOutcome::from_precommit_outcome)?;
    if let Some(pid) = preview
        .preview_nodes(preview.len())
        .iter()
        .find_map(|node| {
            let info = snapshot.iter().find(|info| info.pid == node.pid)?;
            (info.process_name.is_none() || info.start_time_marker.is_none()).then_some(info.pid)
        })
    {
        return Err(crate::tree::windows::WindowsTreeKillOutcome::Refused(
            TreeRefusal::PartialMetadata { pid },
        ));
    }
    Ok(())
}

/// Plan the tree shown for confirmation. Refusals are printed here and
/// returned as the exit reason.
fn plan_tree_preview(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<tree::ProcessTreeTarget, ExitReason> {
    tree::plan_process_tree(
        root.pid,
        snapshot,
        protected_names,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(|error| match error {
        tree::TreePlanError::RootMissing => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            ExitReason::NoMatch
        }
        tree::TreePlanError::SnapshotLimitExceeded { limit } => {
            eprintln!("error: process snapshot exceeds the bounded {limit}-PID index");
            ExitReason::Failure
        }
    })
}

/// Run the confirmation flow. On success, the returned authorization records
/// whether the protected-root confirmation was completed. The execution-time
/// protection guard needs that fact, because a root can be classified as
/// protected by a fresh scan even when the confirmed port row could not be.
fn confirm_tree_kill<Prompt>(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    mode: KillMode,
    yes: bool,
    prompt: &mut Prompt,
) -> Result<tree::ScopeAuthorization, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    confirm_scoped_kill(
        root,
        preview,
        tree_confirmation(root, preview, mode, yes),
        || print_tree_kill_banner(root, preview, mode),
        prompt,
    )
}

/// Execute the confirmation decision shared by tree and group scope.
///
/// Scope-specific policy selects the banner and requirement. This helper keeps
/// prompt ordering identical and records facts for revalidation.
fn confirm_scoped_kill<Prompt, PrintBanner>(
    root: &KillTarget,
    members: &tree::ProcessTreeTarget,
    decision: TreeConfirmDecision,
    print_banner: PrintBanner,
    prompt: &mut Prompt,
) -> Result<tree::ScopeAuthorization, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    PrintBanner: FnOnce(),
{
    if decision == TreeConfirmDecision::RefuseProtectedYes {
        eprintln!(
            "error: {} is protected; --yes cannot bypass protected-process confirmation",
            root.identity(),
        );
        return Err(ExitReason::ProtectedNeedsConfirmation);
    }

    print_banner();
    match decision {
        TreeConfirmDecision::RefuseProtectedYes => {
            unreachable!("protected --yes refusal returned before printing a banner")
        }
        TreeConfirmDecision::Skip => Ok(tree::ScopeAuthorization::SkippedAllClear),
        TreeConfirmDecision::PromptWord(word) => {
            prompt_tree_step(root, members, TreeConfirmation::TypedWord(word), prompt)?;
            Ok(tree::ScopeAuthorization::TypedWordConfirmed)
        }
        TreeConfirmDecision::PromptProtectedThenWord(word) => {
            prompt_tree_step(root, members, TreeConfirmation::ProtectedRoot, prompt)?;
            prompt_tree_step(root, members, TreeConfirmation::TypedWord(word), prompt)?;
            Ok(tree::ScopeAuthorization::ProtectedRootAndWordConfirmed)
        }
    }
}

fn prompt_tree_step<Prompt>(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
    prompt: &mut Prompt,
) -> Result<(), ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    let confirmed = match prompt(root, preview, requirement) {
        Ok(confirmed) => confirmed,
        Err(error) => {
            eprintln!("error: reading confirmation failed: {error}");
            return Err(ExitReason::Failure);
        }
    };
    if confirmed {
        Ok(())
    } else {
        eprintln!("kill cancelled");
        Err(ExitReason::KillCancelled)
    }
}

/// Resolve the confirmed root for a scoped (tree or group) kill.
///
/// Port targets resolve through the socket table exactly like a single kill;
/// a `--pid` target that owns no visible port falls back to the process-table
/// snapshot, because scoped kills legitimately start from portless
/// supervisors. Refusals are printed here and returned as the exit reason.
fn resolve_scoped_kill_root<CollectContext>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    snapshot: &[tree::TreeProcessInfo],
    collect_context: &mut CollectContext,
) -> Result<KillTarget, ExitReason>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    match (
        resolve_kill_target(args, entries, collect_context),
        args.pid,
    ) {
        (Ok(target), _) => Ok(target),
        (Err(KillTargetError::NoMatch), Some(pid)) => {
            match resolve_pid_tree_root_from_snapshot(pid, snapshot, &config.protected_processes) {
                Ok(target) => Ok(target),
                Err(KillTargetError::NoMatch) => {
                    eprintln!("error: root PID {pid} is no longer running; nothing to terminate");
                    Err(ExitReason::NoMatch)
                }
                Err(error) => Err(print_target_error(error)),
            }
        }
        (Err(KillTargetError::NoMatch), None) => {
            eprintln!("error: no open port matches the requested target");
            Err(ExitReason::NoMatch)
        }
        (Err(error), _) => Err(print_target_error(error)),
    }
}

fn resolve_pid_tree_root_from_snapshot(
    pid: u32,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<KillTarget, KillTargetError> {
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }
    let Some(info) = snapshot.iter().find(|info| info.pid == pid) else {
        return Err(KillTargetError::NoMatch);
    };
    Ok(kill_target_from_tree_info(info, protected_names))
}

fn kill_target_from_tree_info(
    info: &tree::TreeProcessInfo,
    protected_names: &[String],
) -> KillTarget {
    let protected = info.process_name.as_deref().is_some_and(|name| {
        crate::protection::is_protected_process_name(TREE_HOST_PLATFORM, name, protected_names)
    });
    let system_process = SystemProcessCheck {
        platform: TREE_HOST_PLATFORM,
        pid: Some(info.pid),
        parent_pid: info.parent_pid,
        process_name: info.process_name.as_deref(),
        parent_process_name: info.parent_process_name.as_deref(),
    }
    .is_system_process();
    // Identity fields determine metadata completeness. Owner UID is retained for
    // warnings, but a missing UID alone does not make metadata partial.
    let complete = info.process_name.is_some() && info.start_time_marker.is_some();
    KillTarget {
        pid: info.pid,
        process_name: info.process_name.clone(),
        platform: TREE_HOST_PLATFORM,
        permission: if complete {
            PermissionStatus::Full
        } else {
            PermissionStatus::Partial
        },
        protected,
        system_process,
        ports: Vec::new(),
        owner_uid: info.owner_uid,
        process_start_time_marker: info.start_time_marker,
        child_count: 0,
        children_truncated: false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_tree_root_before_freeze<Ops, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmation: tree::ScopeAuthorization,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    ops: &mut Ops,
) -> Result<KillTarget, tree::TreeKillOutcome>
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree {
            root_pid: confirmed.pid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let root =
            revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)?;
        fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| tree_outcome_from_termination(confirmed, outcome))?;
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree { root_pid: root.pid });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    };
    Ok(fresh_root)
}

/// The fresh-scan gates for a freeze-first tree kill: the plan must still
/// build, and the pre-flight, root-protection, and `--yes`-skip rules must
/// re-pass against the fresh snapshot.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fresh_tree_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmation: tree::ScopeAuthorization,
) -> Result<(), tree::TreeKillOutcome> {
    let preview = tree::plan_process_tree(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(tree::plan_error_outcome)?;
    tree::preflight_outcome(&preview)?;
    tree::root_protection_outcome(&preview, confirmation.protected_root_confirmed())?;
    fresh_tree_yes_outcome(root, &preview, confirmation)
}

fn fresh_tree_yes_outcome(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    confirmation: tree::ScopeAuthorization,
) -> Result<(), tree::TreeKillOutcome> {
    if confirmation.prompt_skipped() && !tree_yes_skip_allowed(root, preview) {
        return Err(tree::TreeKillOutcome::FreshConfirmationRequired);
    }
    Ok(())
}

/// Translate a single-kill revalidation refusal into the scoped-kill outcome
/// vocabulary, so tree and group revalidation report identically.
fn tree_outcome_from_termination(
    confirmed: &KillTarget,
    outcome: TerminationOutcome,
) -> tree::TreeKillOutcome {
    match outcome {
        TerminationOutcome::ProtectedProcess => tree::TreeKillOutcome::ProtectedRoot {
            pid: confirmed.pid,
            name: confirmed.process_name.clone(),
        },
        TerminationOutcome::UnsafePid(reason) => tree::TreeKillOutcome::UnsafePid {
            pid: confirmed.pid,
            reason,
        },
        TerminationOutcome::OwnershipUnavailable => {
            tree::TreeKillOutcome::OwnershipUnavailable { pid: confirmed.pid }
        }
        TerminationOutcome::AlreadyExited => tree::TreeKillOutcome::RootAlreadyExited,
        TerminationOutcome::TargetChanged
        | TerminationOutcome::Success
        | TerminationOutcome::Cancelled => {
            tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid }
        }
        TerminationOutcome::PermissionDenied => {
            tree::TreeKillOutcome::PermissionDenied { pid: confirmed.pid }
        }
        TerminationOutcome::UnknownFailure(error) => tree::TreeKillOutcome::SnapshotFailed(error),
        TerminationOutcome::ThawFailed { pid, prior } => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                tree::TreeKillOutcome::ThawFailed {
                    pids: vec![pid],
                    cause: Box::new(tree_outcome_from_termination(confirmed, *prior)),
                }
            }
            #[cfg(windows)]
            {
                let _ = (pid, prior);
                tree::TreeKillOutcome::SnapshotFailed(
                    "unexpected thaw failure in Windows tree preparation".to_owned(),
                )
            }
        }
    }
}

fn revalidate_portless_tree_root(
    confirmed: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<KillTarget, tree::TreeKillOutcome> {
    let Some(info) = snapshot.iter().find(|info| info.pid == confirmed.pid) else {
        return Err(tree::TreeKillOutcome::RootAlreadyExited);
    };
    let (Some(confirmed_start), Some(fresh_start)) =
        (confirmed.process_start_time_marker, info.start_time_marker)
    else {
        return Err(tree::TreeKillOutcome::PartialMetadata { pid: confirmed.pid });
    };
    if confirmed_start != fresh_start {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid });
    }
    if let Some(expected) = confirmed.process_name.as_deref()
        && info.process_name.as_deref() != Some(expected)
    {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid });
    }
    let fresh = kill_target_from_tree_info(info, protected_names);
    if fresh.protected && !confirmed.protected {
        return Err(tree::TreeKillOutcome::ProtectedRoot {
            pid: fresh.pid,
            name: fresh.process_name.clone(),
        });
    }
    Ok(fresh)
}

/// Refuse a tree or group that fails a pre-flight rule, before any signal is
/// sent. `scope_noun` is `"tree"` or `"group"` and only changes the wording;
/// the gates and exit codes are identical for both scopes.
fn scoped_preflight_refusal(
    preview: &tree::ProcessTreeTarget,
    scope_noun: &str,
) -> Option<ExitReason> {
    tree::preflight_outcome(preview).err().map(|outcome| match outcome {
        tree::TreeKillOutcome::Truncated { limit } => {
            eprintln!(
                "error: process {scope_noun} exceeds the {limit} process cap; refusing to kill a partial {scope_noun}",
            );
            ExitReason::Failure
        }
        tree::TreeKillOutcome::UnsafePid { pid, .. } => {
            eprintln!("error: process {scope_noun} contains unsafe PID {pid}; refusing {scope_noun} kill");
            ExitReason::Failure
        }
        tree::TreeKillOutcome::ProtectedDescendant { pid, name } => {
            let name = sanitize(name.as_deref().unwrap_or("<unknown>"));
            eprintln!("error: process {scope_noun} contains protected process PID {pid} ({name}); refusing {scope_noun} kill");
            ExitReason::ProtectedNeedsConfirmation
        }
        // Refuse unknown preflight outcomes with an explicit diagnostic.
        other => {
            eprintln!("error: process {scope_noun} pre-flight refused the kill: {other:?}");
            ExitReason::Failure
        }
    })
}

fn tree_confirmation(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    mode: KillMode,
    yes: bool,
) -> TreeConfirmDecision {
    // Treat the root as protected if either the named socket row or the tree
    // scan classifies it that way. Protection wins when the readers disagree.
    if root.protected || preview.root().is_some_and(|node| node.protected) {
        if yes {
            return TreeConfirmDecision::RefuseProtectedYes;
        }
        return TreeConfirmDecision::PromptProtectedThenWord(tree::tree_scope_word(mode));
    }

    // Terminate requires "tree"; force requires "force".
    let word = tree::tree_scope_word(mode);
    if yes && tree_yes_skip_allowed(root, preview) {
        return TreeConfirmDecision::Skip;
    }
    TreeConfirmDecision::PromptWord(word)
}

fn tree_yes_skip_allowed(root: &KillTarget, preview: &tree::ProcessTreeTarget) -> bool {
    !preview.has_warnings() && !root_has_tree_yes_blocking_warning(root)
}

fn root_has_tree_yes_blocking_warning(root: &KillTarget) -> bool {
    // The child-count notice is informational under tree scope (the tree
    // preview supersedes it); every other warning kind blocks a `--yes` skip.
    root.warnings()
        .iter()
        .any(|warning| !matches!(warning, process::KillWarning::HasChildren { .. }))
}

fn print_tree_kill_banner(root: &KillTarget, preview: &tree::ProcessTreeTarget, mode: KillMode) {
    eprintln!(
        "{} process tree from {}",
        mode.action_label(),
        root.identity()
    );
    eprintln!("Scope: tree ({} processes)", preview.len());
    eprintln!("Ports: {}", sanitize(&root.ports_text()));
    let mut command = format!("kick kill --pid {} --tree", root.pid);
    if mode == KillMode::Force {
        command.push_str(" --force");
    }
    eprintln!("Command: {}", sanitize(&command));
    for node in preview.preview_nodes(TREE_PREVIEW_MAX) {
        let indent = "  ".repeat(node.depth + 1);
        let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
        eprintln!("{indent}PID {} ({name})", node.pid);
    }
    if preview.len() > TREE_PREVIEW_MAX {
        eprintln!("  ... and {} more", preview.len() - TREE_PREVIEW_MAX);
    }
    if let Some(warning) = mode.force_warning(root.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    if root.platform == Platform::Windows {
        eprintln!(
            "Warning: Windows tree kill uses Job Object containment and hard termination; close apps normally first when possible."
        );
        eprintln!(
            "Warning: Windows may also terminate newly spawned job-contained children that were not visible in this preview."
        );
    }
    if preview.has_system_process() {
        eprintln!(
            "Warning: tree includes system/service processes; verify this is safe to terminate."
        );
    }
    if let Some(warning) = scoped_owner_warning(preview, "tree") {
        eprintln!("Warning: {warning}.");
    }
    for warning in root.warnings() {
        eprintln!(
            "Warning: {}.",
            sanitize(&warning.text(process::WarningScope::Tree))
        );
    }
}

fn prompt_tree_confirmation(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
) -> std::io::Result<bool> {
    match requirement {
        TreeConfirmation::TypedWord(word) => eprint!(
            "Type {word} to terminate all {} processes, or press Enter to cancel: ",
            preview.len(),
        ),
        TreeConfirmation::ProtectedRoot => eprint!(
            "Protected root: type PID {} or process name {} to confirm: ",
            root.pid,
            sanitize(root.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(tree_confirmation_matches(&answer, root, requirement))
}

fn tree_confirmation_matches(
    input: &str,
    root: &KillTarget,
    requirement: TreeConfirmation,
) -> bool {
    match requirement {
        TreeConfirmation::TypedWord(word) => tree::word_confirmation_matches(input, word),
        TreeConfirmation::ProtectedRoot => process::confirmation_input_matches(
            input,
            root,
            ConfirmationRequirement::ProtectedProcess,
        ),
    }
}

mod report;

#[cfg(windows)]
use report::map_windows_tree_outcome;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use report::{map_group_outcome, map_tree_outcome};
#[cfg(all(test, windows))]
use report::{
    map_windows_tree_completed_outcome, map_windows_tree_system_failure,
    windows_post_commit_issue_exit_reason, windows_post_commit_issue_text,
    windows_tree_partial_report_text,
};

// The group `--yes` skip ceiling lives in `tree.rs` because the final
// frozen-set policy re-applies it after the sweep; the confirmation gate here
// and that policy must share one number.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree::GROUP_YES_SKIP_MAX_PROCESSES;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn run_group_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    run_group_kill_with(
        args,
        config,
        entries,
        mode,
        &mut ops,
        TreeKillIo {
            collect_context: &mut platform::collect_process_context,
            prompt: &mut prompt_group_confirmation,
            collect_kill_ports: &mut || collector::collect_kill_ports(args.pid, args.port),
            collect_ports: &mut || {
                collector::collect_ports_with_profile(MetadataProfile::IdentityOnly)
            },
        },
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_group_kill_with<Ops>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
    ops: &mut Ops,
    mut io: TreeKillIo<'_>,
) -> ExitReason
where
    Ops: tree::TreeProcessOps,
{
    // The preview is informational. Execution enumerates again after freezing.
    let snapshot = match ops.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process group failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    let root =
        match resolve_scoped_kill_root(args, config, entries, &snapshot, &mut io.collect_context) {
            Ok(target) => target,
            Err(reason) => return reason,
        };
    let group = match tree::plan_process_group(
        root.pid,
        &snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_GROUP_PROCESSES,
    ) {
        Ok(group) => group,
        Err(tree::GroupPlanError::RootMissing) => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            return ExitReason::NoMatch;
        }
        Err(tree::GroupPlanError::GroupUnavailable) => {
            eprintln!(
                "error: PID {} has no targetable process group; refusing group kill",
                root.pid
            );
            return ExitReason::Failure;
        }
    };

    if let Some(reason) = scoped_preflight_refusal(group.members(), "group") {
        return reason;
    }

    let confirmation = match confirm_group_kill(&root, &group, mode, args.yes, &mut io.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    if let Err(outcome) = tree::pin_root_before_revalidation(root.pid, ops) {
        return map_group_outcome(&root, group.pgid(), mode, &outcome, &mut io.collect_ports);
    }

    let fresh_root = match revalidate_group_root_before_freeze(
        args,
        config,
        &root,
        ConfirmedGroupFacts {
            pgid: group.pgid(),
            confirmation,
        },
        &mut io.collect_context,
        &mut io.collect_kill_ports,
        ops,
    ) {
        Ok(root) => root,
        Err(outcome) => {
            return map_group_outcome(&root, group.pgid(), mode, &outcome, &mut io.collect_ports);
        }
    };

    let outcome = tree::execute_group_kill(
        &fresh_root,
        group.pgid(),
        mode,
        &config.protected_processes,
        fresh_root.platform,
        confirmation,
        ops,
    );
    map_group_outcome(
        &fresh_root,
        group.pgid(),
        mode,
        &outcome,
        &mut io.collect_ports,
    )
}

/// Run the group confirmation flow; mirrors [`confirm_tree_kill`], including
/// the returned authorization.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn confirm_group_kill<Prompt>(
    root: &KillTarget,
    group: &tree::ProcessGroupTarget,
    mode: KillMode,
    yes: bool,
    prompt: &mut Prompt,
) -> Result<tree::ScopeAuthorization, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    confirm_scoped_kill(
        root,
        group.members(),
        group_confirmation(root, group, mode, yes),
        || print_group_kill_banner(root, group, mode),
        prompt,
    )
}

/// The confirmation gate for a group kill.
///
/// Stricter than tree scope on `--yes`: a process group has no structural tie
/// to the confirmed target, so beyond the tree rules (no warnings anywhere,
/// no protected root) the group must also be tiny before the typed word may
/// be skipped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_confirmation(
    root: &KillTarget,
    group: &tree::ProcessGroupTarget,
    mode: KillMode,
    yes: bool,
) -> TreeConfirmDecision {
    let members = group.members();
    // Protected if *either* reader says so, exactly like tree scope.
    if root.protected || members.root().is_some_and(|node| node.protected) {
        if yes {
            return TreeConfirmDecision::RefuseProtectedYes;
        }
        return TreeConfirmDecision::PromptProtectedThenWord(tree::group_scope_word(mode));
    }

    let word = tree::group_scope_word(mode);
    if yes && group_yes_skip_allowed(root, members) {
        return TreeConfirmDecision::Skip;
    }
    TreeConfirmDecision::PromptWord(word)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_yes_skip_allowed(root: &KillTarget, members: &tree::ProcessTreeTarget) -> bool {
    members.len() <= GROUP_YES_SKIP_MAX_PROCESSES
        && !members.has_warnings()
        && !root_has_tree_yes_blocking_warning(root)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_group_kill_banner(root: &KillTarget, group: &tree::ProcessGroupTarget, mode: KillMode) {
    let members = group.members();
    eprintln!(
        "{} process group {} of {}",
        mode.action_label(),
        group.pgid(),
        root.identity()
    );
    eprintln!(
        "Scope: group {} ({} processes)",
        group.pgid(),
        members.len()
    );
    eprintln!("Ports: {}", sanitize(&root.ports_text()));
    let mut command = format!("kick kill --pid {} --group", root.pid);
    if mode == KillMode::Force {
        command.push_str(" --force");
    }
    eprintln!("Command: {}", sanitize(&command));
    // Show every member. The builder already bounds the set, and process groups
    // can contain unrelated commands from the same shell.
    for node in members.preview_nodes(members.len()) {
        let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
        let root_marker = if node.depth == 0 {
            " [confirmed target]"
        } else {
            ""
        };
        eprintln!("  PID {} ({name}){root_marker}", node.pid);
    }
    if let Some(warning) = mode.force_warning(root.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    if members.has_system_process() {
        eprintln!(
            "Warning: group includes system/service processes; verify this is safe to terminate."
        );
    }
    if let Some(warning) = scoped_owner_warning(members, "group") {
        eprintln!("Warning: {warning}.");
    }
    eprintln!(
        "Warning: a process group can include unrelated processes started from the same shell; review every member above."
    );
    for warning in root.warnings() {
        eprintln!(
            "Warning: {}.",
            sanitize(&warning.text(process::WarningScope::Group))
        );
    }
}

fn scoped_owner_warning(preview: &tree::ProcessTreeTarget, scope_noun: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let _ = preview;
        let _ = scope_noun;
        None
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let current_uid = process::current_user_id();
        let mut count = 0_usize;
        let mut first = None;
        for node in preview.preview_nodes(preview.len()) {
            let Some(owner_uid) = node.owner_uid else {
                continue;
            };
            if owner_uid == current_uid {
                continue;
            }
            count += 1;
            first.get_or_insert((node.pid, owner_uid));
        }

        let (pid, owner_uid) = first?;
        Some(format!(
            "{scope_noun} includes {count} process(es) owned by another uid; first is PID {pid} owned by uid {owner_uid}, current effective uid is {current_uid}"
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prompt_group_confirmation(
    root: &KillTarget,
    members: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
) -> std::io::Result<bool> {
    match requirement {
        TreeConfirmation::TypedWord(word) => eprint!(
            "Type {word} to terminate all {} processes in the group, or press Enter to cancel: ",
            members.len(),
        ),
        TreeConfirmation::ProtectedRoot => eprint!(
            "Protected root: type PID {} or process name {} to confirm: ",
            root.pid,
            sanitize(root.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(tree_confirmation_matches(&answer, root, requirement))
}

/// Group identity and protected-root confirmation carried into revalidation.
/// These record which group was shown and whether the
/// protected-root confirmation was completed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy)]
struct ConfirmedGroupFacts {
    pgid: u32,
    confirmation: tree::ScopeAuthorization,
}

/// Revalidate the confirmed root and re-run every group gate against a fresh
/// scan immediately before the freeze. The root must match exactly and must
/// still sit in the group the user confirmed; membership may have churned but
/// must re-pass the cap, unsafe-PID, and protection gates.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_group_root_before_freeze<Ops, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmed_group: ConfirmedGroupFacts,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    ops: &mut Ops,
) -> Result<KillTarget, tree::TreeKillOutcome>
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Group {
            root_pid: confirmed.pid,
            pgid: confirmed_group.pgid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let root =
            revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)?;
        fresh_group_gates(&root, &snapshot, config, confirmed_group)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| tree_outcome_from_termination(confirmed, outcome))?;
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Group {
            root_pid: root.pid,
            pgid: confirmed_group.pgid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        fresh_group_gates(&root, &snapshot, config, confirmed_group)?;
        root
    };
    Ok(fresh_root)
}

/// Fresh-scan gates for a group kill. The member set must build, the root must
/// remain in the confirmed group, and preflight and root-protection checks must
/// pass again. A changed root group would target an unconfirmed member set.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fresh_group_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmed_group: ConfirmedGroupFacts,
) -> Result<(), tree::TreeKillOutcome> {
    let group = tree::plan_process_group(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_GROUP_PROCESSES,
    )
    .map_err(|error| match error {
        tree::GroupPlanError::RootMissing => tree::TreeKillOutcome::RootAlreadyExited,
        tree::GroupPlanError::GroupUnavailable => {
            tree::TreeKillOutcome::TargetChanged { pid: root.pid }
        }
    })?;
    if group.pgid() != confirmed_group.pgid {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: root.pid });
    }
    tree::preflight_outcome(group.members())?;
    tree::root_protection_outcome(
        group.members(),
        confirmed_group.confirmation.protected_root_confirmed(),
    )?;
    if confirmed_group.confirmation.prompt_skipped()
        && !group_yes_skip_allowed(root, group.members())
    {
        return Err(tree::TreeKillOutcome::FreshConfirmationRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
