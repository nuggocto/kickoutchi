//! The single-process `kill` command resolves, confirms, revalidates, then
//! signals one target. Scoped (`--tree`/`--group`) flows reuse the resolution,
//! revalidation, and confirmation-input helpers defined here.

use std::io::{self, BufRead, ErrorKind, Read, Write};
use std::time::Duration;

use crate::collector;
use crate::command;
use crate::config::Config;
use crate::display::{human_endpoint_text, sanitize};
use crate::model::{PortEntry, PortEntryView, ProcessContext};
use crate::observation::{MetadataProfile, ProcessIdentity};
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, ExitObservation, KillMode,
    KillTarget, TerminationOutcome, UnsafePidReason, WarningScope,
};
use crate::protection::mark_protected;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::scoped::run_group_kill;
use super::scoped::run_tree_kill;
use super::{ExitReason, KillArgs, settle};

pub(super) fn run_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    if args.tree {
        return run_tree_kill(args, config, entries);
    }

    // clap rejects `--tree --group` at parse time, so exactly one scope
    // branch can be taken here.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if args.group {
        return run_group_kill(args, config, entries);
    }

    run_kill_with(
        args,
        config,
        entries,
        KillCollectors {
            context: &mut platform::collect_process_context,
            kill_ports: &mut || collector::collect_kill_ports(args.pid, args.port),
            visibility_ports: &mut || {
                collector::collect_ports_with_profile(POST_KILL_VISIBILITY_PROFILE)
            },
            observe_exit: &mut process::observe_exit,
            sleep: &mut std::thread::sleep,
        },
        prompt_confirmation,
        process::prepare_termination,
        process::terminate_handle_checked,
    )
}

struct KillCollectors<'a> {
    context: &'a mut dyn FnMut(u32) -> ProcessContext,
    kill_ports: &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    visibility_ports: &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    observe_exit: &'a mut dyn FnMut(ProcessIdentity) -> ExitObservation,
    sleep: &'a mut dyn FnMut(Duration),
}

fn run_kill_with<Handle>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mut collectors: KillCollectors<'_>,
    mut prompt: impl FnMut(&KillTarget, KillMode, ConfirmationRequirement) -> std::io::Result<bool>,
    mut prepare: impl FnMut(u32) -> Result<Handle, TerminationOutcome>,
    mut terminate: impl FnMut(&Handle, &KillTarget, &[String], KillMode) -> TerminationOutcome,
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    let target = match resolve_kill_target(args, entries, &mut collectors.context) {
        Ok(target) => target,
        Err(error) => return print_target_error(error),
    };

    let requirement = match process::confirmation_requirement(
        target.protected,
        mode,
        args.yes,
        config.confirm_force_kill,
    ) {
        Ok(requirement) => requirement,
        Err(outcome) => {
            // Only `--yes` on a protected target is refused before confirmation.
            eprintln!(
                "error: {}; --yes cannot bypass protected-process confirmation",
                outcome.status_description(&target, mode),
            );
            return exit_reason_for_outcome(&outcome);
        }
    };

    // Print identity, ports, equivalent command, and warnings before handling
    // confirmation. `--yes` skips the prompt but not safety warnings.
    print_kill_banner(&target, mode);

    if let Some(requirement) = requirement {
        let confirmed = match prompt(&target, mode, requirement) {
            Ok(confirmed) => confirmed,
            Err(error) => {
                eprintln!("error: reading confirmation failed: {error}");
                return ExitReason::Failure;
            }
        };
        if !confirmed {
            let outcome = TerminationOutcome::Cancelled;
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    }

    let handle = match prepare(target.pid) {
        Ok(handle) => handle,
        Err(outcome) => {
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    };

    let target = match revalidate_single_cli_target(
        args,
        config,
        &target,
        &mut collectors.context,
        &mut collectors.kill_ports,
    ) {
        Ok(target) => target,
        Err(outcome) => {
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    };
    let outcome = terminate(&handle, &target, &config.protected_processes, mode);
    print_termination_outcome(&target, mode, &outcome);
    if outcome == TerminationOutcome::Success {
        print_single_settle_report(&target, mode, &mut collectors);
    }
    exit_reason_for_outcome(&outcome)
}

const POST_KILL_VISIBILITY_PROFILE: MetadataProfile = MetadataProfile::IdentityOnly;

/// Poll the root's confirmed ports after a delivery that has no exit check of
/// its own, and print the result.
pub(super) fn print_post_kill_refresh_status(
    target: &KillTarget,
    collect_ports: &mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
) {
    if let Some(message) = settle::ports_only_status_message(target, collect_ports) {
        eprintln!("{message}");
    }
}

/// Wait for one signalled process to exit and its confirmed ports to clear,
/// then print both facts.
fn print_single_settle_report(
    target: &KillTarget,
    mode: KillMode,
    collectors: &mut KillCollectors<'_>,
) {
    let identity = target
        .process_start_time_marker
        .map(|start_marker| ProcessIdentity {
            pid: target.pid,
            start_marker,
        });
    let report = settle::settle(
        identity.as_slice(),
        &target.ports,
        &mut settle::SettleProbe {
            collect_ports: collectors.visibility_ports,
            observe_exit: collectors.observe_exit,
            sleep: collectors.sleep,
        },
    );
    for line in settle::single_report_lines(target, mode, identity.is_some(), &report) {
        eprintln!("{line}");
    }
}

pub(super) fn revalidate_cli_target<CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
) -> Result<KillTarget, TerminationOutcome>
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    revalidate_cli_target_with(
        args,
        config,
        confirmed,
        collect_context,
        collect_ports,
        false,
    )
}

fn revalidate_single_cli_target<CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
) -> Result<KillTarget, TerminationOutcome>
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    revalidate_cli_target_with(
        args,
        config,
        confirmed,
        collect_context,
        collect_ports,
        true,
    )
}

fn revalidate_cli_target_with<CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    require_protection_name: bool,
) -> Result<KillTarget, TerminationOutcome>
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let mut fresh_entries = collect_ports().map_err(|error| {
        if error.is_ownership_permission_denied() {
            TerminationOutcome::OwnershipUnavailable
        } else {
            TerminationOutcome::UnknownFailure(format!(
                "collecting ports before kill failed: {error}"
            ))
        }
    })?;
    mark_protected(&mut fresh_entries, &config.protected_processes);
    // The closure owns the snapshot it collected from, so the rows arrive owned
    // and are borrowed once here for every read below.
    let fresh_entries = fresh_entries
        .iter()
        .map(PortEntryView::from)
        .collect::<Vec<_>>();

    // If a confirmed port remains visible without an owner PID, report ownership
    // loss before PID re-resolution. This keeps PID, port, and TUI paths on the
    // same permission-denied result.
    if process::confirmed_port_owner_unavailable(confirmed, &fresh_entries) {
        return Err(TerminationOutcome::OwnershipUnavailable);
    }

    let fresh = match resolve_kill_target(args, &fresh_entries, collect_context) {
        Ok(fresh) => fresh,
        Err(KillTargetError::NoMatch) => {
            return Err(TerminationOutcome::TargetChanged);
        }
        Err(KillTargetError::MissingPid { .. }) => {
            return Err(TerminationOutcome::OwnershipUnavailable);
        }
        Err(KillTargetError::AmbiguousPort { port, candidates }) => {
            eprintln!(
                "error: port {port} became ambiguous before termination; refusing to guess. Use --pid with one of:",
            );
            for candidate in candidates {
                eprintln!("  {candidate}");
            }
            return Err(TerminationOutcome::TargetChanged);
        }
        Err(KillTargetError::UnsafePid(reason)) => {
            return Err(TerminationOutcome::UnsafePid(reason));
        }
    };
    if require_protection_name {
        process::validate_single_delivery_evidence(confirmed, &fresh)?;
    }
    if !process::target_still_matches_confirmation(confirmed, &fresh) {
        return Err(TerminationOutcome::TargetChanged);
    }
    if fresh.protected && !confirmed.protected {
        return Err(TerminationOutcome::ProtectedProcess);
    }
    Ok(fresh)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum KillTargetError {
    NoMatch,
    MissingPid { port: u16 },
    AmbiguousPort { port: u16, candidates: Vec<String> },
    UnsafePid(UnsafePidReason),
}

pub(super) fn resolve_kill_target<CollectContext>(
    args: &KillArgs,
    entries: &[PortEntryView<'_>],
    collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    match (args.pid, args.port) {
        (Some(pid), None) => resolve_pid_target(pid, entries, collect_context),
        (None, Some(port)) => resolve_port_target(port, entries, collect_context),
        (None, None) | (Some(_), Some(_)) => unreachable!("clap requires exactly one kill target"),
    }
}

fn resolve_pid_target<CollectContext>(
    pid: u32,
    entries: &[PortEntryView<'_>],
    mut collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }

    let rows: Vec<PortEntryView<'_>> = entries
        .iter()
        .copied()
        .filter(|entry| entry.pid == Some(pid))
        .collect();
    if rows.is_empty() {
        return Err(KillTargetError::NoMatch);
    }
    let context = collect_context(pid);
    Ok(KillTarget::from_entries(pid, rows, Some(&context)))
}

fn resolve_port_target<CollectContext>(
    port: u16,
    entries: &[PortEntryView<'_>],
    mut collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    let (pid, rows) = resolve_single_port_owner(port, entries)?;
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }

    let context = collect_context(pid);
    Ok(KillTarget::from_entries(pid, rows, Some(&context)))
}

/// Resolve the single PID that owns `port`. Refuse when there is no matching
/// socket, the owner PID is hidden, or several distinct owners exist. Kill and
/// inspect resolution use this function to share the same policy. The kill
/// caller retains the unsafe-PID guard because inspecting PID 1 is valid while
/// signalling it is not.
pub(super) fn resolve_single_port_owner<'a>(
    port: u16,
    entries: &[PortEntryView<'a>],
) -> Result<(u32, Vec<PortEntryView<'a>>), KillTargetError> {
    let rows: Vec<PortEntryView<'a>> = entries
        .iter()
        .copied()
        .filter(|entry| entry.local_port == port)
        .collect();
    if rows.is_empty() {
        return Err(KillTargetError::NoMatch);
    }
    if rows.iter().any(|entry| entry.pid.is_none()) {
        return Err(KillTargetError::MissingPid { port });
    }

    let mut pids = rows
        .iter()
        .filter_map(|entry| entry.pid)
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    let [pid] = pids.as_slice() else {
        return Err(KillTargetError::AmbiguousPort {
            port,
            candidates: candidate_labels(&rows),
        });
    };
    Ok((*pid, rows))
}

fn candidate_labels(rows: &[PortEntryView<'_>]) -> Vec<String> {
    let mut candidates = rows
        .iter()
        .filter_map(|entry| {
            let pid = entry.pid?;
            let name = sanitize(entry.process_name.unwrap_or("<unknown>"));
            Some(format!(
                "PID {pid} ({name}) {} {}",
                entry.protocol.label(),
                human_endpoint_text(entry.local_addr, entry.local_port, entry.ipv6_scope),
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    candidates
}

pub(super) fn print_target_error(error: KillTargetError) -> ExitReason {
    let (lines, reason) = target_error_lines(error);
    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            eprintln!("error: {line}");
        } else {
            eprintln!("  {line}");
        }
    }
    reason
}

/// The refusal for an unresolvable target: the message, any candidate lines,
/// and the exit reason.
pub(super) fn target_error_lines(error: KillTargetError) -> (Vec<String>, ExitReason) {
    match error {
        KillTargetError::NoMatch => (
            vec!["no open port matches the requested target".to_owned()],
            ExitReason::NoMatch,
        ),
        KillTargetError::MissingPid { port } => (
            vec![format!(
                "port {port} is visible, but no owning PID is available; rerun with higher privileges or pass --pid when known",
            )],
            ExitReason::PermissionDenied,
        ),
        KillTargetError::AmbiguousPort { port, candidates } => {
            let mut lines = vec![format!(
                "port {port} is owned by multiple PIDs; refusing to guess. Use --pid with one of:",
            )];
            lines.extend(candidates);
            (lines, ExitReason::Failure)
        }
        KillTargetError::UnsafePid(reason) => (
            vec![format!("unsafe PID blocked: {}", reason.message())],
            ExitReason::Failure,
        ),
    }
}

fn print_kill_banner(target: &KillTarget, mode: KillMode) {
    eprintln!("{} {}", mode.action_label(), target.identity());
    eprintln!("Scope: process");
    eprintln!("Ports: {}", sanitize(&target.ports_text()));
    eprintln!(
        "Command: {}",
        sanitize(&command::render_kill_command(
            target.platform,
            target.pid,
            mode
        )),
    );
    if let Some(warning) = mode.force_warning(target.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    for warning in target.warnings() {
        eprintln!(
            "Warning: {}.",
            sanitize(&warning.text(WarningScope::Process))
        );
    }
    if let Some(note) = deleted_executable_note(target) {
        eprintln!("{note}");
    }
}

/// A banner note when the target runs a deleted or replaced executable.
pub(super) fn deleted_executable_note(target: &KillTarget) -> Option<String> {
    let start_marker = target.process_start_time_marker?;
    let path = platform::deleted_executable(ProcessIdentity {
        pid: target.pid,
        start_marker,
    })?;
    Some(format!(
        "Note: {} runs an executable that was deleted or replaced after it started: {}",
        target.identity(),
        sanitize(&path.to_string_lossy()),
    ))
}

fn prompt_confirmation(
    target: &KillTarget,
    mode: KillMode,
    requirement: ConfirmationRequirement,
) -> std::io::Result<bool> {
    match requirement {
        ConfirmationRequirement::Yes => eprint!("Type y to confirm, or press Enter to cancel: "),
        ConfirmationRequirement::ForceWord => {
            eprint!(
                "Type force to confirm {}: ",
                mode.delivery_label(target.platform)
            );
        }
        ConfirmationRequirement::ProtectedProcess => eprint!(
            "Protected process: type {} to confirm: ",
            target.protected_confirmation_choices(),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(process::confirmation_input_matches(
        &answer,
        target,
        requirement,
    ))
}

pub(super) fn read_confirmation_line(max_bytes: usize) -> std::io::Result<String> {
    read_confirmation_line_from(&mut std::io::stdin().lock(), max_bytes)
}

fn read_confirmation_line_from(reader: &mut impl BufRead, max_bytes: usize) -> io::Result<String> {
    // `usize` is at most 64 bits on every supported target, so widening to the
    // `u64` `Take` limit is lossless; the sole production limit is the small
    // constant `CONFIRMATION_INPUT_MAX_BYTES`, so the two bytes of headroom
    // for a trailing "\r\n" cannot overflow either. `saturating_add` only
    // guards the theoretical `usize::MAX` limit.
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(2);
    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(2));
    (&mut *reader).take(limit).read_until(b'\n', &mut bytes)?;

    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("confirmation input exceeds the {max_bytes}-byte limit"),
        ));
    }

    String::from_utf8(bytes).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}

fn print_termination_outcome(target: &KillTarget, mode: KillMode, outcome: &TerminationOutcome) {
    let description = outcome.status_description(target, mode);
    match outcome {
        TerminationOutcome::Success
        | TerminationOutcome::AlreadyExited
        | TerminationOutcome::Cancelled => eprintln!("{description}"),
        TerminationOutcome::PermissionDenied => eprintln!(
            "error: {description}; {}",
            process::permission_denied_hint(target.platform),
        ),
        TerminationOutcome::ProtectedProcess => {
            eprintln!(
                "error: {description}; it became protected after confirmation, so no termination was sent; rerun to confirm the protected process"
            );
        }
        TerminationOutcome::OwnershipUnavailable
        | TerminationOutcome::TargetChanged
        | TerminationOutcome::UnsafePid(_)
        | TerminationOutcome::UnknownFailure(_)
        | TerminationOutcome::ThawFailed { .. } => eprintln!("error: {description}"),
    }
}

fn exit_reason_for_outcome(outcome: &TerminationOutcome) -> ExitReason {
    match outcome {
        TerminationOutcome::Success => ExitReason::Success,
        TerminationOutcome::PermissionDenied | TerminationOutcome::OwnershipUnavailable => {
            ExitReason::PermissionDenied
        }
        TerminationOutcome::AlreadyExited | TerminationOutcome::TargetChanged => {
            ExitReason::NoMatch
        }
        TerminationOutcome::Cancelled => ExitReason::KillCancelled,
        TerminationOutcome::ProtectedProcess => ExitReason::ProtectedNeedsConfirmation,
        TerminationOutcome::UnsafePid(_)
        | TerminationOutcome::UnknownFailure(_)
        | TerminationOutcome::ThawFailed { .. } => ExitReason::Failure,
    }
}

pub(super) mod batch;

#[cfg(test)]
mod tests;
