//! Multi-target `kill`.
//!
//! Several single-process kills share one banner, one confirmation, one
//! revalidation snapshot, and one summary. Each target keeps the single-kill
//! guarantees: resolution against the first snapshot, a handle retained before
//! revalidation, revalidation against a fresh snapshot, and identity-checked
//! delivery. A target that cannot be resolved or authorized stops the whole
//! batch before any signal is sent, because the confirmation covers exactly
//! the listed set.

use std::io;

use crate::collector::{self, CollectorError};
use crate::config::Config;
use crate::display::sanitize;
use crate::model::{PortEntryView, ProcessContext};
use crate::observation::{MetadataProfile, NetworkSnapshot, ProcessIdentity};
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    KillTargetPort, TerminationOutcome, WarningScope,
};

use super::{
    POST_KILL_VISIBILITY_PROFILE, deleted_executable_note, exit_reason_for_outcome,
    read_confirmation_line, resolve_kill_target, revalidate_single_cli_target,
    target_refusal_lines,
};
use crate::cli::{ExitReason, KillArgs, settle, unprovable_port_kill_message};

/// Most targets one command may name.
pub(crate) const BATCH_TARGETS_MAX: usize = 128;

/// One resolved process and the selectors that named it.
struct Planned<'a> {
    args: &'a KillArgs,
    target: KillTarget,
    /// Ports of later selectors that resolved to the same process. They are
    /// polled after delivery but are not part of revalidation.
    extra_ports: Vec<KillTargetPort>,
}

/// A target refused before any signal was sent.
struct Refusal {
    selector: String,
    lines: Vec<String>,
    reason: ExitReason,
}

/// Final, identity-checked delivery to one revalidated target.
type Deliver<'a, Handle> =
    &'a mut dyn FnMut(&Handle, &KillTarget, &[String], KillMode) -> TerminationOutcome;

/// One target's outcome, keyed by its position in the plan.
type TargetOutcome = (usize, KillTarget, TerminationOutcome);

/// Outcomes in plan order, plus the handles retained for each prepared target.
type Delivery<Handle> = (Vec<TargetOutcome>, Vec<(usize, Handle)>);

/// The reads, prompt, and delivery a batch performs. Tests inject all of them.
pub(super) struct BatchIo<'a, Handle> {
    pub(super) context: &'a mut dyn FnMut(u32) -> ProcessContext,
    /// Show the prompt text and return the typed answer.
    pub(super) prompt: &'a mut dyn FnMut(&str) -> io::Result<String>,
    pub(super) fresh_snapshot: &'a mut dyn FnMut() -> Result<NetworkSnapshot, CollectorError>,
    pub(super) prepare: &'a mut dyn FnMut(u32) -> Result<Handle, TerminationOutcome>,
    pub(super) terminate: Deliver<'a, Handle>,
    pub(super) settle: settle::SettleProbe<'a>,
}

pub(in crate::cli) fn run_batch_kill(
    targets: &[KillArgs],
    config: &Config,
    snapshot: &NetworkSnapshot,
) -> ExitReason {
    run_batch_kill_with(
        targets,
        config,
        snapshot,
        BatchIo {
            context: &mut platform::collect_process_context,
            prompt: &mut prompt_line,
            fresh_snapshot: &mut || collector::collect_snapshot(MetadataProfile::Display),
            prepare: &mut process::prepare_termination,
            terminate: &mut process::terminate_handle_checked,
            settle: settle::SettleProbe {
                collect_ports: &mut || {
                    collector::collect_ports_with_profile(POST_KILL_VISIBILITY_PROFILE)
                },
                observe_exit: &mut process::observe_exit,
                sleep: &mut std::thread::sleep,
            },
        },
    )
}

fn prompt_line(text: &str) -> io::Result<String> {
    use std::io::Write as _;

    eprint!("{text}");
    io::stderr().flush()?;
    read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)
}

pub(super) fn run_batch_kill_with<Handle>(
    targets: &[KillArgs],
    config: &Config,
    snapshot: &NetworkSnapshot,
    mut io: BatchIo<'_, Handle>,
) -> ExitReason {
    let Some(first) = targets.first() else {
        return ExitReason::InvalidArguments;
    };
    // Every target shares the command's flags.
    let mode = if first.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };

    let planned = match plan(targets, config, snapshot, &mut io) {
        Ok(planned) => planned,
        Err(refusals) => return report_refusals(&refusals, targets.len()),
    };

    print_banner(&planned, mode);
    if let Some(reason) = confirm(&planned, config, mode, first.yes, &mut io) {
        return reason;
    }

    let (outcomes, handles) = match deliver(&planned, config, mode, &mut io) {
        Ok(delivery) => delivery,
        Err(reason) => return reason,
    };

    let delivered = outcomes
        .iter()
        .filter(|(_, _, outcome)| *outcome == TerminationOutcome::Success)
        .map(|(index, target, _)| (&planned[*index], target))
        .collect::<Vec<_>>();
    let identities = delivered
        .iter()
        .filter_map(|(_, target)| {
            target
                .process_start_time_marker
                .map(|start_marker| ProcessIdentity {
                    pid: target.pid,
                    start_marker,
                })
        })
        .collect::<Vec<_>>();
    let mut ports = delivered
        .iter()
        .flat_map(|(planned, target)| target.ports.iter().chain(&planned.extra_ports))
        .copied()
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    let settled = settle::settle(&identities, &ports, &mut io.settle);
    drop(handles);

    let failures = outcomes
        .iter()
        .filter(|(_, _, outcome)| *outcome != TerminationOutcome::Success)
        .map(|(_, target, outcome)| (target, outcome))
        .collect::<Vec<_>>();
    let delivered_targets = delivered
        .iter()
        .map(|(_, target)| *target)
        .collect::<Vec<_>>();
    for line in summary_lines(&Summary {
        mode,
        total: planned.len(),
        delivered: &delivered_targets,
        verified: identities.len(),
        ports: ports.len(),
        settled: &settled,
        failures: &failures,
    }) {
        eprintln!("{line}");
    }
    aggregate_exit(
        outcomes
            .iter()
            .map(|(_, _, outcome)| exit_reason_for_outcome(outcome)),
    )
}

/// Retain every handle, revalidate every target against one fresh snapshot,
/// and deliver. Outcomes come back in plan order with the retained handles,
/// which the caller keeps until exit checks finish.
fn deliver<Handle>(
    planned: &[Planned<'_>],
    config: &Config,
    mode: KillMode,
    io: &mut BatchIo<'_, Handle>,
) -> Result<Delivery<Handle>, ExitReason> {
    // Retain every handle before the shared revalidation read, as a single
    // kill does, so a recycled PID cannot receive the signal.
    let mut outcomes = Vec::with_capacity(planned.len());
    let mut handles = Vec::with_capacity(planned.len());
    for (index, planned) in planned.iter().enumerate() {
        match (io.prepare)(planned.target.pid) {
            Ok(handle) => handles.push((index, handle)),
            Err(outcome) => outcomes.push((index, planned.target.clone(), outcome)),
        }
    }
    let fresh = (io.fresh_snapshot)().map_err(|error| {
        eprintln!("error: collecting ports before kill failed: {error}; no signal was sent");
        ExitReason::Failure
    })?;
    for (index, handle) in &handles {
        let planned = &planned[*index];
        let args = planned.args;
        let revalidated = revalidate_single_cli_target(
            args,
            config,
            &planned.target,
            &mut io.context,
            &mut || collector::kill_ports_from_snapshot(&fresh, args.pid, args.port),
        );
        let (target, outcome) = match revalidated {
            Ok(target) => {
                let outcome = (io.terminate)(handle, &target, &config.protected_processes, mode);
                (target, outcome)
            }
            Err(outcome) => (planned.target.clone(), outcome),
        };
        outcomes.push((*index, target, outcome));
    }
    outcomes.sort_by_key(|(index, _, _)| *index);
    Ok((outcomes, handles))
}

/// Resolve and authorize every target against the first snapshot.
fn plan<'a, Handle>(
    targets: &'a [KillArgs],
    config: &Config,
    snapshot: &NetworkSnapshot,
    io: &mut BatchIo<'_, Handle>,
) -> Result<Vec<Planned<'a>>, Vec<Refusal>> {
    let descriptors = snapshot
        .port_entry_descriptors(&config.protected_processes)
        .map_err(|error| {
            vec![Refusal {
                selector: "collection".to_owned(),
                lines: vec![format!("projecting collected ports failed: {error}")],
                reason: ExitReason::Failure,
            }]
        })?;
    let entries = descriptors
        .iter()
        .map(|descriptor| snapshot.port_entry_view(descriptor))
        .collect::<Vec<PortEntryView<'_>>>();

    let mut planned: Vec<Planned<'a>> = Vec::with_capacity(targets.len());
    let mut refusals = Vec::new();
    for args in targets {
        let selector = selector_text(args);
        let refuse = |lines, reason| Refusal {
            selector: selector.clone(),
            lines,
            reason,
        };
        if let Some(port) = args.port
            && let Some(message) = unprovable_port_kill_message(args, port, snapshot, &entries)
        {
            refusals.push(refuse(vec![message], ExitReason::PermissionDenied));
            continue;
        }
        let target = match resolve_kill_target(args, &entries, &mut *io.context) {
            Ok(target) => target,
            Err(error) => {
                let (lines, reason) = target_refusal_lines(args, error, &mut io.context);
                refusals.push(refuse(lines, reason));
                continue;
            }
        };
        if target.protected {
            refusals.push(refuse(
                vec![format!(
                    "{} is protected; kill it on its own so it can be confirmed by PID or name",
                    target.identity()
                )],
                ExitReason::ProtectedNeedsConfirmation,
            ));
            continue;
        }
        if let Some(existing) = planned
            .iter_mut()
            .find(|existing| existing.target.pid == target.pid)
        {
            existing.extra_ports.extend(target.ports);
            continue;
        }
        planned.push(Planned {
            args,
            target,
            extra_ports: Vec::new(),
        });
    }
    if refusals.is_empty() {
        Ok(planned)
    } else {
        Err(refusals)
    }
}

fn selector_text(args: &KillArgs) -> String {
    match (args.pid, args.port) {
        (Some(pid), _) => format!("--pid {pid}"),
        (None, Some(port)) => format!("--port {port}"),
        (None, None) => unreachable!("every batch target has one selector"),
    }
}

fn report_refusals(refusals: &[Refusal], total: usize) -> ExitReason {
    eprintln!(
        "error: {} of {total} target(s) cannot be killed, so no signal was sent:",
        refusals.len()
    );
    for refusal in refusals {
        let mut lines = refusal.lines.iter();
        if let Some(first) = lines.next() {
            eprintln!("  {}: {first}", refusal.selector);
        }
        for line in lines {
            eprintln!("    {line}");
        }
    }
    aggregate_exit(refusals.iter().map(|refusal| refusal.reason))
}

fn print_banner(planned: &[Planned<'_>], mode: KillMode) {
    eprintln!("{} {} processes:", mode.action_label(), planned.len());
    for planned in planned {
        let mut ports = planned.target.ports.clone();
        ports.extend(&planned.extra_ports);
        ports.sort_unstable();
        ports.dedup();
        let ports = if ports.is_empty() {
            "no visible open ports".to_owned()
        } else {
            ports
                .iter()
                .map(KillTargetPort::label)
                .collect::<Vec<_>>()
                .join(", ")
        };
        eprintln!("  {}: {}", planned.target.identity(), sanitize(&ports));
    }
    if let Some(platform) = planned.first().map(|planned| planned.target.platform)
        && let Some(warning) = mode.force_warning(platform)
    {
        eprintln!("Warning: {}", sanitize(warning));
    }
    for planned in planned {
        for warning in planned.target.warnings() {
            eprintln!(
                "Warning: {}: {}.",
                planned.target.identity(),
                sanitize(&warning.text(WarningScope::Process))
            );
        }
        if let Some(note) = deleted_executable_note(&planned.target) {
            eprintln!("{note}");
        }
    }
}

/// Ask once for the whole set. `None` means confirmed or skipped by `--yes`.
fn confirm<Handle>(
    planned: &[Planned<'_>],
    config: &Config,
    mode: KillMode,
    yes: bool,
    io: &mut BatchIo<'_, Handle>,
) -> Option<ExitReason> {
    let first = &planned.first()?.target;
    // Protected targets were refused, so every target shares one requirement.
    let requirement =
        match process::confirmation_requirement(false, mode, yes, config.confirm_force_kill) {
            Ok(requirement) => requirement?,
            Err(_) => unreachable!("only protected targets are refused before confirmation"),
        };
    let text = match requirement {
        ConfirmationRequirement::Yes => format!(
            "Type y to confirm all {} kills, or press Enter to cancel: ",
            planned.len()
        ),
        ConfirmationRequirement::ForceWord => format!(
            "Type force to confirm {} for all {} processes: ",
            mode.delivery_label(first.platform),
            planned.len()
        ),
        ConfirmationRequirement::ProtectedProcess => {
            unreachable!("protected targets never reach a batch prompt")
        }
    };
    match (io.prompt)(&text) {
        Ok(answer) if process::confirmation_input_matches(&answer, first, requirement) => None,
        Ok(_) => {
            eprintln!("kill cancelled");
            Some(ExitReason::KillCancelled)
        }
        Err(error) => {
            eprintln!("error: reading confirmation failed: {error}");
            Some(ExitReason::Failure)
        }
    }
}

/// Everything the summary reports.
struct Summary<'a> {
    mode: KillMode,
    total: usize,
    delivered: &'a [&'a KillTarget],
    /// Delivered targets with a start identity, whose exit was checked.
    verified: usize,
    /// Distinct confirmed ports of the delivered targets.
    ports: usize,
    settled: &'a settle::SettleReport,
    failures: &'a [(&'a KillTarget, &'a TerminationOutcome)],
}

/// One summary line, then one line per kind of problem.
fn summary_lines(summary: &Summary<'_>) -> Vec<String> {
    let Summary {
        mode,
        total,
        delivered,
        verified,
        ports,
        settled,
        failures,
    } = *summary;
    let platform = delivered
        .first()
        .or_else(|| failures.first().map(|(target, _)| target))
        .map_or(crate::model::Platform::Linux, |target| target.platform);
    let delivery = mode.delivery_label(platform);
    let ports_text = match &settled.ports {
        settle::PortsStatus::NotChecked | settle::PortsStatus::Cleared => {
            format!("{ports} of {ports} confirmed port(s) no longer visible")
        }
        settle::PortsStatus::StillVisible => format!(
            "{} of {ports} confirmed port(s) no longer visible",
            ports.saturating_sub(settled.visible_ports.len())
        ),
        settle::PortsStatus::RefreshFailed(_) => "confirmed ports not rechecked".to_owned(),
    };
    let mut lines = vec![format!(
        "summary: sent {delivery} to {} of {total} process(es); {} exited; {ports_text}; {} failed",
        delivered.len(),
        settled.exited.len(),
        failures.len(),
    )];

    let label = |pid: u32| {
        delivered
            .iter()
            .find(|target| target.pid == pid)
            .map_or_else(|| format!("PID {pid}"), |target| target.identity())
    };
    for (target, outcome) in failures {
        let mut line = format!("  failed: {}", outcome.status_description(target, mode));
        if **outcome == TerminationOutcome::PermissionDenied {
            line.push_str("; ");
            line.push_str(process::permission_denied_hint(target.platform));
        }
        lines.push(line);
    }
    if !settled.running.is_empty() {
        // Whether a survivor still owns one of the visible ports is unknown
        // here, so suggest the retry that also works without a port.
        let hint = settle::sigkill_retry_hint(platform, mode, &settled.running, false);
        lines.push(format!(
            "  still running {} after {delivery}: {}{hint}",
            settle::settle_window_text(),
            settled
                .running
                .iter()
                .map(|pid| label(*pid))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    for (pid, error) in &settled.unknown {
        lines.push(format!(
            "  exit not confirmed: {}: {}",
            label(*pid),
            sanitize(error)
        ));
    }
    if let Some(missing) = delivered.len().checked_sub(verified).filter(|n| *n > 0) {
        lines.push(format!(
            "  exit not confirmed for {missing} process(es) without a start identity"
        ));
    }
    match &settled.ports {
        settle::PortsStatus::StillVisible => lines.push(format!(
            "  still visible: {}; another process may own them or shutdown may still be completing",
            sanitize(
                &settled
                    .visible_ports
                    .iter()
                    .map(KillTargetPort::label)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
        settle::PortsStatus::RefreshFailed(error) => lines.push(format!(
            "  warning: collecting ports after termination failed; refresh manually to verify: {error}"
        )),
        settle::PortsStatus::NotChecked | settle::PortsStatus::Cleared => {}
    }
    lines
}

/// The most serious exit reason: failure, then permission, then protection,
/// then no match, then cancellation.
fn aggregate_exit(reasons: impl Iterator<Item = ExitReason>) -> ExitReason {
    let rank = |reason: ExitReason| match reason {
        ExitReason::Success => 0,
        ExitReason::KillCancelled => 1,
        ExitReason::NoMatch => 2,
        ExitReason::ProtectedNeedsConfirmation => 3,
        ExitReason::PermissionDenied => 4,
        ExitReason::InvalidArguments => 5,
        ExitReason::Failure => 6,
    };
    reasons
        .max_by_key(|reason| rank(*reason))
        .unwrap_or(ExitReason::Success)
}

#[cfg(test)]
mod tests;
