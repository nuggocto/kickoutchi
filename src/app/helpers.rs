//! Small, platform-neutral helpers shared by the TUI state transitions.

use crate::command;
use crate::docker;
use crate::model::{DockerPortContext, PortEntryView, ProcessContext};
use crate::observation::{ProcessIdentity, ProcessStartMarker};
use crate::platform;
use crate::process::{self, KillMode, KillTarget, TerminationOutcome};

pub(super) fn collect_selected_process_context(
    entry: PortEntryView<'_>,
    docker_enrichment: bool,
) -> ProcessContext {
    collect_selected_process_context_with(
        entry,
        docker_enrichment,
        platform::collect_process_context,
        platform::process_start_time_marker,
        docker::enrich_port,
    )
}

pub(super) fn collect_selected_process_context_with<CollectContext, ReadMarker, EnrichDocker>(
    entry: PortEntryView<'_>,
    docker_enrichment: bool,
    collect_context: CollectContext,
    read_marker: ReadMarker,
    enrich_docker: EnrichDocker,
) -> ProcessContext
where
    CollectContext: FnOnce(u32) -> ProcessContext,
    ReadMarker: FnOnce(u32) -> Option<ProcessStartMarker>,
    EnrichDocker: FnOnce(PortEntryView<'_>) -> Option<DockerPortContext>,
{
    let mut context = entry
        .process_identity
        .map(|identity| same_generation_context(identity, collect_context, read_marker))
        .unwrap_or_default();
    context.docker = if docker_enrichment {
        enrich_docker(entry)
    } else {
        None
    };
    context
}

/// Read process-owned context only for the generation the snapshot row named.
///
/// The worker reads the PID after the snapshot was captured. If the PID was
/// reused in between, the owner UID and children would describe a different
/// process than the row's name, path, and sockets. The start marker must match
/// both inside the context read and after it, so every field read in between
/// belongs to the row's process; otherwise no process-owned fact is returned.
fn same_generation_context(
    identity: ProcessIdentity,
    collect_context: impl FnOnce(u32) -> ProcessContext,
    read_marker: impl FnOnce(u32) -> Option<ProcessStartMarker>,
) -> ProcessContext {
    let context = collect_context(identity.pid);
    if context.process_start_time_marker == Some(identity.start_marker)
        && read_marker(identity.pid) == Some(identity.start_marker)
    {
        context
    } else {
        ProcessContext::default()
    }
}

pub(super) fn termination_status_line(
    target: &KillTarget,
    mode: KillMode,
    outcome: &TerminationOutcome,
) -> String {
    let description = outcome.status_description(target, mode);
    match outcome {
        TerminationOutcome::PermissionDenied => format!(
            "{description}; {}",
            process::permission_denied_hint(target.platform),
        ),
        TerminationOutcome::ProtectedProcess => {
            format!("{description} and requires stronger confirmation")
        }
        TerminationOutcome::Success
        | TerminationOutcome::OwnershipUnavailable
        | TerminationOutcome::AlreadyExited
        | TerminationOutcome::Cancelled
        | TerminationOutcome::TargetChanged
        | TerminationOutcome::UnsafePid(_)
        | TerminationOutcome::UnknownFailure(_)
        | TerminationOutcome::ThawFailed { .. } => description,
    }
}

pub(crate) fn kill_command_text(target: &KillTarget, mode: KillMode) -> String {
    command::render_kill_command(target.platform, target.pid, mode)
}

pub(super) fn preserved_selection(
    visible_row_indices: &[usize],
    selected_source_rows: Option<&[bool]>,
    fallback_index: usize,
) -> Option<usize> {
    if visible_row_indices.is_empty() {
        return None;
    }
    if let Some(selected_source_rows) = selected_source_rows
        && let Some(index) = visible_row_indices.iter().position(|&index| {
            *selected_source_rows
                .get(index)
                .expect("visible source indices must fit the selection mask")
        })
    {
        return Some(index);
    }
    Some(fallback_index.min(visible_row_indices.len() - 1))
}
