//! Home of the platform-specific collectors.

use crate::model::{ProcessContext, RelatedProcessHint};
use crate::observation::{ProcessIdentity, ProcessStartMarker};

/// Display and traversal bounds for optional process context. These hints
/// never participate in termination authority, so every platform degrades by
/// truncating at the same policy limits.
const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(windows)]
pub(crate) mod windows;

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    #[cfg(target_os = "linux")]
    {
        linux::collect_process_context(pid)
    }

    #[cfg(windows)]
    {
        windows::collect_process_context(pid)
    }

    #[cfg(target_os = "macos")]
    {
        macos::collect_process_context(pid)
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<ProcessStartMarker> {
    #[cfg(target_os = "linux")]
    {
        linux::process_start_time_marker(pid)
    }

    #[cfg(windows)]
    {
        windows::process_start_time_marker(pid)
    }

    #[cfg(target_os = "macos")]
    {
        macos::process_start_time_marker(pid)
    }
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    #[cfg(target_os = "linux")]
    {
        linux::collect_related_process_hints(port)
    }

    #[cfg(windows)]
    {
        windows::collect_related_process_hints(port)
    }

    #[cfg(target_os = "macos")]
    {
        macos::collect_related_process_hints(port)
    }
}

/// Best-effort command-line reader for inspect reports.
///
/// Windows snapshots are relatively expensive, so the Windows reader captures
/// one process snapshot and reuses it for every PID rendered in the same report.
pub(crate) fn inspect_command_line_reader(
    identities: &[ProcessIdentity],
) -> impl FnMut(u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        marker_checked_command_line_reader(
            identities,
            linux::process_start_time_marker,
            linux::process_command_line,
        )
    }

    #[cfg(target_os = "macos")]
    {
        marker_checked_command_line_reader(
            identities,
            macos::process_start_time_marker,
            macos::process_command_line,
        )
    }

    #[cfg(windows)]
    {
        windows::process_command_line_reader(identities)
    }
}

/// Reads a PID's command line only when its start-time marker matches the
/// identity captured at observation time, re-checking the marker after the
/// read so PID reuse cannot return another process's command.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn marker_checked_command_line_reader(
    identities: &[ProcessIdentity],
    start_time_marker: fn(u32) -> Option<ProcessStartMarker>,
    command_line: fn(u32) -> Option<String>,
) -> impl FnMut(u32) -> Option<String> {
    let expected = identities
        .iter()
        .map(|identity| (identity.pid, identity.start_marker))
        .collect::<std::collections::HashMap<_, _>>();
    move |pid| {
        let marker = expected.get(&pid).copied()?;
        (start_time_marker(pid) == Some(marker)).then_some(())?;
        let command = command_line(pid)?;
        (start_time_marker(pid) == Some(marker)).then_some(command)
    }
}
