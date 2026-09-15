//! macOS stop verification, process evidence, and raw-PID delivery.

use crate::observation::ProcessStartMarker;
#[cfg(target_os = "macos")]
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};

#[cfg(target_os = "macos")]
use super::{
    KillMode, KillTarget, TerminationHandle, UNIX_STOP_ACKNOWLEDGEMENT_MAX, check_final_evidence,
    finish_stopped_termination, outcome_after_thaw, refuse_stopped_termination,
    run_before_stop_deadline, tree_cont, tree_send_signal, unix_signal,
};
use super::{
    StopFailure, TerminationOutcome, UnixProcessState, UnixProcessStatus, stop_deadline_failure,
    tree_stop_error,
};

#[cfg(target_os = "macos")]
const UNIX_STOP_POLL: std::time::Duration = std::time::Duration::from_millis(1);

#[cfg(target_os = "macos")]
pub(super) fn macos_status_is_exited(status: u32) -> bool {
    status == libc::SZOMB
}

#[cfg(target_os = "macos")]
fn macos_process_state(pid: u32) -> std::io::Result<UnixProcessState> {
    let platform_pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "PID exceeds pid_t"))?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "proc_bsdinfo size exceeds c_int",
        )
    })?;
    let bytes = unsafe {
        // SAFETY: `info` points to one writable proc_bsdinfo and proc_pidinfo
        // writes at most the supplied structure size without retaining it.
        libc::proc_pidinfo(
            platform_pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if bytes != size {
        return Err(if bytes <= 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proc_pidinfo returned a partial proc_bsdinfo",
            )
        });
    }
    let info = unsafe {
        // SAFETY: proc_pidinfo reported that it initialized the full structure.
        info.assume_init()
    };
    let microseconds = u32::try_from(info.pbi_start_tvusec).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "process start microseconds exceed u32",
        )
    })?;
    let marker = ProcessStartMarker::macos(info.pbi_start_tvsec, microseconds).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid process start time",
        )
    })?;
    Ok(UnixProcessState {
        marker,
        status: if macos_status_is_exited(info.pbi_status) {
            UnixProcessStatus::Exited
        } else if info.pbi_status == libc::SSTOP {
            UnixProcessStatus::Stopped
        } else {
            UnixProcessStatus::Running
        },
    })
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
pub(super) fn macos_stop_observation_result(
    before: UnixProcessState,
    observed: UnixProcessState,
    deadline_expired: bool,
) -> Option<Result<bool, StopFailure>> {
    if observed.status == UnixProcessStatus::Exited {
        return Some(Err(StopFailure {
            outcome: TerminationOutcome::AlreadyExited,
            cleanup_required: false,
            rollback_start_time_marker: None,
        }));
    }
    if observed.marker != before.marker {
        return Some(Err(StopFailure {
            outcome: TerminationOutcome::TargetChanged,
            cleanup_required: observed.status == UnixProcessStatus::Stopped,
            rollback_start_time_marker: (observed.status == UnixProcessStatus::Stopped)
                .then_some(observed.marker),
        }));
    }
    if deadline_expired {
        let cleanup_required = before.status != UnixProcessStatus::Stopped;
        return Some(Err(stop_deadline_failure(
            cleanup_required,
            cleanup_required.then_some(observed.marker),
        )));
    }
    (observed.status == UnixProcessStatus::Stopped)
        .then_some(Ok(before.status != UnixProcessStatus::Stopped))
}

#[cfg(target_os = "macos")]
fn macos_stop_process(
    pid: u32,
    expected_marker: Option<ProcessStartMarker>,
    deadline: std::time::Instant,
) -> Result<bool, StopFailure> {
    let before = macos_process_state(pid).map_err(|error| StopFailure {
        outcome: macos_signal_outcome("proc_pidinfo before SIGSTOP", &error),
        cleanup_required: false,
        rollback_start_time_marker: None,
    })?;
    if before.status == UnixProcessStatus::Exited {
        return Err(StopFailure {
            outcome: TerminationOutcome::AlreadyExited,
            cleanup_required: false,
            rollback_start_time_marker: None,
        });
    }
    if expected_marker.is_some_and(|expected| expected != before.marker) {
        return Err(StopFailure {
            outcome: TerminationOutcome::TargetChanged,
            cleanup_required: false,
            rollback_start_time_marker: None,
        });
    }
    let platform_pid = pid_to_macos_pid(pid).map_err(|outcome| StopFailure {
        outcome,
        cleanup_required: false,
        rollback_start_time_marker: None,
    })?;
    let stop = run_before_stop_deadline(deadline, std::time::Instant::now, || unsafe {
        // SAFETY: pid is range checked and SIGSTOP has no pointer arguments.
        libc::kill(platform_pid, libc::SIGSTOP)
    })?;
    if stop != 0 {
        return Err(StopFailure {
            outcome: macos_signal_outcome("kill(SIGSTOP)", &std::io::Error::last_os_error()),
            cleanup_required: false,
            rollback_start_time_marker: None,
        });
    }

    loop {
        if std::time::Instant::now() >= deadline {
            let cleanup_required = before.status != UnixProcessStatus::Stopped;
            return Err(stop_deadline_failure(
                cleanup_required,
                cleanup_required.then_some(before.marker),
            ));
        }
        match macos_process_state(pid) {
            Ok(state) => {
                if let Some(result) = macos_stop_observation_result(
                    before,
                    state,
                    std::time::Instant::now() >= deadline,
                ) {
                    return result;
                }
            }
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    let cleanup_required = before.status != UnixProcessStatus::Stopped;
                    return Err(stop_deadline_failure(cleanup_required, None));
                }
                return Err(StopFailure {
                    outcome: macos_signal_outcome("proc_pidinfo after SIGSTOP", &error),
                    cleanup_required: before.status != UnixProcessStatus::Stopped,
                    rollback_start_time_marker: None,
                });
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            let cleanup_required = before.status != UnixProcessStatus::Stopped;
            return Err(stop_deadline_failure(
                cleanup_required,
                cleanup_required.then_some(before.marker),
            ));
        }
        std::thread::sleep(UNIX_STOP_POLL.min(deadline.saturating_duration_since(now)));
    }
}

#[cfg(target_os = "macos")]
pub(super) fn prepare_termination_platform(
    pid: u32,
) -> Result<TerminationHandle, TerminationOutcome> {
    let platform_pid = pid_to_macos_pid(pid)?;
    let Some(process_start_time_marker) = crate::platform::macos::process_start_time_marker(pid)
    else {
        return if macos_process_exists(platform_pid) {
            Err(TerminationOutcome::OwnershipUnavailable)
        } else {
            Err(TerminationOutcome::AlreadyExited)
        };
    };
    Ok(TerminationHandle {
        pid,
        process_start_time_marker,
    })
}

#[cfg(target_os = "macos")]
pub(super) fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    if target.process_start_time_marker != Some(handle.process_start_time_marker) {
        return TerminationOutcome::TargetChanged;
    }
    let cancellation = match super::cancellation::KillCancellationGuard::block() {
        Ok(guard) => guard,
        Err(error) => return TerminationOutcome::UnknownFailure(error.to_string()),
    };
    let stop_deadline = std::time::Instant::now() + UNIX_STOP_ACKNOWLEDGEMENT_MAX;
    let transitioned =
        match macos_stop_process(handle.pid, target.process_start_time_marker, stop_deadline) {
            Ok(transitioned) => transitioned,
            Err(failure) if failure.cleanup_required => {
                let rollback_marker = failure
                    .rollback_start_time_marker
                    .or_else(|| {
                        macos_process_state(handle.pid)
                            .ok()
                            .map(|state| state.marker)
                    })
                    .or(target.process_start_time_marker);
                return outcome_after_thaw(
                    handle.pid,
                    failure.outcome,
                    macos_cont_if_matches(handle.pid, rollback_marker),
                );
            }
            Err(failure) => return failure.outcome,
        };
    let pid = match pid_to_macos_pid(handle.pid) {
        Ok(pid) => pid,
        Err(outcome) => return outcome,
    };
    let fresh = crate::platform::macos::fresh_process_evidence(handle.pid);
    finish_macos_stopped_process(
        handle.pid,
        target,
        protected_names,
        mode,
        transitioned,
        fresh,
        |mode| {
            if let Err(error) = cancellation.check() {
                return TerminationOutcome::UnknownFailure(error.to_string());
            }
            let signal = unix_signal(mode);
            let result = unsafe {
                // SAFETY: pid is range checked and signal is one of two fixed values.
                libc::kill(pid, signal)
            };
            if result == 0 {
                TerminationOutcome::Success
            } else {
                macos_signal_outcome("kill", &std::io::Error::last_os_error())
            }
        },
        macos_cont_if_matches,
    )
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::too_many_arguments,
    reason = "the testable macOS stop boundary keeps termination, cleanup ownership, and injected signal operations explicit"
)]
pub(super) fn finish_macos_stopped_process<Terminate, Continue>(
    pid: u32,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
    resume_on_cleanup: bool,
    fresh: Result<FreshProcessEvidence, ProcessEvidenceError>,
    terminate: Terminate,
    continue_process: Continue,
) -> TerminationOutcome
where
    Terminate: FnOnce(KillMode) -> TerminationOutcome,
    Continue: FnOnce(u32, Option<ProcessStartMarker>) -> crate::tree::TreeSignalResult,
{
    let rollback_marker = fresh
        .as_ref()
        .ok()
        .map(|evidence| evidence.start_marker)
        .or(target.process_start_time_marker);
    if let Err(outcome) = check_final_evidence(target, protected_names, fresh) {
        return refuse_stopped_termination(
            pid,
            resume_on_cleanup,
            rollback_marker,
            outcome,
            continue_process,
        );
    }
    finish_stopped_termination(
        pid,
        mode,
        resume_on_cleanup,
        rollback_marker,
        terminate,
        continue_process,
    )
}

#[cfg(target_os = "macos")]
fn macos_cont_if_matches(
    pid: u32,
    rollback_marker: Option<ProcessStartMarker>,
) -> crate::tree::TreeSignalResult {
    macos_cont_if_matches_with(
        pid,
        rollback_marker,
        crate::platform::macos::process_start_time_marker_result,
        tree_cont,
    )
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
pub(super) fn macos_cont_if_matches_with<ReadMarker, Continue>(
    pid: u32,
    rollback_marker: Option<ProcessStartMarker>,
    read_marker: ReadMarker,
    continue_process: Continue,
) -> crate::tree::TreeSignalResult
where
    ReadMarker: FnOnce(u32) -> std::io::Result<ProcessStartMarker>,
    Continue: FnOnce(u32) -> crate::tree::TreeSignalResult,
{
    let Some(rollback_marker) = rollback_marker else {
        return crate::tree::TreeSignalResult::Denied;
    };
    match read_marker(pid) {
        Ok(marker) if marker == rollback_marker => continue_process(pid),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
            crate::tree::TreeSignalResult::NotFound
        }
        Ok(_) | Err(_) => crate::tree::TreeSignalResult::Denied,
    }
}

#[cfg(target_os = "macos")]
fn pid_to_macos_pid(pid: u32) -> Result<libc::pid_t, TerminationOutcome> {
    libc::pid_t::try_from(pid).map_err(|_| {
        TerminationOutcome::UnknownFailure("PID does not fit platform pid_t".to_owned())
    })
}

#[cfg(target_os = "macos")]
fn macos_process_exists(pid: libc::pid_t) -> bool {
    let result = unsafe {
        // SAFETY: signal 0 performs existence/permission checking only and writes
        // no Rust-managed memory.
        libc::kill(pid, 0)
    };
    if result == 0 {
        return true;
    }
    let error = std::io::Error::last_os_error();
    !matches!(error.raw_os_error(), Some(code) if code == libc::ESRCH)
}

#[cfg(target_os = "macos")]
fn macos_signal_outcome(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TerminationOutcome::AlreadyExited,
        Some(code) if code == libc::EPERM || code == libc::EACCES => {
            TerminationOutcome::PermissionDenied
        }
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

/// Classify a stop attempt's `Result` into the tree signal/stop outcome pair.
///
/// A clean stop maps to `Delivered`/`Stopped`; a process that already exited
/// or changed identity without needing cleanup maps to `NotFound`; every other
/// failure maps to `Denied`/`Failed` with its cleanup requirements preserved.
#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
pub(super) fn macos_tree_stop_result(
    result: Result<bool, StopFailure>,
) -> crate::tree::TreeStopResult {
    use crate::tree::TreeStopResult;

    match result {
        Ok(transitioned) => TreeStopResult::Stopped { transitioned },
        Err(StopFailure {
            outcome: TerminationOutcome::AlreadyExited | TerminationOutcome::TargetChanged,
            cleanup_required: false,
            ..
        }) => TreeStopResult::NotFound,
        Err(failure) => TreeStopResult::Failed {
            cleanup_required: failure.cleanup_required,
            rollback_start_time_marker: failure.rollback_start_time_marker,
            error: tree_stop_error(failure.outcome),
        },
    }
}

/// Send `SIGSTOP` to a PID for the process-tree freeze.
///
/// macOS stops by PID and verifies identity after the stop. Linux uses pidfds
/// through `tree_stop_handle` instead.
#[cfg(target_os = "macos")]
pub(crate) fn tree_stop(pid: u32, deadline: std::time::Instant) -> crate::tree::TreeStopResult {
    macos_tree_stop_result(macos_stop_process(pid, None, deadline))
}

/// macOS delivery preparation: probe that the stopped process still exists.
///
/// Darwin has no pidfd. The pipeline stops and verifies each member, then
/// `MacosTreeOps` checks the start marker again immediately before each raw-PID
/// signal. Signal `0` checks existence and permission without delivering a
/// signal. An external kill and reap can still recycle a PID between the marker
/// check and delivery.
#[cfg(target_os = "macos")]
pub(crate) fn tree_prepare_delivery_probe(pid: u32) -> crate::tree::TreeSignalResult {
    tree_send_signal(pid, 0)
}

/// macOS terminating delivery, by PID. Only called after the member was
/// frozen, verified, and marker-rechecked (see `tree_prepare_delivery_probe`
/// and `MacosTreeOps::recheck_marker` for the layered reuse defense).
#[cfg(target_os = "macos")]
pub(crate) fn tree_deliver_by_pid(pid: u32, mode: KillMode) -> crate::tree::TreeSignalResult {
    tree_send_signal(pid, unix_signal(mode))
}
