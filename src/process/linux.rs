//! Linux pidfd preparation, stop verification, and signal delivery.

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::observation::ProcessStartMarker;

use super::{
    KillMode, KillTarget, StopFailure, TerminationHandle, TerminationOutcome, TreeDeliveryHandle,
    UNIX_STOP_ACKNOWLEDGEMENT_MAX, UnixProcessState, UnixProcessStatus, check_final_evidence,
    finish_stopped_termination, outcome_after_thaw, outcome_from_errno, refuse_stopped_termination,
    run_before_stop_deadline, stop_deadline_failure, tree_signal_result_from_errno,
    tree_stop_error, unix_signal, unsafe_pid_reason,
};

pub(super) fn prepare_termination_platform(
    pid: u32,
) -> Result<TerminationHandle, TerminationOutcome> {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return Err(TerminationOutcome::UnknownFailure(
            "PID does not fit platform pid_t".to_owned(),
        ));
    };

    // Open the pidfd before revalidation. That gives us a stable handle to the
    // process we are about to re-check, so if the original process exits and
    // Linux recycles the numeric PID before signal delivery, the signal still
    // goes through this handle instead of chasing the recycled number.
    // SAFETY: pid has already been range-checked to pid_t, flags is zero as
    // required by pidfd_open(2), and the syscall writes no Rust-managed memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(outcome_from_errno("pidfd_open", &error));
    }

    let Ok(fd) = libc::c_int::try_from(fd) else {
        // Unreachable in practice (kernel fds fit c_int), but if it ever fires
        // the raw descriptor must not leak.
        // SAFETY: fd came from a successful pidfd_open and has not been wrapped
        // in an owner yet, so closing it here closes exactly one live fd.
        unsafe { libc::syscall(libc::SYS_close, fd) };
        return Err(TerminationOutcome::UnknownFailure(
            "pidfd_open returned a file descriptor that does not fit c_int".to_owned(),
        ));
    };

    // SAFETY: pidfd_open returned this fd successfully, so we now own exactly one
    // descriptor and hand that ownership to OwnedFd for close-on-drop.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(TerminationHandle {
        pid: u32::try_from(pid).expect("pid_t came from u32 and must fit back into u32"),
        pidfd,
    })
}

pub(super) fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    let cancellation = match super::cancellation::KillCancellationGuard::block() {
        Ok(guard) => guard,
        Err(error) => return TerminationOutcome::UnknownFailure(error.to_string()),
    };
    let stop_deadline = std::time::Instant::now() + UNIX_STOP_ACKNOWLEDGEMENT_MAX;
    let transitioned = match linux_stop_pidfd(
        handle.pid,
        handle.pidfd.as_raw_fd(),
        target.process_start_time_marker,
        stop_deadline,
    ) {
        Ok(transitioned) => transitioned,
        Err(failure) if failure.cleanup_required => {
            return outcome_after_thaw(
                handle.pid,
                failure.outcome,
                tree_signal_result_from_outcome(&linux_pidfd_signal(handle, libc::SIGCONT)),
            );
        }
        Err(failure) => return failure.outcome,
    };
    if let Err(outcome) = check_final_evidence(
        target,
        protected_names,
        crate::platform::linux::fresh_process_evidence(handle.pid),
    ) {
        return refuse_stopped_termination(
            handle.pid,
            transitioned,
            target.process_start_time_marker,
            outcome,
            |_, _| tree_signal_result_from_outcome(&linux_pidfd_signal(handle, libc::SIGCONT)),
        );
    }
    let signal = unix_signal(mode);
    finish_stopped_termination(
        handle.pid,
        mode,
        transitioned,
        target.process_start_time_marker,
        |_| {
            if let Err(error) = cancellation.check() {
                return TerminationOutcome::UnknownFailure(error.to_string());
            }
            linux_pidfd_signal(handle, signal)
                .map_or_else(|outcome| outcome, |()| TerminationOutcome::Success)
        },
        |_, _| tree_signal_result_from_outcome(&linux_pidfd_signal(handle, libc::SIGCONT)),
    )
}

const LINUX_PROC_STAT_MAX_BYTES: u64 = 4096;
const UNIX_STOP_POLL: std::time::Duration = std::time::Duration::from_millis(1);

pub(super) fn parse_linux_process_state(bytes: &[u8]) -> std::io::Result<UnixProcessState> {
    let close = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing stat comm terminator",
            )
        })?;
    let fields = bytes
        .get(close + 1..)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated stat"))?
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|field| (field.len() == 1).then_some(field[0]))
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing process state")
        })?;
    // `fields[0]` is proc stat field 3; starttime is field 22.
    let start_ticks = std::str::from_utf8(fields.get(19).copied().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing process start time",
        )
    })?)
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 start time"))?
    .parse::<u64>()
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid start time"))?;
    let marker = ProcessStartMarker::linux(start_ticks).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "zero process start time")
    })?;
    Ok(UnixProcessState {
        marker,
        status: match state {
            b'T' | b't' => UnixProcessStatus::Stopped,
            b'Z' | b'X' | b'x' => UnixProcessStatus::Exited,
            _ => UnixProcessStatus::Running,
        },
    })
}

pub(super) fn linux_process_state(pid: u32) -> std::io::Result<UnixProcessState> {
    let mut file = std::fs::File::open(format!("/proc/{pid}/stat"))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(LINUX_PROC_STAT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > LINUX_PROC_STAT_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "process stat exceeded bounded read",
        ));
    }
    parse_linux_process_state(&bytes)
}

pub(super) fn linux_stop_observation_result(
    before: UnixProcessState,
    transitioned: bool,
    observed: UnixProcessState,
    deadline_expired: bool,
) -> Option<Result<bool, StopFailure>> {
    if observed.marker != before.marker || observed.status == UnixProcessStatus::Exited {
        return Some(Err(StopFailure {
            outcome: TerminationOutcome::AlreadyExited,
            cleanup_required: false,
            rollback_start_time_marker: None,
        }));
    }
    if deadline_expired {
        return Some(Err(stop_deadline_failure(transitioned, None)));
    }
    (observed.status == UnixProcessStatus::Stopped).then_some(Ok(transitioned))
}

fn linux_state_failure(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match error.kind() {
        std::io::ErrorKind::NotFound => TerminationOutcome::AlreadyExited,
        std::io::ErrorKind::PermissionDenied => TerminationOutcome::PermissionDenied,
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

fn linux_stop_pidfd(
    pid: u32,
    pidfd: libc::c_int,
    expected_marker: Option<ProcessStartMarker>,
    deadline: std::time::Instant,
) -> Result<bool, StopFailure> {
    let before = linux_process_state(pid).map_err(|error| StopFailure {
        outcome: linux_state_failure("reading process state before SIGSTOP", &error),
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
    let transitioned = before.status != UnixProcessStatus::Stopped;
    let result = run_before_stop_deadline(deadline, std::time::Instant::now, || unsafe {
        // SAFETY: pidfd is live for this call; SIGSTOP has no pointer payload.
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGSTOP,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    })?;
    if result != 0 {
        return Err(StopFailure {
            outcome: outcome_from_errno(
                "pidfd_send_signal(SIGSTOP)",
                &std::io::Error::last_os_error(),
            ),
            cleanup_required: false,
            rollback_start_time_marker: None,
        });
    }

    loop {
        if std::time::Instant::now() >= deadline {
            return Err(stop_deadline_failure(transitioned, None));
        }
        match linux_process_state(pid) {
            Ok(state) => {
                if let Some(result) = linux_stop_observation_result(
                    before,
                    transitioned,
                    state,
                    std::time::Instant::now() >= deadline,
                ) {
                    return result;
                }
            }
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    return Err(stop_deadline_failure(transitioned, None));
                }
                let outcome = linux_state_failure("reading process state after SIGSTOP", &error);
                return Err(StopFailure {
                    cleanup_required: transitioned && outcome != TerminationOutcome::AlreadyExited,
                    outcome,
                    rollback_start_time_marker: None,
                });
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(stop_deadline_failure(transitioned, None));
        }
        std::thread::sleep(UNIX_STOP_POLL.min(deadline.saturating_duration_since(now)));
    }
}

fn tree_signal_result_from_outcome(
    result: &Result<(), TerminationOutcome>,
) -> crate::tree::TreeSignalResult {
    match result {
        Ok(()) => crate::tree::TreeSignalResult::Delivered,
        Err(TerminationOutcome::AlreadyExited) => crate::tree::TreeSignalResult::NotFound,
        Err(_) => crate::tree::TreeSignalResult::Denied,
    }
}

fn linux_pidfd_signal(
    handle: &TerminationHandle,
    signal: libc::c_int,
) -> Result<(), TerminationOutcome> {
    let result = unsafe {
        // SAFETY: pidfd is owned for this call; signal is a fixed process signal.
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(outcome_from_errno(
            "pidfd_send_signal",
            &std::io::Error::last_os_error(),
        ))
    }
}

pub(crate) fn tree_open_delivery_handle(
    pid: u32,
) -> Result<TreeDeliveryHandle, crate::tree::TreeSignalResult> {
    use crate::tree::TreeSignalResult;

    if unsafe_pid_reason(pid).is_some() {
        return Err(TreeSignalResult::Denied);
    }
    let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
        return Err(TreeSignalResult::NotFound);
    };
    // SAFETY: pid has been range-checked to pid_t, flags is zero as required by
    // pidfd_open(2), and the syscall writes no Rust-managed memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, platform_pid, 0) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(tree_signal_result_from_errno(&error));
    }
    let Ok(fd) = libc::c_int::try_from(fd) else {
        // Unreachable in practice (kernel fds fit c_int), but if it ever fires
        // the raw descriptor must not leak.
        // SAFETY: fd came from a successful pidfd_open and has not been wrapped
        // in an owner yet, so closing it here closes exactly one live fd.
        unsafe { libc::syscall(libc::SYS_close, fd) };
        return Err(TreeSignalResult::Denied);
    };
    // SAFETY: pidfd_open returned this fd successfully, so OwnedFd owns it once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(TreeDeliveryHandle { pid, pidfd })
}

pub(crate) fn tree_stop_handle(
    handle: &TreeDeliveryHandle,
    deadline: std::time::Instant,
) -> crate::tree::TreeStopResult {
    use crate::tree::TreeStopResult;

    match linux_stop_pidfd(handle.pid, handle.pidfd.as_raw_fd(), None, deadline) {
        Ok(transitioned) => TreeStopResult::Stopped { transitioned },
        Err(StopFailure {
            outcome: TerminationOutcome::AlreadyExited | TerminationOutcome::TargetChanged,
            ..
        }) => TreeStopResult::NotFound,
        Err(failure) => TreeStopResult::Failed {
            cleanup_required: failure.cleanup_required,
            rollback_start_time_marker: failure.rollback_start_time_marker,
            error: tree_stop_error(failure.outcome),
        },
    }
}

pub(crate) fn tree_cont_handle(handle: &TreeDeliveryHandle) -> crate::tree::TreeSignalResult {
    tree_send_pidfd_signal(handle, libc::SIGCONT)
}

pub(crate) fn tree_deliver_handle(
    handle: &TreeDeliveryHandle,
    mode: KillMode,
) -> crate::tree::TreeSignalResult {
    tree_send_pidfd_signal(handle, unix_signal(mode))
}

fn tree_send_pidfd_signal(
    handle: &TreeDeliveryHandle,
    signal: libc::c_int,
) -> crate::tree::TreeSignalResult {
    // SAFETY: pidfd is an open descriptor from pidfd_open, signal is one of the
    // fixed process-tree signals, siginfo is null by pidfd_send_signal(2)
    // convention, and flags is zero. No Rust-managed memory is written.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        return crate::tree::TreeSignalResult::Delivered;
    }
    let error = std::io::Error::last_os_error();
    tree_signal_result_from_errno(&error)
}
