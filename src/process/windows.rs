//! Windows process-handle preparation, evidence refresh, delivery, and waiting.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, STILL_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};

use super::{KillMode, KillTarget, TerminationHandle, TerminationOutcome, check_final_evidence};

pub(super) fn prepare_termination_platform(
    pid: u32,
) -> Result<TerminationHandle, TerminationOutcome> {
    let desired_access =
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    let handle = unsafe {
        // SAFETY: OpenProcess takes a PID and access mask by value. We request no
        // inherited handle, and no Rust-managed memory crosses this FFI boundary.
        OpenProcess(desired_access, 0, pid)
    };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        return Err(windows_api_outcome("OpenProcess", &error));
    }

    let process_handle = unsafe {
        // SAFETY: OpenProcess returned a non-null owned process handle. OwnedHandle
        // closes it exactly once.
        OwnedHandle::from_raw_handle(handle)
    };
    Ok(TerminationHandle {
        pid,
        process_handle,
    })
}

fn terminate_handle_platform(handle: &TerminationHandle, _mode: KillMode) -> TerminationOutcome {
    if !windows_process_is_alive(handle) {
        return TerminationOutcome::AlreadyExited;
    }

    let result = unsafe {
        // SAFETY: the handle is the still-owned process handle opened during
        // preparation. Windows has one hard stop here; both UI modes use it.
        TerminateProcess(
            handle.process_handle.as_raw_handle(),
            WINDOWS_TERMINATE_EXIT_CODE,
        )
    };
    if result != 0 {
        return wait_for_windows_process_exit(handle);
    }

    let error = std::io::Error::last_os_error();
    if !windows_process_is_alive(handle) {
        return TerminationOutcome::AlreadyExited;
    }
    windows_api_outcome("TerminateProcess", &error)
}

pub(super) fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    let fresh = windows_fresh_process_evidence(handle);
    if let Err(outcome) = check_final_evidence(target, protected_names, fresh) {
        return outcome;
    }
    terminate_handle_platform(handle, mode)
}

fn windows_fresh_process_evidence(
    handle: &TerminationHandle,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    use windows_sys::Win32::System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW};
    const CODE_UNITS: usize = crate::observation::PROTECTION_NAME_MAX_BYTES / 2;

    let marker =
        crate::platform::windows::process_start_time_marker_from_handle(&handle.process_handle)
            .ok_or(ProcessEvidenceError::Missing { pid: handle.pid })?;
    let mut buffer = [0_u16; CODE_UNITS];
    let mut length = u32::try_from(buffer.len()).expect("fixed evidence buffer fits u32");
    let result = unsafe {
        // SAFETY: the prepared process handle remains owned and the fixed buffer
        // is valid for `length` UTF-16 writes.
        QueryFullProcessImageNameW(
            handle.process_handle.as_raw_handle(),
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return Err(if windows_error_code(&error) == Some(ERROR_ACCESS_DENIED) {
            ProcessEvidenceError::PermissionDenied { pid: handle.pid }
        } else {
            ProcessEvidenceError::Missing { pid: handle.pid }
        });
    }
    let code_units =
        native_utf16_prefix(&buffer, length).ok_or(ProcessEvidenceError::NameOversized {
            pid: handle.pid,
            bytes: usize::try_from(length)
                .unwrap_or(usize::MAX)
                .saturating_mul(2),
        })?;
    let path = String::from_utf16_lossy(code_units);
    let name = std::path::Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or(ProcessEvidenceError::NameMissing { pid: handle.pid })?;
    Ok(FreshProcessEvidence {
        pid: handle.pid,
        start_marker: marker,
        name,
    })
}

pub(super) fn native_utf16_prefix(buffer: &[u16], reported_length: u32) -> Option<&[u16]> {
    buffer.get(..usize::try_from(reported_length).ok()?)
}

const WINDOWS_TERMINATE_EXIT_CODE: u32 = 1;
const WINDOWS_TERMINATE_WAIT_MS: u32 = 5_000;

fn wait_for_windows_process_exit(handle: &TerminationHandle) -> TerminationOutcome {
    let result = unsafe {
        // SAFETY: the process handle is owned by `TerminationHandle` and was
        // opened with PROCESS_SYNCHRONIZE during preparation. Waiting does not
        // transfer ownership or write Rust-managed memory.
        WaitForSingleObject(
            handle.process_handle.as_raw_handle(),
            WINDOWS_TERMINATE_WAIT_MS,
        )
    };
    match result {
        WAIT_OBJECT_0 => TerminationOutcome::Success,
        WAIT_TIMEOUT => match windows_exit_code(handle) {
            Ok(Some(code)) => TerminationOutcome::UnknownFailure(format!(
                "process did not exit within {WINDOWS_TERMINATE_WAIT_MS}ms after TerminateProcess; exit code {code}"
            )),
            Ok(None) => TerminationOutcome::UnknownFailure(format!(
                "process did not exit within {WINDOWS_TERMINATE_WAIT_MS}ms after TerminateProcess"
            )),
            Err(outcome) => outcome,
        },
        WAIT_FAILED => {
            let error = std::io::Error::last_os_error();
            windows_api_outcome("WaitForSingleObject", &error)
        }
        other => TerminationOutcome::UnknownFailure(format!(
            "WaitForSingleObject returned unexpected status {other}"
        )),
    }
}

fn windows_process_is_alive(handle: &TerminationHandle) -> bool {
    match windows_wait_status(handle, 0) {
        // Signaled: the process has already exited.
        Ok(WAIT_OBJECT_0) => false,
        // WAIT_TIMEOUT is a definitive "still running"; an Err means we couldn't
        // even ask, so we keep the conservative live assumption and let the real
        // termination call surface the error. Both cases mean "treat as alive".
        Ok(WAIT_TIMEOUT) | Err(_) => true,
        // Any other wait status is unexpected, so fall back to the exit code and
        // treat a real code as "not alive".
        Ok(_) => matches!(windows_exit_code(handle), Ok(None)),
    }
}

fn windows_wait_status(
    handle: &TerminationHandle,
    milliseconds: u32,
) -> Result<u32, TerminationOutcome> {
    let result = unsafe {
        // SAFETY: the process handle is owned by `TerminationHandle` and was
        // opened with PROCESS_SYNCHRONIZE during preparation.
        WaitForSingleObject(handle.process_handle.as_raw_handle(), milliseconds)
    };
    match result {
        WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(result),
        WAIT_FAILED => Err(windows_api_outcome(
            "WaitForSingleObject",
            &std::io::Error::last_os_error(),
        )),
        other => Ok(other),
    }
}

fn windows_exit_code(handle: &TerminationHandle) -> Result<Option<u32>, TerminationOutcome> {
    let mut exit_code = 0_u32;
    let result = unsafe {
        // SAFETY: the pointer is valid for one u32 write and the process handle is
        // owned by `TerminationHandle` for this whole call.
        GetExitCodeProcess(handle.process_handle.as_raw_handle(), &raw mut exit_code)
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return Err(windows_api_outcome("GetExitCodeProcess", &error));
    }
    if exit_code == windows_still_active_exit_code() {
        Ok(None)
    } else {
        Ok(Some(exit_code))
    }
}

fn windows_still_active_exit_code() -> u32 {
    u32::try_from(STILL_ACTIVE).expect("STILL_ACTIVE must fit in a process exit code")
}

pub(super) fn windows_api_outcome(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match windows_error_code(error) {
        Some(ERROR_INVALID_PARAMETER) => TerminationOutcome::AlreadyExited,
        Some(ERROR_ACCESS_DENIED) => TerminationOutcome::PermissionDenied,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

fn windows_error_code(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}
