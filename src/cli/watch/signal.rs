//! Process-wide cancellation handler ownership for watch sessions.

use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) static WATCH_CANCELLED: AtomicBool = AtomicBool::new(false);
static WATCH_SIGNAL_RESERVED: AtomicBool = AtomicBool::new(false);

pub(super) struct WatchSignalReservation<'a> {
    slot: &'a AtomicBool,
    release_on_drop: bool,
}

impl<'a> WatchSignalReservation<'a> {
    pub(super) fn acquire(slot: &'a AtomicBool) -> io::Result<Self> {
        slot.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| {
                io::Error::new(
                    ErrorKind::WouldBlock,
                    "another watch session already owns the process signal handler",
                )
            })?;
        Ok(Self {
            slot,
            release_on_drop: true,
        })
    }

    pub(super) fn keep_reserved(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for WatchSignalReservation<'_> {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.slot.store(false, Ordering::Release);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct WatchSignalGuard {
    previous: libc::sigaction,
    reservation: WatchSignalReservation<'static>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) extern "C" fn handle_sigint(_: libc::c_int) {
    WATCH_CANCELLED.store(true, Ordering::Relaxed);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl WatchSignalGuard {
    pub(crate) fn cancelled() -> bool {
        WATCH_CANCELLED.load(Ordering::Relaxed)
    }

    pub(crate) fn install() -> io::Result<Self> {
        let reservation = WatchSignalReservation::acquire(&WATCH_SIGNAL_RESERVED)?;
        // SAFETY: sigaction structures are initialized before use, the handler only
        // uses a lock-free atomic, and the previous process action is retained.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handle_sigint as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_flags = 0;
            let mut previous: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGINT, &raw const action, &raw mut previous) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                previous,
                reservation,
            })
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for WatchSignalGuard {
    fn drop(&mut self) {
        // SAFETY: `previous` came from a successful sigaction call and remains valid.
        if unsafe { libc::sigaction(libc::SIGINT, &raw const self.previous, std::ptr::null_mut()) }
            != 0
        {
            let error = io::Error::last_os_error();
            self.reservation.keep_reserved();
            warn_stderr!("failed to restore watch signal handler: {error}");
        }
    }
}

#[cfg(windows)]
pub(crate) struct WatchSignalGuard {
    reservation: WatchSignalReservation<'static>,
}

#[cfg(windows)]
unsafe extern "system" fn handle_console_control(control: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if matches!(control, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        WATCH_CANCELLED.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

#[cfg(windows)]
impl WatchSignalGuard {
    pub(crate) fn cancelled() -> bool {
        WATCH_CANCELLED.load(Ordering::Relaxed)
    }

    pub(crate) fn install() -> io::Result<Self> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        let reservation = WatchSignalReservation::acquire(&WATCH_SIGNAL_RESERVED)?;
        // SAFETY: the handler has static lifetime and performs only an atomic store.
        if unsafe { SetConsoleCtrlHandler(Some(handle_console_control), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { reservation })
    }
}

#[cfg(windows)]
impl Drop for WatchSignalGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        // SAFETY: unregisters the exact static handler installed by this guard.
        if unsafe { SetConsoleCtrlHandler(Some(handle_console_control), 0) } == 0 {
            let error = io::Error::last_os_error();
            self.reservation.keep_reserved();
            warn_stderr!("failed to unregister watch signal handler: {error}");
        }
    }
}
