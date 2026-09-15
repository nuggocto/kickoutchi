//! Defer termination of the synchronous Unix kill owner until its targets are
//! thawed. CLI kills run on the main thread without workers; TUI workers already
//! block SIGTERM/SIGHUP and the terminal delivers Ctrl-C as input in raw mode.

use std::io;
use std::marker::PhantomData;
use std::rc::Rc;

const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

pub(crate) struct KillCancellationGuard {
    previous: libc::sigset_t,
    // Signal masks belong to a thread. Never restore one on another thread.
    _owner_thread: PhantomData<Rc<()>>,
}

impl KillCancellationGuard {
    pub(crate) fn block() -> io::Result<Self> {
        // SAFETY: libc initializes both sets before use; all signals are valid.
        unsafe {
            let mut signals: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&raw mut signals) != 0 {
                return Err(io::Error::last_os_error());
            }
            for signal in SIGNALS {
                if libc::sigaddset(&raw mut signals, signal) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut previous: libc::sigset_t = std::mem::zeroed();
            let error =
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, &raw mut previous);
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            Ok(Self {
                previous,
                _owner_thread: PhantomData,
            })
        }
    }

    /// Refuse further freezing or delivery when a termination signal is pending.
    /// Leave it pending so restoring the mask preserves the caller's disposition.
    #[expect(
        clippy::unused_self,
        reason = "checking cancellation requires a live thread-bound signal mask owner"
    )]
    pub(crate) fn check(&self) -> io::Result<()> {
        // SAFETY: sigpending initializes the set before sigismember reads it.
        unsafe {
            let mut pending: libc::sigset_t = std::mem::zeroed();
            if libc::sigpending(&raw mut pending) != 0 {
                return Err(io::Error::last_os_error());
            }
            for signal in SIGNALS {
                match libc::sigismember(&raw const pending, signal) {
                    0 => {}
                    1 => {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "kill interrupted",
                        ));
                    }
                    _ => return Err(io::Error::last_os_error()),
                }
            }
        }
        Ok(())
    }
}

impl Drop for KillCancellationGuard {
    fn drop(&mut self) {
        // SAFETY: previous was saved on this thread, and the !Send guard keeps
        // restoration here. A pending signal may terminate us during this call;
        // callers must finish all target cleanup before dropping the guard.
        let error = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
        if error != 0 {
            tracing::error!(error = %io::Error::from_raw_os_error(error), "failed to restore kill signal mask");
        }
    }
}

#[cfg(test)]
use crate::test_support::command as test_command;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};

    static DELIVERED_SIGNAL: AtomicI32 = AtomicI32::new(0);

    extern "C" fn record_signal(signal: libc::c_int) {
        DELIVERED_SIGNAL.store(signal, Ordering::Relaxed);
    }

    #[test]
    fn cancellation_preserves_signal_handlers_and_the_prior_mask() {
        const HELPER_ENV: &str = "KICKOUTCHI_TEST_KILL_SIGNAL_MASK";
        if std::env::var_os(HELPER_ENV).is_none() {
            let output = test_command::run_command_with_deadline(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "process::cancellation::tests::cancellation_preserves_signal_handlers_and_the_prior_mask", "--nocapture"])
                    .env(HELPER_ENV, "1"),
                None,
                std::time::Duration::from_secs(10),
            ).unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }

        // SAFETY: this subprocess owns its signal dispositions. pthread_kill
        // targets only this test thread, so the harness cannot consume it.
        unsafe {
            let mut initial: libc::sigset_t = std::mem::zeroed();
            let mut prior: libc::sigset_t = std::mem::zeroed();
            assert_eq!(libc::sigemptyset(&raw mut initial), 0);
            assert_eq!(libc::sigaddset(&raw mut initial, libc::SIGUSR1), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const initial, &raw mut prior),
                0
            );
            for signal in SIGNALS {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = record_signal as *const () as usize;
                assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
                let mut previous: libc::sigaction = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(signal, &raw const action, &raw mut previous),
                    0
                );
                DELIVERED_SIGNAL.store(0, Ordering::Relaxed);

                let guard = KillCancellationGuard::block().unwrap();
                assert!(guard.check().is_ok());
                assert_eq!(libc::pthread_kill(libc::pthread_self(), signal), 0);
                assert_eq!(
                    guard.check().unwrap_err().kind(),
                    io::ErrorKind::Interrupted
                );
                assert_eq!(DELIVERED_SIGNAL.load(Ordering::Relaxed), 0);
                drop(guard);
                assert_eq!(DELIVERED_SIGNAL.load(Ordering::Relaxed), signal);

                let mut restored: libc::sigset_t = std::mem::zeroed();
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &raw mut restored),
                    0
                );
                assert_eq!(libc::sigismember(&raw const restored, libc::SIGUSR1), 1);
                assert_eq!(libc::sigismember(&raw const restored, signal), 0);
                assert_eq!(
                    libc::sigaction(signal, &raw const previous, std::ptr::null_mut()),
                    0
                );
            }
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const prior, std::ptr::null_mut()),
                0
            );
        }
    }
}
