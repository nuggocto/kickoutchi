//! Terminal lifecycle, the event loop, and drawing.
//!
//! Terminal state is restored after normal return, propagated error, or panic.

mod confirm;
mod details;
mod help;
mod table;
mod theme;

use std::any::Any;
use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Stdout};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
#[cfg(unix)]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::{Frame, Terminal};
use unicode_width::UnicodeWidthChar;

use crate::app::{App, ModalKind};
use crate::config::Config;
use crate::display::sanitize;
use crate::error::AppResult;
use crate::input;

use self::theme::Theme;

// The concrete terminal type we use all over the UI.
type Tui = Terminal<CrosstermBackend<Stdout>>;

const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);
static TUI_SESSION_LOCK: Mutex<()> = Mutex::new(());
static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static OWNS_TUI_SESSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static IS_TUI_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

type PanicHook = dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static;

struct OriginalPanicHook {
    hook: Box<PanicHook>,
}

/// Restores the process hook when this TUI session completes.
///
/// `run_owned` has exclusive process panic-hook ownership for its lifetime.
/// Embedders must not replace the process hook concurrently; Rust exposes no
/// hook identity that would let us distinguish our dispatcher from a replacement.
pub(crate) struct PanicHookGuard {
    active: Arc<AtomicBool>,
    original: Option<Arc<OriginalPanicHook>>,
}

/// A panic caught at the TUI worker boundary and handed back to its owner.
#[derive(Debug, thiserror::Error)]
#[error("TUI worker {worker} panicked: {message}")]
pub(crate) struct WorkerFailure {
    worker: String,
    message: String,
}

impl WorkerFailure {
    fn from_panic(payload: &(dyn Any + Send)) -> Self {
        let message = payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned());
        let worker = thread::current().name().unwrap_or("unnamed").to_owned();
        Self { worker, message }
    }

    #[cfg(test)]
    pub(crate) fn for_test(worker: &str, message: &str) -> Self {
        Self {
            worker: worker.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Result channel for one detached-capable TUI worker.
pub(crate) struct Worker<T> {
    receiver: mpsc::Receiver<Result<T, WorkerFailure>>,
    handle: thread::JoinHandle<()>,
}

impl<T> Worker<T> {
    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Result<T, WorkerFailure>, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    #[cfg(test)]
    fn recv(&self) -> Result<Result<T, WorkerFailure>, mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Keep only the completion channel. Dropping the handle preserves Rust's
    /// normal detached-thread behavior used by refresh/details/tree workers.
    pub(crate) fn detach(self) -> mpsc::Receiver<Result<T, WorkerFailure>> {
        self.receiver
    }

    fn join(self) -> thread::Result<()> {
        self.handle.join()
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let installed = std::panic::take_hook();
        drop(installed);
        let Some(shared) = self.original.take() else {
            return;
        };
        if let Ok(original) = Arc::try_unwrap(shared) {
            std::panic::set_hook(original.hook);
        }
    }
}

struct TuiSessionGuard {
    _lock: MutexGuard<'static, ()>,
}

impl TuiSessionGuard {
    fn acquire() -> io::Result<Self> {
        if OWNS_TUI_SESSION.with(std::cell::Cell::get) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "a nested TUI session is not supported",
            ));
        }
        let lock = TUI_SESSION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        OWNS_TUI_SESSION.with(|owns| owns.set(true));
        Ok(Self { _lock: lock })
    }
}

impl Drop for TuiSessionGuard {
    fn drop(&mut self) {
        OWNS_TUI_SESSION.with(|owns| owns.set(false));
    }
}

#[cfg(unix)]
static TERMINATION_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Keep the first shutdown request and ignore every later one.
///
/// Split out from the handler so the first-wins rule can be exercised against a
/// caller-supplied slot. Driving the process-global from a test instead would
/// race every concurrent reader of it, including the one inside
/// [`wait_for_startup_worker`], which consumes the slot on each poll and would
/// silently steal the recorded signal.
///
/// A relaxed compare-exchange is the whole body, so this stays
/// async-signal-safe: no allocation, no locks, no reentrancy.
#[cfg(unix)]
fn record_first_signal(slot: &AtomicI32, signal: libc::c_int) {
    let _ = slot.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

#[cfg(unix)]
extern "C" fn record_termination_signal(signal: libc::c_int) {
    record_first_signal(&TERMINATION_SIGNAL, signal);
}

#[cfg(unix)]
struct TuiSignalGuard {
    previous_term: libc::sigaction,
    previous_hup: libc::sigaction,
    installed: bool,
}

#[cfg(unix)]
impl TuiSignalGuard {
    fn install() -> io::Result<Self> {
        TERMINATION_SIGNAL.store(0, Ordering::Relaxed);
        // SAFETY: both actions are fully initialized before installation. The
        // handler only performs a lock-free atomic operation, and both previous
        // dispositions are retained for normal teardown.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_termination_signal as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_flags = 0;

            let mut previous_term: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGTERM, &raw const action, &raw mut previous_term) != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut previous_hup: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGHUP, &raw const action, &raw mut previous_hup) != 0 {
                let error = io::Error::last_os_error();
                libc::sigaction(
                    libc::SIGTERM,
                    &raw const previous_term,
                    std::ptr::null_mut(),
                );
                return Err(error);
            }

            Ok(Self {
                previous_term,
                previous_hup,
                installed: true,
            })
        }
    }

    fn restore_previous(&mut self) -> io::Result<()> {
        if !self.installed {
            return Ok(());
        }
        // SAFETY: these actions were returned by successful `sigaction` calls
        // and remain valid for the lifetime of the guard.
        unsafe {
            let term_result = libc::sigaction(
                libc::SIGTERM,
                &raw const self.previous_term,
                std::ptr::null_mut(),
            );
            let term_error = (term_result != 0).then(io::Error::last_os_error);
            let hup_result = libc::sigaction(
                libc::SIGHUP,
                &raw const self.previous_hup,
                std::ptr::null_mut(),
            );
            let hup_error = (hup_result != 0).then(io::Error::last_os_error);
            if let Some(error) = term_error.or(hup_error) {
                return Err(error);
            }
        }
        self.installed = false;
        Ok(())
    }

    fn previous_disposition(&self, signal: libc::c_int) -> usize {
        match signal {
            libc::SIGTERM => self.previous_term.sa_sigaction,
            libc::SIGHUP => self.previous_hup.sa_sigaction,
            _ => libc::SIG_DFL,
        }
    }
}

#[cfg(unix)]
impl Drop for TuiSignalGuard {
    fn drop(&mut self) {
        if let Err(error) = self.restore_previous() {
            tracing::warn!(%error, "failed to restore TUI signal handlers");
        }
    }
}

#[cfg(unix)]
struct BlockedTerminationSignals {
    previous: libc::sigset_t,
    active: bool,
}

#[cfg(unix)]
impl BlockedTerminationSignals {
    fn block() -> io::Result<Self> {
        // SAFETY: both sets are initialized by libc before being passed to
        // pthread_sigmask, and remain live for the duration of the call.
        unsafe {
            let mut signals: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&raw mut signals) != 0
                || libc::sigaddset(&raw mut signals, libc::SIGTERM) != 0
                || libc::sigaddset(&raw mut signals, libc::SIGHUP) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut previous: libc::sigset_t = std::mem::zeroed();
            let result =
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, &raw mut previous);
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            Ok(Self {
                previous,
                active: true,
            })
        }
    }

    fn restore(mut self) -> io::Result<()> {
        // SAFETY: `previous` is the exact mask returned by pthread_sigmask.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for BlockedTerminationSignals {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: `previous` remains initialized until this guard is dropped.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            tracing::warn!(error = %io::Error::from_raw_os_error(result), "failed to restore signal mask");
        }
    }
}

/// Owns raw mode and alternate-screen state, restoring both on drop.
struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    /// Enter raw mode and the alternate screen, returning a restoration guard.
    ///
    /// If setup fails after enabling raw mode, restore the terminal before
    /// returning the error because no guard exists yet.
    fn enter() -> AppResult<Self> {
        enable_raw_mode()?;
        TERMINAL_ACTIVE.store(true, Ordering::Release);
        match Self::enter_alternate_screen() {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                restore_terminal_if_active();
                Err(error)
            }
        }
    }

    /// The fallible steps between raw mode and a live guard, pulled out so every
    /// failure in here funnels through that one restore back in `enter`.
    fn enter_alternate_screen() -> AppResult<Tui> {
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(terminal)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_if_active();
    }
}

/// Put the terminal back, logging instead of propagating if a step fails.
///
/// Called from `Drop`, the panic hook, and setup failure. Restoration errors are
/// logged so they do not replace the original error. Calls may overlap during
/// panic unwinding, so restoration must be idempotent.
///
/// Teardown leaves the alternate screen, then disables raw mode. Both steps are
/// attempted even if the first fails.
fn best_effort_restore() {
    if let Err(error) = execute!(io::stdout(), LeaveAlternateScreen) {
        tracing::warn!(%error, "failed to leave alternate screen");
    }
    if let Err(error) = disable_raw_mode() {
        tracing::warn!(%error, "failed to disable raw mode");
    }
}

fn restore_terminal_if_active() {
    if TERMINAL_ACTIVE.swap(false, Ordering::AcqRel) {
        best_effort_restore();
    }
}

/// Install a panic hook that restores the terminal before the panic prints.
///
/// Install before entering the alternate screen. The hook restores the normal
/// screen before invoking the original hook, preserving panic messages and
/// backtraces.
fn install_panic_hook() -> PanicHookGuard {
    let original_hook = std::panic::take_hook();
    let original = Arc::new(OriginalPanicHook {
        hook: original_hook,
    });
    let hook_original = Arc::clone(&original);
    let active = Arc::new(AtomicBool::new(true));
    let hook_active = Arc::clone(&active);
    std::panic::set_hook(Box::new(move |panic_info| {
        if hook_active.load(Ordering::Acquire) && IS_TUI_WORKER.with(std::cell::Cell::get) {
            // `spawn_worker` catches this panic and reports it to owner control
            // flow. Printing or restoring here would happen on the worker while
            // the alternate screen still belongs to the owner.
            return;
        }
        if hook_active.load(Ordering::Acquire) && OWNS_TUI_SESSION.with(std::cell::Cell::get) {
            restore_terminal_if_active();
        }
        (hook_original.hook)(panic_info);
    }));
    PanicHookGuard {
        active,
        original: Some(original),
    }
}

/// Own the process-global terminal and panic hook for one complete session.
/// The unwind is caught so hook restoration always occurs from normal control
/// flow; nested ownership is rejected rather than deadlocking the same thread.
pub(crate) fn run_owned<T>(operation: impl FnOnce() -> T) -> io::Result<T> {
    let session = TuiSessionGuard::acquire()?;
    let panic_hook = install_panic_hook();
    let outcome = catch_unwind(AssertUnwindSafe(operation));
    drop(panic_hook);
    drop(session);
    match outcome {
        Ok(value) => Ok(value),
        Err(payload) => resume_unwind(payload),
    }
}

/// Spawn a TUI worker with SIGTERM/SIGHUP blocked from its first instruction.
/// The child waits behind a gate until the owner thread's exact prior mask has
/// been restored, so a failed restore never starts background work.
pub(crate) fn spawn_worker<T: Send + 'static>(
    builder: thread::Builder,
    operation: impl FnOnce() -> T + Send + 'static,
) -> io::Result<Worker<T>> {
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let run = move || {
        IS_TUI_WORKER.with(|worker| worker.set(true));
        match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(value) => {
                let _ = result_sender.send(Ok(value));
            }
            Err(payload) => {
                let failure = WorkerFailure::from_panic(payload.as_ref());
                if let Err(mpsc::SendError(Err(failure))) = result_sender.send(Err(failure)) {
                    report_abandoned_worker_failure(&failure);
                    resume_unwind(payload);
                }
            }
        }
        IS_TUI_WORKER.with(|worker| worker.set(false));
    };

    #[cfg(not(unix))]
    {
        let handle = builder.spawn(run)?;
        Ok(Worker {
            receiver: result_receiver,
            handle,
        })
    }

    #[cfg(unix)]
    {
        let blocked = BlockedTerminationSignals::block()?;
        let (start_sender, start_receiver) = mpsc::sync_channel(0);
        let worker = match builder.spawn(move || {
            if start_receiver.recv().is_ok() {
                run();
            }
        }) {
            Ok(worker) => worker,
            Err(error) => {
                return match blocked.restore() {
                    Ok(()) => Err(error),
                    Err(restore_error) => Err(restore_error),
                };
            }
        };

        if let Err(error) = blocked.restore() {
            drop(start_sender);
            let _ = worker.join();
            return Err(error);
        }
        if start_sender.send(()).is_err() {
            let _ = worker.join();
            return Err(io::Error::other("TUI worker stopped before its start gate"));
        }
        Ok(Worker {
            receiver: result_receiver,
            handle: worker,
        })
    }
}

fn report_abandoned_worker_failure(failure: &WorkerFailure) {
    use std::io::Write;

    // The receiver is gone, so its owner cannot join this worker. Wait until
    // the session releases the terminal before writing the fallback diagnostic.
    let _session = TUI_SESSION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = writeln!(io::stderr().lock(), "{failure}");
}

/// Enter the TUI and run the event loop until the user quits.
///
/// Every exit path restores the terminal because the guard drops at the end of
/// this function's scope, after the loop's result has been computed.
pub(crate) fn run(config: &Config) -> AppResult<()> {
    #[cfg(unix)]
    let signal_guard = TuiSignalGuard::install()?;

    let startup = wait_for_initial_app(config.clone());
    let mut app = match startup {
        Ok(StartupOutcome::Ready(app)) => app,
        #[cfg(unix)]
        Ok(StartupOutcome::Signal(signal)) => {
            return finalize_unix(signal_guard, None, Ok(EventLoopExit::Signal(signal)));
        }
        Err(error) => {
            #[cfg(unix)]
            return finalize_unix(signal_guard, None, Err(error));
            #[cfg(not(unix))]
            return Err(error);
        }
    };

    let mut guard = match TerminalGuard::enter() {
        Ok(guard) => guard,
        Err(error) => {
            #[cfg(unix)]
            return finalize_unix(signal_guard, None, Err(error));
            #[cfg(not(unix))]
            return Err(error);
        }
    };
    let theme = Theme::from_environment();
    let outcome = event_loop(&mut guard.terminal, &mut app, config, theme);

    #[cfg(unix)]
    return finalize_unix(signal_guard, Some(guard), outcome);

    #[cfg(not(unix))]
    drop(guard);
    #[cfg(not(unix))]
    let _ = outcome?;
    #[cfg(not(unix))]
    Ok(())
}

fn wait_for_initial_app(config: Config) -> AppResult<StartupOutcome> {
    let worker = spawn_worker(
        thread::Builder::new().name("kickoutchi-initial-collection".to_owned()),
        move || App::new(&config),
    )?;

    wait_for_startup_worker(worker)
}

fn wait_for_startup_worker<T: Send + 'static>(
    worker: Worker<T>,
) -> AppResult<StartupOutcomeGeneric<T>> {
    loop {
        #[cfg(unix)]
        if let Some(signal) = take_termination_signal() {
            drop(worker);
            return Ok(StartupOutcomeGeneric::Signal(signal));
        }

        match worker.recv_timeout(SIGNAL_POLL_INTERVAL) {
            Ok(Ok(app)) => {
                worker.join().map_err(|_| {
                    io::Error::other("initial collection worker panicked after returning")
                })?;
                return Ok(StartupOutcomeGeneric::Ready(app));
            }
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error.into());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                let message = if worker.join().is_err() {
                    "initial collection worker panicked"
                } else {
                    "initial collection worker exited before returning"
                };
                return Err(io::Error::other(message).into());
            }
        }
    }
}

type StartupOutcome = StartupOutcomeGeneric<App>;

#[derive(Debug)]
enum StartupOutcomeGeneric<T> {
    Ready(T),
    #[cfg(unix)]
    Signal(libc::c_int),
}

#[cfg(unix)]
fn finalize_unix(
    mut signal_guard: TuiSignalGuard,
    terminal: Option<TerminalGuard>,
    outcome: AppResult<EventLoopExit>,
) -> AppResult<()> {
    finalize_unix_after_block(&mut signal_guard, terminal, outcome, || {})
}

#[cfg(unix)]
fn finalize_unix_after_block(
    signal_guard: &mut TuiSignalGuard,
    terminal: Option<TerminalGuard>,
    outcome: AppResult<EventLoopExit>,
    after_block: impl FnOnce(),
) -> AppResult<()> {
    let blocked = BlockedTerminationSignals::block()?;
    drop(terminal);
    after_block();

    let requested_signal = match &outcome {
        Ok(EventLoopExit::Signal(signal)) => Some(*signal),
        _ => take_termination_signal(),
    };
    let default_disposition = requested_signal
        .is_some_and(|signal| signal_guard.previous_disposition(signal) == libc::SIG_DFL);
    signal_guard.restore_previous()?;

    if let Some(signal) = requested_signal {
        // Re-raise with the embedder's exact disposition while blocked. Restoring
        // the old mask below delivers default/custom handlers atomically; an
        // ignored disposition discards the signal.
        // SAFETY: `signal` is one of SIGTERM/SIGHUP recorded by our handler.
        if unsafe { libc::raise(signal) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    blocked.restore()?;

    if default_disposition {
        return Err(
            io::Error::other("default termination signal did not terminate process").into(),
        );
    }
    if requested_signal.is_some() {
        return Ok(());
    }
    let _ = outcome?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventLoopExit {
    Quit,
    #[cfg(unix)]
    Signal(libc::c_int),
}

// Run the draw, input, and update loop until quit.
fn event_loop(
    terminal: &mut Tui,
    app: &mut App,
    config: &Config,
    theme: Theme,
) -> AppResult<EventLoopExit> {
    let mut details_text = details::TextCache::default();
    let mut rendered_age = None;
    loop {
        #[cfg(unix)]
        if let Some(signal) = take_termination_signal() {
            return Ok(EventLoopExit::Signal(signal));
        }

        if let Some(error) = poll_workers(app) {
            return Err(error.into());
        }
        // Poll signals/workers at 100 ms, but redraw the age only when its
        // displayed whole second changes. Input and worker results request frames.
        let age = app.refresh_age().map(|age| age.as_secs());
        if app.take_redraw_request() || rendered_age != Some(age) {
            terminal.draw(|frame| draw(frame, app, theme, &mut details_text))?;
            rendered_age = Some(age);
        }

        let wait = std::cmp::min(
            config.tick_interval,
            app.time_until_refresh(config.refresh_interval),
        );
        match event::poll(bounded_event_wait(wait)) {
            Ok(true) => {
                let event = event::read()?;
                if matches!(event, Event::Resize(_, _)) {
                    app.request_redraw();
                }
                if let Event::Key(key) = event {
                    if handle_modal_scroll(app, key) {
                        continue;
                    }
                    app.apply_action(input::action_for_key(
                        key,
                        app.modal(),
                        app.search_mode(),
                        !app.filter_text().is_empty(),
                    ));
                    // A worker can fail while input is blocked. Poll again before
                    // honoring quit so a queued programmer error cannot become a
                    // successful TUI exit.
                    if let Some(error) = poll_workers(app) {
                        return Err(error.into());
                    }
                }
            }
            Ok(false) => {}
            Err(error) => {
                #[cfg(unix)]
                if let Some(signal) = take_termination_signal() {
                    return Ok(EventLoopExit::Signal(signal));
                }
                return Err(error.into());
            }
        }

        if app.should_quit() {
            return Ok(EventLoopExit::Quit);
        }

        if app.refresh_due(config.refresh_interval) {
            app.refresh();
        }
    }
}

fn poll_workers(app: &mut App) -> Option<WorkerFailure> {
    app.poll_refresh();
    app.poll_process_context();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    app.poll_tree_preview();
    app.take_worker_failure()
}

fn handle_modal_scroll(app: &mut App, key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press
        || !matches!(app.modal(), ModalKind::Details | ModalKind::Help)
    {
        return false;
    }
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => app.scroll_modal_by(1),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_modal_by(-1),
        KeyCode::PageDown => app.scroll_modal_by(8),
        KeyCode::PageUp => app.scroll_modal_by(-8),
        KeyCode::Home => app.set_modal_scroll(0),
        KeyCode::End => app.set_modal_scroll(u16::MAX),
        _ => return false,
    }
    true
}

fn bounded_event_wait(wait: Duration) -> Duration {
    wait.min(SIGNAL_POLL_INTERVAL)
}

/// Consume the recorded request, leaving the slot empty. See
/// [`record_first_signal`] for why this takes the slot as an argument.
#[cfg(unix)]
fn take_first_signal(slot: &AtomicI32) -> Option<libc::c_int> {
    match slot.swap(0, Ordering::Relaxed) {
        0 => None,
        signal => Some(signal),
    }
}

#[cfg(unix)]
fn take_termination_signal() -> Option<libc::c_int> {
    take_first_signal(&TERMINATION_SIGNAL)
}

fn draw(frame: &mut Frame, app: &mut App, theme: Theme, details_text: &mut details::TextCache) {
    details_text.update(app.selected_process_metadata());
    let area = frame.area();

    if is_too_small(area) {
        cancel_hidden_confirmation(app);
        render_too_small(frame, area, theme);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, chunks[0], theme);
    table::render(frame, chunks[1], app, theme);
    details::render_panel(frame, chunks[2], app, theme, details_text);
    render_status(frame, chunks[3], app, theme);

    let modal_area = centered_rect(76, 76, area);
    match app.modal() {
        ModalKind::None => {}
        ModalKind::Details => details::render_modal(frame, modal_area, app, theme, details_text),
        ModalKind::Help => help::render(frame, centered_rect(90, 90, area), app, theme),
        ModalKind::ConfirmKill => confirm::render(frame, modal_area, app, theme),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        ModalKind::ConfirmTreeKill => {
            if !confirm::render_tree(frame, centered_rect(76, 90, area), app, theme) {
                app.cancel_confirmation_for_layout();
            }
        }
    }
}

fn cancel_hidden_confirmation(app: &mut App) {
    let destructive_confirmation = match app.modal() {
        ModalKind::ConfirmKill => true,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        ModalKind::ConfirmTreeKill => true,
        _ => false,
    };
    if destructive_confirmation {
        app.apply_action(input::Action::CancelKill);
    }
}

// The header advertises only keys that exist on this build: tree kill is a
// Linux/macOS feature, so Windows must not see a t/T hint it cannot use.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HEADER_KEY_HINTS: &str = "   r refresh  / search  s sort  x/X kill  t/T tree  ? help  q quit";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const HEADER_KEY_HINTS: &str = "   r refresh  / search  s sort  x/X kill  ? help  q quit";

fn render_header(frame: &mut Frame, area: Rect, theme: Theme) {
    let line = Line::from(vec![
        Span::styled("Kickoutchi", theme.title()),
        Span::raw(HEADER_KEY_HINTS),
    ]);
    let header = Paragraph::new(line)
        .alignment(Alignment::Center)
        .block(Block::bordered().border_style(theme.border()));
    frame.render_widget(header, area);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let filter = if app.filter_text().is_empty() {
        "none".to_owned()
    } else {
        sanitize(app.filter_text())
    };
    let search = if app.search_mode() { "editing" } else { "idle" };
    let mut status = String::new();
    let _ = write!(
        status,
        "Status: {}/{} open ports, refreshed {} | sort: {} | filter: {filter} | search: {search}",
        app.rows().len(),
        app.total_row_count(),
        format_age(app.refresh_age()),
        app.sort_mode().label(),
    );

    if let Some(error) = app.filter_error() {
        append_status_field(&mut status, "filter error", error);
    }

    if let Some(error) = app.latest_error() {
        append_status_field(&mut status, "error", error);
    }

    if let Some(kill_status) = app.kill_status() {
        append_status_field(&mut status, "kill", kill_status);
    }

    frame.render_widget(Paragraph::new(status).style(theme.status()), area);
}

fn append_status_field(status: &mut String, label: &str, value: &str) {
    status.push_str(" | ");
    status.push_str(label);
    status.push_str(": ");
    status.push_str(&sanitize(value));
}

fn render_too_small(frame: &mut Frame, area: Rect, theme: Theme) {
    let message = Paragraph::new("Terminal too small\nNeed at least 80x20 to show the table")
        .alignment(Alignment::Center)
        .style(theme.warning())
        .block(
            Block::bordered()
                .title("Kickoutchi")
                .title_style(theme.title())
                .border_style(theme.border()),
        );
    frame.render_widget(message, area);
}

fn is_too_small(area: Rect) -> bool {
    area.width < 80 || area.height < 20
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    debug_assert!(percent_x <= 100);
    debug_assert!(percent_y <= 100);

    let vertical_margin = (100 - percent_y) / 2;
    let horizontal_margin = (100 - percent_x) / 2;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(vertical_margin),
            Constraint::Percentage(percent_y),
            Constraint::Percentage(vertical_margin),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(horizontal_margin),
            Constraint::Percentage(percent_x),
            Constraint::Percentage(horizontal_margin),
        ])
        .split(vertical[1]);
    horizontal[1]
}

/// A `Label: value` line, shared by the details panel, the details modal, and
/// the kill-confirmation modal so those panels stay visually consistent. It
/// lives in the parent module so all panels use the same label style and
/// separator.
fn field<'a>(label: &'static str, value: impl Into<Cow<'a, str>>, theme: Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label}: "), theme.label()),
        Span::raw(value),
    ])
}

/// Conservative terminal-row budget for ratatui word wrapping. Unicode
/// whitespace is charged explicitly, wide characters use terminal columns,
/// and long words are hard-wrapped.
fn wrapped_rows(text: &str, content_cols: usize) -> usize {
    let cols = content_cols.max(1);
    text.split('\n')
        .map(|logical| {
            let mut rows = 1usize;
            let mut used = 0usize;
            let mut chars = logical.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch.is_whitespace() {
                    let width = ch.width().unwrap_or(0);
                    if width > 0 && used + width > cols {
                        rows += 1;
                        used = 0;
                    }
                    used = used.saturating_add(width).min(cols);
                    continue;
                }

                let mut word_width = ch.width().unwrap_or(0);
                while chars.peek().is_some_and(|next| !next.is_whitespace()) {
                    word_width = word_width.saturating_add(
                        chars.next().and_then(UnicodeWidthChar::width).unwrap_or(0),
                    );
                }
                if word_width <= cols {
                    if used > 0 && used + word_width > cols {
                        rows += 1;
                        used = 0;
                    }
                    used += word_width;
                } else {
                    if used > 0 {
                        rows += 1;
                    }
                    rows += word_width.div_ceil(cols).saturating_sub(1);
                    used = word_width % cols;
                    if used == 0 {
                        used = cols;
                    }
                }
            }
            rows
        })
        .sum::<usize>()
        .max(1)
}

fn rendered_rows(lines: &[Line<'_>], content_cols: usize) -> usize {
    lines
        .iter()
        .map(|line| wrapped_rows(&line.to_string(), content_cols))
        .sum()
}

fn format_age(duration: Option<Duration>) -> String {
    let Some(duration) = duration else {
        return "never".to_owned();
    };
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s ago")
    } else {
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        format!("{minutes}m {seconds}s ago")
    }
}

#[cfg(test)]
mod tests;
