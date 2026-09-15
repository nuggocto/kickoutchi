#[cfg(unix)]
use std::sync::mpsc;
use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::{SIGNAL_POLL_INTERVAL, Theme, append_status_field, bounded_event_wait, draw};

use crate::app::{App, ModalKind};
use crate::config::Config;
use crate::input::Action;
use crate::labels::{LabelInput, LabelRegistry};
use crate::test_support::command as test_command;

#[cfg(unix)]
static CUSTOM_SIGNAL_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn custom_sigterm_handler(_: libc::c_int) {
    CUSTOM_SIGNAL_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn render_text(app: &mut App, width: u16, height: u16) -> String {
    render_text_cached(
        app,
        width,
        height,
        &mut super::details::TextCache::default(),
    )
}

fn render_text_cached(
    app: &mut App,
    width: u16,
    height: u16,
    cache: &mut super::details::TextCache,
) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend must initialize");
    terminal
        .draw(|frame| {
            draw(frame, app, Theme::from_environment(), cache);
        })
        .expect("test frame must draw");

    let buffer = terminal.backend().buffer();
    let area = buffer.area;
    let mut text = String::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }
    text
}

#[test]
fn default_frame_renders_table_details_and_status() {
    let config = Config::default();
    let mut app = App::new_fake(&config);

    let text = render_text(&mut app, 100, 30);

    assert!(text.contains("Kickoutchi"), "{text}");
    assert!(text.contains("x/X kill"), "{text}");
    assert!(text.contains("Open Ports"), "{text}");
    assert!(text.contains("3000"), "{text}");
    assert!(text.contains("node"), "{text}");
    assert!(text.contains("Details"), "{text}");
    assert!(text.contains("PID: 18422 | Process: node"), "{text}");
    assert!(text.contains("Status: 5/5 open ports"), "{text}");
}

#[test]
fn protected_details_render_one_warning_and_keep_permission_at_minimum_size() {
    let config = Config {
        protected_processes: vec!["node".to_owned()],
        ..Config::default()
    };
    let mut app = App::new_fake(&config);
    let mut row =
        crate::test_support::port_entry(3000, Some(42), crate::model::Protocol::Tcp, "node");
    row.executable_path =
        Some(std::path::PathBuf::from(format!("/{}", "long-path/".repeat(1024))).into());
    row.command_line = Some("hidden command ".repeat(8192).into());
    app.apply_test_rows(vec![row], std::time::Instant::now());

    let text = render_text(&mut app, 80, 20);

    assert_eq!(
        text.matches("Warning: protected process").count(),
        1,
        "{text}",
    );
    assert!(text.contains("Permission: full"), "{text}");
    assert!(
        !text.contains("Command:"),
        "hidden fields cannot displace the warning"
    );
}

#[test]
fn configured_labels_render_only_when_table_width_can_preserve_legacy_layout() {
    let config = Config {
        labels: LabelRegistry::from_inputs(vec![LabelInput {
            protocol: "tcp".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 3000,
            scope_id: None,
            label: "web dev".to_owned(),
        }])
        .unwrap(),
        ..Config::default()
    };
    let mut app = App::new_fake(&config);

    let wide = render_text(&mut app, 120, 30);
    assert!(wide.contains("LABEL"), "{wide}");
    assert!(wide.contains("web dev"), "{wide}");

    let minimum = render_text(&mut app, 80, 20);
    assert!(!minimum.contains("LABEL"), "{minimum}");
    assert!(minimum.contains("SCOPE"), "{minimum}");

    let below_boundary = render_text(&mut app, 105, 30);
    assert!(!below_boundary.contains("LABEL"), "{below_boundary}");
    let at_boundary = render_text(&mut app, 106, 30);
    assert!(at_boundary.contains("LABEL"), "{at_boundary}");
    assert!(at_boundary.contains("web dev"), "{at_boundary}");
}

#[test]
fn configured_unmatched_selector_still_enables_wide_label_column() {
    let config = Config {
        labels: LabelRegistry::from_inputs(vec![LabelInput {
            protocol: "tcp".to_owned(),
            address: "*".to_owned(),
            port: 65_000,
            scope_id: None,
            label: "unused".to_owned(),
        }])
        .unwrap(),
        ..Config::default()
    };
    let mut app = App::new_fake(&config);

    let wide = render_text(&mut app, 120, 30);
    assert!(wide.contains("LABEL"), "{wide}");
    assert!(!wide.contains("unused"), "{wide}");
}

#[test]
fn help_modal_renders_keybinds() {
    let config = Config::default();
    let mut app = App::new_fake(&config);
    app.apply_action(Action::OpenHelp);

    let text = render_text(&mut app, 100, 30);

    assert!(text.contains("Help"), "{text}");
    assert!(text.contains("Kickoutchi"), "{text}");
    assert!(text.contains("j / Down"), "{text}");
    assert!(text.contains('x'), "{text}");
    assert!(text.contains('/'), "{text}");
    assert!(text.contains("Ctrl+C"), "{text}");
    for filter in ["label:", "address:", "scope_id:", "family:"] {
        assert!(text.contains(filter), "missing {filter} in {text}");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(text.contains("terminate selected process tree"), "{text}");
}

#[test]
fn status_shows_active_search_text() {
    let config = Config::default();
    let mut app = App::new_fake(&config);
    app.apply_action(Action::StartSearch);
    app.apply_action(Action::SearchAppend('3'));

    let text = render_text(&mut app, 100, 30);

    assert!(text.contains("filter: 3"), "{text}");
    assert!(text.contains("search: editing"), "{text}");
}

#[test]
fn status_fields_are_sanitized_before_rendering() {
    let mut status = "Status: ok".to_owned();

    append_status_field(&mut status, "kill", "\x1b[31mfailed\nagain");

    assert_eq!(status, "Status: ok | kill: failed again");
}

#[test]
fn help_and_details_bottom_rows_are_scrollable_at_minimum_size() {
    let mut config = Config::default();
    config.protected_processes.push("node".to_owned());
    let mut app = App::new_fake(&config);
    app.apply_action(Action::OpenHelp);

    let first = render_text(&mut app, 80, 20);
    assert!(first.contains("Up/Down"), "{first}");
    app.set_modal_scroll(u16::MAX);
    let bottom = render_text(&mut app, 80, 20);
    for filter in [
        "label:web",
        "address:127.0.0.1",
        "scope_id:3",
        "family:ipv6",
    ] {
        assert!(bottom.contains(filter), "missing {filter} in {bottom}");
    }

    app.apply_action(Action::CloseModal);
    app.apply_action(Action::OpenDetails);
    let top = render_text(&mut app, 80, 20);
    assert!(top.contains("Protected process"), "{top}");
    assert!(top.contains("Up/Down"), "{top}");
    app.set_modal_scroll(u16::MAX);
    let bottom = render_text(&mut app, 80, 20);
    assert!(bottom.contains("Path: /usr/bin/node"), "{bottom}");
    assert!(bottom.contains("Command: node server.js"), "{bottom}");
    assert!(bottom.contains("Protected process"), "{bottom}");
}

#[test]
fn initial_worker_panic_is_reported_as_a_typed_failure() {
    let error = super::run_owned(|| {
        let worker = super::spawn_worker(
            std::thread::Builder::new().name("initial-test".to_owned()),
            || panic!("startup failed"),
        )
        .unwrap();
        super::wait_for_startup_worker(worker)
    })
    .unwrap()
    .expect_err("worker panic must be reported");
    assert!(
        error
            .to_string()
            .contains("TUI worker initial-test panicked: startup failed")
    );
}

#[test]
fn details_modal_renders_selected_row_metadata() {
    let config = Config::default();
    let mut app = App::new_fake(&config);
    app.apply_action(Action::OpenDetails);

    let text = render_text(&mut app, 100, 30);

    assert!(text.contains("Port Details"), "{text}");
    assert!(text.contains("cursor-agent (PID 18001)"), "{text}");
    assert!(text.contains("node server.js"), "{text}");
}

#[test]
fn kill_confirmation_modal_renders_target_and_command() {
    let config = Config::default();
    let mut app = App::new_fake(&config);
    app.apply_action(Action::RequestForceKill);

    let text = render_text(&mut app, 100, 30);

    assert!(text.contains("Confirm Termination"), "{text}");
    assert!(text.contains("Force-kill PID 18422"), "{text}");
    assert!(text.contains("kill -9 18422"), "{text}");
    assert!(text.contains("force"), "{text}");
}

#[test]
fn small_terminal_renders_fallback_message() {
    let config = Config::default();
    let mut app = App::new_fake(&config);

    let text = render_text(&mut app, 40, 10);

    assert!(text.contains("Terminal too small"), "{text}");
    assert!(text.contains("Need at least 80x20"), "{text}");
}

#[test]
fn small_terminal_cancels_a_single_process_confirmation() {
    let config = Config::default();
    let mut app = App::new_fake(&config);
    app.apply_action(Action::RequestForceKill);
    assert_eq!(app.modal(), ModalKind::ConfirmKill);

    let text = render_text(&mut app, 40, 10);

    assert!(text.contains("Terminal too small"), "{text}");
    assert_eq!(app.modal(), ModalKind::None);
    assert!(app.kill_confirmation().is_none());
    assert_eq!(app.kill_status(), Some("kill cancelled"));
    app.apply_action(Action::SubmitKillConfirmation);
    assert_eq!(app.modal(), ModalKind::None);
}

#[test]
fn signal_observation_bounds_an_otherwise_long_event_wait() {
    assert_eq!(
        bounded_event_wait(Duration::from_secs(30)),
        SIGNAL_POLL_INTERVAL,
    );
    assert_eq!(
        bounded_event_wait(Duration::from_millis(25)),
        Duration::from_millis(25),
    );
}

#[cfg(unix)]
fn current_signal_mask_contains(signal: libc::c_int) -> bool {
    // SAFETY: a null set queries the calling thread's current mask into the
    // initialized output set without modifying it.
    unsafe {
        let mut current: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(0, std::ptr::null(), &raw mut current),
            0,
        );
        libc::sigismember(&raw const current, signal) == 1
    }
}

#[cfg(unix)]
#[test]
fn tui_worker_inherits_blocked_termination_signals_and_parent_mask_is_exact() {
    let parent_term = current_signal_mask_contains(libc::SIGTERM);
    let parent_hup = current_signal_mask_contains(libc::SIGHUP);
    let (sender, receiver) = mpsc::sync_channel(1);

    let worker = super::spawn_worker(
        std::thread::Builder::new().name("signal-mask-probe".to_owned()),
        move || {
            sender
                .send((
                    current_signal_mask_contains(libc::SIGTERM),
                    current_signal_mask_contains(libc::SIGHUP),
                ))
                .unwrap();
        },
    )
    .unwrap();

    assert_eq!(receiver.recv().unwrap(), (true, true));
    worker.recv().unwrap().unwrap();
    worker.join().unwrap();
    assert_eq!(current_signal_mask_contains(libc::SIGTERM), parent_term);
    assert_eq!(current_signal_mask_contains(libc::SIGHUP), parent_hup);
}

#[cfg(unix)]
#[test]
fn finalization_delivers_process_signal_only_after_worker_safe_teardown() {
    use std::process::Command;
    use std::sync::atomic::Ordering;

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_FINAL_SIGNAL_RACE";
    if std::env::var_os(CHILD_ENV).is_some() {
        CUSTOM_SIGNAL_CALLS.store(0, Ordering::Relaxed);
        // SAFETY: this isolated child owns the process disposition.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = custom_sigterm_handler as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut()),
                0,
            );
        }
        let mut guard = super::TuiSignalGuard::install().unwrap();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let worker = super::spawn_worker(
            std::thread::Builder::new().name("final-signal-worker".to_owned()),
            move || {
                ready_sender
                    .send(current_signal_mask_contains(libc::SIGTERM))
                    .unwrap();
                release_receiver.recv().unwrap();
            },
        )
        .unwrap();
        assert!(ready_receiver.recv().unwrap());

        super::finalize_unix_after_block(&mut guard, None, Ok(super::EventLoopExit::Quit), || {
            // SAFETY: queue SIGTERM specifically for the owner while it
            // is blocked; the live TUI worker independently proves it
            // inherited the same blocked set above.
            assert_eq!(
                unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) },
                0,
            );
        })
        .unwrap();
        assert_eq!(CUSTOM_SIGNAL_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(super::take_termination_signal(), None);
        release_sender.send(()).unwrap();
        worker.recv().unwrap().unwrap();
        worker.join().unwrap();
        return;
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ui::tests::finalization_delivers_process_signal_only_after_worker_safe_teardown",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .expect("final-signal child must start");
    assert!(status.success(), "final-signal child exited with {status}");
}

/// The slot is local because the process-global one is consumed by
/// `wait_for_startup_worker` on every poll, so a test that recorded into it
/// would hand its signal to whichever other test happened to be polling,
/// which is the race this test used to lose intermittently. The
/// installed handler is covered end to end by the child-process tests
/// below, with real signals; this one owns the first-wins state machine.
#[cfg(unix)]
#[test]
fn signal_handler_records_the_first_shutdown_request_for_normal_control_flow() {
    use super::{record_first_signal, take_first_signal};
    use std::sync::atomic::AtomicI32;

    let slot = AtomicI32::new(0);
    record_first_signal(&slot, libc::SIGTERM);
    record_first_signal(&slot, libc::SIGHUP);

    assert_eq!(take_first_signal(&slot), Some(libc::SIGTERM));
    assert_eq!(take_first_signal(&slot), None);
}

#[cfg(unix)]
#[test]
fn sigterm_is_reraised_with_conventional_process_status() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_TUI_SIGTERM_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        let guard = super::TuiSignalGuard::install().expect("signal handlers must install");
        // SAFETY: SIGTERM is handled by the just-installed atomic-only
        // handler, and this call occurs in ordinary test control flow.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        let signal = super::take_termination_signal().expect("handler must record SIGTERM");
        super::finalize_unix(guard, None, Ok(super::EventLoopExit::Signal(signal)))
            .expect("default SIGTERM must terminate before returning");
        unreachable!("default SIGTERM returned");
    }

    let status = Command::new(std::env::current_exe().expect("test executable must exist"))
        .args([
            "--exact",
            "ui::tests::sigterm_is_reraised_with_conventional_process_status",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .expect("signal child must start");

    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

#[cfg(unix)]
#[test]
fn sigterm_restores_and_honors_custom_and_ignored_dispositions() {
    use std::process::Command;
    use std::sync::atomic::Ordering;

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_TUI_SIGTERM_DISPOSITION";
    if let Some(mode) = std::env::var_os(CHILD_ENV) {
        let expected = if mode == "custom" {
            custom_sigterm_handler as *const () as usize
        } else {
            libc::SIG_IGN
        };
        // SAFETY: the action is initialized in full and this subprocess has
        // no other test manipulating SIGTERM.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = expected;
            libc::sigemptyset(&raw mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut()),
                0,
            );
        }
        let guard = super::TuiSignalGuard::install().unwrap();
        // SAFETY: the temporary TUI handler records SIGTERM atomically.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        let signal = super::take_termination_signal().unwrap();
        super::finalize_unix(guard, None, Ok(super::EventLoopExit::Signal(signal))).unwrap();

        let mut restored: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `restored` is writable and a null action performs a query.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &raw mut restored) },
            0,
        );
        assert_eq!(restored.sa_sigaction, expected);
        assert_eq!(
            CUSTOM_SIGNAL_CALLS.load(Ordering::Relaxed),
            usize::from(mode == "custom"),
        );
        return;
    }

    for mode in ["custom", "ignored"] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ui::tests::sigterm_restores_and_honors_custom_and_ignored_dispositions",
                "--nocapture",
            ])
            .env(CHILD_ENV, mode)
            .status()
            .expect("signal-disposition child must start");
        assert!(status.success(), "{mode} child exited with {status}");
    }
}

#[test]
fn completed_tui_session_restores_the_previous_panic_hook() {
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_PANIC_HOOK_CHILD";
    static PANICS: AtomicUsize = AtomicUsize::new(0);
    if std::env::var_os(CHILD_ENV).is_some() {
        std::panic::set_hook(Box::new(|_| {
            PANICS.fetch_add(1, Ordering::Relaxed);
        }));

        let caught = std::panic::catch_unwind(|| {
            super::run_owned(|| panic!("caught TUI panic")).unwrap();
        });
        assert!(caught.is_err());
        assert_eq!(PANICS.load(Ordering::Relaxed), 1);

        let _ = std::panic::catch_unwind(|| panic!("probe restored hook"));
        assert_eq!(PANICS.load(Ordering::Relaxed), 2);

        super::run_owned(|| {
            let worker = super::spawn_worker(
                std::thread::Builder::new().name("pre-terminal-panic".to_owned()),
                || panic!("startup worker panic"),
            )
            .unwrap();
            let failure = worker
                .recv()
                .unwrap()
                .expect_err("worker panic must be typed");
            assert!(failure.to_string().contains("startup worker panic"));
            worker.join().unwrap();
        })
        .unwrap();
        assert_eq!(PANICS.load(Ordering::Relaxed), 2);

        super::run_owned(|| {
            let error = super::run_owned(|| ()).expect_err("nested TUI must be refused");
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        })
        .unwrap();

        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let first = std::thread::spawn(move || {
            super::run_owned(|| {
                entered_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
            })
            .unwrap();
        });
        entered_receiver.recv().unwrap();
        let (second_sender, second_receiver) = mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            super::run_owned(|| second_sender.send(()).unwrap()).unwrap();
        });
        assert_eq!(
            second_receiver.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout),
        );
        release_sender.send(()).unwrap();
        second_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("concurrent session starts after ownership release");
        first.join().unwrap();
        second.join().unwrap();
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable must exist"))
        .args([
            "--exact",
            "ui::tests::completed_tui_session_restores_the_previous_panic_hook",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("panic-hook child must start");

    assert!(
        output.status.success(),
        "panic-hook child exited with {}",
        output.status,
    );
    assert!(
        !output
            .stdout
            .windows(8)
            .any(|bytes| bytes == b"\x1b[?1049l"),
        "pre-terminal panic emitted alternate-screen teardown: {:?}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
fn worker_panic_after_terminal_activation_is_reported_by_owner_only() {
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_ACTIVE_WORKER_PANIC";
    static HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);
    if std::env::var_os(CHILD_ENV).is_some() {
        std::panic::set_hook(Box::new(|_| {
            HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
            eprintln!("panic hook printed while terminal was active");
        }));

        super::run_owned(|| {
            super::TERMINAL_ACTIVE.store(true, Ordering::Release);
            let worker = super::spawn_worker(
                std::thread::Builder::new().name("kickoutchi-refresh".to_owned()),
                || panic!("refresh invariant failed"),
            )
            .unwrap();
            let failure = worker
                .recv()
                .unwrap()
                .expect_err("owner must receive the worker panic");

            assert!(
                super::TERMINAL_ACTIVE.load(Ordering::Acquire),
                "the worker must not restore terminal state"
            );
            super::TERMINAL_ACTIVE.store(false, Ordering::Release);
            eprintln!("owner diagnostic after restore: {failure}");
            worker.join().unwrap();
        })
        .unwrap();
        assert_eq!(HOOK_CALLS.load(Ordering::Relaxed), 0);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable must exist"))
        .args([
            "--exact",
            "ui::tests::worker_panic_after_terminal_activation_is_reported_by_owner_only",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("worker-panic child must start");
    let stderr = String::from_utf8(output.stderr).expect("child stderr must be UTF-8");

    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "owner diagnostic after restore: TUI worker kickoutchi-refresh panicked: refresh invariant failed"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("panic hook printed"), "{stderr}");
}

#[test]
fn abandoned_worker_panic_is_reported_after_the_tui_session_ends() {
    use std::process::Command;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_ABANDONED_WORKER_PANIC";
    if std::env::var_os(CHILD_ENV).is_some() {
        struct Unwinding(mpsc::Sender<()>);
        impl Drop for Unwinding {
            fn drop(&mut self) {
                self.0.send(()).unwrap();
            }
        }

        std::panic::set_hook(Box::new(|_| eprintln!("original panic hook")));
        let handle = super::run_owned(|| {
            super::TERMINAL_ACTIVE.store(true, Ordering::Release);
            let (release, start) = mpsc::channel();
            let (unwinding, observed) = mpsc::channel();
            let worker = super::spawn_worker(
                std::thread::Builder::new().name("abandoned-refresh".to_owned()),
                move || {
                    start.recv().unwrap();
                    let _unwinding = Unwinding(unwinding);
                    panic!("abandoned refresh failed");
                },
            )
            .unwrap();
            let super::Worker { receiver, handle } = worker;
            drop(receiver);
            release.send(()).unwrap();
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
            super::TERMINAL_ACTIVE.store(false, Ordering::Release);
            eprintln!("owner ended terminal session");
            handle
        })
        .unwrap();
        assert!(handle.join().is_err());
        return;
    }

    let output = test_command::run_command_with_deadline(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ui::tests::abandoned_worker_panic_is_reported_after_the_tui_session_ends",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1"),
        None,
        Duration::from_secs(10),
    )
    .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}");
    let restored = stderr.find("owner ended terminal session").unwrap();
    let reported = stderr
        .find("TUI worker abandoned-refresh panicked: abandoned refresh failed")
        .unwrap_or_else(|| panic!("missing abandoned-worker diagnostic: {stderr}"));
    assert!(restored < reported, "{stderr}");
    assert!(!stderr.contains("original panic hook"), "{stderr}");
    assert!(
        !stderr.contains('\u{1b}'),
        "worker must not restore the terminal: {stderr}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn tree_confirmation_modal_renders_loading_then_preview() {
    let config = Config::default();
    let mut app = App::new_fake(&config);

    assert!(render_text(&mut app, 100, 30).contains("t/T tree"));

    app.apply_action(Action::RequestTreeTerminate);
    let text = render_text(&mut app, 100, 30);
    assert!(text.contains("Confirm Tree Termination"), "{text}");
    assert!(text.contains("Enumerating the process tree"), "{text}");
    assert!(text.contains("Wait for the process count"), "{text}");
    assert!(!text.contains("Type tree"), "{text}");

    let infos = vec![
        crate::tree::TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(1),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            owner_uid: None,
            process_group: None,
        },
        crate::tree::TreeProcessInfo {
            pid: 18_430,
            parent_pid: Some(18_422),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("worker".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(56).ok(),
            owner_uid: None,
            process_group: None,
        },
    ];
    let preview =
        crate::tree::plan_process_tree(18_422, &infos, &[], crate::model::Platform::Linux, 256)
            .expect("preview must build");
    app.finish_tree_preview_for_test(Ok(preview));

    let text = render_text(&mut app, 100, 30);
    assert!(
        text.contains("Terminate process tree from PID 18422"),
        "{text}"
    );
    assert!(text.contains("tree (2 processes)"), "{text}");
    assert!(text.contains("PID 18430 (worker)"), "{text}");
    assert!(text.contains("Type tree"), "{text}");

    let mut crowded_infos = infos;
    for pid in 18_431..18_451 {
        crowded_infos.push(crate::tree::TreeProcessInfo {
            pid,
            parent_pid: Some(18_422),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("aaaaaaaaaaa bbbbbbbbbbb ccccccccccc".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid)).ok(),
            owner_uid: None,
            process_group: None,
        });
    }
    let preview = crate::tree::plan_process_tree(
        18_422,
        &crowded_infos,
        &[],
        crate::model::Platform::Linux,
        256,
    )
    .expect("crowded preview must build");
    app.finish_tree_preview_for_test(Ok(preview));
    for ch in "tre".chars() {
        app.apply_action(Action::KillInputAppend(ch));
    }
    app.apply_action(Action::SubmitKillConfirmation);

    let text = render_text(&mut app, 80, 20);
    assert!(text.contains("Type tree"), "{text}");
    assert!(text.contains("Input: tre"), "{text}");
    assert!(text.contains("Error: type tree"), "{text}");
    assert!(text.contains("Esc cancels."), "{text}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn small_terminal_cancels_a_tree_confirmation() {
    let config = Config::default();
    let mut app = App::new_fake(&config);
    app.apply_action(Action::RequestTreeForceKill);
    assert_eq!(app.modal(), ModalKind::ConfirmTreeKill);

    let text = render_text(&mut app, 40, 10);

    assert!(text.contains("Terminal too small"), "{text}");
    assert_eq!(app.modal(), ModalKind::None);
    assert!(app.tree_confirmation().is_none());
    assert_eq!(app.kill_status(), Some("tree kill cancelled"));
    app.apply_action(Action::SubmitKillConfirmation);
    assert_eq!(app.modal(), ModalKind::None);
}

#[test]
fn details_cache_tracks_selection_refresh_and_missing_metadata() {
    use crate::model::Protocol;
    use crate::test_support::port_entry;
    let mut first = port_entry(3000, Some(42), Protocol::Tcp, "first");
    first.command_line = Some("first-command".into());
    first.executable_path = Some(std::path::PathBuf::from("/first-path").into());
    let mut second = port_entry(4000, Some(43), Protocol::Tcp, "second");
    second.command_line = Some("second-command".into());
    second.executable_path = Some(std::path::PathBuf::from("/second-path").into());
    let mut app = App::new_fake(&Config::default());
    app.apply_test_rows(vec![first, second.clone()], std::time::Instant::now());
    let mut cache = super::details::TextCache::default();
    let initial = render_text_cached(&mut app, 100, 30, &mut cache);
    assert!(initial.contains("Command: first-command"));
    assert!(initial.contains("Path: /first-path"));
    app.apply_action(Action::MoveDown);
    let selected = render_text_cached(&mut app, 100, 30, &mut cache);
    assert!(selected.contains("Command: second-command"));
    assert!(!selected.contains("first-command"));

    // Same PID and start identity, new immutable metadata from a refresh.
    second.command_line = Some("changed\x1b[31m-command\x1b[0m".into());
    second.executable_path = None;
    app.apply_test_rows(vec![second.clone()], std::time::Instant::now());
    let refreshed = render_text_cached(&mut app, 100, 30, &mut cache);
    assert!(refreshed.contains("Command: changed-command"));
    assert!(refreshed.contains("Path: -"));
    assert!(!refreshed.contains("second-command"));
    assert!(!refreshed.contains("second-path"));

    second.command_line = None;
    app.apply_test_rows(vec![second], std::time::Instant::now());
    let missing = render_text_cached(&mut app, 100, 30, &mut cache);
    assert!(missing.contains("Command: -"));
    assert!(!missing.contains("changed-command"));
}
