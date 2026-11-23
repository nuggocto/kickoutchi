//! TUI lifecycle on a real pseudo-terminal.
//!
//! Closing a terminal window closes the pty master and hangs up the TUI's tty.
//! The TUI leaves `SIGHUP` at its default action, so the hangup ends it at
//! once. A handled `SIGHUP` would let it outlive its window, spinning in
//! crossterm 0.29's input reader and holding up a later reboot for systemd's
//! stop timeout.

use super::*;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;

/// Generous for loaded CI hosts. A TUI stuck after hangup never exits at all.
const TUI_EXIT_WAIT: Duration = Duration::from_secs(10);
const TUI_READY_WAIT: Duration = Duration::from_secs(20);
/// Time for the first frame's process to reach its input wait. The original
/// defect only appeared when the hangup arrived during that wait.
const TUI_SETTLE: Duration = Duration::from_millis(300);
const ENTER_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";

struct TuiOnPty {
    master: Option<fs::File>,
    child: CommandChild,
    _config: super::super::TemporaryDirectory,
}

/// Start the TUI as the session leader of a fresh pty, as a terminal emulator
/// starts a shell, so the hangup's `SIGHUP` goes to the TUI itself.
fn spawn_tui_on_pty() -> TuiOnPty {
    let config = super::super::TemporaryDirectory::new("tui-pty");
    let config_path = config.path().join("config.toml");
    fs::write(&config_path, "").unwrap();

    // std opens with O_CLOEXEC, so concurrent test children never inherit the
    // master and keep the pty alive after it is closed here.
    let master = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/ptmx")
        .unwrap();
    let mut slave_name = [0 as libc::c_char; 128];
    let size = libc::winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the master descriptor is live, the name buffer is writable for
    // its full length, and `size` outlives the ioctl that reads it.
    unsafe {
        assert_eq!(libc::grantpt(master.as_raw_fd()), 0);
        assert_eq!(libc::unlockpt(master.as_raw_fd()), 0);
        assert_eq!(
            libc::ptsname_r(
                master.as_raw_fd(),
                slave_name.as_mut_ptr(),
                slave_name.len()
            ),
            0
        );
        assert_eq!(
            libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &raw const size),
            0
        );
    }
    // SAFETY: ptsname_r wrote a NUL-terminated path into the buffer.
    let slave_path = unsafe { std::ffi::CStr::from_ptr(slave_name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_owned();
    let slave = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(&slave_path)
        .unwrap();

    let mut command = Command::new(kick_binary());
    command
        .arg("--config")
        .arg(&config_path)
        .env("TERM", "xterm-256color")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    // SAFETY: the hook only makes async-signal-safe calls between fork and
    // exec. stdin is already the pty slave when it runs, and every libc struct
    // is zero-initialized and populated with sigemptyset before use.
    unsafe {
        command.pre_exec(move || {
            // Reset SIGHUP and SIGTERM to SIG_DFL and unblock them so a parent
            // shell or test runner running with SIG_IGN (e.g., nohup or
            // non-interactive harnesses) does not mask the child's signal behavior.
            let mut default_action: libc::sigaction = std::mem::zeroed();
            default_action.sa_sigaction = libc::SIG_DFL;
            if libc::sigemptyset(&raw mut default_action.sa_mask) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut unblock: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&raw mut unblock) < 0 {
                return Err(io::Error::last_os_error());
            }
            for signal in [libc::SIGHUP, libc::SIGTERM] {
                if libc::sigaction(signal, &raw const default_action, std::ptr::null_mut()) < 0
                    || libc::sigaddset(&raw mut unblock, signal) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::sigprocmask(libc::SIG_UNBLOCK, &raw const unblock, std::ptr::null_mut()) < 0
                || libc::setsid() < 0
                || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = CommandChild(Some(command.spawn().unwrap()));
    // The parent's slave descriptors were moved into the child's stdio and
    // dropped here, so the child alone holds the slave side.
    let mut tui = TuiOnPty {
        master: Some(master),
        child,
        _config: config,
    };
    tui.wait_until_drawn();
    tui
}

impl TuiOnPty {
    fn master(&self) -> &fs::File {
        self.master.as_ref().expect("pty master is open")
    }

    /// Read output until `deadline`, stopping early once `done` accepts it.
    fn drain(&self, deadline: Instant, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 8192];
        while Instant::now() < deadline && !done(&output) {
            let mut pollfd = libc::pollfd {
                fd: self.master().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized pollfd entry that outlives the call.
            let ready = unsafe { libc::poll(&raw mut pollfd, 1, 20) };
            if ready <= 0 {
                continue;
            }
            match (&mut self.master()).read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => output.extend_from_slice(&buffer[..read]),
            }
        }
        output
    }

    fn wait_until_drawn(&mut self) {
        let output = self.drain(Instant::now() + TUI_READY_WAIT, |output| {
            output
                .windows(ENTER_ALTERNATE_SCREEN.len())
                .any(|window| window == ENTER_ALTERNATE_SCREEN)
                && output.windows(10).any(|window| window == b"Kickoutchi")
        });
        assert!(
            output.windows(10).any(|window| window == b"Kickoutchi"),
            "TUI never drew its first frame: {}",
            String::from_utf8_lossy(&output)
        );
        self.drain(Instant::now() + TUI_SETTLE, |_| false);
    }

    /// Close the pty master, which hangs up the terminal like closing a window.
    fn hang_up(&mut self) {
        drop(self.master.take());
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + TUI_EXIT_WAIT;
        loop {
            if let Some(status) = self.child.child_mut().try_wait().unwrap() {
                self.child.disarm();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "TUI was still running {TUI_EXIT_WAIT:?} later"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn tui_exits_by_sighup_when_its_terminal_hangs_up() {
    let mut tui = spawn_tui_on_pty();

    tui.hang_up();
    let status = tui.wait_for_exit();

    assert_eq!(status.signal(), Some(libc::SIGHUP), "{status:?}");
}

/// Keys delivered in a single write are buffered by crossterm and must all be
/// handled in order.
#[test]
fn tui_handles_every_key_delivered_in_one_write() {
    let mut tui = spawn_tui_on_pty();

    tui.master().write_all(b"jjq").unwrap();
    let status = tui.wait_for_exit();

    assert!(status.success(), "{status:?}");
}

#[test]
fn tui_honors_sigterm_while_its_terminal_is_open() {
    let mut tui = spawn_tui_on_pty();

    let pid = libc::pid_t::try_from(tui.child.child_mut().id()).unwrap();
    // SAFETY: kill(2) takes the live child's PID and a signal number by value.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = tui.wait_for_exit();

    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
}
