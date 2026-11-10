mod support;

use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use support::*;

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn command_runner_helper_process() {
    match std::env::var(COMMAND_RUNNER_HELPER_ENV).as_deref() {
        Ok("dual-output") => {
            let bytes = vec![0xa5; 256 * 1024];
            io::stdout()
                .write_all(&bytes)
                .expect("helper stdout must be writable");
            io::stderr()
                .write_all(&bytes)
                .expect("helper stderr must be writable");
        }
        Ok("output-over-limit") => {
            let bytes = vec![0xa5; usize::try_from(COMMAND_OUTPUT_BYTES_MAX + 1).unwrap()];
            let _ = io::stdout().write_all(&bytes);
        }
        Ok("park") => loop {
            thread::park();
        },
        _ => {}
    }
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn binary_override_helper_process() {
    if std::env::var_os(BINARY_OVERRIDE_HELPER_ENV).is_some() {
        drop(kickoutchi_binary());
        drop(kick_binary());
    }
}

#[test]
fn verbose_flag_keeps_json_stdout_valid() {
    let config_dir = TemporaryDirectory::new("verbose-diagnostics");
    let config_path = config_dir.path().join("config.toml");
    fs::write(&config_path, "").expect("empty isolated config must be writable");
    let output = run_command_with_deadline(
        Command::new(kickoutchi_binary())
            .arg("list")
            .arg("--port")
            .arg("65535")
            .arg("--json")
            .arg("--verbose")
            .arg("--config")
            .arg(config_path),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("verbose product command must exit before its deadline");

    assert!(matches!(output.status.code(), Some(0 | 3)), "{output:?}");
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .expect("--verbose must leave stdout as valid JSON");
}

#[test]
fn binary_overrides_are_all_or_nothing() {
    fn helper() -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test binary path resolves"));
        command
            .args([
                "--exact",
                "binary_override_helper_process",
                "--ignored",
                "--nocapture",
            ])
            .env(BINARY_OVERRIDE_HELPER_ENV, "1")
            .env_remove(RELEASE_E2E_REQUIRED_ENV)
            .env_remove(KICKOUTCHI_BINARY_ENV)
            .env_remove(KICK_BINARY_ENV);
        command
    }

    let stale = run_command_with_deadline(
        helper().env(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi")),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("stale override helper must exit before its deadline");
    assert!(!stale.status.success());

    let incomplete = run_command_with_deadline(
        helper()
            .env(RELEASE_E2E_REQUIRED_ENV, "1")
            .env(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi")),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("incomplete override helper must exit before its deadline");
    assert!(!incomplete.status.success());

    let complete = run_command_with_deadline(
        helper()
            .env(RELEASE_E2E_REQUIRED_ENV, "1")
            .env(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi"))
            .env(KICK_BINARY_ENV, env!("CARGO_BIN_EXE_kick")),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("complete override helper must exit before its deadline");
    assert!(complete.status.success());
}

#[test]
#[allow(
    clippy::naive_bytecount,
    reason = "the helper output includes test-harness text around the exact binary payload"
)]
fn command_runner_drains_large_stdout_and_stderr_without_deadlock() {
    let output = run_command_with_deadline(
        Command::new(std::env::current_exe().expect("test binary path resolves"))
            .env(COMMAND_RUNNER_HELPER_ENV, "dual-output")
            .args([
                "--exact",
                "command_runner_helper_process",
                "--ignored",
                "--nocapture",
            ]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("dual-output helper must finish before its deadline");

    assert!(output.status.success());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == 0xa5).count(),
        256 * 1024,
    );
    assert_eq!(
        output.stderr.iter().filter(|byte| **byte == 0xa5).count(),
        256 * 1024,
    );
}

#[test]
fn command_runner_rejects_output_past_its_byte_limit() {
    let error = run_command_with_deadline(
        Command::new(std::env::current_exe().expect("test binary path resolves"))
            .env(COMMAND_RUNNER_HELPER_ENV, "output-over-limit")
            .args([
                "--exact",
                "command_runner_helper_process",
                "--ignored",
                "--nocapture",
            ]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect_err("over-limit command output must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn command_runner_timeout_kills_and_reaps_child() {
    let child = Command::new(std::env::current_exe().expect("test binary path resolves"))
        .env(COMMAND_RUNNER_HELPER_ENV, "park")
        .args([
            "--exact",
            "command_runner_helper_process",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("parked helper must start");
    #[cfg(unix)]
    let pid = child.id();

    let error = collect_child_output(child, None, Duration::from_millis(100))
        .expect_err("parked helper must exceed its deadline");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);

    #[cfg(unix)]
    {
        let pid = libc::pid_t::try_from(pid).expect("helper PID must fit pid_t");
        let result = unsafe { libc::kill(pid, 0) };
        assert_eq!(result, -1, "timed-out helper must have been reaped");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "timed-out helper PID must no longer exist",
        );
    }
}

#[test]
#[ignore = "release-only: requires explicit packaged binary paths"]
fn required_release_artifact_paths_are_complete_and_versioned() {
    assert!(
        std::env::var_os(RELEASE_E2E_REQUIRED_ENV).is_some(),
        "release artifact verification requires {RELEASE_E2E_REQUIRED_ENV}",
    );

    let canonical = kickoutchi_binary();
    let short = kick_binary();
    assert_ne!(canonical, short, "release binary paths must be distinct");
    for path in [canonical, short] {
        let metadata = std::fs::metadata(&path).expect("release binary path must be readable");
        assert!(metadata.is_file(), "release binary must be a regular file");
        assert!(metadata.len() > 0, "release binary must not be empty");

        let output = run_command_with_deadline(
            Command::new(&path).arg("--version"),
            None,
            REAL_BINARY_EXIT_WAIT,
        )
        .expect("release binary version command must finish before its deadline");
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(String::from_utf8_lossy(&output.stderr), "");
        assert_eq!(
            String::from_utf8(output.stdout).expect("version output must be UTF-8"),
            format!("kickoutchi {}\n", env!("CARGO_PKG_VERSION")),
        );
    }
}

#[test]
fn cli_and_config_errors_sanitize_terminal_controls() {
    let argument = run_command_with_deadline(
        Command::new(kickoutchi_binary()).args(["list", "--sort", "evil\u{202e}value"]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("invalid argument command runs");
    assert_eq!(argument.status.code(), Some(2));
    let stderr = String::from_utf8(argument.stderr).expect("stderr is UTF-8");
    assert!(!stderr.contains('\u{202e}'), "{stderr:?}");
    assert!(
        stderr.contains("\n\nFor more information, try '--help'."),
        "{stderr:?}"
    );

    let config = run_command_with_deadline(
        Command::new(kickoutchi_binary()).args([
            "--config",
            "missing\nforged: success\x1b]0;spoof\x07.toml",
            "list",
        ]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("missing config command runs");
    assert_eq!(config.status.code(), Some(1));
    let stderr = String::from_utf8(config.stderr).expect("stderr is UTF-8");
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    assert!(!stderr.contains('\x07'), "{stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
    assert!(!stderr.lines().any(|line| line.starts_with("forged:")));
}

#[cfg(any(target_os = "macos", windows))]
#[path = "cli_contract/why_native.rs"]
mod why_native;

#[cfg(any(target_os = "macos", windows))]
#[path = "cli_contract/watch_native.rs"]
mod watch_native;

#[path = "cli_contract/kill.rs"]
mod kill;

#[cfg(target_os = "linux")]
#[path = "cli_contract/linux.rs"]
mod linux;

#[cfg(windows)]
#[path = "cli_contract/windows.rs"]
mod windows;

#[cfg(target_os = "macos")]
#[path = "cli_contract/macos.rs"]
mod macos;
