use crate::support::*;
use std::fs;
use std::process::{Command, Stdio};

#[test]
fn plain_pid_refuses_a_live_portless_process_without_signalling_it() {
    let child = Command::new(std::env::current_exe().expect("test binary path resolves"))
        .env(COMMAND_RUNNER_HELPER_ENV, "park")
        .args([
            "--exact",
            "command_runner_helper_process",
            "--ignored",
            "--nocapture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("portless helper must start");
    let mut helper = CommandChild(Some(child));
    let pid = helper.child_mut().id();
    let pid_text = pid.to_string();
    assert!(
        helper
            .child_mut()
            .try_wait()
            .expect("portless helper status must be readable")
            .is_none(),
        "portless helper must be live before the kill attempt",
    );

    let config_dir = TemporaryDirectory::new("plain-pid-portless");
    let config_path = config_dir.path().join("config.toml");
    fs::write(&config_path, "").expect("isolated config file must be written");
    let output = run_command_with_deadline(
        Command::new(kickoutchi_binary())
            .args(["kill", "--pid", pid_text.as_str(), "--yes"])
            .arg("--config")
            .arg(&config_path),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("plain PID refusal must finish before its deadline");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty(), "refusal must not write to stdout");
    let error = String::from_utf8_lossy(&output.stderr);
    // The refusal names the live portless PID and the scoped kill that can
    // target it, rather than claiming nothing matched.
    assert!(
        error.starts_with(&format!(
            "error: PID {pid} still exists but owns no visible open port"
        )),
        "{error}"
    );
    assert!(
        error.contains(&format!("`kick kill --pid {pid} --tree`")),
        "{error}"
    );
    assert!(
        helper
            .child_mut()
            .try_wait()
            .expect("portless helper status must remain readable")
            .is_none(),
        "plain --pid refusal must not signal the live portless helper",
    );
}
