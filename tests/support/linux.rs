use super::{
    CommandChild, HELPER_PARK_MAX, REAL_BINARY_EXIT_WAIT, collect_child_output, kick_binary,
    kickoutchi_binary, lock_host_observation, park_bounded, run_command_with_deadline, stderr,
    stdout, stdout_table_has_pid,
};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CMDLINE_WAIT: Duration = Duration::from_secs(10);
const CHILD_EXIT_WAIT: Duration = Duration::from_secs(10);

/// Building a deep chain re-execs this test binary once per link, so its
/// ready file gets a deadline far beyond the usual helper waits.
const DEEP_CHAIN_READY_WAIT: Duration = Duration::from_secs(30);
const DEEP_CHAIN_DEPTH: usize = 12;

/// How long the live spawner keeps forking before it settles into a plain
/// park. Long enough that the kill under test always lands mid-burst.
const LIVE_SPAWN_WINDOW: Duration = Duration::from_secs(20);
const LIVE_SPAWN_MAX: usize = 400;

fn required_linux_capabilities() -> bool {
    std::env::var_os("KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES").is_some()
}

/// Deadline for a spawned `kick` to print an expected stderr line and for
/// it to exit after confirmation input.
const PROMPT_WAIT: Duration = Duration::from_secs(10);
const KICK_EXIT_WAIT: Duration = Duration::from_secs(10);

/// Deadline for a killed helper's whole process group to drain to empty.
const GROUP_CLEAR_WAIT: Duration = Duration::from_secs(10);
const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
const HELPER_TREE_ENV: &str = "KICKOUTCHI_TEST_HELPER_TREE";
const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
const HELPER_BIND_ANY_ENV: &str = "KICKOUTCHI_TEST_HELPER_BIND_ANY";
const HELPER_NONDUMPABLE_ENV: &str = "KICKOUTCHI_TEST_HELPER_NONDUMPABLE";
const HELPER_NAME_ENV: &str = "KICKOUTCHI_TEST_HELPER_NAME";
const HELPER_LINGER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LINGER";

/// Set by the lingering listener's `SIGTERM` handler.
static HELPER_TERM_SEEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn record_helper_term(_signal: libc::c_int) {
    // Only an atomic store: async-signal-safe.
    HELPER_TERM_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
}
const IPC_WAIT: Duration = Duration::from_secs(10);
// Each no-match diagnostic runs in its own network namespace, where this
// valid boundary port is guaranteed to have no unrelated host listener.
const ISOLATED_DIAGNOSTIC_TEST_PORT: u16 = u16::MAX;
const CONTROLLED_BIND_FAULT_PORT: &str = "49151";

fn run_in_isolated_user_network_namespace(
    script: &str,
    arguments: &[&std::ffi::OsStr],
) -> Option<Output> {
    let mut command = Command::new("unshare");
    command.args([
        "--user",
        "--map-root-user",
        "--net",
        "--pid",
        "--fork",
        "--mount-proc",
        "sh",
        "-c",
        script,
        "sh",
    ]);
    command.args(arguments);
    run_namespace_command(&mut command)
}

fn run_namespace_command(command: &mut Command) -> Option<Output> {
    let output = match run_command_with_deadline(command, None, CHILD_EXIT_WAIT) {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            assert!(
                !required_linux_capabilities(),
                "required unshare capability is unavailable: {error}"
            );
            eprintln!("unshare unavailable: {error}");
            return None;
        }
        Err(error) => panic!("unshare must start: {error}"),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && (stderr.contains("unshare failed: Operation not permitted")
            || stderr.contains("unshare failed: Permission denied"))
    {
        assert!(
            !required_linux_capabilities(),
            "required user/network namespaces are unavailable: {stderr}"
        );
        eprintln!("user/network namespaces unavailable: {stderr}");
        return None;
    }
    Some(output)
}

fn isolated_no_match_diagnostic(json: bool) -> Option<Output> {
    let config_home = isolated_config_home();
    let _config_guard = DirectoryGuard(config_home.clone());
    let port = ISOLATED_DIAGNOSTIC_TEST_PORT.to_string();
    let json_flag = if json { "--json" } else { "" };
    let script = r#"
            sh -c 'sleep 30; :' --port "$2" &
            helper=$!
            attempts=0
            while :; do
                cmdline=$(tr '\000' ' ' < "/proc/${helper}/cmdline")
                case "$cmdline" in
                    *"--port $2"*) break ;;
                esac
                attempts=$((attempts + 1))
                if test "$attempts" -ge 100; then
                    kill "$helper" 2>/dev/null || true
                    wait "$helper" 2>/dev/null || true
                    exit 90
                fi
                sleep 0.01
            done
            if test -n "$4"; then
                XDG_CONFIG_HOME="$3" "$1" list --port "$2" "$4"
            else
                XDG_CONFIG_HOME="$3" "$1" list --port "$2"
            fi
            status=$?
            kill "$helper" 2>/dev/null || true
            wait "$helper" 2>/dev/null || true
            exit "$status"
        "#;
    run_in_isolated_user_network_namespace(
        script,
        &[
            kickoutchi_binary().as_os_str(),
            port.as_ref(),
            config_home.as_os_str(),
            json_flag.as_ref(),
        ],
    )
}

fn assert_json_keys(value: &serde_json::Value, expected: &[&str]) {
    let actual = value
        .as_object()
        .expect("contract value must be an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        continue_pid(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct DirectoryGuard(PathBuf);

impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct DeepChainGuard {
    root: Option<Child>,
    process_group: u32,
    pids: Vec<u32>,
    _directory: DirectoryGuard,
}

impl DeepChainGuard {
    fn root_id(&self) -> u32 {
        self.root
            .as_ref()
            .expect("deep-chain root must be owned")
            .id()
    }

    fn wait_for_all_gone(&mut self) {
        let deadline = Instant::now() + GROUP_CLEAR_WAIT;
        loop {
            let exited = self
                .root
                .as_mut()
                .expect("deep-chain root must be owned")
                .try_wait()
                .expect("deep-chain root status must be readable")
                .is_some();
            if exited {
                self.root.take();
                break;
            }
            assert!(Instant::now() < deadline, "deep-chain root did not exit");
            thread::sleep(Duration::from_millis(10));
        }
        for &pid in &self.pids {
            while !pid_is_terminated(pid) {
                assert!(
                    Instant::now() < deadline,
                    "deep-chain PID {pid} survived termination"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn cleanup(&mut self, deadline: Instant) {
        let Ok(process_group) = libc::pid_t::try_from(self.process_group) else {
            return;
        };
        // SAFETY: a negative PID targets the dedicated process group created
        // for this test fixture; no pointer or borrowed memory crosses FFI.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
        let mut root = CommandChild(self.root.take());
        let _ = root.kill_and_reap(deadline);
        while Instant::now() < deadline {
            if self.pids.iter().all(|pid| pid_is_terminated(*pid)) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for DeepChainGuard {
    fn drop(&mut self) {
        self.cleanup(Instant::now() + GROUP_CLEAR_WAIT);
    }
}

struct FileGuard(PathBuf);

impl Drop for FileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct SocketLifecycle {
    child: Option<Child>,
    stdin: Option<std::process::ChildStdin>,
    lines: mpsc::Receiver<io::Result<String>>,
    reader: Option<thread::JoinHandle<()>>,
    reader_done: mpsc::Receiver<()>,
}

fn finish_reader_thread(
    reader: &mut Option<thread::JoinHandle<()>>,
    reader_done: &mpsc::Receiver<()>,
    deadline: Instant,
) -> io::Result<()> {
    if reader.is_none() {
        return Ok(());
    }
    let completion = reader_done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    match completion {
        Ok(()) => reader
            .take()
            .expect("completed helper reader must be owned")
            .join()
            .map_err(|_| io::Error::other("helper reader panicked")),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let joined = reader
                .take()
                .expect("disconnected helper reader must be owned")
                .join();
            match joined {
                Ok(()) => Err(io::Error::other("helper reader stopped without completion")),
                Err(_) => Err(io::Error::other("helper reader panicked")),
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "helper reader exceeded its exit deadline",
        )),
    }
}

impl SocketLifecycle {
    fn spawn(binary: &Path, args: &[&str]) -> (Self, u16) {
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("socket lifecycle helper must start");
        let stdin = child.stdin.take().expect("helper stdin must be piped");
        let stdout = child.stdout.take().expect("helper stdout must be piped");
        let (sender, lines) = mpsc::channel();
        let (done_sender, reader_done) = mpsc::channel();
        let mut helper = Self {
            child: Some(child),
            stdin: Some(stdin),
            lines,
            reader: None,
            reader_done,
        };
        helper.reader = Some(
            thread::Builder::new()
                .name("socket-lifecycle-reader".to_owned())
                .spawn(move || {
                    for line in BufReader::new(stdout).lines() {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    let _ = done_sender.send(());
                })
                .expect("socket lifecycle reader must start"),
        );
        let ready = helper.response();
        let port = ready
            .strip_prefix("READY ")
            .expect("helper must acknowledge readiness with its port")
            .parse::<u16>()
            .expect("helper port must be a u16");
        (helper, port)
    }

    fn command(&mut self, command: &str) {
        let stdin = self.stdin.as_mut().expect("helper stdin must remain open");
        writeln!(stdin, "{command}").expect("helper command must be writable");
        stdin.flush().expect("helper command must be flushed");
        assert_eq!(self.response(), command);
    }

    fn id(&self) -> u32 {
        self.child
            .as_ref()
            .expect("helper child must be owned")
            .id()
    }

    fn response(&self) -> String {
        self.lines
            .recv_timeout(IPC_WAIT)
            .expect("helper acknowledgement must arrive before its deadline")
            .expect("helper acknowledgement must be readable")
    }

    fn exit(&mut self) {
        self.command("EXIT");
        drop(self.stdin.take());
        let deadline = Instant::now() + IPC_WAIT;
        let status = self
            .wait_for_exit(deadline)
            .expect("helper must exit after acknowledging EXIT");
        assert!(status.success(), "helper must exit successfully");
        self.finish_reader(deadline)
            .expect("helper reader must finish before its deadline");
    }

    fn wait_for_exit(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("helper child is not owned"))?;
        loop {
            if let Some(status) = child.try_wait()? {
                self.child.take();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper exceeded its exit deadline",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish_reader(&mut self, deadline: Instant) -> io::Result<()> {
        finish_reader_thread(&mut self.reader, &self.reader_done, deadline)
    }

    fn cleanup(&mut self, deadline: Instant) -> io::Result<()> {
        drop(self.stdin.take());
        let mut first_error = None;
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child.take();
                }
                Ok(None) => {
                    first_error = child.kill().err();
                }
                Err(error) => first_error = Some(error),
            }
        }
        if self.child.is_some()
            && let Err(error) = self.wait_for_exit(deadline)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Err(error) = self.finish_reader(deadline)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for SocketLifecycle {
    fn drop(&mut self) {
        let _ = self.cleanup(Instant::now() + IPC_WAIT);
    }
}

struct PidGuard {
    pidfd: OwnedFd,
}

impl PidGuard {
    fn new(pid: u32) -> Self {
        let platform_pid = libc::pid_t::try_from(pid).expect("test PID must fit pid_t");
        let raw_pidfd = unsafe {
            // SAFETY: pidfd_open takes value arguments and returns a new owned
            // descriptor. Keeping it open pins cleanup to this process identity.
            libc::syscall(libc::SYS_pidfd_open, platform_pid, 0)
        };
        assert!(raw_pidfd >= 0, "test helper PID {pid} must open a pidfd");
        let pidfd = unsafe {
            // SAFETY: a nonnegative pidfd_open result is one owned descriptor.
            OwnedFd::from_raw_fd(i32::try_from(raw_pidfd).expect("pidfd must fit i32"))
        };
        Self { pidfd }
    }

    fn signal(&self, signal: libc::c_int) {
        unsafe {
            // SAFETY: the owned pidfd remains live for this call; null siginfo
            // and zero flags are the documented basic signal form.
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        self.signal(libc::SIGCONT);
        self.signal(libc::SIGTERM);
    }
}

fn kickoutchi(args: &[&str]) -> Output {
    run_binary(kickoutchi_binary(), args, None)
}

fn kickoutchi_with_stdin(args: &[&str], stdin: &str) -> Output {
    run_binary(kickoutchi_binary(), args, Some(stdin))
}

fn kickoutchi_with_config(args: &[&str], config_text: &str) -> Output {
    kickoutchi_with_config_deadline(args, config_text)
}

fn kickoutchi_with_config_deadline(args: &[&str], config_text: &str) -> Output {
    binary_with_config_deadline_with_env(kickoutchi_binary(), args, config_text, &[], None)
}

fn kickoutchi_with_config_and_stdin(args: &[&str], config_text: &str, stdin: &str) -> Output {
    binary_with_config_deadline_with_env(kickoutchi_binary(), args, config_text, &[], Some(stdin))
}

fn binary_with_config_deadline_with_env(
    path: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
    config_text: &str,
    environment: &[(&str, &std::ffi::OsStr)],
    stdin: Option<&str>,
) -> Output {
    let config_dir = isolated_config_home();
    let config_guard = DirectoryGuard(config_dir.clone());
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_text).expect("test config file must be written");
    let mut command = Command::new(path);
    command
        .arg("--config")
        .arg(&config_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let output = run_command_with_deadline(&mut command, stdin.map(str::as_bytes), KICK_EXIT_WAIT)
        .expect("CLI binary must run with explicit config before its deadline");
    drop(config_guard);
    output
}

fn why(args: &[&str]) -> Output {
    why_with_config(args, "")
}

fn why_with_config(args: &[&str], config_text: &str) -> Output {
    let mut command_args = Vec::with_capacity(args.len() + 1);
    command_args.push("why");
    command_args.extend_from_slice(args);
    kickoutchi_with_config_deadline(&command_args, config_text)
}

fn why_with_bind_faults(args: &[&str], library: &Path, mode: &str) -> Output {
    let mut command_args = Vec::with_capacity(args.len() + 1);
    command_args.push("why");
    command_args.extend_from_slice(args);
    binary_with_config_deadline_with_env(
        kickoutchi_binary(),
        &command_args,
        "",
        &[
            ("LD_PRELOAD", library.as_os_str()),
            (
                "KICKOUTCHI_TEST_BIND_FAULT_MODE",
                std::ffi::OsStr::new(mode),
            ),
        ],
        None,
    )
}

fn build_bind_fault_library() -> (DirectoryGuard, PathBuf) {
    let directory = temp_file_path("bind-faults");
    fs::create_dir(&directory).expect("bind-fault directory must be created");
    let guard = DirectoryGuard(directory.clone());
    let library = directory.join("libkickoutchi_bind_faults.so");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bind_faults.c");
    let output = run_command_with_deadline(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-ldl")
            .arg("-o")
            .arg(&library),
        None,
        CHILD_EXIT_WAIT,
    )
    .expect("C compiler must build the bind-fault fixture before its deadline");
    assert!(
        output.status.success(),
        "bind-fault fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (guard, library)
}

fn build_collect_fault_library() -> (DirectoryGuard, PathBuf) {
    let directory = temp_file_path("collect-faults");
    fs::create_dir(&directory).expect("collect-fault directory must be created");
    let guard = DirectoryGuard(directory.clone());
    let library = directory.join("libkickoutchi_collect_faults.so");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/collect_faults.c");
    let output = run_command_with_deadline(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-ldl")
            .arg("-o")
            .arg(&library),
        None,
        CHILD_EXIT_WAIT,
    )
    .expect("C compiler must build the collect-fault fixture before its deadline");
    assert!(
        output.status.success(),
        "collect-fault fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (guard, library)
}

fn build_socket_lifecycle_helper() -> (DirectoryGuard, PathBuf) {
    let directory = temp_file_path("socket-lifecycle");
    fs::create_dir(&directory).expect("socket lifecycle directory must be created");
    let guard = DirectoryGuard(directory.clone());
    let binary = directory.join("socket-lifecycle");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/socket_lifecycle.c");
    let output = run_command_with_deadline(
        Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&binary),
        None,
        CHILD_EXIT_WAIT,
    )
    .expect("C compiler must build the socket helper before its deadline");
    assert!(
        output.status.success(),
        "socket helper compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (guard, binary)
}

fn kick(args: &[&str]) -> Output {
    run_binary(kick_binary(), args, None)
}

fn run_binary(path: impl AsRef<std::ffi::OsStr>, args: &[&str], stdin: Option<&str>) -> Output {
    let config_home = isolated_config_home();
    let config_guard = DirectoryGuard(config_home.clone());
    let mut command = Command::new(path);
    command.env("XDG_CONFIG_HOME", &config_home).args(args);
    let output = run_command_with_deadline(
        &mut command,
        stdin.map(str::as_bytes),
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("kickoutchi output must be collected before its deadline");
    drop(config_guard);
    output
}

fn run_why_with_closed_stdout(args: &[&str]) -> Output {
    let config_home = isolated_config_home();
    let config_guard = DirectoryGuard(config_home.clone());
    let (reader, writer) = UnixStream::pair().expect("test pipe must be created");
    drop(reader);
    let child = Command::new(kick_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .arg("why")
        .args(args)
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .spawn()
        .expect("why binary must run with a closed stdout reader");
    let output = collect_child_output(child, None, KICK_EXIT_WAIT)
        .expect("why output must be collected before its deadline");
    drop(config_guard);
    output
}

fn run_list_with_closed_stdout(args: &[&str]) -> Output {
    let config_home = isolated_config_home();
    let config_guard = DirectoryGuard(config_home.clone());
    let (reader, writer) = UnixStream::pair().expect("test pipe must be created");
    drop(reader);
    let child = Command::new(kickoutchi_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .arg("list")
        .args(args)
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .spawn()
        .expect("list binary must run with a closed stdout reader");
    let output = collect_child_output(child, None, KICK_EXIT_WAIT)
        .expect("list output must be collected before its deadline");
    drop(config_guard);
    output
}

fn run_subcommand_with_closed_stdout(subcommand: &str, args: &[&str]) -> Output {
    let config_home = isolated_config_home();
    let config_guard = DirectoryGuard(config_home.clone());
    let (reader, writer) = UnixStream::pair().expect("test pipe must be created");
    drop(reader);
    let child = Command::new(kickoutchi_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .arg(subcommand)
        .args(args)
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary must run with a closed stdout reader");
    let output = collect_child_output(child, None, KICK_EXIT_WAIT)
        .expect("closed-stdout command must finish before its deadline");
    drop(config_guard);
    output
}

fn run_list_with_full_stdout(args: &[&str]) -> Output {
    let config_home = isolated_config_home();
    let config_guard = DirectoryGuard(config_home.clone());
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("Linux exposes /dev/full");
    let child = Command::new(kickoutchi_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .arg("list")
        .args(args)
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .spawn()
        .expect("list binary must run with a failing stdout writer");
    let output = collect_child_output(child, None, KICK_EXIT_WAIT)
        .expect("list output must be collected before its deadline");
    drop(config_guard);
    output
}

fn isolated_config_home() -> PathBuf {
    super::create_unique_temp_directory("linux-config")
}

fn spawn_listener_process() -> (ChildGuard, u16, PathBuf) {
    spawn_listener_process_with_metadata_access(true)
}

fn spawn_listener_process_with_metadata_access(
    metadata_accessible: bool,
) -> (ChildGuard, u16, PathBuf) {
    spawn_listener_process_with_options(metadata_accessible, None)
}

fn spawn_lingering_listener_process() -> (ChildGuard, u16, PathBuf) {
    spawn_listener_process_with_env(true, None, &[(HELPER_LINGER_ENV, "1")])
}

fn spawn_listener_process_with_options(
    metadata_accessible: bool,
    name: Option<&str>,
) -> (ChildGuard, u16, PathBuf) {
    spawn_listener_process_with_env(metadata_accessible, name, &[])
}

fn spawn_listener_process_with_env(
    metadata_accessible: bool,
    name: Option<&str>,
    extra_env: &[(&str, &str)],
) -> (ChildGuard, u16, PathBuf) {
    let ready_file = temp_file_path("listener-ready");
    let mut command = Command::new(std::env::current_exe().expect("test binary path resolves"));
    command
        .env(HELPER_LISTENER_ENV, "1")
        .env(HELPER_PORT_ENV, "0")
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "linux::helper_tcp_listener_process",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !metadata_accessible {
        command.env(HELPER_NONDUMPABLE_ENV, "1");
    }
    if let Some(name) = name {
        command.env(HELPER_NAME_ENV, name);
    }
    command.envs(extra_env.iter().copied());
    let child = command.spawn().expect("listener helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let port = fs::read_to_string(&ready_file)
        .expect("helper ready file must contain the bound port")
        .parse::<u16>()
        .expect("helper bound port must be a u16");
    (guard, port, ready_file)
}

fn spawn_group_process() -> (ChildGuard, u16, u32, PathBuf) {
    let ready_file = temp_file_path("group-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, "group-orphan")
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "linux::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("group helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let ready = fs::read_to_string(&ready_file).expect("group ready file must be readable");
    let mut parts = ready.split_whitespace();
    let port = parts
        .next()
        .expect("ready file must contain port")
        .parse::<u16>()
        .expect("group helper port must be a u16");
    let orphan_pid = parts
        .next()
        .expect("ready file must contain orphan pid")
        .parse::<u32>()
        .expect("group orphan pid must be a u32");
    (guard, port, orphan_pid, ready_file)
}


fn spawn_tree_process(mode: &str) -> (ChildGuard, u16, u32, PathBuf) {
    let ready_file = temp_file_path("tree-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, mode)
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "linux::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("tree helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let ready = fs::read_to_string(&ready_file).expect("tree ready file must be readable");
    let mut parts = ready.split_whitespace();
    let port = parts
        .next()
        .expect("ready file must contain port")
        .parse::<u16>()
        .expect("tree helper port must be a u16");
    let child_pid = parts
        .next()
        .expect("ready file must contain child pid")
        .parse::<u32>()
        .expect("tree helper child pid must be a u32");
    (guard, port, child_pid, ready_file)
}

fn temp_file_path(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "kickoutchi-cli-contract-{label}-{}-{unique}",
        std::process::id(),
    ))
}

fn wait_for_file(path: &Path) {
    wait_for_file_within(path, CMDLINE_WAIT);
}

fn wait_for_file_within(path: &Path, wait: Duration) {
    let deadline = Instant::now() + wait;
    loop {
        if path.exists() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "helper process never created ready file {}",
            path.display(),
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child_exit(guard: &mut ChildGuard) {
    let deadline = Instant::now() + CHILD_EXIT_WAIT;
    loop {
        if guard
            .child
            .try_wait()
            .expect("child exit status must be readable")
            .is_some()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "helper process did not exit after SIGTERM",
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_pid_gone(pid: u32) {
    let deadline = Instant::now() + CHILD_EXIT_WAIT;
    loop {
        if pid_is_terminated(pid) {
            return;
        }
        assert!(Instant::now() < deadline, "PID {pid} did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_pid_state(pid: u32, expected: char) {
    let deadline = Instant::now() + CHILD_EXIT_WAIT;
    loop {
        if process_state(pid) == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PID {pid} never reached state {expected:?}",
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn pid_exists(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

fn pid_is_terminated(pid: u32) -> bool {
    matches!(process_state(pid), None | Some('Z' | 'X'))
}

fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")).ok()?;
    let (_before, after) = stat.rsplit_once(") ")?;
    after.chars().next()
}

fn continue_pid(pid: u32) {
    let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    unsafe {
        libc::kill(platform_pid, libc::SIGCONT);
    }
}

fn stop_pid(pid: u32) {
    let platform_pid = libc::pid_t::try_from(pid).expect("test pid must fit pid_t");
    let result = unsafe { libc::kill(platform_pid, libc::SIGSTOP) };
    assert_eq!(result, 0, "SIGSTOP test helper PID {pid} must succeed");
}

/// Native hosts may expose either complete procfs evidence or a
/// restricted/stacked mount, and unrelated host sockets may change during
/// collection even when namespace capabilities are available. Only a
/// successful signal or these exact fail-closed authority refusals are valid.
fn port_kill_refused_for_incomplete_authority(output: &Output) -> bool {
    let stderr = stderr(output);
    let observation_raced = output.status.code() == Some(1)
        && stderr.contains("collecting ports before kill failed: observation raced");
    let refused_during_collection = observation_raced
        || (output.status.code() == Some(1)
            && stderr.contains("collecting ports before kill failed: socket set is partial"));
    let refused_during_revalidation = output.status.code() == Some(4)
        && stderr.contains("ownership for PID")
        && stderr.contains("became unavailable before SIGTERM")
        && stderr.contains("no termination was sent");

    if refused_during_collection || refused_during_revalidation {
        assert!(!stderr.contains("sent SIG"), "{stderr}");
        true
    } else {
        false
    }
}

fn assert_helper_survived_refusal(helper: &mut ChildGuard) {
    let pid = helper.id();
    assert!(
        helper
            .child
            .try_wait()
            .expect("helper status must be readable")
            .is_none(),
        "helper PID {pid} must survive a refused port kill",
    );
    assert_ne!(
        process_state(pid),
        Some('T'),
        "helper PID {pid} must not remain frozen after refusal",
    );
}

fn toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn assert_json_keys_absent_recursively(value: &serde_json::Value, forbidden: &[&str]) {
    match value {
        serde_json::Value::Object(object) => {
            for key in object.keys() {
                assert!(
                    !forbidden.contains(&key.as_str()),
                    "snapshot unexpectedly exposed key {key:?}"
                );
            }
            for child in object.values() {
                assert_json_keys_absent_recursively(child, forbidden);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                assert_json_keys_absent_recursively(child, forbidden);
            }
        }
        _ => {}
    }
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn helper_tcp_listener_process() {
    if std::env::var_os(HELPER_LISTENER_ENV).is_none() {
        return;
    }

    if let Ok(name) = std::env::var(HELPER_NAME_ENV) {
        // Set the process leader's name, not only the test worker thread's.
        // The kernel performs its real byte truncation at this boundary.
        fs::write("/proc/self/comm", name).expect("helper process name must be set");
    }

    if std::env::var_os(HELPER_NONDUMPABLE_ENV).is_some() {
        // SAFETY: prctl is called with the documented PR_SET_DUMPABLE
        // operation and one integer value; no pointer crosses the boundary.
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        assert_eq!(result, 0, "test helper must disable dumpability");
    }

    let port = std::env::var(HELPER_PORT_ENV)
        .expect("helper port must be set")
        .parse::<u16>()
        .expect("helper port must be a u16");
    let ready_file =
        PathBuf::from(std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"));
    let bind_address = if std::env::var_os(HELPER_BIND_ANY_ENV).is_some() {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let listener = TcpListener::bind((bind_address, port))
        .expect("helper listener must bind the requested port");
    let bound_port = listener
        .local_addr()
        .expect("helper listener must have a local address")
        .port();
    let ready_tmp = ready_file.with_extension("tmp");
    fs::write(&ready_tmp, bound_port.to_string()).expect("helper ready file must be written");
    fs::rename(&ready_tmp, &ready_file).expect("helper ready file must be published");

    if std::env::var_os(HELPER_LINGER_ENV).is_some() {
        linger_after_term(listener);
    }
    park_bounded()
}

/// Close the listener on `SIGTERM` but keep running, like a server whose
/// graceful shutdown stalls after it stops accepting.
fn linger_after_term(listener: TcpListener) -> ! {
    // SAFETY: the handler only performs an atomic store, and the function
    // pointer stays valid for the life of the process.
    let previous = unsafe {
        libc::signal(
            libc::SIGTERM,
            record_helper_term as extern "C" fn(libc::c_int) as libc::sighandler_t,
        )
    };
    assert_ne!(previous, libc::SIG_ERR, "helper SIGTERM handler must install");
    let mut listener = Some(listener);
    let deadline = std::time::Instant::now() + IPC_WAIT;
    while std::time::Instant::now() < deadline {
        if HELPER_TERM_SEEN.load(std::sync::atomic::Ordering::SeqCst) {
            drop(listener.take());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::process::exit(0)
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn helper_process_tree() {
    let Some(mode) = std::env::var_os(HELPER_TREE_ENV) else {
        return;
    };
    let mode = mode.to_string_lossy();
    let ready_file =
        PathBuf::from(std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"));

    match mode.as_ref() {
        "root-owns-port" => {
            let listener =
                TcpListener::bind(("127.0.0.1", 0)).expect("root tree helper listener must bind");
            let port = listener.local_addr().expect("listener addr").port();
            let child = Command::new("sleep")
                .arg("300")
                .spawn()
                .expect("tree child must spawn");
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, format!("{port} {}", child.id()))
                .expect("tree ready file must be written");
            fs::rename(&ready_tmp, &ready_file).expect("tree ready file must publish");
            let _child_guard = ChildGuard { child };
            park_bounded()
        }
        "child-owns-port" => {
            let child_ready = ready_file.with_extension("child");
            let child =
                Command::new(std::env::current_exe().expect("test binary path must resolve"))
                    .env(HELPER_LISTENER_ENV, "1")
                    .env(HELPER_PORT_ENV, "0")
                    .env(HELPER_READY_ENV, &child_ready)
                    .args([
                        "--exact",
                        "linux::helper_tcp_listener_process",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("tree listener child must spawn");
            wait_for_file(&child_ready);
            let port = fs::read_to_string(&child_ready).expect("child port must be readable");
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, format!("{} {}", port.trim(), child.id()))
                .expect("tree ready file must be written");
            fs::rename(&ready_tmp, &ready_file).expect("tree ready file must publish");
            let _child_guard = ChildGuard { child };
            park_bounded()
        }
        "live-spawner" => run_live_spawner_helper(&ready_file),
        "fork-on-trigger" => run_fork_on_trigger_helper(&ready_file),
        chain if chain.starts_with("chain-") => run_chain_link_helper(chain, &ready_file),
        "group-orphan" => {
            // Detach into a fresh process group first: the kill target's
            // group must never be the cargo-test session's group, or a
            // group kill in this test would sweep the whole test run (the
            // pipeline would refuse on its own PID, but the test must not
            // depend on that guard for its safety).
            // SAFETY: setpgid(0, 0) makes the calling process a group
            // leader; it takes no pointers and cannot affect other
            // processes.
            let result = unsafe { libc::setpgid(0, 0) };
            assert_eq!(result, 0, "group helper must become a group leader");

            let listener =
                TcpListener::bind(("127.0.0.1", 0)).expect("group helper listener must bind");
            let port = listener.local_addr().expect("listener addr").port();
            // `sh` starts a sleeper in our group, prints its PID, and
            // exits: the sleeper reparents away immediately, leaving a
            // group member that is no longer a descendant. The sleeper's
            // stdio must not inherit the pipe, or `output()` would wait
            // for the sleeper's EOF instead of sh's exit.
            let output = run_command_with_deadline(
                Command::new("sh").args(["-c", "sleep 300 >/dev/null 2>&1 & echo $!"]),
                None,
                CHILD_EXIT_WAIT,
            )
            .expect("group orphan spawner must run");
            let orphan_pid = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .expect("orphan PID must be printed");
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, format!("{port} {orphan_pid}"))
                .expect("group ready file must be written");
            fs::rename(&ready_tmp, &ready_file).expect("group ready file must publish");
            park_bounded()
        }
        other => panic!("unknown tree helper mode {other}"),
    }
}

fn chain_pid_file(ready_file: &Path, depth: usize) -> PathBuf {
    ready_file.with_extension(format!("chain-{depth}-pid"))
}

fn chain_ready_file(ready_file: &Path, depth: usize) -> PathBuf {
    ready_file.with_extension(format!("chain-{depth}-ready"))
}

/// One link of the deep static chain. Each link publishes its PID and does
/// not report subtree readiness until every descendant has done the same.
fn run_chain_link_helper(mode: &str, ready_file: &Path) -> ! {
    let depth = mode
        .strip_prefix("chain-")
        .expect("chain mode must carry a depth")
        .parse::<usize>()
        .expect("chain depth must be numeric");
    let pid_file = chain_pid_file(ready_file, depth);
    let pid_tmp = pid_file.with_extension("tmp");
    fs::write(&pid_tmp, std::process::id().to_string()).expect("chain PID file must be written");
    fs::rename(&pid_tmp, &pid_file).expect("chain PID file must publish");

    let _next_guard = if depth > 1 {
        let next = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, format!("chain-{}", depth - 1))
            .env(HELPER_READY_ENV, ready_file)
            .args([
                "--exact",
                "linux::helper_process_tree",
                "--ignored",
                "--nocapture",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("next chain link must spawn");
        wait_for_file_within(
            &chain_ready_file(ready_file, depth - 1),
            DEEP_CHAIN_READY_WAIT,
        );
        Some(ChildGuard { child: next })
    } else {
        None
    };

    let subtree_ready = chain_ready_file(ready_file, depth);
    let subtree_tmp = subtree_ready.with_extension("tmp");
    fs::write(&subtree_tmp, "ready").expect("chain subtree marker must be written");
    fs::rename(&subtree_tmp, &subtree_ready).expect("chain subtree marker must publish");
    park_bounded()
}

/// A root that actively spawns short-lived children for a bounded window.
/// Missing that window exits the fixture with failure instead of letting the
/// test pass against a settled tree. Every child self-exits after two seconds.
fn run_live_spawner_helper(ready_file: &Path) -> ! {
    // A fresh process group: children inherit pgid == this PID, giving the
    // test one precise membership question to poll after the kill.
    // SAFETY: setpgid(0, 0) makes the calling process a group leader; it
    // takes no pointers and cannot affect other processes.
    let result = unsafe { libc::setpgid(0, 0) };
    assert_eq!(result, 0, "live spawner must become a group leader");

    let spawn_deadline = Instant::now() + LIVE_SPAWN_WINDOW;
    let mut children: Vec<Child> = Vec::new();
    let mut spawned: usize = 0;
    while Instant::now() < spawn_deadline && spawned < LIVE_SPAWN_MAX {
        let child = Command::new("sleep")
            .arg("2")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("live spawner child must spawn");
        children.push(child);
        spawned += 1;
        if spawned == 1 {
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, "spawning").expect("live spawner ready file must be written");
            fs::rename(&ready_tmp, ready_file).expect("live spawner ready file must publish");
        }
        // Reap finished children to bound the live and zombie process counts.
        children.retain_mut(|child| matches!(child.try_wait(), Ok(None)));
        // Pacing, not synchronization: it keeps the burst under the tree cap
        // while still guaranteeing the kill under test lands mid-spawn.
        thread::sleep(Duration::from_millis(50));
    }
    std::process::exit(2)
}

/// A parent that owns one child from the start and forks one more member
/// only when the trigger file appears after the kill's preview has
/// printed. The second ready file publishes the late member's PID.
fn run_fork_on_trigger_helper(ready_file: &Path) -> ! {
    let child = Command::new("sh")
        .args(["-c", "sleep 300"])
        .spawn()
        .expect("fork-on-trigger child must spawn");
    let ready_tmp = ready_file.with_extension("tmp");
    fs::write(&ready_tmp, child.id().to_string())
        .expect("fork-on-trigger ready file must be written");
    fs::rename(&ready_tmp, ready_file).expect("fork-on-trigger ready file must publish");
    let _child_guard = ChildGuard { child };

    let trigger_file = ready_file.with_extension("trigger");
    let deadline = Instant::now() + HELPER_PARK_MAX;
    while Instant::now() < deadline {
        if trigger_file.exists() {
            let grandchild = Command::new("sh")
                .args(["-c", "sleep 300"])
                .spawn()
                .expect("fork-on-trigger late member must spawn");
            let second_tmp = ready_file.with_extension("second-tmp");
            fs::write(&second_tmp, grandchild.id().to_string())
                .expect("fork-on-trigger second ready file must be written");
            fs::rename(&second_tmp, ready_file.with_extension("second"))
                .expect("fork-on-trigger second ready file must publish");
            let _grandchild_guard = ChildGuard { child: grandchild };
            park_bounded()
        }
        thread::sleep(Duration::from_millis(10));
    }
    std::process::exit(0)
}

fn spawn_deep_chain_process(depth: usize) -> DeepChainGuard {
    let directory = temp_file_path("chain-ready");
    fs::create_dir(&directory).expect("chain ready directory must be created");
    let ready_file = directory.join("state");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, format!("chain-{depth}"))
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "linux::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("chain helper process must start");
    let process_group = child.id();
    let mut guard = DeepChainGuard {
        root: Some(child),
        process_group,
        pids: Vec::new(),
        _directory: DirectoryGuard(directory),
    };
    wait_for_file_within(&chain_ready_file(&ready_file, depth), DEEP_CHAIN_READY_WAIT);
    guard.pids = (1..=depth)
        .rev()
        .map(|link_depth| {
            fs::read_to_string(chain_pid_file(&ready_file, link_depth))
                .expect("chain PID file must be readable")
                .trim()
                .parse::<u32>()
                .expect("chain PID must be a u32")
        })
        .collect();
    assert_eq!(guard.pids.len(), depth);
    assert_eq!(guard.pids.first().copied(), Some(guard.root_id()));
    guard
}

fn spawn_live_spawner_process() -> (ChildGuard, PathBuf) {
    let ready_file = temp_file_path("spawner-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, "live-spawner")
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "linux::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("live spawner helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    (guard, ready_file)
}

fn spawn_fork_on_trigger_process() -> (ChildGuard, u32, PathBuf) {
    let ready_file = temp_file_path("fork-trigger-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, "fork-on-trigger")
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "linux::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("fork-on-trigger helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let child_pid = fs::read_to_string(&ready_file)
        .expect("fork-on-trigger ready file must be readable")
        .trim()
        .parse::<u32>()
        .expect("fork-on-trigger child pid must be a u32");
    (guard, child_pid, ready_file)
}

/// Every non-terminated process in group `pgid`, with its one-letter state.
/// Reads `/proc` directly; vanished, zombie, and dead entries drop out.
fn process_group_members(pgid: u32) -> Vec<(u32, char)> {
    let pgid_text = pgid.to_string();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut members = Vec::new();
    for entry in entries.flatten() {
        let Some(member_pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Fields after the ")" closing comm: state, ppid, pgrp, ...
        let Some((_before, after)) = stat.rsplit_once(") ") else {
            continue;
        };
        let mut fields = after.split_whitespace();
        let state = fields.next().and_then(|field| field.chars().next());
        let group = fields.nth(1);
        if group == Some(pgid_text.as_str())
            && let Some(state) = state
            && !matches!(state, 'Z' | 'X')
        {
            members.push((member_pid, state));
        }
    }
    members
}

fn wait_for_process_group_clear(pgid: u32) {
    let deadline = Instant::now() + GROUP_CLEAR_WAIT;
    loop {
        let members = process_group_members(pgid);
        if members.is_empty() {
            return;
        }

        // A survivor frozen in state 'T' would never clear on its own; the
        // deadline turns it into a visible failure listing (pid, state).
        assert!(
            Instant::now() < deadline,
            "process group {pgid} still has members (pid, state): {members:?}",
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// A `kick kill` run whose stdin stays open across the confirmation
/// prompt, so a test can change the world *between* the preview banner and
/// the typed word. Stderr is drained by a reader thread into a shared
/// buffer the test polls; the prompt has no trailing newline, so the
/// buffer fills from raw reads, not lines.
struct InteractiveKick {
    child: Child,
    config_home: PathBuf,
    stderr_buf: Arc<Mutex<String>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl InteractiveKick {
    fn spawn(args: &[&str]) -> Self {
        let config_home = isolated_config_home();
        let mut child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kickoutchi binary must run");
        let mut child_stderr = child.stderr.take().expect("stderr must be piped");
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let buffer = Arc::clone(&stderr_buf);
        let reader = thread::spawn(move || {
            let mut chunk = [0_u8; 4096];
            loop {
                match child_stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => buffer
                        .lock()
                        .expect("stderr buffer lock must not be poisoned")
                        .push_str(&String::from_utf8_lossy(&chunk[..count])),
                }
            }
        });
        Self {
            child,
            config_home,
            stderr_buf,
            reader: Some(reader),
        }
    }

    fn wait_for_stderr(&self, needle: &str) {
        let deadline = Instant::now() + PROMPT_WAIT;
        loop {
            {
                let buffer = self
                    .stderr_buf
                    .lock()
                    .expect("stderr buffer lock must not be poisoned");
                if buffer.contains(needle) {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "kickoutchi never printed {needle:?}; stderr so far:\n{}",
                    buffer.as_str(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn send_stdin(&mut self, input: &str) {
        self.child
            .stdin
            .as_mut()
            .expect("stdin must be piped")
            .write_all(input.as_bytes())
            .expect("confirmation input must be written");
    }

    /// Close stdin, wait (bounded) for exit, and return the exit code
    /// together with the complete stderr transcript.
    fn finish(&mut self) -> (Option<i32>, String) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + KICK_EXIT_WAIT;
        let status = loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("kickoutchi exit status must be readable")
            {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "kickoutchi did not exit after confirmation input",
            );
            thread::sleep(Duration::from_millis(10));
        };
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let transcript = self
            .stderr_buf
            .lock()
            .expect("stderr buffer lock must not be poisoned")
            .clone();
        (status.code(), transcript)
    }
}

impl Drop for InteractiveKick {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = fs::remove_dir_all(&self.config_home);
    }
}
