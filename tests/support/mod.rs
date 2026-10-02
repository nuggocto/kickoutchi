use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::PathBuf;
#[cfg(any(target_os = "macos", windows))]
use std::process::ExitStatus;
use std::process::Output;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const REAL_BINARY_EXIT_WAIT: Duration = Duration::from_secs(10);

mod command;
pub(crate) use command::*;

pub(crate) const COMMAND_RUNNER_HELPER_ENV: &str = "KICKOUTCHI_TEST_COMMAND_RUNNER_HELPER";
pub(crate) const BINARY_OVERRIDE_HELPER_ENV: &str = "KICKOUTCHI_TEST_BINARY_OVERRIDE_HELPER";
pub(crate) const TRACING_HELPER_ENV: &str = "KICKOUTCHI_TEST_TRACING_HELPER";
pub(crate) const RELEASE_E2E_REQUIRED_ENV: &str = "KICKOUTCHI_RELEASE_E2E_REQUIRED";
pub(crate) const KICKOUTCHI_BINARY_ENV: &str = "KICKOUTCHI_E2E_KICKOUTCHI";
pub(crate) const KICK_BINARY_ENV: &str = "KICKOUTCHI_E2E_KICK";

static UNIQUE_TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn create_unique_temp_directory(label: &str) -> PathBuf {
    for _ in 0..u16::MAX {
        let counter = UNIQUE_TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-{label}-{}-{counter}",
            std::process::id(),
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("isolated temporary directory must be created: {error}"),
        }
    }
    panic!("isolated temporary directory collision limit exceeded");
}

pub(crate) struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    pub(crate) fn new(label: &str) -> Self {
        Self(create_unique_temp_directory(label))
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(any(target_os = "macos", windows))]
pub(crate) struct TemporaryConfigFile {
    _directory: TemporaryDirectory,
    path: PathBuf,
}

#[cfg(any(target_os = "macos", windows))]
impl TemporaryConfigFile {
    pub(crate) fn new(label: &str, contents: &str) -> Self {
        let directory = TemporaryDirectory::new(label);
        let path = directory.path().join("config.toml");
        fs::write(&path, contents).expect("isolated config must be written");
        Self {
            _directory: directory,
            path,
        }
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

pub(crate) fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub(crate) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub(crate) fn stdout_table_has_pid(output: &Output, pid: u32) -> bool {
    let pid_text = pid.to_string();
    stdout(output)
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(3) == Some(pid_text.as_str()))
}

/// Maximum lifetime of a parked helper after its test exits.
pub(crate) const HELPER_PARK_MAX: Duration = Duration::from_mins(5);

/// Park a helper until its timeout. This bounds its lifetime when `SIGKILL`
/// prevents the test binary from running cleanup.
pub(crate) fn park_bounded() -> ! {
    let deadline = Instant::now() + HELPER_PARK_MAX;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_secs(1));
    }
    std::process::exit(0)
}

/// Serialize tests that observe host process and socket state (process
/// tables, listening sockets) so parallel tests cannot race each other.
static HOST_OBSERVATION_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock_host_observation() -> std::sync::MutexGuard<'static, ()> {
    HOST_OBSERVATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn product_binary(variable: &str, fallback: &str) -> OsString {
    let required = std::env::var_os(RELEASE_E2E_REQUIRED_ENV).is_some();
    match (required, std::env::var_os(variable)) {
        (true, Some(path)) => path,
        (true, None) => panic!("release E2E requires {variable}"),
        (false, None) => OsString::from(fallback),
        (false, Some(_)) => panic!("{variable} requires {RELEASE_E2E_REQUIRED_ENV}"),
    }
}

pub(crate) fn kickoutchi_binary() -> OsString {
    product_binary(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi"))
}

pub(crate) fn kick_binary() -> OsString {
    product_binary(KICK_BINARY_ENV, env!("CARGO_BIN_EXE_kick"))
}

#[cfg(any(target_os = "macos", windows))]
impl CommandChild {
    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn wait_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            match self.child_mut().try_wait()? {
                Some(status) => return Ok(status),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => return Err(io::Error::new(io::ErrorKind::TimedOut, "command deadline")),
            }
        }
    }
}
