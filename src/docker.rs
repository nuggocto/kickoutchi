//! Optional Docker enrichment for local port ownership.
//!
//! The native OS collectors remain the source of truth. This module only tries
//! to explain Docker-looking or metadata-hidden owners in the selected-row
//! details view, and every failure path returns no enrichment instead of
//! breaking port collection.

use std::io::{self, Read};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::debug;

use crate::model::{
    DockerContainerPort, DockerPortContext, PermissionStatus, PortEntryView, Protocol,
};

const DOCKER_COMMAND_TIMEOUT: Duration = Duration::from_millis(1_500);
// How long to wait for a drain worker after the child is gone. Killing the
// direct docker child closes its pipe fds, so a healthy drain finishes almost
// immediately; the wait exists because a grandchild that inherited the pipe
// (Docker Desktop shims, credential helpers) can hold the write end open
// indefinitely, and an unbounded join would hang with it.
const DOCKER_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const DOCKER_OUTPUT_MAX_BYTES: usize = 256 * 1024;
const DOCKER_OUTPUT_READ_CHUNK_BYTES: usize = 8 * 1024;
const DOCKER_OUTPUT_DRAIN_WORKERS_MAX: usize = 8;
const DOCKER_CHILD_CLEANUP_WORKERS_MAX: usize = 4;
const DOCKER_ROWS_MAX: usize = 128;
const DOCKER_MATCHES_MAX: usize = 8;
const DOCKER_FIELD_MAX_BYTES: usize = 4 * 1024;
const DOCKER_PORT_SEGMENTS_MAX: usize = 64;
const DOCKER_HOST_MAX_BYTES: usize = 4 * 1024;

#[cfg(target_os = "linux")]
const LINUX_STATUS_READ_MAX_BYTES: usize = 64 * 1024;

#[cfg(unix)]
const DEFAULT_LOCAL_DOCKER_HOST: &str = "unix:///var/run/docker.sock";
#[cfg(windows)]
const DEFAULT_LOCAL_DOCKER_HOST: &str = "npipe:////./pipe/docker_engine";

const DOCKER_PROCESS_NAMES: &[&str] = &[
    "docker",
    "docker.exe",
    "docker-proxy",
    "docker-proxy.exe",
    "dockerd",
    "dockerd.exe",
    "Docker Desktop.exe",
    "com.docker.backend",
    "com.docker.backend.exe",
    "com.docker.vpnkit",
    "com.docker.slirp",
    "vpnkit",
];

#[derive(Debug, Deserialize)]
struct DockerPsJsonRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Ports")]
    ports: String,
    #[serde(rename = "Labels")]
    labels: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerContainerRow {
    id: String,
    name: String,
    ports: String,
    compose_project: Option<String>,
    compose_service: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }

    fn mapped_port(self, peer: Self, port: u16) -> Option<u16> {
        if !self.contains(port) {
            return None;
        }
        if peer.start == peer.end {
            return Some(peer.start);
        }
        let offset = port.checked_sub(self.start)?;
        peer.start
            .checked_add(offset)
            .filter(|mapped| *mapped <= peer.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishedPort {
    host_addr: Option<IpAddr>,
    host_ports: PortRange,
    container_ports: PortRange,
    protocol: Protocol,
}

pub(crate) fn enrich_port(entry: PortEntryView<'_>) -> Option<DockerPortContext> {
    if !should_try_docker_enrichment(entry) {
        return None;
    }

    let output = docker_container_ls(entry.local_port, entry.protocol)?;
    docker_context_from_ps_output(entry, &output)
}

fn docker_container_ls(port: u16, protocol: Protocol) -> Option<String> {
    docker_container_ls_with_runner(port, protocol, run_command_bounded)
}

fn docker_container_ls_with_runner(
    port: u16,
    protocol: Protocol,
    run: impl FnOnce(&mut Command) -> Option<std::process::Output>,
) -> Option<String> {
    let configured_host = std::env::var("DOCKER_HOST").ok();
    docker_container_ls_with_host_and_runner(port, protocol, configured_host.as_deref(), run)
}

fn docker_container_ls_with_host_and_runner(
    port: u16,
    protocol: Protocol,
    configured_host: Option<&str>,
    run: impl FnOnce(&mut Command) -> Option<std::process::Output>,
) -> Option<String> {
    if docker_command_is_elevated() {
        debug!("skipping PATH-resolved docker CLI while process is elevated");
        return None;
    }

    let docker_host = local_docker_host(configured_host);
    if configured_host.is_some_and(|host| !docker_host_is_local(host)) {
        debug!("ignoring non-local Docker endpoint during port enrichment");
    }
    let publish_filter = format!("publish={port}/{}", protocol_filter(protocol));
    // Resolve `docker` through PATH because install locations vary too
    // much (distro packages, Docker Desktop, Homebrew) for a fixed allowlist.
    // Elevation is rejected above before PATH resolution. An explicit local
    // host prevents the user's current Docker context from selecting a remote
    // daemon; a local DOCKER_HOST remains useful for rootless engines.
    let mut command = Command::new("docker");
    command
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .arg("--host")
        .arg(docker_host)
        .arg("container")
        .arg("ls")
        .arg("--filter")
        .arg(publish_filter)
        .arg("--format")
        .arg("json");
    let output = run(&mut command)?;
    if !output.status.success() {
        debug!(status = %output.status, "docker CLI returned non-success status");
        return None;
    }

    match String::from_utf8(output.stdout) {
        Ok(stdout) => Some(stdout),
        Err(error) => {
            debug!(%error, "docker CLI output was not UTF-8");
            None
        }
    }
}

fn local_docker_host(configured_host: Option<&str>) -> String {
    #[cfg(windows)]
    if let Some(host) = configured_host.and_then(normalize_windows_npipe_host) {
        return host;
    }

    #[cfg(unix)]
    if let Some(host) = configured_host.filter(|host| docker_host_is_local(host)) {
        return (*host).to_owned();
    }

    DEFAULT_LOCAL_DOCKER_HOST.to_owned()
}

fn docker_host_is_local(host: &str) -> bool {
    if host.is_empty()
        || host.len() > DOCKER_HOST_MAX_BYTES
        || host.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }

    #[cfg(unix)]
    {
        host.strip_prefix("unix://")
            .is_some_and(|path| path.starts_with('/') && path.len() > 1)
    }

    #[cfg(windows)]
    {
        normalize_windows_npipe_host(host).is_some()
    }
}

#[cfg(any(windows, test))]
fn normalize_windows_npipe_host(host: &str) -> Option<String> {
    const LOCAL_PREFIX: &str = "////./pipe/";

    if host.is_empty()
        || host.len() > DOCKER_HOST_MAX_BYTES
        || host.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }

    let (scheme, endpoint) = host.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("npipe")
        || endpoint.contains(['%', '?', '#'])
        || endpoint.contains(':')
    {
        return None;
    }

    let endpoint = endpoint.replace('\\', "/");
    let prefix = endpoint.get(..LOCAL_PREFIX.len())?;
    if !prefix.eq_ignore_ascii_case(LOCAL_PREFIX) {
        return None;
    }
    let pipe_name = &endpoint[LOCAL_PREFIX.len()..];
    if pipe_name.is_empty()
        || pipe_name.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.trim_end_matches([' ', '.']) != component
        })
    {
        return None;
    }

    Some(format!("npipe:////./pipe/{pipe_name}"))
}

#[cfg(test)]
thread_local! {
    static TEST_ELEVATION_OVERRIDE: std::cell::Cell<Option<bool>> = const {
        std::cell::Cell::new(None)
    };
    #[cfg(target_os = "linux")]
    pub(crate) static TEST_LINUX_ELEVATION_SOURCES: std::cell::Cell<Option<(bool, bool, bool)>> = const {
        std::cell::Cell::new(None)
    };
}

fn docker_command_is_elevated() -> bool {
    #[cfg(test)]
    if let Some(elevated) = TEST_ELEVATION_OVERRIDE.with(std::cell::Cell::get) {
        return elevated;
    }
    process_is_elevated()
}

#[cfg(target_os = "linux")]
fn process_is_elevated() -> bool {
    unix_ids_are_elevated() || linux_aux_is_secure() || linux_process_has_capabilities()
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn process_is_elevated() -> bool {
    unix_ids_are_elevated()
}

#[cfg(unix)]
fn unix_ids_are_elevated() -> bool {
    #[cfg(all(test, target_os = "linux"))]
    if let Some((ids, _, _)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return ids;
    }
    unsafe {
        // SAFETY: these libc identity queries take no arguments, access no
        // caller-provided memory, and cannot fail.
        libc::geteuid() == 0
            || libc::geteuid() != libc::getuid()
            || libc::getegid() != libc::getgid()
    }
}

#[cfg(target_os = "linux")]
fn linux_aux_is_secure() -> bool {
    #[cfg(test)]
    if let Some((_, aux_secure, _)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return aux_secure;
    }
    unsafe {
        // SAFETY: getauxval reads the process's immutable auxiliary vector and
        // takes no pointer arguments. AT_SECURE is nonzero for secure-execution
        // modes such as set-ID or file-capability launches.
        libc::getauxval(libc::AT_SECURE) != 0
    }
}

#[cfg(target_os = "linux")]
fn linux_process_has_capabilities() -> bool {
    #[cfg(test)]
    if let Some((_, _, capabilities)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return capabilities;
    }

    // Docker enrichment is optional. If the privilege state cannot be proven
    // ordinary, fail closed and do not cross PATH with the process's authority.
    std::fs::File::open("/proc/self/status")
        .and_then(read_linux_status_bounded)
        .map_or(true, |status| {
            linux_status_has_capabilities(&status).unwrap_or(true)
        })
}

#[cfg(target_os = "linux")]
fn read_linux_status_bounded(mut reader: impl Read) -> io::Result<String> {
    let mut status = String::new();
    reader
        .by_ref()
        .take((LINUX_STATUS_READ_MAX_BYTES + 1) as u64)
        .read_to_string(&mut status)?;
    if status.len() > LINUX_STATUS_READ_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux process status exceeds the read limit",
        ));
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
fn linux_status_has_capabilities(status: &str) -> Option<bool> {
    let mut found = 0_u8;
    let mut any = false;
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !matches!(name, "CapPrm" | "CapEff" | "CapAmb") {
            continue;
        }
        found = found.saturating_add(1);
        any |= u64::from_str_radix(value.trim(), 16).ok()? != 0;
    }
    (found == 3).then_some(any)
}

#[cfg(windows)]
pub(crate) fn process_is_elevated() -> bool {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    let opened = unsafe {
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle, and `token`
        // points to storage for the returned owned token handle.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
    };
    if opened == 0 || token.is_null() {
        return true;
    }
    let token = unsafe {
        // SAFETY: OpenProcessToken returned a non-null handle owned by this
        // scope. OwnedHandle closes it exactly once.
        OwnedHandle::from_raw_handle(token)
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned_bytes = 0_u32;
    let expected_bytes =
        u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION size must fit in u32");
    let queried = unsafe {
        // SAFETY: the token has TOKEN_QUERY access, `elevation` is valid for a
        // TOKEN_ELEVATION write, and both byte counts match its exact size.
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            expected_bytes,
            &raw mut returned_bytes,
        )
    };
    queried == 0 || returned_bytes != expected_bytes || elevation.TokenIsElevated != 0
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

#[derive(Debug)]
struct WorkerCapacity {
    active: AtomicUsize,
    maximum: usize,
}

impl WorkerCapacity {
    const fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn reserve<const COUNT: usize>(self: &Arc<Self>) -> Option<[WorkerPermit; COUNT]> {
        assert!(
            COUNT > 0,
            "worker reservation must contain at least one slot"
        );
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            let reserved = active.checked_add(COUNT)?;
            if reserved > self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                reserved,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(std::array::from_fn(|_| WorkerPermit(Arc::clone(self)))),
                Err(current) => active = current,
            }
        }
    }
}

#[derive(Debug)]
struct WorkerPermit(Arc<WorkerCapacity>);

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "worker capacity reservation underflow");
    }
}

fn global_drain_capacity() -> Arc<WorkerCapacity> {
    static CAPACITY: OnceLock<Arc<WorkerCapacity>> = OnceLock::new();
    Arc::clone(
        CAPACITY.get_or_init(|| Arc::new(WorkerCapacity::new(DOCKER_OUTPUT_DRAIN_WORKERS_MAX))),
    )
}

struct ChildCleanup {
    child: mpsc::SyncSender<Child>,
    completed: mpsc::Receiver<()>,
}

impl ChildCleanup {
    fn handoff(self, child: Child) -> mpsc::Receiver<()> {
        self.child
            .try_send(child)
            .expect("new child cleanup channel must be empty and connected");
        self.completed
    }
}

fn global_child_cleanup_capacity() -> Arc<WorkerCapacity> {
    static CAPACITY: OnceLock<Arc<WorkerCapacity>> = OnceLock::new();
    Arc::clone(
        CAPACITY.get_or_init(|| Arc::new(WorkerCapacity::new(DOCKER_CHILD_CLEANUP_WORKERS_MAX))),
    )
}

fn spawn_child_cleanup(capacity: &Arc<WorkerCapacity>) -> io::Result<ChildCleanup> {
    let [permit] = capacity.reserve::<1>().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "docker child cleanup worker capacity exhausted",
        )
    })?;
    let (child_sender, child_receiver) = mpsc::sync_channel(1);
    let (completed_sender, completed_receiver) = mpsc::channel();
    thread::Builder::new()
        .name("kickoutchi-docker-child-cleanup".to_owned())
        .spawn(move || {
            let _permit = permit;
            let Ok(mut child) = child_receiver.recv() else {
                return;
            };
            if terminate_and_reap(&mut child) == ReapOutcome::OwnershipUncertain {
                // No later code may assume this child was reaped. Retain both
                // the handle and capacity slot without retrying or spinning.
                loop {
                    thread::park();
                }
            }
            let _ = completed_sender.send(());
        })?;
    Ok(ChildCleanup {
        child: child_sender,
        completed: completed_receiver,
    })
}

fn run_command_bounded(command: &mut Command) -> Option<std::process::Output> {
    run_command_bounded_with(command, DOCKER_COMMAND_TIMEOUT, DOCKER_OUTPUT_MAX_BYTES)
}

fn run_command_bounded_with(
    command: &mut Command,
    timeout: Duration,
    output_max_bytes: usize,
) -> Option<std::process::Output> {
    run_command_bounded_with_capacity(command, timeout, output_max_bytes, &global_drain_capacity())
}

fn run_command_bounded_with_capacity(
    command: &mut Command,
    timeout: Duration,
    output_max_bytes: usize,
    drain_capacity: &Arc<WorkerCapacity>,
) -> Option<std::process::Output> {
    let [stdout_permit, stderr_permit] = drain_capacity.reserve::<2>()?;
    let cleanup = match spawn_child_cleanup(&global_child_cleanup_capacity()) {
        Ok(cleanup) => cleanup,
        Err(error) => {
            debug!(%error, "docker CLI child cleanup worker unavailable");
            return None;
        }
    };
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            debug!(%error, "docker CLI unavailable for port enrichment");
            return None;
        }
    };

    let Some(stdout) = child.stdout.take() else {
        let _ = cleanup.handoff(child);
        debug!("docker CLI stdout pipe was unavailable");
        return None;
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = cleanup.handoff(child);
        debug!("docker CLI stderr pipe was unavailable");
        return None;
    };
    let stdout_worker = match spawn_output_drain(
        "kickoutchi-docker-stdout",
        stdout,
        output_max_bytes,
        stdout_permit,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = cleanup.handoff(child);
            debug!(%error, "docker CLI stdout drain worker failed to start");
            return None;
        }
    };
    let stderr_worker = match spawn_output_drain(
        "kickoutchi-docker-stderr",
        stderr,
        output_max_bytes,
        stderr_permit,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            // The stdout worker is detached by design; killing the child
            // closed its pipe, so the worker exits on its own.
            let _ = cleanup.handoff(child);
            debug!(%error, "docker CLI stderr drain worker failed to start");
            return None;
        }
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        let now = Instant::now();
        if now >= deadline {
            let _ = cleanup.handoff(child);
            let drain_deadline = Instant::now() + DOCKER_OUTPUT_DRAIN_TIMEOUT;
            let _ = finish_output_drain_before(&stdout_worker, "stdout", drain_deadline);
            let _ = finish_output_drain_before(&stderr_worker, "stderr", drain_deadline);
            debug!("docker CLI timed out during port enrichment");
            return None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                thread::sleep(
                    Duration::from_millis(10).min(deadline.saturating_duration_since(now)),
                );
            }
            Err(error) => {
                let _ = cleanup.handoff(child);
                let drain_deadline = Instant::now() + DOCKER_OUTPUT_DRAIN_TIMEOUT;
                let _ = finish_output_drain_before(&stdout_worker, "stdout", drain_deadline);
                let _ = finish_output_drain_before(&stderr_worker, "stderr", drain_deadline);
                debug!(%error, "docker CLI wait failed during port enrichment");
                return None;
            }
        }
    };

    let drain_deadline = Instant::now() + DOCKER_OUTPUT_DRAIN_TIMEOUT;
    let stdout = finish_output_drain_before(&stdout_worker, "stdout", drain_deadline)?;
    let stderr = finish_output_drain_before(&stderr_worker, "stderr", drain_deadline)?;
    if stdout.exceeded || stderr.exceeded {
        debug!(
            stdout_exceeded = stdout.exceeded,
            stderr_exceeded = stderr.exceeded,
            "docker CLI output exceeded enrichment cap",
        );
        return None;
    }
    Some(std::process::Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

/// Spawn a detached worker that drains one output pipe while the child runs.
///
/// The worker reports through a channel instead of a `JoinHandle` so the
/// parent can bound its wait: `read` on the pipe only returns once every
/// holder of the write end has closed it, and a grandchild that inherited the
/// fd can outlive the docker CLI itself, turning a `join` into an unbounded
/// hang. A worker that misses `DOCKER_OUTPUT_DRAIN_TIMEOUT` is abandoned and
/// exits on its own once the pipe finally closes; each enrichment attempt
/// remains charged against the global worker cap until its pipe closes.
fn spawn_output_drain<Reader>(
    name: &'static str,
    reader: Reader,
    output_max_bytes: usize,
    permit: WorkerPermit,
) -> io::Result<mpsc::Receiver<io::Result<BoundedOutput>>>
where
    Reader: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _permit = permit;
            // A failed send only means the parent gave up waiting; the result is
            // discarded either way, so there is nothing to handle.
            let _ = sender.send(read_output_bounded(reader, output_max_bytes));
        })?;
    Ok(receiver)
}

fn read_output_bounded(
    mut reader: impl Read,
    output_max_bytes: usize,
) -> io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(output_max_bytes);
    let mut chunk = [0_u8; DOCKER_OUTPUT_READ_CHUNK_BYTES];
    loop {
        let remaining = output_max_bytes.saturating_sub(bytes.len());
        let read_capacity = remaining.saturating_add(1).min(chunk.len());
        let count = reader.read(&mut chunk[..read_capacity])?;
        if count == 0 {
            break;
        }
        let retained = count.min(remaining);
        bytes.extend_from_slice(&chunk[..retained]);
        if retained < count {
            return Ok(BoundedOutput {
                bytes,
                exceeded: true,
            });
        }
    }
    Ok(BoundedOutput {
        bytes,
        exceeded: false,
    })
}

fn finish_output_drain_before(
    worker: &mpsc::Receiver<io::Result<BoundedOutput>>,
    stream: &'static str,
    deadline: Instant,
) -> Option<BoundedOutput> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match worker.recv_timeout(remaining) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(error)) => {
            debug!(%error, stream, "docker CLI output drain failed");
            None
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            debug!(
                stream,
                "docker CLI output drain timed out; abandoning the drain worker",
            );
            None
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            debug!(
                stream,
                "docker CLI output drain worker died before reporting"
            );
            None
        }
    }
}

trait ReapChild {
    fn process_id(&self) -> u32;
    fn terminate(&mut self) -> io::Result<()>;
    fn wait_for_exit(&mut self) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapOutcome {
    Reaped,
    OwnershipUncertain,
}

impl ReapChild for std::process::Child {
    fn process_id(&self) -> u32 {
        self.id()
    }

    fn terminate(&mut self) -> io::Result<()> {
        self.kill()
    }

    fn wait_for_exit(&mut self) -> io::Result<()> {
        self.wait().map(|_| ())
    }
}

fn terminate_and_reap(child: &mut impl ReapChild) -> ReapOutcome {
    if let Err(error) = child.terminate() {
        debug!(%error, pid = child.process_id(), "docker CLI cleanup termination failed");
    }
    match child.wait_for_exit() {
        Ok(()) => ReapOutcome::Reaped,
        Err(error) => {
            debug!(%error, pid = child.process_id(), "docker CLI cleanup wait failed; retaining ownership and capacity");
            ReapOutcome::OwnershipUncertain
        }
    }
}

fn docker_context_from_ps_output(
    entry: PortEntryView<'_>,
    output: &str,
) -> Option<DockerPortContext> {
    let mut containers = Vec::new();
    let mut truncated = false;

    'rows: for (row_index, line) in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if row_index >= DOCKER_ROWS_MAX {
            truncated = true;
            break;
        }

        let Some(row) = parse_container_row(line) else {
            continue;
        };
        for published_port in parse_published_ports(&row.ports) {
            let Some(container_port) = matched_container_port(entry, published_port) else {
                continue;
            };
            if contains_container_match(&containers, &row.id, entry, container_port) {
                continue;
            }
            if containers.len() >= DOCKER_MATCHES_MAX {
                truncated = true;
                break 'rows;
            }
            containers.push(DockerContainerPort {
                id: row.id.clone(),
                name: row.name.clone(),
                compose_project: row.compose_project.clone(),
                compose_service: row.compose_service.clone(),
                host_port: entry.local_port,
                container_port,
                protocol: entry.protocol,
            });
        }
    }

    if containers.is_empty() {
        None
    } else {
        Some(DockerPortContext {
            containers,
            truncated,
        })
    }
}

fn contains_container_match(
    containers: &[DockerContainerPort],
    container_id: &str,
    entry: PortEntryView<'_>,
    container_port: u16,
) -> bool {
    containers.iter().any(|container| {
        container.id == container_id
            && container.host_port == entry.local_port
            && container.container_port == container_port
            && container.protocol == entry.protocol
    })
}

fn should_try_docker_enrichment(entry: PortEntryView<'_>) -> bool {
    looks_like_docker_owner(entry)
        || (entry.permission == PermissionStatus::Partial && entry.process_name.is_none())
}

fn looks_like_docker_owner(entry: PortEntryView<'_>) -> bool {
    entry.process_name.is_some_and(is_docker_process_name)
        || entry
            .executable_path
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .is_some_and(is_docker_process_name)
}

fn is_docker_process_name(name: &str) -> bool {
    DOCKER_PROCESS_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn parse_container_row(line: &str) -> Option<DockerContainerRow> {
    if line.len() > DOCKER_FIELD_MAX_BYTES * 4 {
        return None;
    }

    let row: DockerPsJsonRow = serde_json::from_str(line).ok()?;
    if field_too_large(&row.id)
        || field_too_large(&row.names)
        || field_too_large(&row.ports)
        || field_too_large(&row.labels)
    {
        return None;
    }

    let id = trimmed_non_empty(&row.id)?;
    let name = first_container_name(&row.names).unwrap_or_else(|| id.clone());
    Some(DockerContainerRow {
        id,
        name,
        ports: row.ports,
        compose_project: label_value(&row.labels, "com.docker.compose.project"),
        compose_service: label_value(&row.labels, "com.docker.compose.service"),
    })
}

fn field_too_large(field: &str) -> bool {
    field.len() > DOCKER_FIELD_MAX_BYTES
}

fn trimmed_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn first_container_name(names: &str) -> Option<String> {
    names
        .split(',')
        .map(str::trim)
        .find(|name| !name.is_empty())
        .map(str::to_owned)
}

fn label_value(labels: &str, key: &str) -> Option<String> {
    labels.split(',').find_map(|label| {
        let (label_key, value) = label.split_once('=')?;
        if label_key.trim() == key && !value.is_empty() {
            Some(value.to_owned())
        } else {
            None
        }
    })
}

fn parse_published_ports(ports: &str) -> Vec<PublishedPort> {
    let mut segments = ports.split(',');
    let parsed = segments
        .by_ref()
        .take(DOCKER_PORT_SEGMENTS_MAX)
        .filter_map(|segment| parse_published_port_segment(segment.trim()))
        .collect::<Vec<_>>();
    if segments.next().is_some() {
        Vec::new()
    } else {
        parsed
    }
}

fn parse_published_port_segment(segment: &str) -> Option<PublishedPort> {
    let (host_binding, container_binding) = segment.split_once("->")?;
    let (container_ports, protocol) = parse_container_binding(container_binding.trim())?;
    let (host_addr, host_ports) = parse_host_binding(host_binding.trim())?;
    Some(PublishedPort {
        host_addr,
        host_ports,
        container_ports,
        protocol,
    })
}

fn parse_container_binding(binding: &str) -> Option<(PortRange, Protocol)> {
    let (ports, protocol) = binding.rsplit_once('/')?;
    Some((parse_port_range(ports.trim())?, parse_protocol(protocol)?))
}

fn parse_host_binding(binding: &str) -> Option<(Option<IpAddr>, PortRange)> {
    let (host, ports) = split_host_binding(binding)?;
    let host_addr = match host {
        Some(host) => Some(parse_host_addr(host)?),
        None => None,
    };
    Some((host_addr, parse_port_range(ports)?))
}

fn split_host_binding(binding: &str) -> Option<(Option<&str>, &str)> {
    if binding.is_empty() {
        return None;
    }
    if let Some(stripped) = binding.strip_prefix('[') {
        let (host, ports) = stripped.split_once("]:")?;
        return Some((Some(host), ports));
    }
    if let Some((host, ports)) = binding.rsplit_once(':') {
        if ports.is_empty() {
            return None;
        }
        return if host.is_empty() {
            Some((None, ports))
        } else {
            Some((Some(host), ports))
        };
    }
    Some((None, binding))
}

fn parse_host_addr(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse().ok()
}

fn parse_port_range(ports: &str) -> Option<PortRange> {
    let trimmed = ports.trim();
    let (start, end) = if let Some((start, end)) = trimmed.split_once('-') {
        (parse_port(start)?, parse_port(end)?)
    } else {
        let port = parse_port(trimmed)?;
        (port, port)
    };
    if start > end {
        return None;
    }
    Some(PortRange { start, end })
}

fn parse_port(port: &str) -> Option<u16> {
    port.trim()
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .map(NonZeroU16::get)
}

fn parse_protocol(protocol: &str) -> Option<Protocol> {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

fn matched_container_port(entry: PortEntryView<'_>, published_port: PublishedPort) -> Option<u16> {
    if entry.protocol != published_port.protocol {
        return None;
    }
    if !host_addr_matches(entry.local_addr, published_port.host_addr) {
        return None;
    }
    published_port
        .host_ports
        .mapped_port(published_port.container_ports, entry.local_port)
}

fn host_addr_matches(row_addr: IpAddr, docker_addr: Option<IpAddr>) -> bool {
    let Some(docker_addr) = docker_addr else {
        return true;
    };
    let row_addr = crate::labels::normalize_ip_address(row_addr);
    let docker_addr = crate::labels::normalize_ip_address(docker_addr);
    let same_family = matches!(
        (row_addr, docker_addr),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    );
    same_family
        && (row_addr == docker_addr || row_addr.is_unspecified() || docker_addr.is_unspecified())
}

fn protocol_filter(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

#[cfg(test)]
mod tests;
