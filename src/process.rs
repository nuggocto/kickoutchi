//! Termination policy and signal delivery.
//!
//! This module owns target snapshots, confirmation rules, PID guards, and the OS
//! calls that deliver signals. Unverified targets are refused.

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(windows)]
use std::os::windows::io::OwnedHandle;

use crate::display::{human_endpoint_text, sanitize};
use crate::model::{PermissionStatus, Platform, PortEntryView, ProcessContext, Protocol};
use crate::observation::{Ipv6Scope, ProcessIdentity, ProcessStartMarker};
use crate::process_evidence::{
    ExpectedProcessEvidence, FreshProcessEvidence, ProcessEvidenceError, ProcessEvidenceScope,
};
use crate::protection::{is_protected_process_name, windows_process_name_eq};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const UNIX_STOP_ACKNOWLEDGEMENT_MAX: std::time::Duration =
    std::time::Duration::from_millis(500);

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct StopFailure {
    outcome: TerminationOutcome,
    cleanup_required: bool,
    rollback_start_time_marker: Option<ProcessStartMarker>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixProcessState {
    marker: ProcessStartMarker,
    status: UnixProcessStatus,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixProcessStatus {
    Running,
    Stopped,
    Exited,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_deadline_failure(
    cleanup_required: bool,
    rollback_start_time_marker: Option<ProcessStartMarker>,
) -> StopFailure {
    StopFailure {
        outcome: TerminationOutcome::UnknownFailure(
            "process did not enter stopped state before the SIGSTOP acknowledgement deadline"
                .to_owned(),
        ),
        cleanup_required,
        rollback_start_time_marker,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_before_stop_deadline<T>(
    deadline: std::time::Instant,
    now: impl FnOnce() -> std::time::Instant,
    operation: impl FnOnce() -> T,
) -> Result<T, StopFailure> {
    if now() >= deadline {
        Err(stop_deadline_failure(false, None))
    } else {
        Ok(operation())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_stop_error(outcome: TerminationOutcome) -> crate::tree::TreeStopError {
    match outcome {
        TerminationOutcome::PermissionDenied => crate::tree::TreeStopError::PermissionDenied,
        TerminationOutcome::UnknownFailure(error) => {
            crate::tree::TreeStopError::ObservationFailed(error)
        }
        other => crate::tree::TreeStopError::ObservationFailed(format!(
            "stopped-state observation failed: {other:?}"
        )),
    }
}

pub(crate) const CONFIRMATION_INPUT_MAX_BYTES: usize = 128;

/// Suffix appended to permission-denied termination messages.
///
/// `EPERM`/`EACCES` from the pidfd syscalls usually means a lack of
/// permission to signal the target (same rule as `kill`), but a sandbox or
/// seccomp policy that blocks `pidfd_open`/`pidfd_send_signal` produces the same
/// errno. We can't tell the two apart at this layer, so the message names both.
const PERMISSION_DENIED_SANDBOX_HINT: &str =
    "a sandbox or seccomp policy blocking the pidfd syscalls can also cause this";

pub(crate) fn permission_denied_hint(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => PERMISSION_DENIED_SANDBOX_HINT,
        Platform::Windows => {
            "try an elevated terminal; protected or higher-integrity processes can also reject TerminateProcess"
        }
        Platform::Macos => "try again with sufficient privileges",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillMode {
    Terminate,
    Force,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const fn unix_signal(mode: KillMode) -> libc::c_int {
    match mode {
        KillMode::Terminate => libc::SIGTERM,
        KillMode::Force => libc::SIGKILL,
    }
}

impl KillMode {
    pub(crate) fn action_label(self) -> &'static str {
        match self {
            Self::Terminate => "Terminate",
            Self::Force => "Force-kill",
        }
    }

    fn signal_label(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::Force => "SIGKILL",
        }
    }

    pub(crate) fn delivery_label(self, platform: Platform) -> &'static str {
        match platform {
            Platform::Linux | Platform::Macos => self.signal_label(),
            Platform::Windows => "TerminateProcess",
        }
    }

    pub(crate) fn force_warning(self, platform: Platform) -> Option<&'static str> {
        match (platform, self) {
            (Platform::Linux | Platform::Macos, Self::Force) => {
                Some("SIGKILL is immediate; prefer normal termination first.")
            }
            (Platform::Windows, Self::Terminate) => Some(
                "Windows termination uses TerminateProcess, which is immediate; close the app normally first when possible.",
            ),
            (Platform::Windows, Self::Force) => Some(
                "TerminateProcess is immediate; use force only when normal termination did not work.",
            ),
            (Platform::Linux | Platform::Macos, Self::Terminate) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmationRequirement {
    Yes,
    ForceWord,
    ProtectedProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsafePidReason {
    Zero,
    One,
    #[cfg(windows)]
    WindowsSystem,
    CurrentProcess,
}

impl UnsafePidReason {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Zero => "PID 0 is a process-group target, not one process",
            Self::One => "PID 1 is the init/system process",
            #[cfg(windows)]
            Self::WindowsSystem => "PID 4 is the Windows System process",
            Self::CurrentProcess => "Kickoutchi cannot terminate itself",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TerminationOutcome {
    Success,
    PermissionDenied,
    OwnershipUnavailable,
    AlreadyExited,
    Cancelled,
    ProtectedProcess,
    TargetChanged,
    UnsafePid(UnsafePidReason),
    UnknownFailure(String),
    #[cfg_attr(
        windows,
        allow(
            dead_code,
            reason = "Windows termination does not stop processes before delivery"
        )
    )]
    ThawFailed {
        pid: u32,
        prior: Box<TerminationOutcome>,
    },
}

impl TerminationOutcome {
    /// Stable, interface-neutral wording for one direct termination outcome.
    ///
    /// CLI and TUI callers may add interface-specific recovery guidance, but
    /// the underlying event is described here so they use the same wording.
    pub(crate) fn status_description(&self, target: &KillTarget, mode: KillMode) -> String {
        let delivery = mode.delivery_label(target.platform);
        match self {
            Self::Success => format!("sent {delivery} to {}", target.identity()),
            Self::PermissionDenied => {
                format!(
                    "permission denied sending {delivery} to {}",
                    target.identity()
                )
            }
            Self::OwnershipUnavailable => format!(
                "ownership for {} became unavailable before {delivery}; no termination was sent",
                target.identity(),
            ),
            Self::AlreadyExited => {
                format!(
                    "{} already exited before termination was sent",
                    target.identity()
                )
            }
            Self::Cancelled => "kill cancelled".to_owned(),
            Self::ProtectedProcess => format!("{} is protected", target.identity()),
            Self::TargetChanged => format!(
                "{} no longer owns the confirmed port target; no termination was sent",
                target.identity(),
            ),
            Self::UnsafePid(reason) => format!("unsafe PID blocked: {}", reason.message()),
            Self::UnknownFailure(error) => format!(
                "sending {delivery} to {} failed: {}",
                target.identity(),
                sanitize(error),
            ),
            Self::ThawFailed { pid, prior } => format!(
                "{}; cleanup could not continue PID {pid}; it may remain stopped and require SIGCONT",
                sanitize(&prior.failure_cause_text()),
            ),
        }
    }

    pub(crate) fn failure_cause_text(&self) -> String {
        match self {
            Self::Success => "the termination signal was accepted".to_owned(),
            Self::PermissionDenied => {
                "permission denied delivering the termination signal".to_owned()
            }
            Self::OwnershipUnavailable => "process ownership became unavailable".to_owned(),
            Self::AlreadyExited => "the process already exited".to_owned(),
            Self::Cancelled => "termination was cancelled".to_owned(),
            Self::ProtectedProcess => "the process became protected".to_owned(),
            Self::TargetChanged => "the confirmed process identity changed".to_owned(),
            Self::UnsafePid(reason) => format!("unsafe PID: {}", reason.message()),
            Self::UnknownFailure(error) => error.clone(),
            Self::ThawFailed { pid, prior } => format!(
                "{}; cleanup could not continue PID {pid}",
                prior.failure_cause_text()
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TerminationHandle {
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    #[cfg(windows)]
    process_handle: OwnedHandle,
    #[cfg(target_os = "macos")]
    process_start_time_marker: ProcessStartMarker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KillTarget {
    pub(crate) pid: u32,
    pub(crate) process_name: Option<String>,
    pub(crate) platform: Platform,
    pub(crate) permission: PermissionStatus,
    pub(crate) protected: bool,
    pub(crate) system_process: bool,
    pub(crate) ports: Vec<KillTargetPort>,
    pub(crate) owner_uid: Option<u32>,
    pub(crate) process_start_time_marker: Option<ProcessStartMarker>,
    pub(crate) child_count: usize,
    pub(crate) children_truncated: bool,
}

impl KillTarget {
    pub(crate) fn from_entries<'a>(
        pid: u32,
        entries: impl IntoIterator<Item = PortEntryView<'a>>,
        context: Option<&ProcessContext>,
    ) -> Self {
        let mut process_name = None;
        let mut platform = Platform::Linux;
        let mut permission = PermissionStatus::Full;
        let mut protected = false;
        let mut system_process = false;
        let mut ports = Vec::new();
        let mut process_identity: Option<ProcessIdentity> = None;
        let mut identity_consistent = true;
        let mut saw_entry = false;

        for entry in entries {
            saw_entry = true;
            assert_eq!(
                entry.pid,
                Some(pid),
                "kill target row PID must match target PID",
            );
            if process_name.is_none() {
                process_name = entry.process_name.map(str::to_owned);
            }
            platform = entry.platform;
            if entry.permission == PermissionStatus::Partial {
                permission = PermissionStatus::Partial;
            }
            protected |= entry.protected;
            system_process |= entry.is_system_process();
            if let Some(identity) = entry.process_identity {
                identity_consistent &= identity.pid == pid
                    && process_identity.is_none_or(|existing| existing == identity);
                process_identity.get_or_insert(identity);
            } else {
                identity_consistent = false;
            }
            ports.push(KillTargetPort::from(entry));
        }
        // Port rows define the target used by confirmation and revalidation.
        // An empty set is a programmer error, so the invariant is enforced in
        // release builds as well.
        assert!(saw_entry, "kill target must contain at least one row");

        ports.sort_unstable();
        ports.dedup();

        let child_snapshot = context.map(|context| &context.children);
        Self {
            pid,
            process_name,
            platform,
            permission,
            protected,
            system_process,
            ports,
            owner_uid: context.and_then(|context| context.owner_uid),
            process_start_time_marker: identity_consistent
                .then_some(process_identity)
                .flatten()
                .map(|identity| identity.start_marker),
            child_count: child_snapshot.map_or(0, |snapshot| snapshot.children.len()),
            children_truncated: child_snapshot.is_some_and(|snapshot| snapshot.truncated),
        }
    }

    pub(crate) fn identity(&self) -> String {
        format!(
            "PID {} ({})",
            self.pid,
            sanitize(self.process_name.as_deref().unwrap_or("<unknown>"))
        )
    }

    pub(crate) fn process_name_or_unknown(&self) -> &str {
        self.process_name.as_deref().unwrap_or("<unknown>")
    }

    pub(crate) fn ports_text(&self) -> String {
        if self.ports.is_empty() {
            return "no visible open ports".to_owned();
        }
        self.ports
            .iter()
            .map(KillTargetPort::label)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn has_children(&self) -> bool {
        self.child_count > 0 || self.children_truncated
    }

    /// The typed warnings attached to this target. Policy gates (for example
    /// the `--yes` all-clear check) and display surfaces both consume these
    /// variants, so policy never depends on rendered prose.
    pub(crate) fn warnings(&self) -> Vec<KillWarning> {
        let mut warnings = Vec::new();

        if self.protected {
            warnings.push(KillWarning::Protected);
        }

        if self.system_process {
            warnings.push(KillWarning::SystemProcess);
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let owner_mismatch = self.owner_uid.and_then(|owner_uid| {
            let current_uid = current_user_id();
            (owner_uid != current_uid).then_some(KillWarning::OwnerMismatch {
                owner_uid,
                current_uid,
            })
        });
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let owner_mismatch: Option<KillWarning> = None;

        let owner_mismatch_reported = owner_mismatch.is_some();
        if let Some(warning) = owner_mismatch {
            warnings.push(warning);
        }

        if !owner_mismatch_reported && self.permission == PermissionStatus::Partial {
            warnings.push(KillWarning::PartialMetadata);
        }

        if self.has_children() {
            warnings.push(KillWarning::HasChildren {
                child_count: self.child_count,
                children_truncated: self.children_truncated,
            });
        }

        warnings
    }
}

/// One warning attached to a kill target, typed so policy can match on the
/// kind instead of on banner prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KillWarning {
    Protected,
    SystemProcess,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    OwnerMismatch {
        owner_uid: u32,
        current_uid: u32,
    },
    PartialMetadata,
    HasChildren {
        child_count: usize,
        children_truncated: bool,
    },
}

/// The termination scope in which a target warning is presented.
///
/// Keeping this typed through the presentation boundary prevents tree and group
/// renderers from having to recognize and rewrite single-process prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WarningScope {
    Process,
    Tree,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Group,
}

impl KillWarning {
    pub(crate) fn text(&self, scope: WarningScope) -> String {
        match self {
            Self::Protected => "protected process; stronger confirmation is required".to_owned(),
            Self::SystemProcess => {
                "system/service process; verify this is safe to terminate".to_owned()
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::OwnerMismatch {
                owner_uid,
                current_uid,
            } => format!(
                "target is owned by uid {owner_uid}, current effective uid is {current_uid}",
            ),
            Self::PartialMetadata => {
                "process metadata is partial; termination may fail with permission denied"
                    .to_owned()
            }
            Self::HasChildren {
                child_count,
                children_truncated,
            } => {
                let suffix = if *children_truncated { " or more" } else { "" };
                let scope_clause = match scope {
                    WarningScope::Process => "termination targets only the confirmed PID",
                    WarningScope::Tree => {
                        "tree kill targets the bounded descendant tree shown above"
                    }
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    WarningScope::Group => "group kill targets every group member shown above",
                };
                format!("target has {child_count}{suffix} direct child process(es); {scope_clause}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KillTargetPort {
    pub(crate) protocol: Protocol,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) ipv6_scope: Option<Ipv6Scope>,
}

impl Ord for KillTargetPort {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.local_port,
            self.protocol,
            self.local_addr,
            self.ipv6_scope,
        )
            .cmp(&(
                other.local_port,
                other.protocol,
                other.local_addr,
                other.ipv6_scope,
            ))
    }
}

impl PartialOrd for KillTargetPort {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl KillTargetPort {
    fn label(&self) -> String {
        format!(
            "{} {}",
            self.protocol.label(),
            human_endpoint_text(self.local_addr, self.local_port, self.ipv6_scope),
        )
    }
}

pub(crate) fn kill_target_has_port(ports: &[KillTargetPort], port: &KillTargetPort) -> bool {
    ports.binary_search(port).is_ok()
}

impl From<PortEntryView<'_>> for KillTargetPort {
    fn from(entry: PortEntryView<'_>) -> Self {
        Self {
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
            ipv6_scope: entry.ipv6_scope,
        }
    }
}

pub(crate) fn confirmation_requirement(
    protected: bool,
    mode: KillMode,
    yes: bool,
    confirm_force_kill: bool,
) -> Result<Option<ConfirmationRequirement>, TerminationOutcome> {
    if protected {
        if yes {
            return Err(TerminationOutcome::ProtectedProcess);
        }
        return Ok(Some(ConfirmationRequirement::ProtectedProcess));
    }

    if yes {
        return Ok(None);
    }

    if mode == KillMode::Force && confirm_force_kill {
        Ok(Some(ConfirmationRequirement::ForceWord))
    } else {
        Ok(Some(ConfirmationRequirement::Yes))
    }
}

pub(crate) fn confirmation_input_matches(
    input: &str,
    target: &KillTarget,
    requirement: ConfirmationRequirement,
) -> bool {
    let trimmed = input.trim();
    match requirement {
        ConfirmationRequirement::Yes => {
            trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
        }
        ConfirmationRequirement::ForceWord => trimmed.eq_ignore_ascii_case("force"),
        ConfirmationRequirement::ProtectedProcess => {
            trimmed == target.pid.to_string()
                || target
                    .process_name
                    .as_deref()
                    .is_some_and(|name| match target.platform {
                        Platform::Windows => windows_process_name_eq(trimmed, &sanitize(name)),
                        Platform::Linux | Platform::Macos => trimmed == sanitize(name),
                    })
        }
    }
}

pub(crate) fn target_still_matches_confirmation(
    confirmed: &KillTarget,
    fresh: &KillTarget,
) -> bool {
    if confirmed.pid != fresh.pid {
        return false;
    }
    if let Some(confirmed_name) = &confirmed.process_name {
        let Some(fresh_name) = &fresh.process_name else {
            return false;
        };
        if confirmed_name != fresh_name {
            return false;
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        match (
            confirmed.process_start_time_marker,
            fresh.process_start_time_marker,
        ) {
            (Some(confirmed_start), Some(fresh_start)) if confirmed_start == fresh_start => {}
            _ => return false,
        }
    }

    confirmed
        .ports
        .iter()
        .all(|confirmed_port| kill_target_has_port(&fresh.ports, confirmed_port))
}

/// True when a confirmed target port is still visible but its owning PID is no
/// longer readable.
///
/// The CLI and TUI treat this as ownership loss and refuse to signal. The
/// confirmed port still exists, but its current owner is unknown.
pub(crate) fn confirmed_port_owner_unavailable(
    confirmed: &KillTarget,
    fresh_entries: &[PortEntryView<'_>],
) -> bool {
    fresh_entries.iter().any(|entry| {
        entry.pid.is_none() && kill_target_has_port(&confirmed.ports, &KillTargetPort::from(*entry))
    })
}

pub(crate) fn revalidate_confirmed_target(
    confirmed: &KillTarget,
    fresh_entries: &[PortEntryView<'_>],
    fresh_context: Option<&ProcessContext>,
) -> Result<KillTarget, TerminationOutcome> {
    if confirmed_port_owner_unavailable(confirmed, fresh_entries) {
        return Err(TerminationOutcome::OwnershipUnavailable);
    }

    let rows = fresh_entries
        .iter()
        .copied()
        .filter(|entry| entry.pid == Some(confirmed.pid))
        .filter(|entry| kill_target_has_port(&confirmed.ports, &KillTargetPort::from(*entry)))
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Err(TerminationOutcome::TargetChanged);
    }

    let fresh = KillTarget::from_entries(confirmed.pid, rows, fresh_context);
    if !target_still_matches_confirmation(confirmed, &fresh) {
        return Err(TerminationOutcome::TargetChanged);
    }
    if fresh.protected && !confirmed.protected {
        return Err(TerminationOutcome::ProtectedProcess);
    }
    Ok(fresh)
}

pub(crate) fn validate_single_delivery_evidence(
    confirmed: &KillTarget,
    fresh: &KillTarget,
) -> Result<(), TerminationOutcome> {
    let expected_marker = confirmed
        .process_start_time_marker
        .ok_or(TerminationOutcome::TargetChanged)?;
    let fresh_marker = fresh
        .process_start_time_marker
        .ok_or(TerminationOutcome::TargetChanged)?;
    let fresh_name = fresh.process_name.clone().ok_or_else(|| {
        TerminationOutcome::UnknownFailure(
            "fresh process name evidence is missing; refusing termination".to_owned(),
        )
    })?;
    let expected = ExpectedProcessEvidence {
        pid: confirmed.pid,
        start_marker: expected_marker,
        name: confirmed.process_name.as_deref(),
    };
    let mut scope = ProcessEvidenceScope::new(1).map_err(single_evidence_outcome)?;
    scope
        .observe(
            &expected,
            Ok(FreshProcessEvidence {
                pid: fresh.pid,
                start_marker: fresh_marker,
                name: fresh_name,
            }),
        )
        .map_err(single_evidence_outcome)?;
    scope.finish().map_err(single_evidence_outcome)
}

fn single_evidence_outcome(error: ProcessEvidenceError) -> TerminationOutcome {
    match error {
        ProcessEvidenceError::PermissionDenied { .. } => TerminationOutcome::PermissionDenied,
        ProcessEvidenceError::IdentityChanged { .. } | ProcessEvidenceError::NameChanged { .. } => {
            TerminationOutcome::UnknownFailure(
                "fresh process identity or protection name changed; refusing termination"
                    .to_owned(),
            )
        }
        ProcessEvidenceError::Missing { .. }
        | ProcessEvidenceError::NameMissing { .. }
        | ProcessEvidenceError::NameOversized { .. }
        | ProcessEvidenceError::IncompleteScope { .. }
        | ProcessEvidenceError::MemberLimitExceeded { .. }
        | ProcessEvidenceError::ByteLimitExceeded { .. } => TerminationOutcome::UnknownFailure(
            "fresh bounded process identity/name evidence is incomplete; refusing termination"
                .to_owned(),
        ),
    }
}

pub(crate) fn unsafe_pid_reason(pid: u32) -> Option<UnsafePidReason> {
    // Three PIDs are never signalled: 0 addresses a process group rather than
    // one process, 1 is the system init process, and our own PID would terminate
    // Kickoutchi itself. An ordinary parent PID is not categorically unsafe.
    // Higher-level resolution must still establish a valid port-owning or scoped
    // target before signal delivery.
    if pid == 0 {
        return Some(UnsafePidReason::Zero);
    }
    if pid == 1 {
        return Some(UnsafePidReason::One);
    }
    #[cfg(windows)]
    if pid == 4 {
        return Some(UnsafePidReason::WindowsSystem);
    }
    if pid == std::process::id() {
        return Some(UnsafePidReason::CurrentProcess);
    }
    None
}

pub(crate) fn prepare_termination(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    if let Some(reason) = unsafe_pid_reason(pid) {
        return Err(TerminationOutcome::UnsafePid(reason));
    }

    prepare_termination_platform(pid)
}

pub(crate) fn terminate_handle_checked(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    debug_assert_eq!(handle.pid, target.pid);
    terminate_handle_checked_platform(handle, target, protected_names, mode)
}

fn check_final_evidence(
    target: &KillTarget,
    protected_names: &[String],
    fresh: Result<FreshProcessEvidence, ProcessEvidenceError>,
) -> Result<(), TerminationOutcome> {
    let expected = ExpectedProcessEvidence {
        pid: target.pid,
        start_marker: target
            .process_start_time_marker
            .ok_or(TerminationOutcome::TargetChanged)?,
        name: target.process_name.as_deref(),
    };
    let mut scope = ProcessEvidenceScope::new(1).map_err(single_evidence_outcome)?;
    let fresh = scope
        .observe(&expected, fresh)
        .map_err(single_evidence_outcome)?;
    scope.finish().map_err(single_evidence_outcome)?;
    if is_protected_process_name(target.platform, &fresh.name, protected_names) && !target.protected
    {
        return Err(TerminationOutcome::ProtectedProcess);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn outcome_after_thaw(
    pid: u32,
    prior: TerminationOutcome,
    thaw: crate::tree::TreeSignalResult,
) -> TerminationOutcome {
    if thaw == crate::tree::TreeSignalResult::Denied {
        TerminationOutcome::ThawFailed {
            pid,
            prior: Box::new(prior),
        }
    } else {
        prior
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn refuse_stopped_termination<Continue>(
    pid: u32,
    transitioned: bool,
    rollback_marker: Option<ProcessStartMarker>,
    outcome: TerminationOutcome,
    continue_process: Continue,
) -> TerminationOutcome
where
    Continue: FnOnce(u32, Option<ProcessStartMarker>) -> crate::tree::TreeSignalResult,
{
    if transitioned {
        outcome_after_thaw(pid, outcome, continue_process(pid, rollback_marker))
    } else {
        outcome
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finish_stopped_termination<Terminate, Continue>(
    pid: u32,
    mode: KillMode,
    transitioned: bool,
    rollback_marker: Option<ProcessStartMarker>,
    terminate: Terminate,
    continue_process: Continue,
) -> TerminationOutcome
where
    Terminate: FnOnce(KillMode) -> TerminationOutcome,
    Continue: FnOnce(u32, Option<ProcessStartMarker>) -> crate::tree::TreeSignalResult,
{
    let outcome = terminate(mode);
    let successful_terminate =
        mode == KillMode::Terminate && outcome == TerminationOutcome::Success;
    let cleanup_after_failure = transitioned && outcome != TerminationOutcome::Success;
    if successful_terminate || cleanup_after_failure {
        outcome_after_thaw(pid, outcome, continue_process(pid, rollback_marker))
    } else {
        outcome
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct TreeDeliveryHandle {
    pid: u32,
    pidfd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl TreeDeliveryHandle {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn current_user_id() -> u32 {
    // SAFETY: geteuid takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
mod macos;

#[cfg(all(test, target_os = "macos"))]
use macos::{finish_macos_stopped_process, macos_status_is_exited};
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use macos::{macos_cont_if_matches_with, macos_stop_observation_result};
#[cfg(target_os = "macos")]
use macos::{prepare_termination_platform, terminate_handle_checked_platform};
#[cfg(target_os = "macos")]
pub(crate) use macos::{tree_deliver_by_pid, tree_prepare_delivery_probe, tree_stop};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod cancellation;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(all(test, target_os = "linux"))]
use linux::{linux_process_state, linux_stop_observation_result, parse_linux_process_state};
#[cfg(target_os = "linux")]
use linux::{prepare_termination_platform, terminate_handle_checked_platform};
#[cfg(target_os = "linux")]
pub(crate) use linux::{
    tree_cont_handle, tree_deliver_handle, tree_open_delivery_handle, tree_stop_handle,
};

/// Send `SIGCONT` to a PID. Used to resume a process after its terminating
/// signal and to thaw the tree on any abort. `NotFound` means the process
/// already exited and nothing is left stopped; callers report only `Denied` as
/// a cleanup failure.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn tree_cont(pid: u32) -> crate::tree::TreeSignalResult {
    tree_send_signal(pid, libc::SIGCONT)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_send_signal(pid: u32, signal: libc::c_int) -> crate::tree::TreeSignalResult {
    use crate::tree::TreeSignalResult;

    if unsafe_pid_reason(pid).is_some() {
        return TreeSignalResult::Denied;
    }
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return TreeSignalResult::NotFound;
    };
    // SAFETY: kill(2) takes a pid and a fixed signal constant by value and writes
    // no Rust-managed memory. Every tree member is stopped and identity-verified
    // before it is targeted. Terminating signals also re-check the
    // verified start marker just before this call (see MacosTreeOps).
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        return TreeSignalResult::Delivered;
    }
    let error = std::io::Error::last_os_error();
    tree_signal_result_from_errno(&error)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_signal_result_from_errno(error: &std::io::Error) -> crate::tree::TreeSignalResult {
    use crate::tree::TreeSignalResult;

    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TreeSignalResult::NotFound,
        // EPERM is a real permission failure; anything else is treated as a
        // refusal too, so an unexpected errno fails closed rather than pretending
        // the signal landed.
        _ => TreeSignalResult::Denied,
    }
}

#[cfg(target_os = "linux")]
fn outcome_from_errno(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TerminationOutcome::AlreadyExited,
        // EACCES isn't documented for pidfd_open/pidfd_send_signal (they report
        // EPERM), but map any permission-shaped errno to denial defensively.
        Some(code) if code == libc::EPERM || code == libc::EACCES => {
            TerminationOutcome::PermissionDenied
        }
        // pidfd_open landed in Linux 5.3 and pidfd_send_signal in 5.1, so an
        // older kernel reports ENOSYS for the missing syscall. Name the floor so
        // the message is actionable rather than just "unsupported".
        Some(code) if code == libc::ENOSYS => TerminationOutcome::UnknownFailure(format!(
            "process termination requires Linux 5.3+ (pidfd); {operation} is unavailable on this kernel and no signal was sent",
        )),
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

#[cfg(windows)]
mod windows;

#[cfg(all(test, windows))]
use windows::{native_utf16_prefix, windows_api_outcome};
#[cfg(windows)]
use windows::{prepare_termination_platform, terminate_handle_checked_platform};

#[cfg(test)]
mod tests;
