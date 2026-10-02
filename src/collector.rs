//! Collector contracts and deterministic test data.
//!
//! Platform collectors implement one interface consumed by the CLI and TUI.

#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(test, target_os = "linux"))]
use std::path::PathBuf;
use std::time::SystemTime;

use thiserror::Error;

use crate::model::{PortEntry, Protocol};
#[cfg(test)]
use crate::observation::{
    EndpointIdentity, EvidenceGap, Ipv6Scope, MetadataCompleteness, ProcessIdentity,
    ProcessObservation, ProcessStartMarker, SocketObservation,
};
use crate::observation::{
    EvidenceGapCode, EvidenceImpact, MetadataProfile, NativeObservationPass, NetworkSnapshot,
    ObservationError, ObservationScope, ObservationSource, OwnerCompleteness, ProcessReadBatch,
    SnapshotCompleteness, SocketState as ObservationSocketState, collect_consistent,
    project_legacy, project_legacy_target,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::observation::{ProcessRead, process_read_metadata_bytes};

/// What went wrong during a collection pass.
#[derive(Debug, Error)]
pub(crate) enum CollectorError {
    /// A required path could not be read. Optional per-process metadata failures
    /// produce partial rows instead.
    #[cfg(target_os = "linux")]
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A platform API failed without a filesystem path to name.
    #[cfg(any(target_os = "macos", windows))]
    #[error("{operation} failed: {detail}")]
    Platform {
        operation: &'static str,
        detail: String,
    },
    /// A background TUI refresh worker disappeared before sending its result.
    #[error("refresh worker exited before returning a snapshot")]
    WorkerExited,
    #[error(transparent)]
    Observation(#[from] ObservationError),
    #[error("permission denied while verifying complete endpoint ownership")]
    OwnershipPermissionDenied,
}

/// Source of open-port snapshots.
///
/// Each call returns a complete snapshot. The application refreshes at
/// second-scale intervals and does not consume incremental updates.
pub(crate) trait Collector {
    /// Collect one bounded, consistency-checked observation.
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError>;
}

/// Collect the authoritative snapshot for the selected metadata profile.
pub(crate) fn collect_snapshot(
    profile: MetadataProfile,
) -> Result<NetworkSnapshot, CollectorError> {
    #[cfg(target_os = "linux")]
    {
        <crate::platform::linux::LinuxCollector as Collector>::collect(
            &crate::platform::linux::LinuxCollector::new(),
            profile,
        )
    }

    #[cfg(windows)]
    {
        <crate::platform::windows::WindowsCollector as Collector>::collect(
            &crate::platform::windows::WindowsCollector,
            profile,
        )
    }

    #[cfg(target_os = "macos")]
    {
        <crate::platform::macos::MacosCollector as Collector>::collect(
            &crate::platform::macos::MacosCollector,
            profile,
        )
    }
}

/// Collect one snapshot and return owned legacy rows that outlive it.
///
/// Kill seams return after dropping the snapshot. Callers that retain their
/// snapshot should borrow `PortEntryView` instead.
pub(crate) fn collect_ports_with_profile(
    profile: MetadataProfile,
) -> Result<Vec<PortEntry>, CollectorError> {
    let snapshot = collect_snapshot(profile)?;
    project_legacy(&snapshot).map_err(CollectorError::from)
}

pub(crate) fn collect_kill_ports(
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, CollectorError> {
    let snapshot = collect_snapshot(MetadataProfile::Display)?;
    kill_ports_from_snapshot(&snapshot, pid, port)
}

/// Project the rows a destructive command is allowed to act on, or refuse.
///
/// This fail-closed gate evaluates signalling authority before returning rows.
/// It combines matched-socket evidence with snapshot gaps before selecting the
/// refusal, so an early return cannot omit a reason.
pub(crate) fn kill_ports_from_snapshot(
    snapshot: &NetworkSnapshot,
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, CollectorError> {
    let target_mode = match (pid, port) {
        (Some(pid), None) => DestructiveTargetMode::Pid(pid),
        (None, Some(port)) => DestructiveTargetMode::Port(port),
        _ => return Err(ObservationError::NativeDataMalformed.into()),
    };

    // An omitted gap is evidence we never got to inspect, so it is partial
    // before any socket is examined. Races stay distinct because a raced
    // observation cannot support a permission diagnosis from the same read.
    let mut authority = Authority::Complete;
    if snapshot.omitted_evidence_gap_count != 0 {
        authority.merge(Authority::Partial);
    }
    if snapshot.completeness == SnapshotCompleteness::Raced {
        authority.merge(Authority::Raced);
    }

    let mut matched_endpoints = std::collections::BTreeSet::new();
    for socket in &snapshot.sockets {
        let Some(target_match) = destructive_socket_match(socket, target_mode) else {
            continue;
        };
        matched_endpoints.insert(socket.local_endpoint.clone());
        authority.merge(socket_authority(socket, target_mode, target_match));
    }

    for gap in &snapshot.evidence_gaps {
        // A raced observation invalidates the whole snapshot regardless of
        // which endpoint or PID the gap names.
        if gap.code == EvidenceGapCode::ObservationRaced {
            authority.merge(Authority::Raced);
        }
        if !gap_applies_to_target(gap, target_mode, &matched_endpoints) {
            continue;
        }
        authority.merge(if gap.code == EvidenceGapCode::OwnerPermissionDenied {
            Authority::PermissionDenied
        } else {
            Authority::Partial
        });
    }

    match authority {
        // A race outranks all observations made inside that unstable read.
        // Reporting permission denial would claim a stable cause we did not prove.
        Authority::Raced => return Err(ObservationError::ObservationRaced.into()),
        // Permission denial outranks non-raced partiality because it is the more
        // specific refusal and maps to a distinct exit code.
        Authority::PermissionDenied => return Err(CollectorError::OwnershipPermissionDenied),
        Authority::Partial => return Err(ObservationError::PartialSocketSet.into()),
        Authority::Complete => {}
    }
    project_legacy_target(snapshot, pid, port).map_err(CollectorError::from)
}

/// Strongest reason a destructive command may not act on a snapshot.
///
/// Variant order is the refusal priority `merge` relies on: a race outranks a
/// permission denial, which outranks plain partiality. Do not reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Authority {
    Complete,
    Partial,
    PermissionDenied,
    Raced,
}

impl Authority {
    fn merge(&mut self, other: Self) {
        *self = (*self).max(other);
    }
}

/// How a candidate socket matched the destructive target, if it matched.
#[derive(Debug, Clone, Copy)]
struct DestructiveSocketMatch {
    /// The reason the target PID's owner edge could not be verified, when the
    /// socket matched through an unverified owner rather than a verified one.
    unverified_target_reason: Option<crate::observation::UnverifiedOwnerReason>,
}

/// Match one socket against the destructive target.
///
/// Only listening TCP and bound UDP sockets carry destructive authority; a
/// snapshot's established and transitional connections are real observations
/// but are not something a kill can target.
fn destructive_socket_match(
    socket: &crate::observation::SocketObservation,
    target_mode: DestructiveTargetMode,
) -> Option<DestructiveSocketMatch> {
    if !matches!(
        (socket.local_endpoint.protocol, socket.state),
        (Protocol::Tcp, ObservationSocketState::Listen)
            | (Protocol::Udp, ObservationSocketState::Bound)
    ) {
        return None;
    }
    match target_mode {
        DestructiveTargetMode::Port(target_port) => {
            (socket.local_endpoint.port.get() == target_port).then_some(DestructiveSocketMatch {
                unverified_target_reason: None,
            })
        }
        DestructiveTargetMode::Pid(target_pid) => {
            let verified = socket.owners.iter().any(|owner| {
                matches!(
                    owner,
                    crate::observation::OwnerObservation::Verified(identity)
                        if identity.pid == target_pid
                )
            });
            let unverified_target_reason = socket.owners.iter().find_map(|owner| match owner {
                crate::observation::OwnerObservation::UnverifiedPid {
                    pid: owner_pid,
                    reason,
                } if *owner_pid == target_pid => Some(*reason),
                _ => None,
            });
            (verified || unverified_target_reason.is_some()).then_some(DestructiveSocketMatch {
                unverified_target_reason,
            })
        }
    }
}

/// The authority one matched socket contributes.
///
/// Port targets are held to a stricter rule than PID targets: a PID target has
/// already been resolved to one verified identity, but a port target must prove
/// that every potential holder is accounted for. Otherwise the signal may
/// leave an unobserved co-holder keeping the port open.
fn socket_authority(
    socket: &crate::observation::SocketObservation,
    target_mode: DestructiveTargetMode,
    target_match: DestructiveSocketMatch,
) -> Authority {
    let socket_local_permission_gap = matches!(
        &socket.owner_completeness,
        OwnerCompleteness::Partial { reasons }
            if reasons.contains(&EvidenceGapCode::OwnerPermissionDenied)
    );
    let target_owner_permission_denied = target_match.unverified_target_reason
        == Some(crate::observation::UnverifiedOwnerReason::PermissionDenied);

    let mut authority = Authority::Complete;
    if target_match.unverified_target_reason.is_some() || !socket.owner_completeness.is_complete() {
        authority.merge(Authority::Partial);
    }
    if socket_local_permission_gap || target_owner_permission_denied {
        authority.merge(Authority::PermissionDenied);
    }
    if socket.owner_completeness == OwnerCompleteness::Raced
        || target_match.unverified_target_reason
            == Some(crate::observation::UnverifiedOwnerReason::Raced)
    {
        authority.merge(Authority::Raced);
    }

    if matches!(target_mode, DestructiveTargetMode::Port(_)) {
        // No owner at all, or any owner we could not tie to a start identity,
        // means the port's holder set is unproven.
        if socket.owners.is_empty()
            || socket
                .owners
                .iter()
                .any(|owner| !matches!(owner, crate::observation::OwnerObservation::Verified(_)))
        {
            authority.merge(Authority::Partial);
        }
        if socket.owners.iter().any(|owner| {
            matches!(
                owner,
                crate::observation::OwnerObservation::UnverifiedPid {
                    reason: crate::observation::UnverifiedOwnerReason::PermissionDenied,
                    ..
                }
            )
        }) {
            authority.merge(Authority::PermissionDenied);
        }
    }

    authority
}

/// Whether an evidence gap can affect this target's authority.
///
/// A gap tied to another endpoint does not affect this target. A gap without
/// endpoint provenance could hide a co-holder of the selected port and causes
/// refusal. PID targets use PID and matched-endpoint provenance because they ask
/// whether one resolved process identity remains authoritative.
fn gap_applies_to_target(
    gap: &crate::observation::EvidenceGap,
    target_mode: DestructiveTargetMode,
    matched_endpoints: &std::collections::BTreeSet<crate::observation::EndpointIdentity>,
) -> bool {
    let names_matched_endpoint = || {
        gap.endpoint
            .as_ref()
            .is_some_and(|endpoint| matched_endpoints.contains(endpoint))
    };
    match (target_mode, gap.impact) {
        // Metadata and scope gaps never remove destructive authority: they
        // describe optional enrichment and declared observation boundaries,
        // neither of which changes who holds the endpoint.
        (_, EvidenceImpact::Metadata | EvidenceImpact::Scope) => false,
        (DestructiveTargetMode::Pid(target_pid), EvidenceImpact::SocketSet) => {
            gap.pid == Some(target_pid)
                || names_matched_endpoint()
                // An unattributed socket-set loss could have hidden a socket
                // belonging to this PID.
                || (gap.endpoint.is_none() && gap.pid.is_none())
        }
        (DestructiveTargetMode::Pid(target_pid), EvidenceImpact::Ownership) => {
            names_matched_endpoint() || (gap.endpoint.is_none() && gap.pid == Some(target_pid))
        }
        // Any socket-set or ownership loss that is not provably about another
        // port could have hidden a co-holder of this one.
        (
            DestructiveTargetMode::Port(target_port),
            EvidenceImpact::SocketSet | EvidenceImpact::Ownership,
        ) => gap
            .endpoint
            .as_ref()
            .is_none_or(|endpoint| endpoint.port.get() == target_port),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestructiveTargetMode {
    Pid(u32),
    Port(u16),
}

impl CollectorError {
    pub(crate) fn is_ownership_permission_denied(&self) -> bool {
        matches!(self, Self::OwnershipPermissionDenied)
    }
}

/// Deterministic rows for tests.
///
/// The rows cover full and partial metadata, a default-protected name, IPv6,
/// and a bound UDP socket.
#[cfg(test)]
pub(crate) struct FakeCollector;

#[cfg(test)]
impl Collector for FakeCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        Ok(fake_snapshot(profile)?)
    }
}

pub(crate) fn collect_native_snapshot<Collect, ReadProcesses>(
    profile: MetadataProfile,
    scope: ObservationScope,
    collect_pass: Collect,
    read_processes: ReadProcesses,
) -> Result<NetworkSnapshot, CollectorError>
where
    Collect: FnMut(MetadataProfile) -> Result<NativeObservationPass, CollectorError>,
    ReadProcesses:
        FnMut(&[u32], MetadataProfile, usize) -> Result<ProcessReadBatch, CollectorError>,
{
    let mut source = NativeObservationSource {
        collect_pass,
        read_processes,
    };
    collect_consistent(&mut source, scope, profile).map_err(CollectorError::from)
}

struct NativeObservationSource<Collect, ReadProcesses> {
    collect_pass: Collect,
    read_processes: ReadProcesses,
}

impl<Collect, ReadProcesses> ObservationSource for NativeObservationSource<Collect, ReadProcesses>
where
    Collect: FnMut(MetadataProfile) -> Result<NativeObservationPass, CollectorError>,
    ReadProcesses:
        FnMut(&[u32], MetadataProfile, usize) -> Result<ProcessReadBatch, CollectorError>,
{
    fn wall_clock(&mut self) -> Result<SystemTime, ObservationError> {
        Ok(SystemTime::now())
    }

    fn collect_native_pass(
        &mut self,
        profile: MetadataProfile,
    ) -> Result<NativeObservationPass, ObservationError> {
        (self.collect_pass)(profile).map_err(native_observation_error)
    }

    fn read_processes(
        &mut self,
        sorted_pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessReadBatch, ObservationError> {
        (self.read_processes)(sorted_pids, profile, optional_metadata_bytes_remaining)
            .map_err(native_observation_error)
    }
}

fn native_observation_error(error: CollectorError) -> ObservationError {
    match error {
        CollectorError::Observation(error) => error,
        error => ObservationError::PlatformApiFailed(error.to_string()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn read_processes_sequentially<ReadProcess>(
    sorted_pids: &[u32],
    profile: MetadataProfile,
    optional_metadata_bytes_remaining: usize,
    mut read_process: ReadProcess,
) -> Result<ProcessReadBatch, CollectorError>
where
    ReadProcess: FnMut(u32, MetadataProfile, usize) -> Result<ProcessRead, CollectorError>,
{
    let mut reads = Vec::with_capacity(sorted_pids.len());
    let mut retained_bytes = 0usize;
    for &pid in sorted_pids {
        let remaining = optional_metadata_bytes_remaining.saturating_sub(retained_bytes);
        let read = read_process(pid, profile, remaining)?;
        retained_bytes = retained_bytes.saturating_add(process_read_metadata_bytes(&read));
        reads.push((pid, read));
    }
    Ok(reads)
}

/// Deterministic authoritative fixture. It is built in snapshot form so tests
/// exercise the same borrowed projection as native collectors.
#[cfg(test)]
#[expect(
    clippy::too_many_lines,
    reason = "the five-row authoritative fixture keeps all snapshot facts together"
)]
fn fake_snapshot(profile: MetadataProfile) -> Result<NetworkSnapshot, ObservationError> {
    struct Fixture {
        protocol: Protocol,
        address: IpAddr,
        port: u16,
        state: ObservationSocketState,
        pid: Option<u32>,
        name: Option<&'static str>,
        path: Option<&'static str>,
        command: Option<&'static str>,
        parent_pid: Option<u32>,
        parent_name: Option<&'static str>,
        metadata: MetadataCompleteness,
    }

    let fixtures = [
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST.into(),
            port: 3000,
            state: ObservationSocketState::Listen,
            pid: Some(18_422),
            name: Some("node"),
            path: Some("/usr/bin/node"),
            command: Some("node server.js"),
            parent_pid: Some(18_001),
            parent_name: Some("cursor-agent"),
            metadata: MetadataCompleteness::Complete,
        },
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST.into(),
            port: 5173,
            state: ObservationSocketState::Listen,
            pid: Some(21_988),
            name: Some("vite"),
            path: Some("/usr/bin/node"),
            command: Some("node /usr/local/bin/vite --port 5173"),
            parent_pid: Some(18_001),
            parent_name: Some("cursor-agent"),
            metadata: MetadataCompleteness::Complete,
        },
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::UNSPECIFIED.into(),
            port: 5432,
            state: ObservationSocketState::Listen,
            pid: Some(1_201),
            name: Some("postgres"),
            path: None,
            command: Some("/usr/lib/postgresql/16/bin/postgres"),
            parent_pid: Some(1),
            parent_name: Some("systemd"),
            metadata: MetadataCompleteness::Partial,
        },
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv6Addr::UNSPECIFIED.into(),
            port: 8080,
            state: ObservationSocketState::Listen,
            pid: None,
            name: None,
            path: None,
            command: None,
            parent_pid: None,
            parent_name: None,
            metadata: MetadataCompleteness::Partial,
        },
        Fixture {
            protocol: Protocol::Udp,
            address: Ipv4Addr::UNSPECIFIED.into(),
            port: 5353,
            state: ObservationSocketState::Bound,
            pid: Some(902),
            name: Some("avahi-daemon"),
            path: Some("/usr/bin/avahi-daemon"),
            command: Some("avahi-daemon: running [linux.local]"),
            parent_pid: Some(1),
            parent_name: Some("systemd"),
            metadata: MetadataCompleteness::Complete,
        },
    ];
    let mut sockets = Vec::with_capacity(fixtures.len());
    let mut processes = std::collections::HashMap::new();
    for fixture in fixtures {
        let endpoint = EndpointIdentity::new(
            fixture.protocol,
            fixture.address,
            u32::from(fixture.port),
            fixture.address.is_ipv6().then_some(Ipv6Scope::Unavailable),
        )
        .map_err(|_| ObservationError::NativeDataMalformed)?;
        let owners = fixture.pid.map_or_else(Vec::new, |pid| {
            let identity = ProcessIdentity {
                pid,
                start_marker: ProcessStartMarker::linux(u64::from(pid) + 1)
                    .expect("fake PID produces a nonzero marker"),
            };
            processes.insert(
                identity,
                ProcessObservation {
                    name: (profile != MetadataProfile::IdentityOnly)
                        .then(|| fixture.name.map(Into::into))
                        .flatten(),
                    executable_path: (profile != MetadataProfile::IdentityOnly)
                        .then(|| fixture.path.map(|path| PathBuf::from(path).into()))
                        .flatten(),
                    command_line: (profile == MetadataProfile::LegacyList)
                        .then(|| fixture.command.map(Into::into))
                        .flatten(),
                    parent_pid: (profile != MetadataProfile::IdentityOnly)
                        .then_some(fixture.parent_pid)
                        .flatten(),
                    parent_process_name: (profile != MetadataProfile::IdentityOnly)
                        .then(|| fixture.parent_name.map(Into::into))
                        .flatten(),
                    metadata_omission: None,
                    metadata_completeness: fixture.metadata,
                },
            );
            vec![crate::observation::OwnerObservation::Verified(identity)]
        });
        sockets.push(SocketObservation {
            local_endpoint: endpoint,
            state: fixture.state,
            timer: None,
            owners,
            owner_completeness: if fixture.pid.is_some() {
                OwnerCompleteness::Complete
            } else {
                OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])?
            },
            socket_token: None,
        });
    }
    let ownerless_endpoint = sockets[3].local_endpoint.clone();
    Ok(NetworkSnapshot {
        capture_started_at: SystemTime::UNIX_EPOCH,
        capture_completed_at: SystemTime::UNIX_EPOCH,
        scope: ObservationScope::new(
            crate::observation::ObservationScopeKind::CurrentNetworkNamespace,
            Some("net:[fake]"),
            [crate::observation::ScopeLimitation::OtherNetworkNamespacesExcluded],
        )?,
        completeness: SnapshotCompleteness::Partial,
        owner_completeness: OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
        ])?,
        evidence_gaps: vec![
            EvidenceGap::new(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerAttributionIncomplete,
                Some(ownerless_endpoint.clone()),
                None,
                "fake socket has no attributable owner PID",
            ),
            EvidenceGap::new(
                EvidenceImpact::Scope,
                EvidenceGapCode::NativeFieldUnavailable,
                Some(ownerless_endpoint),
                None,
                "fake IPv6 socket has no interface scope",
            ),
        ],
        omitted_evidence_gap_count: 0,
        sockets,
        processes,
    })
}

#[cfg(test)]
mod tests;
