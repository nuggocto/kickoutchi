//! The Linux `/proc` collector.
//!
//! This module reads kernel-provided `/proc` files instead of invoking `ss`,
//! `lsof`, or `netstat`. Linux file formats remain inside this adapter.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::ErrorKind;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, ProcessContext, Protocol, RelatedProcessHint,
};
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact,
    FILE_DESCRIPTOR_ENTRIES_MAX, Ipv6Scope, MetadataCompleteness, MetadataOmission,
    MetadataProfile, NATIVE_SOCKET_TABLE_MAX_BYTES, NativeSocketObservation, NativeSocketRow,
    NetworkSnapshot, OWNER_EDGES_MAX, ObservationScope, ObservationScopeKind, OwnerCompleteness,
    PROCESS_NAME_MAX_BYTES, PlatformSocketToken, ProcessIdentity, ProcessObservation, ProcessRead,
    ProcessReadBatch, ProcessStartMarker, SCOPE_IDENTIFIER_MAX_BYTES, SOCKET_OBSERVATIONS_MAX,
    ScopeLimitation, SnapshotCompleteness, SocketState as ObservationSocketState,
    TcpTimerObservation, UnverifiedOwnerReason,
};
use crate::process::{
    TreeDeliveryHandle, tree_cont, tree_cont_handle, tree_deliver_handle,
    tree_open_delivery_handle, tree_stop_handle,
};
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};
use crate::tree::{
    TreeProcessInfo, TreeProcessOps, TreeSignalResult, TreeStopError, TreeStopResult,
};

use super::{MAX_CHILD_PROCESSES, MAX_PROCESS_ANCESTORS, MAX_RELATED_PROCESS_HINTS};

const PROC_ROOT: &str = "/proc";

// Shared limits and their rationale live in `observation.rs`; the constants
// below are the ones only this adapter has an opinion about.

/// `/proc/<pid>/cmdline` bytes. Degrades to `None` plus partial metadata. A
/// command line is optional enrichment, so an over-cap read is representable.
const MAX_CMDLINE_BYTES: usize = crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;

/// `/proc/<pid>/status` and `/proc/<pid>/stat` bytes.
///
/// Both fail closed past the cap rather than truncating, because a short `stat`
/// line could parse a *prefix* of the start-time marker as a valid but wrong
/// number. That would corrupt an identity check on the kill path.
///
/// Real files cannot reach either cap: `stat` is a fixed ~52-field line whose
/// `comm` is capped at 16 bytes, and `status` stays small except for `Groups:`,
/// which can legitimately list `NGROUPS_MAX` (65536) GIDs at roughly 450 KiB.
/// `take()` reads only what exists, so the headroom costs nothing on the ~1 KiB
/// common case.
const MAX_STATUS_BYTES: usize = 1024 * 1024;
const MAX_STAT_BYTES: usize = 4 * 1024;

/// The `/proc/<pid>/fd` symlink shape that identifies a socket descriptor.
const SOCKET_LINK_PREFIX: &str = "socket:[";
const SOCKET_LINK_SUFFIX: &str = "]";

/// The Linux end of the collector contract.
pub(crate) struct LinuxCollector {
    proc_root: PathBuf,
    limits: CollectionLimits,
}

#[derive(Debug, Clone, Copy)]
struct CollectionLimits {
    process_ids: usize,
    fd_entries: usize,
    socket_observations: usize,
}

impl CollectionLimits {
    const PRODUCTION: Self = Self {
        process_ids: CANDIDATE_PROCESS_IDS_MAX,
        fd_entries: FILE_DESCRIPTOR_ENTRIES_MAX,
        socket_observations: SOCKET_OBSERVATIONS_MAX,
    };
}

impl LinuxCollector {
    pub(crate) fn new() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
            limits: CollectionLimits::PRODUCTION,
        }
    }

    #[cfg(test)]
    fn with_proc_root(proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            limits: CollectionLimits::PRODUCTION,
        }
    }

    #[cfg(test)]
    fn with_proc_root_and_limits(proc_root: PathBuf, limits: CollectionLimits) -> Self {
        Self { proc_root, limits }
    }
}

pub(crate) fn fresh_process_evidence(
    pid: u32,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    read_fresh_process_evidence(Path::new(PROC_ROOT), pid)
}

impl Collector for LinuxCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        let raw_scope_identifier = fs::read_link(self.proc_root.join("self/ns/net")).ok();
        let scope_identifier = raw_scope_identifier
            .as_deref()
            .and_then(bounded_scope_identifier);
        let scope_read_failed = scope_identifier.is_none();
        let scope = ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
            scope_identifier,
            [
                ScopeLimitation::OtherNetworkNamespacesExcluded,
                ScopeLimitation::Ipv6ScopeUnavailable,
                ScopeLimitation::ScopedIpv6ExactMatchingUnavailable,
            ],
        )?;
        let mut snapshot = crate::collector::collect_native_snapshot(
            profile,
            scope,
            |_profile| self.collect_native_pass(),
            |pids, profile, remaining| self.read_native_processes(pids, profile, remaining),
        )?;
        if snapshot
            .sockets
            .iter()
            .any(|socket| socket.local_endpoint.ipv6_scope == Some(Ipv6Scope::Unavailable))
        {
            push_snapshot_gap(
                &mut snapshot,
                EvidenceGap::new(
                    EvidenceImpact::Scope,
                    EvidenceGapCode::NativeFieldUnavailable,
                    None,
                    None,
                    "IPv6 scope identifiers are unavailable from Linux procfs socket rows",
                ),
            );
        }
        if scope_read_failed {
            push_snapshot_gap(
                &mut snapshot,
                EvidenceGap::new(
                    EvidenceImpact::Scope,
                    EvidenceGapCode::NativeFieldUnavailable,
                    None,
                    None,
                    "current network namespace identifier is unavailable",
                ),
            );
        }
        Ok(snapshot)
    }
}

fn push_snapshot_gap(snapshot: &mut NetworkSnapshot, gap: EvidenceGap) {
    if snapshot.evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
        snapshot.evidence_gaps.push(gap);
        snapshot.evidence_gaps.sort();
    } else {
        snapshot.omitted_evidence_gap_count = snapshot.omitted_evidence_gap_count.saturating_add(1);
    }
    if snapshot.completeness != SnapshotCompleteness::Raced {
        snapshot.completeness = SnapshotCompleteness::Partial;
    }
}

fn bounded_scope_identifier(path: &Path) -> Option<&str> {
    path.to_str()
        .filter(|identifier| identifier.len() <= SCOPE_IDENTIFIER_MAX_BYTES)
}

impl LinuxCollector {
    fn read_native_processes(
        &self,
        pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessReadBatch, CollectorError> {
        let mut parent_names = HashMap::new();
        crate::collector::read_processes_sequentially(
            pids,
            profile,
            optional_metadata_bytes_remaining,
            |pid, profile, remaining| {
                self.read_native_process_cached(pid, profile, remaining, &mut parent_names)
            },
        )
    }

    fn collect_native_pass(
        &self,
    ) -> Result<crate::observation::NativeObservationPass, CollectorError> {
        let records =
            collect_socket_records_bounded(&self.proc_root, self.limits.socket_observations)?;
        let target_inodes: HashSet<u64> = records.iter().map(|record| record.inode).collect();
        let owner_scan = collect_socket_owners_detailed(
            &self.proc_root,
            &target_inodes,
            self.limits.process_ids,
            self.limits.fd_entries,
        )?;
        native_pass_from_records(&records, &owner_scan)
    }

    #[cfg(test)]
    fn read_native_process(
        &self,
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessRead, CollectorError> {
        self.read_native_process_cached(
            pid,
            profile,
            optional_metadata_bytes_remaining,
            &mut HashMap::new(),
        )
    }

    fn read_native_process_cached(
        &self,
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
        parent_names: &mut HashMap<ProcessIdentity, Option<String>>,
    ) -> Result<ProcessRead, CollectorError> {
        let process_dir = self.proc_root.join(pid.to_string());
        let stat_path = process_dir.join("stat");
        let marker = match read_native_process_marker(&stat_path) {
            Ok(marker) => marker,
            Err(error) if error.kind() == ErrorKind::FileTooLarge => {
                return Err(crate::observation::ObservationError::NativeDataOversized.into());
            }
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                return Err(crate::observation::ObservationError::NativeDataMalformed.into());
            }
            Err(error) => {
                return Ok(ProcessRead::Unverified(unverified_reason_for_io(&error)));
            }
        };
        if profile == MetadataProfile::IdentityOnly {
            return Ok(ProcessRead::Verified {
                marker,
                observation: ProcessObservation::identity_only(),
            });
        }
        let metadata = if optional_metadata_bytes_remaining == 0 {
            ProcessMetadata {
                partial: true,
                budget_omitted: true,
                ..ProcessMetadata::default()
            }
        } else {
            read_process_metadata_bounded_with_parent_cache(
                &self.proc_root,
                pid,
                profile,
                optional_metadata_bytes_remaining,
                parent_names,
            )
        };
        let marker_after = match read_native_process_marker(&stat_path) {
            Ok(marker) => marker,
            Err(error) if error.kind() == ErrorKind::FileTooLarge => {
                return Err(crate::observation::ObservationError::NativeDataOversized.into());
            }
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                return Err(crate::observation::ObservationError::NativeDataMalformed.into());
            }
            Err(error) => {
                return Ok(ProcessRead::Unverified(unverified_reason_for_io(&error)));
            }
        };
        if marker_after != marker {
            return Ok(ProcessRead::Unverified(UnverifiedOwnerReason::Raced));
        }
        let path_invalid_utf8 = metadata
            .executable_path
            .as_ref()
            .is_some_and(|path| path.to_str().is_none());
        Ok(ProcessRead::Verified {
            marker: marker_after,
            observation: ProcessObservation {
                name: metadata.process_name.map(Into::into),
                executable_path: metadata
                    .executable_path
                    .filter(|path| path.to_str().is_some())
                    .map(Into::into),
                command_line: metadata.command_line.map(Into::into),
                parent_pid: metadata.parent_pid,
                parent_process_name: metadata.parent_process_name.map(Into::into),
                metadata_omission: metadata
                    .budget_omitted
                    .then_some(MetadataOmission::BudgetExceeded),
                metadata_completeness: if metadata.partial || path_invalid_utf8 {
                    MetadataCompleteness::Partial
                } else {
                    MetadataCompleteness::Complete
                },
            },
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct SocketTable {
    relative_path: &'static str,
    protocol: Protocol,
    address_family: AddressFamily,
    optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    state: ObservationSocketState,
    timer: Option<TcpTimerObservation>,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OwnerScanLoss {
    EnumerationIncomplete,
    AncestorPidOwnersInvisible,
    PermissionDenied(u32),
    Disappeared(u32),
    Unattributable(u32),
}

#[derive(Debug, Default)]
struct OwnerScanResult {
    owners: HashMap<u64, Vec<u32>>,
    losses: BTreeSet<OwnerScanLoss>,
    aggregate_losses: OwnerScanAggregateLosses,
    omitted_loss_count: u64,
    owner_edges: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct OwnerScanAggregateLosses {
    permission_denied: u64,
    disappeared: u64,
    unattributable: u64,
}

impl OwnerScanResult {
    fn record_loss(&mut self, loss: OwnerScanLoss) {
        if self.losses.contains(&loss) {
            return;
        }
        if self.losses.len() < crate::observation::EVIDENCE_GAPS_MAX {
            self.losses.insert(loss);
        } else {
            self.omitted_loss_count = self.omitted_loss_count.saturating_add(1);
        }
    }

    fn record_pid_losses(&mut self, losses: BTreeSet<OwnerScanLoss>, has_target_owner_edge: bool) {
        for loss in losses {
            if has_target_owner_edge {
                self.record_loss(loss);
                continue;
            }
            match loss {
                OwnerScanLoss::PermissionDenied(_) => {
                    self.aggregate_losses.permission_denied =
                        self.aggregate_losses.permission_denied.saturating_add(1);
                }
                OwnerScanLoss::Disappeared(_) => {
                    self.aggregate_losses.disappeared =
                        self.aggregate_losses.disappeared.saturating_add(1);
                }
                OwnerScanLoss::Unattributable(_) => {
                    self.aggregate_losses.unattributable =
                        self.aggregate_losses.unattributable.saturating_add(1);
                }
                OwnerScanLoss::EnumerationIncomplete
                | OwnerScanLoss::AncestorPidOwnersInvisible => {
                    unreachable!("PID scan losses always carry a PID")
                }
            }
        }
    }
}

fn owner_evidence(
    owner_scan: &OwnerScanResult,
) -> Result<(OwnerCompleteness, Vec<EvidenceGap>, u64), CollectorError> {
    let mut reasons = BTreeSet::new();
    let aggregate_loss_count = [
        owner_scan.aggregate_losses.permission_denied,
        owner_scan.aggregate_losses.disappeared,
        owner_scan.aggregate_losses.unattributable,
    ]
    .into_iter()
    .filter(|count| *count != 0)
    .count();
    let mut evidence_gaps =
        Vec::with_capacity(owner_scan.losses.len().saturating_add(aggregate_loss_count));
    let mut omitted_evidence_gap_count = owner_scan.omitted_loss_count;
    for loss in &owner_scan.losses {
        let (pid, code, message) = match *loss {
            OwnerScanLoss::EnumerationIncomplete => (
                None,
                EvidenceGapCode::OwnerAttributionIncomplete,
                "process visibility or enumeration was incomplete before socket ownership could be attributed",
            ),
            OwnerScanLoss::AncestorPidOwnersInvisible => (
                None,
                EvidenceGapCode::OwnerAttributionIncomplete,
                "ancestor PID namespace processes may own sockets but are invisible to this process enumeration",
            ),
            OwnerScanLoss::PermissionDenied(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerPermissionDenied,
                "permission denied before the PID's socket ownership could be attributed",
            ),
            OwnerScanLoss::Disappeared(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerDisappeared,
                "PID disappeared before its socket ownership could be attributed",
            ),
            OwnerScanLoss::Unattributable(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerAttributionIncomplete,
                "a PID file-descriptor entry could not be attributed to a socket",
            ),
        };
        reasons.insert(code);
        let gap = EvidenceGap::new(EvidenceImpact::Ownership, code, None, pid, message);
        if evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
            evidence_gaps.push(gap);
        } else {
            omitted_evidence_gap_count = omitted_evidence_gap_count.saturating_add(1);
        }
    }
    for (count, code, message) in [
        (
            owner_scan.aggregate_losses.permission_denied,
            EvidenceGapCode::OwnerPermissionDenied,
            "permission denied before socket ownership could be attributed for at least the reported number of PIDs",
        ),
        (
            owner_scan.aggregate_losses.disappeared,
            EvidenceGapCode::OwnerDisappeared,
            "at least the reported number of PIDs disappeared before socket ownership could be attributed",
        ),
        (
            owner_scan.aggregate_losses.unattributable,
            EvidenceGapCode::OwnerAttributionIncomplete,
            "file-descriptor entries for at least the reported number of PIDs could not be attributed to sockets",
        ),
    ] {
        let Some(affected_pid_count) = NonZeroU64::new(count) else {
            continue;
        };
        reasons.insert(code);
        let gap = EvidenceGap::aggregate_for_pids(
            EvidenceImpact::Ownership,
            code,
            None,
            affected_pid_count,
            message,
        );
        if evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
            evidence_gaps.push(gap);
        } else {
            omitted_evidence_gap_count = omitted_evidence_gap_count.saturating_add(1);
        }
    }
    Ok((
        OwnerCompleteness::partial(reasons)?,
        evidence_gaps,
        omitted_evidence_gap_count,
    ))
}

fn native_pass_from_records(
    records: &[SocketRecord],
    owner_scan: &OwnerScanResult,
) -> Result<crate::observation::NativeObservationPass, CollectorError> {
    let ancestor_pid_owners_invisible = owner_scan
        .losses
        .contains(&OwnerScanLoss::AncestorPidOwnersInvisible);
    let owner_completeness = if ancestor_pid_owners_invisible {
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])?
    } else {
        OwnerCompleteness::Complete
    };
    let mut rows = Vec::with_capacity(records.len());
    for record in records {
        let ipv6_scope = record
            .local_addr
            .is_ipv6()
            .then_some(Ipv6Scope::Unavailable);
        let endpoint = EndpointIdentity::new(
            record.protocol,
            record.local_addr,
            u32::from(record.local_port),
            ipv6_scope,
        )
        .map_err(|error| {
            CollectorError::Observation(crate::observation::ObservationError::PlatformApiFailed(
                error.to_string(),
            ))
        })?;
        rows.push(NativeSocketRow {
            socket: NativeSocketObservation {
                endpoint,
                state: record.state,
                timer: record.timer,
                token: PlatformSocketToken::linux_inode(record.inode),
            },
            owner_pids: owner_scan
                .owners
                .get(&record.inode)
                .cloned()
                .unwrap_or_default(),
            owner_completeness: owner_completeness.clone(),
        });
    }

    let (global_completeness, evidence_gaps, omitted_evidence_gap_count) =
        owner_evidence(owner_scan)?;
    // Ordinary PID/fd traversal losses have no endpoint provenance and reduce
    // only global authority. Nested PID namespaces are different: an invisible
    // ancestor-namespace process may share any socket visible in the current
    // network namespace, so no socket's owner set is provably complete.
    Ok(crate::observation::NativeObservationPass {
        rows,
        global_owner_completeness: global_completeness,
        evidence_gaps,
        omitted_evidence_gap_count,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum SocketParseError {
    #[error("invalid /proc/net socket table header")]
    InvalidHeader,
    #[error("missing field {field}")]
    MissingField { field: &'static str },
    #[error("local address must be ADDRESS:PORT, got {value}")]
    MalformedLocalAddress { value: String },
    #[error("invalid IPv4 address {value}")]
    InvalidIpv4Address { value: String },
    #[error("invalid IPv6 address {value}")]
    InvalidIpv6Address { value: String },
    #[error("invalid port {value}")]
    InvalidPort { value: String },
    #[error("invalid socket state {value}")]
    InvalidState { value: String },
    #[error("invalid TCP timer {value}")]
    InvalidTcpTimer { value: String },
    #[error("invalid inode {value}")]
    InvalidInode { value: String },
    #[error("socket observation limit exceeded")]
    SocketObservationLimitExceeded,
}

#[derive(Debug, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    partial: bool,
    budget_omitted: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProcessStatus {
    parent_pid: Option<u32>,
    owner_uid: Option<u32>,
}

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    collect_process_context_from(&PathBuf::from(PROC_ROOT), pid)
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    collect_related_process_hints_from(&PathBuf::from(PROC_ROOT), port)
}

/// Best-effort command line for one PID, for the read-only inspect view.
/// `None` covers vanished, restricted, and kernel processes alike. Inspect
/// renders it as unknown rather than failing the report.
pub(crate) fn process_command_line(pid: u32) -> Option<String> {
    let path = PathBuf::from(PROC_ROOT)
        .join(pid.to_string())
        .join("cmdline");
    read_cmdline(&path)
        .ok()
        .and_then(|(command_line, _)| command_line)
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<ProcessStartMarker> {
    let path = PathBuf::from(PROC_ROOT).join(pid.to_string()).join("stat");
    read_process_start_time_ticks(&path)
        .ok()
        .and_then(|ticks| ProcessStartMarker::linux(ticks).ok())
}

#[cfg(test)]
fn collect_socket_records(proc_root: &Path) -> Result<Vec<SocketRecord>, CollectorError> {
    collect_socket_records_bounded(proc_root, crate::observation::SOCKET_OBSERVATIONS_MAX)
}

fn collect_socket_records_bounded(
    proc_root: &Path,
    max_records: usize,
) -> Result<Vec<SocketRecord>, CollectorError> {
    let clock_ticks_per_second = linux_clock_ticks_per_second();
    let tables = [
        SocketTable {
            relative_path: "net/tcp",
            protocol: Protocol::Tcp,
            address_family: AddressFamily::Ipv4,
            optional: false,
        },
        SocketTable {
            relative_path: "net/tcp6",
            protocol: Protocol::Tcp,
            address_family: AddressFamily::Ipv6,
            optional: true,
        },
        SocketTable {
            relative_path: "net/udp",
            protocol: Protocol::Udp,
            address_family: AddressFamily::Ipv4,
            optional: false,
        },
        SocketTable {
            relative_path: "net/udp6",
            protocol: Protocol::Udp,
            address_family: AddressFamily::Ipv6,
            optional: true,
        },
    ];

    let mut records = Vec::new();
    for table in tables {
        let path = proc_root.join(table.relative_path);
        let Some(text) = read_socket_table(&path, table.optional)? else {
            continue;
        };
        let remaining = max_records.saturating_sub(records.len());
        let parsed = parse_socket_table(
            &text,
            table.protocol,
            table.address_family,
            clock_ticks_per_second,
            remaining,
        )
        .map_err(|error| match error {
            SocketParseError::SocketObservationLimitExceeded => CollectorError::Observation(
                crate::observation::ObservationError::SocketObservationLimitExceeded,
            ),
            _ => CollectorError::Observation(
                crate::observation::ObservationError::NativeDataMalformed,
            ),
        })?;
        for record in parsed {
            if records.len() >= max_records {
                return Err(
                    crate::observation::ObservationError::SocketObservationLimitExceeded.into(),
                );
            }
            records.push(record);
        }
    }
    Ok(records)
}

fn read_socket_table(path: &Path, optional: bool) -> Result<Option<String>, CollectorError> {
    read_socket_table_bounded(path, optional, NATIVE_SOCKET_TABLE_MAX_BYTES)
}

fn read_socket_table_bounded(
    path: &Path,
    optional: bool,
    max_bytes: usize,
) -> Result<Option<String>, CollectorError> {
    match read_bounded_bytes(path, max_bytes) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| crate::observation::ObservationError::NativeDataMalformed.into()),
        Err(source) if optional && source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) if source.kind() == ErrorKind::PermissionDenied => {
            Err(crate::observation::ObservationError::SocketTablePermissionDenied.into())
        }
        Err(source) if source.kind() == ErrorKind::InvalidData => {
            Err(crate::observation::ObservationError::NativeDataOversized.into())
        }
        Err(_) => Err(crate::observation::ObservationError::SocketTableUnavailable.into()),
    }
}

fn read_bounded_text(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    String::from_utf8(read_bounded_bytes(path, max_bytes)?)
        .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
}

fn read_bounded_bytes(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    read_bounded_bytes_with_overflow_kind(path, max_bytes, ErrorKind::InvalidData)
}

fn read_bounded_bytes_with_overflow_kind(
    path: &Path,
    max_bytes: usize,
    overflow_kind: ErrorKind,
) -> std::io::Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)
        .expect("/proc read byte limit must fit in u64")
        .saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            overflow_kind,
            format!("file exceeds {max_bytes} byte read limit"),
        ));
    }
    Ok(bytes)
}

fn read_bounded_lossy_text(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    let bytes = read_bounded_bytes(path, max_bytes)?;
    let decoded_len = crate::observation::lossy_utf8_len(&bytes).ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidData, "decoded text length overflow")
    })?;
    if decoded_len > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("decoded text exceeds {max_bytes} byte limit"),
        ));
    }
    let mut text = String::with_capacity(decoded_len);
    crate::observation::push_utf8_lossy(&mut text, &bytes);
    Ok(text)
}

fn parse_socket_table(
    text: &str,
    protocol: Protocol,
    address_family: AddressFamily,
    clock_ticks_per_second: Option<u64>,
    max_records: usize,
) -> Result<Vec<SocketRecord>, SocketParseError> {
    let mut lines = text.lines();
    let header = lines.next().ok_or(SocketParseError::InvalidHeader)?;
    let mut header_fields = header.split_whitespace();
    let expected_remote_address = match address_family {
        AddressFamily::Ipv4 => "rem_address",
        AddressFamily::Ipv6 => "remote_address",
    };
    if header_fields.next() != Some("sl")
        || header_fields.next() != Some("local_address")
        || header_fields.next() != Some(expected_remote_address)
        || header_fields.next() != Some("st")
        || header_fields.nth(7) != Some("inode")
    {
        return Err(SocketParseError::InvalidHeader);
    }

    let mut records = Vec::new();
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if records.len() >= max_records {
            return Err(SocketParseError::SocketObservationLimitExceeded);
        }
        match parse_socket_line(line, protocol, address_family, clock_ticks_per_second) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(line = line_index + 2, %error, "malformed /proc/net row");
                return Err(error);
            }
        }
    }
    Ok(records)
}

fn parse_socket_line(
    line: &str,
    protocol: Protocol,
    address_family: AddressFamily,
    clock_ticks_per_second: Option<u64>,
) -> Result<Option<SocketRecord>, SocketParseError> {
    let mut fields = line.split_whitespace();
    let _slot = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "sl" })?;
    let local = fields.next().ok_or(SocketParseError::MissingField {
        field: "local_address",
    })?;
    let _remote = fields.next().ok_or(SocketParseError::MissingField {
        field: "remote_address",
    })?;
    let state_hex = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "st" })?;
    let _queues = fields.next().ok_or(SocketParseError::MissingField {
        field: "tx_queue:rx_queue",
    })?;
    let timer_text = fields.next().ok_or(SocketParseError::MissingField {
        field: "tr:tm->when",
    })?;
    let _retransmits = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "retrnsmt" })?;
    let _uid = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "uid" })?;
    let _timeout = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "timeout" })?;
    let inode_hex = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "inode" })?;

    let (addr_hex, port_hex) =
        local
            .split_once(':')
            .ok_or_else(|| SocketParseError::MalformedLocalAddress {
                value: local.to_owned(),
            })?;
    let local_addr = decode_addr(addr_hex, address_family)?;
    let local_port =
        u16::from_str_radix(port_hex, 16).map_err(|_| SocketParseError::InvalidPort {
            value: port_hex.to_owned(),
        })?;
    let inode = inode_hex
        .parse::<u64>()
        .map_err(|_| SocketParseError::InvalidInode {
            value: inode_hex.to_owned(),
        })?;
    let native_state =
        u32::from_str_radix(state_hex, 16).map_err(|_| SocketParseError::InvalidState {
            value: state_hex.to_owned(),
        })?;
    let state = match protocol {
        Protocol::Tcp => linux_tcp_state(native_state),
        Protocol::Udp => ObservationSocketState::Bound,
    };
    let timer = match protocol {
        Protocol::Tcp => Some(parse_tcp_timer(timer_text, clock_ticks_per_second)?),
        Protocol::Udp => None,
    };

    Ok(Some(SocketRecord {
        protocol,
        local_addr,
        local_port,
        state,
        timer,
        inode,
    }))
}

const fn linux_tcp_state(native_state: u32) -> ObservationSocketState {
    match native_state {
        0x01 => ObservationSocketState::Established,
        0x02 => ObservationSocketState::SynSent,
        0x03 => ObservationSocketState::SynReceived,
        0x04 => ObservationSocketState::FinWait1,
        0x05 => ObservationSocketState::FinWait2,
        0x06 => ObservationSocketState::TimeWait,
        0x07 => ObservationSocketState::Closed,
        0x08 => ObservationSocketState::CloseWait,
        0x09 => ObservationSocketState::LastAck,
        0x0A => ObservationSocketState::Listen,
        0x0B => ObservationSocketState::Closing,
        0x0C => ObservationSocketState::NewSynReceived,
        code => ObservationSocketState::Unknown(code),
    }
}

fn parse_tcp_timer(
    value: &str,
    clock_ticks_per_second: Option<u64>,
) -> Result<TcpTimerObservation, SocketParseError> {
    let (kind, raw_ticks) =
        value
            .split_once(':')
            .ok_or_else(|| SocketParseError::InvalidTcpTimer {
                value: value.to_owned(),
            })?;
    let native_code =
        u32::from_str_radix(kind, 16).map_err(|_| SocketParseError::InvalidTcpTimer {
            value: value.to_owned(),
        })?;
    let raw_ticks =
        u64::from_str_radix(raw_ticks, 16).map_err(|_| SocketParseError::InvalidTcpTimer {
            value: value.to_owned(),
        })?;
    Ok(TcpTimerObservation::from_linux_native(
        native_code,
        raw_ticks,
        clock_ticks_per_second,
    ))
}

fn linux_clock_ticks_per_second() -> Option<u64> {
    // SAFETY: sysconf reads process-global configuration for a valid constant and
    // does not dereference pointers or retain caller-owned memory.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks).ok().filter(|ticks| *ticks != 0)
}

fn decode_addr(hex: &str, address_family: AddressFamily) -> Result<IpAddr, SocketParseError> {
    match address_family {
        AddressFamily::Ipv4 => decode_ipv4_addr(hex).map(IpAddr::V4),
        AddressFamily::Ipv6 => decode_ipv6_addr(hex),
    }
}

fn decode_ipv4_addr(hex: &str) -> Result<Ipv4Addr, SocketParseError> {
    if hex.len() != 8 {
        return Err(SocketParseError::InvalidIpv4Address {
            value: hex.to_owned(),
        });
    }
    let raw = u32::from_str_radix(hex, 16).map_err(|_| SocketParseError::InvalidIpv4Address {
        value: hex.to_owned(),
    })?;
    // The kernel prints the address as its raw in-memory u32, so the hex uses
    // *host* byte order. Localhost reads "0100007F" on little-endian machines.
    // Native-endian decoding is therefore correct on every target; a big-endian
    // "fix" here would flip every address (and fail the parser fixture tests).
    Ok(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn decode_ipv6_addr(hex: &str) -> Result<IpAddr, SocketParseError> {
    if hex.len() != 32 {
        return Err(SocketParseError::InvalidIpv6Address {
            value: hex.to_owned(),
        });
    }

    // The kernel prints an IPv6 address as four raw in-memory u32 words, each
    // rendered as 8 hex chars in *host* byte order (same convention as the IPv4
    // decoder above). Each chunk of 8 hex chars covers 4 address bytes, so the
    // hex-char index `start` maps to byte index `start / 2`.
    let mut bytes = [0_u8; 16];
    for chunk_index in 0..4 {
        let start = chunk_index * 8;
        let end = start + 8;
        let chunk = hex
            .get(start..end)
            .ok_or_else(|| SocketParseError::InvalidIpv6Address {
                value: hex.to_owned(),
            })?;
        let word =
            u32::from_str_radix(chunk, 16).map_err(|_| SocketParseError::InvalidIpv6Address {
                value: hex.to_owned(),
            })?;
        bytes[start / 2..start / 2 + 4].copy_from_slice(&word.to_ne_bytes());
    }

    let addr = Ipv6Addr::from(bytes);
    if let Some(mapped) = addr.to_ipv4_mapped() {
        Ok(IpAddr::V4(mapped))
    } else {
        Ok(IpAddr::V6(addr))
    }
}

#[cfg(test)]
fn collect_socket_owners(
    proc_root: &Path,
    target_inodes: &HashSet<u64>,
    max_process_ids: usize,
    max_fd_entries: usize,
) -> Result<HashMap<u64, Vec<u32>>, CollectorError> {
    collect_socket_owners_detailed(proc_root, target_inodes, max_process_ids, max_fd_entries)
        .map(|result| result.owners)
}

fn collect_socket_owners_detailed(
    proc_root: &Path,
    target_inodes: &HashSet<u64>,
    max_process_ids: usize,
    max_fd_entries: usize,
) -> Result<OwnerScanResult, CollectorError> {
    let mut result = OwnerScanResult {
        owners: HashMap::with_capacity(target_inodes.len()),
        ..OwnerScanResult::default()
    };
    if proc_visibility_restricted(proc_root) {
        result.record_loss(OwnerScanLoss::EnumerationIncomplete);
    }
    if ancestor_pid_visibility_not_proven(proc_root) {
        result.record_loss(OwnerScanLoss::AncestorPidOwnersInvisible);
    }
    if target_inodes.is_empty() {
        return Ok(result);
    }

    let (pids, enumeration_incomplete) = owner_process_ids_with_limit(proc_root, max_process_ids)
        .map_err(|source| {
        if source.kind() == ErrorKind::InvalidData {
            CollectorError::Observation(
                crate::observation::ObservationError::ProcessIdentityLimitExceeded,
            )
        } else {
            CollectorError::Read {
                path: proc_root.to_path_buf(),
                source,
            }
        }
    })?;
    if enumeration_incomplete {
        result.record_loss(OwnerScanLoss::EnumerationIncomplete);
    }

    // Scan every PID and descriptor. Fork inheritance and `SO_REUSEPORT` allow
    // one socket inode to have several owners. Stopping at the first owner would
    // make `kill --port` miss co-owners that keep the port open.
    let mut fd_entries_visited = 0;
    for pid in pids {
        scan_pid_socket_owners(
            proc_root,
            pid,
            target_inodes,
            &mut result,
            &mut fd_entries_visited,
            max_fd_entries,
        )?;
    }
    Ok(result)
}

fn process_ids(proc_root: &Path) -> std::io::Result<Vec<u32>> {
    process_ids_with_limit(proc_root, CANDIDATE_PROCESS_IDS_MAX)
}

/// How a `/proc` PID scan treats a directory entry that fails to read.
#[derive(Clone, Copy)]
enum EntryErrorPolicy {
    /// Abort the scan and propagate the I/O error to the caller.
    Propagate,
    /// Skip the entry and flag the scan result as incomplete.
    MarkIncomplete,
}

fn process_ids_with_limit(proc_root: &Path, max_process_ids: usize) -> std::io::Result<Vec<u32>> {
    scan_process_ids(proc_root, max_process_ids, EntryErrorPolicy::Propagate)
        .map(|(pids, _incomplete)| pids)
}

fn owner_process_ids_with_limit(
    proc_root: &Path,
    max_process_ids: usize,
) -> std::io::Result<(Vec<u32>, bool)> {
    scan_process_ids(proc_root, max_process_ids, EntryErrorPolicy::MarkIncomplete)
}

fn scan_process_ids(
    proc_root: &Path,
    max_process_ids: usize,
    entry_error_policy: EntryErrorPolicy,
) -> std::io::Result<(Vec<u32>, bool)> {
    let mut pids = Vec::new();
    let mut incomplete = false;
    for entry in fs::read_dir(proc_root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => match entry_error_policy {
                EntryErrorPolicy::Propagate => return Err(error),
                EntryErrorPolicy::MarkIncomplete => {
                    incomplete = true;
                    continue;
                }
            },
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pids.len() >= max_process_ids {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("process list exceeds {max_process_ids} PID cap"),
            ));
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    Ok((pids, incomplete))
}

fn proc_visibility_restricted(proc_root: &Path) -> bool {
    let Ok(mounts) = read_bounded_text(&proc_root.join("mounts"), MAX_STATUS_BYTES) else {
        return true;
    };
    let proc_root = proc_root.as_os_str().as_bytes();
    let mut matching_options = None;
    for line in mounts.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 6
            || fields[4].parse::<u32>().is_err()
            || fields[5].parse::<u32>().is_err()
        {
            return true;
        }
        if fields[1].as_bytes() != proc_root {
            continue;
        }
        if matching_options.replace((fields[2], fields[3])).is_some() {
            return true;
        }
    }

    let Some((filesystem, options)) = matching_options else {
        return true;
    };
    if filesystem != "proc" {
        return true;
    }

    let mut hidepid = None;
    for option in options.split(',') {
        if option.is_empty() {
            return true;
        }
        if let Some(mode) = option.strip_prefix("hidepid=") {
            if mode.is_empty() || hidepid.replace(mode).is_some() {
                return true;
            }
        } else if option == "hidepid" {
            return true;
        }
    }
    !matches!(hidepid, None | Some("0" | "off"))
}

fn ancestor_pid_visibility_not_proven(proc_root: &Path) -> bool {
    // NSpid is relative to the procfs mount, so a nested namespace with its
    // own procfs also has one entry. Compare the kernel's reserved initial
    // PID namespace identity instead. PID_NS_INIT_INO is 0xEFFFFFFC in
    // include/uapi/linux/nsfs.h, formerly PROC_PID_INIT_INO in linux/proc_ns.h.
    // https://github.com/torvalds/linux/blob/v6.19/include/uapi/linux/nsfs.h
    // Unknown or unreadable identities cannot establish complete visibility.
    const INITIAL_PID_NAMESPACE: &str = "pid:[4026531836]";
    !read_link_bounded(&proc_root.join("self/ns/pid"), SCOPE_IDENTIFIER_MAX_BYTES)
        .is_ok_and(|namespace| namespace.as_os_str() == INITIAL_PID_NAMESPACE)
}

#[cfg(test)]
fn collect_pid_socket_owners(
    proc_root: &Path,
    pid: u32,
    target_inodes: &HashSet<u64>,
    owners: &mut HashMap<u64, Vec<u32>>,
    fd_entries_visited: &mut usize,
    max_fd_entries: usize,
) -> Result<(), CollectorError> {
    let owner_edges = owners.values().map(Vec::len).sum();
    let mut result = OwnerScanResult {
        owners: std::mem::take(owners),
        owner_edges,
        ..OwnerScanResult::default()
    };
    let scan = scan_pid_socket_owners(
        proc_root,
        pid,
        target_inodes,
        &mut result,
        fd_entries_visited,
        max_fd_entries,
    );
    *owners = result.owners;
    scan
}

fn scan_pid_socket_owners(
    proc_root: &Path,
    pid: u32,
    target_inodes: &HashSet<u64>,
    result: &mut OwnerScanResult,
    fd_entries_visited: &mut usize,
    max_fd_entries: usize,
) -> Result<(), CollectorError> {
    let owner_edges_before = result.owner_edges;
    let mut pid_losses = BTreeSet::new();
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let fd_entries = match fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(error) if process_vanished(&error) => {
            pid_losses.insert(OwnerScanLoss::Disappeared(pid));
            result.record_pid_losses(pid_losses, false);
            return Ok(());
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            pid_losses.insert(OwnerScanLoss::PermissionDenied(pid));
            result.record_pid_losses(pid_losses, false);
            return Ok(());
        }
        Err(source) => {
            return Err(CollectorError::Read {
                path: fd_dir,
                source,
            });
        }
    };

    for entry in fd_entries {
        if *fd_entries_visited >= max_fd_entries {
            return Err(crate::observation::ObservationError::OwnerAttributionLimitExceeded.into());
        }
        *fd_entries_visited += 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                pid_losses.insert(owner_scan_loss(pid, &error));
                continue;
            }
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) => {
                pid_losses.insert(owner_scan_loss(pid, &error));
                continue;
            }
        };
        let Some(inode) = parse_socket_inode(&target) else {
            continue;
        };
        if !target_inodes.contains(&inode) {
            continue;
        }
        let pids = result.owners.entry(inode).or_default();
        if pids.last().copied() != Some(pid) {
            if result.owner_edges >= OWNER_EDGES_MAX {
                return Err(
                    crate::observation::ObservationError::OwnerAttributionLimitExceeded.into(),
                );
            }
            pids.push(pid);
            result.owner_edges += 1;
        }
    }
    let has_target_owner_edge = result.owner_edges > owner_edges_before;
    result.record_pid_losses(pid_losses, has_target_owner_edge);
    Ok(())
}

fn owner_scan_loss(pid: u32, error: &std::io::Error) -> OwnerScanLoss {
    if error.kind() == ErrorKind::PermissionDenied {
        OwnerScanLoss::PermissionDenied(pid)
    } else if process_vanished(error) {
        OwnerScanLoss::Disappeared(pid)
    } else {
        OwnerScanLoss::Unattributable(pid)
    }
}

fn unverified_reason_for_io(error: &std::io::Error) -> UnverifiedOwnerReason {
    if error.kind() == ErrorKind::PermissionDenied {
        UnverifiedOwnerReason::PermissionDenied
    } else if process_vanished(error) {
        UnverifiedOwnerReason::Disappeared
    } else {
        UnverifiedOwnerReason::IdentityUnavailable
    }
}

fn read_native_process_marker(path: &Path) -> std::io::Result<ProcessStartMarker> {
    let ticks = read_process_start_time_ticks(path)?;
    ProcessStartMarker::linux(ticks)
        .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
}

fn parse_socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_str()?;
    let inode = text
        .strip_prefix(SOCKET_LINK_PREFIX)?
        .strip_suffix(SOCKET_LINK_SUFFIX)?;
    inode.parse::<u64>().ok()
}

#[cfg(test)]
fn read_process_metadata_bounded(
    proc_root: &Path,
    pid: u32,
    profile: MetadataProfile,
    aggregate_remaining: usize,
) -> ProcessMetadata {
    read_process_metadata_bounded_with_parent_cache(
        proc_root,
        pid,
        profile,
        aggregate_remaining,
        &mut HashMap::new(),
    )
}

fn read_process_metadata_bounded_with_parent_cache(
    proc_root: &Path,
    pid: u32,
    profile: MetadataProfile,
    aggregate_remaining: usize,
    parent_names: &mut HashMap<ProcessIdentity, Option<String>>,
) -> ProcessMetadata {
    if profile == MetadataProfile::IdentityOnly {
        return ProcessMetadata::default();
    }
    let process_dir = proc_root.join(pid.to_string());
    let mut metadata = ProcessMetadata::default();
    let mut remaining = aggregate_remaining;

    let name_budget = remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES);
    if let Ok(name) = read_bounded_lossy_text(&process_dir.join("comm"), name_budget)
        .map(|text| trimmed_non_empty(&text))
    {
        metadata.process_name = name;
        metadata.partial |= metadata.process_name.is_none();
        remaining = remaining.saturating_sub(metadata.process_name.as_ref().map_or(0, String::len));
    } else {
        metadata.partial = true;
        metadata.budget_omitted |= name_budget < crate::observation::PROCESS_NAME_MAX_BYTES;
    }

    let path_budget = remaining.min(crate::observation::EXECUTABLE_PATH_MAX_BYTES);
    if let Ok(path) = read_link_bounded(&process_dir.join("exe"), path_budget) {
        remaining = remaining.saturating_sub(path.as_os_str().as_encoded_bytes().len());
        metadata.executable_path = Some(path);
    } else {
        metadata.partial = true;
        metadata.budget_omitted |= path_budget < crate::observation::EXECUTABLE_PATH_MAX_BYTES;
    }

    match read_process_status(&process_dir.join("status")) {
        Ok(ProcessStatus {
            parent_pid: Some(parent_pid),
            ..
        }) => {
            metadata.parent_pid = Some(parent_pid);
            if parent_pid != 0 {
                let parent_name_budget = remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES);
                let parent_marker = read_native_process_marker(
                    &proc_root.join(parent_pid.to_string()).join("stat"),
                );
                let name = parent_marker.ok().and_then(|start_marker| {
                    let identity = ProcessIdentity {
                        pid: parent_pid,
                        start_marker,
                    };
                    if let Some(name) = parent_names.get(&identity) {
                        return name
                            .as_ref()
                            .filter(|name| name.len() <= parent_name_budget)
                            .cloned();
                    }
                    let name = (parent_name_budget != 0)
                        .then(|| {
                            read_bounded_lossy_text(
                                &proc_root.join(parent_pid.to_string()).join("comm"),
                                parent_name_budget,
                            )
                            .ok()
                            .and_then(|text| trimmed_non_empty(&text))
                        })
                        .flatten();
                    let marker_after = read_native_process_marker(
                        &proc_root.join(parent_pid.to_string()).join("stat"),
                    );
                    let verified = matches!(marker_after, Ok(after) if after == start_marker)
                        .then_some(name)
                        .flatten();
                    parent_names.insert(identity, verified.clone());
                    verified
                });
                if let Some(name) = name {
                    metadata.parent_process_name = Some(name);
                    remaining = remaining.saturating_sub(
                        metadata.parent_process_name.as_ref().map_or(0, String::len),
                    );
                } else {
                    metadata.partial = true;
                    metadata.budget_omitted |=
                        parent_name_budget < crate::observation::PROCESS_NAME_MAX_BYTES;
                }
            }
        }
        Ok(ProcessStatus {
            parent_pid: None, ..
        })
        | Err(_) => metadata.partial = true,
    }

    if profile == MetadataProfile::LegacyList {
        let command_line_budget = remaining.min(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES);
        if let Ok((command_line, truncated)) =
            read_cmdline_bounded(&process_dir.join("cmdline"), command_line_budget)
        {
            metadata.command_line = command_line;
            metadata.partial |= truncated;
            metadata.budget_omitted |= truncated;
        } else {
            metadata.partial = true;
            metadata.budget_omitted |=
                command_line_budget < crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
        }
    }

    metadata
}

fn read_link_bounded(path: &Path, max_bytes: usize) -> std::io::Result<PathBuf> {
    if max_bytes == 0 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "symlink target has no remaining byte budget",
        ));
    }
    let read_capacity = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "symlink target byte limit overflow",
        )
    })?;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut bytes = vec![0_u8; read_capacity];
    let written = unsafe {
        // SAFETY: `path` is NUL terminated, `bytes` is writable for its length
        // bytes, and readlink does not retain either pointer.
        libc::readlink(path.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len())
    };
    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let written = usize::try_from(written).expect("non-negative readlink size fits usize");
    if written > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("symlink target exceeds {max_bytes} byte limit"),
        ));
    }
    bytes.truncate(written);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

fn collect_process_context_from(proc_root: &Path, pid: u32) -> ProcessContext {
    let process_dir = proc_root.join(pid.to_string());
    let owner_uid = read_process_status(&process_dir.join("status"))
        .ok()
        .and_then(|status| status.owner_uid);
    let process_start_time_marker = read_process_start_time_ticks(&process_dir.join("stat"))
        .ok()
        .and_then(|ticks| ProcessStartMarker::linux(ticks).ok());
    ProcessContext {
        owner_uid,
        process_start_time_marker,
        children: collect_child_processes_from(proc_root, pid),
        docker: None,
    }
}

fn collect_child_processes_from(proc_root: &Path, parent_pid: u32) -> ChildProcessSnapshot {
    let Ok(pids) = process_ids(proc_root) else {
        return ChildProcessSnapshot::default();
    };

    let mut children = Vec::new();
    let mut truncated = false;
    for pid in pids {
        if pid == parent_pid {
            continue;
        }
        let process_dir = proc_root.join(pid.to_string());
        let Ok(status) = read_process_status(&process_dir.join("status")) else {
            continue;
        };
        if status.parent_pid != Some(parent_pid) {
            continue;
        }

        if children.len() == MAX_CHILD_PROCESSES {
            truncated = true;
            break;
        }
        let process_name = read_process_name(&process_dir).ok().flatten();
        children.push(ChildProcess { pid, process_name });
    }

    ChildProcessSnapshot {
        children,
        truncated,
    }
}

fn collect_related_process_hints_from(proc_root: &Path, port: u16) -> Vec<RelatedProcessHint> {
    collect_related_process_hints_from_with_limit(
        proc_root,
        port,
        diagnostic::RELATED_PROCESS_COMMAND_READS_MAX,
    )
}

fn collect_related_process_hints_from_with_limit(
    proc_root: &Path,
    port: u16,
    command_read_limit: usize,
) -> Vec<RelatedProcessHint> {
    let Ok(pids) = process_ids(proc_root) else {
        return Vec::new();
    };
    let current_pid = std::process::id();
    let excluded_pids = process_ancestor_pids_from(proc_root, current_pid);
    let mut hints = Vec::new();
    let mut command_reads = 0usize;

    for pid in pids.into_iter().rev() {
        if excluded_pids.contains(&pid) {
            continue;
        }
        if command_reads == command_read_limit {
            break;
        }
        command_reads += 1;
        let process_dir = proc_root.join(pid.to_string());
        let Ok((Some(command_line), _truncated)) = read_cmdline(&process_dir.join("cmdline"))
        else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }

        let process_name = read_process_name(&process_dir).ok().flatten();
        hints.push(RelatedProcessHint {
            pid,
            process_name,
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }

    hints
}

/// The Linux end of the process-tree I/O contract.
///
/// Snapshots come from a single `/proc` scan; signal delivery goes through the
/// `process` module's `libc` boundary. Every snapshot is a fresh read, which is
/// exactly what the freeze-first sweep relies on. The one thing held between
/// calls is deliberate state: the per-member pidfds opened before each
/// `SIGSTOP`, making the root and every descendant reuse-proof from the first
/// freeze signal through final delivery and thaw.
pub(crate) struct LinuxTreeOps {
    proc_root: PathBuf,
    delivery_handles: HashMap<u32, TreeDeliveryHandle>,
}

impl LinuxTreeOps {
    pub(crate) fn new() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
            delivery_handles: HashMap::new(),
        }
    }
}

impl TreeProcessOps for LinuxTreeOps {
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        collect_tree_process_infos(&self.proc_root).map_err(|error| error.to_string())
    }

    fn pin_root_for_revalidation(&mut self, pid: u32) -> TreeSignalResult {
        // The verified marker is not known yet at pin time; the pidfd itself is
        // the reuse proof, so nothing is lost by passing None.
        self.prepare_delivery(pid, None)
    }

    fn stop(&mut self, pid: u32, deadline: std::time::Instant) -> TreeStopResult {
        let handle = match self.delivery_handles.remove(&pid) {
            Some(handle) => handle,
            None => match tree_open_delivery_handle(pid) {
                Ok(handle) => handle,
                Err(TreeSignalResult::NotFound) => return TreeStopResult::NotFound,
                Err(TreeSignalResult::Denied) => {
                    return TreeStopResult::Failed {
                        cleanup_required: false,
                        rollback_start_time_marker: None,
                        error: TreeStopError::PermissionDenied,
                    };
                }
                Err(TreeSignalResult::Delivered) => unreachable!("opening a pidfd does not signal"),
            },
        };
        let result = tree_stop_handle(&handle, deadline);
        if matches!(
            result,
            TreeStopResult::Stopped { .. }
                | TreeStopResult::Failed {
                    cleanup_required: true,
                    ..
                }
        ) {
            // Retain the exact process handle whenever rollback may need it.
            self.delivery_handles.insert(pid, handle);
        }
        result
    }

    fn cont(&mut self, pid: u32) -> TreeSignalResult {
        if let Some(handle) = self.delivery_handles.get(&pid) {
            tree_cont_handle(handle)
        } else {
            tree_cont(pid)
        }
    }

    // The verified start marker is unused on Linux: the pidfd opened before the
    // first stop already pins the process object, so delivery can never reach a
    // recycled PID regardless of markers.
    fn prepare_delivery(
        &mut self,
        pid: u32,
        _verified_start_marker: Option<ProcessStartMarker>,
    ) -> TreeSignalResult {
        if self.delivery_handles.contains_key(&pid) {
            return TreeSignalResult::Delivered;
        }
        match tree_open_delivery_handle(pid) {
            Ok(handle) => {
                debug_assert_eq!(handle.pid(), pid);
                self.delivery_handles.insert(pid, handle);
                TreeSignalResult::Delivered
            }
            Err(result) => result,
        }
    }

    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        read_fresh_process_evidence(&self.proc_root, pid)
    }

    fn deliver(&mut self, pid: u32, mode: crate::process::KillMode) -> TreeSignalResult {
        let Some(handle) = self.delivery_handles.get(&pid) else {
            return TreeSignalResult::Denied;
        };
        tree_deliver_handle(handle, mode)
    }
}

fn read_fresh_process_evidence(
    proc_root: &Path,
    pid: u32,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    let process_dir = proc_root.join(pid.to_string());
    let start_marker = read_process_start_time_ticks(&process_dir.join("stat"))
        .map_err(|error| process_evidence_io_error(pid, &error))?;
    // comm is a byte string and the kernel can truncate it mid-UTF-8 scalar.
    // Match collection and protection's bounded lossy representation.
    let name = read_bounded_lossy_text(
        &process_dir.join("comm"),
        crate::observation::PROTECTION_NAME_MAX_BYTES,
    )
    .map_err(|error| {
        if error.kind() == ErrorKind::InvalidData {
            ProcessEvidenceError::NameOversized {
                pid,
                bytes: crate::observation::PROTECTION_NAME_MAX_BYTES + 1,
            }
        } else {
            process_evidence_io_error(pid, &error)
        }
    })?
    .trim_end_matches(['\n', '\r'])
    .to_owned();
    if name.is_empty() {
        return Err(ProcessEvidenceError::NameMissing { pid });
    }
    let marker_after = read_process_start_time_ticks(&process_dir.join("stat"))
        .map_err(|error| process_evidence_io_error(pid, &error))?;
    if marker_after != start_marker {
        return Err(ProcessEvidenceError::IdentityChanged { pid });
    }
    Ok(FreshProcessEvidence {
        pid,
        start_marker: ProcessStartMarker::linux(marker_after)
            .map_err(|_| ProcessEvidenceError::IdentityChanged { pid })?,
        name,
    })
}

fn process_evidence_io_error(pid: u32, error: &std::io::Error) -> ProcessEvidenceError {
    if error.kind() == ErrorKind::PermissionDenied {
        ProcessEvidenceError::PermissionDenied { pid }
    } else {
        ProcessEvidenceError::Missing { pid }
    }
}

/// Read one snapshot of the process table for scoped tree execution.
///
/// Reuses the same bounded `/proc` readers as the socket collector, so every
/// read here is capped exactly like the rest of the module. Fail-closed on
/// purpose: a process that vanished mid-scan (`NotFound`/`ESRCH`) is skipped, but a
/// live process whose name, parent, or start marker cannot be read is a hard
/// error. Tree kill must not run against a table with holes because
/// a missing parent edge silently drops that process's whole subtree.
fn collect_tree_process_infos(proc_root: &Path) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let pids = process_ids(proc_root).map_err(|source| CollectorError::Read {
        path: proc_root.to_path_buf(),
        source,
    })?;

    let mut infos = Vec::with_capacity(pids.len());
    for pid in pids {
        let process_dir = proc_root.join(pid.to_string());
        let Some(status) = read_tree_status(&process_dir.join("status"))? else {
            continue;
        };
        let Some(process_name) = read_tree_process_name(&process_dir)? else {
            continue;
        };
        let Some(stat) = read_tree_stat(&process_dir.join("stat"))? else {
            continue;
        };
        infos.push(TreeProcessInfo {
            pid,
            parent_pid: status.parent_pid,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(process_name),
            start_time_marker: Some(stat.start_time_marker),
            owner_uid: status.owner_uid,
            process_group: stat.process_group,
        });
    }
    Ok(infos)
}

/// The two `stat` fields the tree snapshot carries, read in one pass.
struct TreeStat {
    start_time_marker: ProcessStartMarker,
    process_group: Option<u32>,
}

fn read_tree_status(path: &Path) -> Result<Option<ProcessStatus>, CollectorError> {
    match read_process_status(path) {
        Ok(status) => Ok(Some(status)),
        Err(error) if process_vanished(&error) => Ok(None),
        Err(source) => Err(CollectorError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn process_vanished(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn read_tree_process_name(process_dir: &Path) -> Result<Option<String>, CollectorError> {
    let path = process_dir.join("comm");
    match read_process_name(process_dir) {
        Ok(Some(name)) => Ok(Some(name)),
        Ok(None) => Err(CollectorError::Read {
            path,
            source: std::io::Error::new(ErrorKind::InvalidData, "empty process name"),
        }),
        Err(error) if process_vanished(&error) => Ok(None),
        Err(source) => Err(CollectorError::Read { path, source }),
    }
}

fn read_tree_stat(path: &Path) -> Result<Option<TreeStat>, CollectorError> {
    let bytes = match read_stat_bytes(path) {
        Ok(bytes) => bytes,
        Err(error) if process_vanished(&error) => return Ok(None),
        Err(source) => {
            return Err(CollectorError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    // Both fields are kill-safety data and fail closed: group kill derives its
    // membership from the group ID, so an unreadable group would be a silent
    // hole in the member set, exactly like a missing start marker would be a
    // hole in identity verification. Group 0 is the kernel's own group and is
    // not targetable, so it maps to "no targetable group" rather than an error.
    let start_time_marker = parse_process_start_time_ticks(&bytes)
        .and_then(|ticks| {
            ProcessStartMarker::linux(ticks)
                .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
        })
        .map_err(|source| CollectorError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(process_group) = parse_process_group_id(&bytes) else {
        return Err(CollectorError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(ErrorKind::InvalidData, "process group is unreadable"),
        });
    };
    Ok(Some(TreeStat {
        start_time_marker,
        process_group: (process_group != 0).then_some(process_group),
    }))
}

fn read_stat_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    read_bounded_bytes(path, MAX_STAT_BYTES)
}

/// Process group ID from `/proc/<pid>/stat`: field 5 overall, so the third
/// token after the `") "` comm terminator (state, ppid, pgrp).
fn parse_process_group_id(bytes: &[u8]) -> Option<u32> {
    let value = stat_field(bytes, 2).ok()?;
    std::str::from_utf8(value).ok()?.parse::<u32>().ok()
}

fn process_ancestor_pids_from(proc_root: &Path, pid: u32) -> HashSet<u32> {
    let mut ancestors = HashSet::from([pid]);
    let mut current = pid;
    for _ in 0..MAX_PROCESS_ANCESTORS {
        let process_dir = proc_root.join(current.to_string());
        let Some(parent_pid) = read_process_status(&process_dir.join("status"))
            .ok()
            .and_then(|status| status.parent_pid)
        else {
            break;
        };
        if !ancestors.insert(parent_pid) {
            break;
        }
        current = parent_pid;
    }
    ancestors
}

fn read_process_name(process_dir: &Path) -> std::io::Result<Option<String>> {
    let mut text = read_bounded_lossy_text(&process_dir.join("comm"), PROCESS_NAME_MAX_BYTES)?;
    let trimmed_len = text.trim_end_matches(['\n', '\r']).len();
    text.truncate(trimmed_len);
    Ok((!text.is_empty()).then_some(text))
}

fn read_process_status(path: &Path) -> std::io::Result<ProcessStatus> {
    parse_process_status(&read_bounded_text(path, MAX_STATUS_BYTES)?)
}

fn read_process_start_time_ticks(path: &Path) -> std::io::Result<u64> {
    parse_process_start_time_ticks(&read_bounded_bytes_with_overflow_kind(
        path,
        MAX_STAT_BYTES,
        ErrorKind::FileTooLarge,
    )?)
}

fn parse_process_start_time_ticks(bytes: &[u8]) -> std::io::Result<u64> {
    // `/proc/<pid>/stat` is `pid (comm) state ...`, and comm is an unescaped task
    // name that can itself contain `)` and even `) `. Every field after comm is a
    // single char or an integer and holds no parens, so the *last* `") "` in the
    // line is always the real comm terminator. Splitting from the right is what
    // keeps this robust against a process named e.g. `ev) il`; a first/left split
    // would be fooled by a paren inside comm.
    // Once comm is stripped the fields are 1-indexed from `state` (field 3), so
    // start time (field 22) is the 20th token here, or nth(19) zero-indexed.
    let start_time = stat_field(bytes, 19)?;
    let start_time = std::str::from_utf8(start_time)
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))?;
    start_time
        .parse::<u64>()
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))
}

fn stat_field(bytes: &[u8], index: usize) -> std::io::Result<&[u8]> {
    let comm_end = bytes
        .windows(2)
        .rposition(|window| window == b") ")
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "missing process-name terminator")
        })?;
    bytes[comm_end + 2..]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .nth(index)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing process stat field"))
}

fn parse_process_status(text: &str) -> std::io::Result<ProcessStatus> {
    let mut status = ProcessStatus::default();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("PPid:") {
            status.parent_pid = Some(parse_status_u32(value)?);
        } else if let Some(value) = line.strip_prefix("Uid:") {
            status.owner_uid = Some(parse_status_u32(value)?);
        }
    }
    Ok(status)
}

fn parse_status_u32(value: &str) -> std::io::Result<u32> {
    let first = value
        .split_whitespace()
        .next()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing numeric value"))?;
    first
        .parse::<u32>()
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))
}

#[cfg(any(test, fuzzing))]
pub(crate) fn exercise_proc_parser(bytes: &[u8]) {
    const FUZZ_INPUT_BYTES_MAX: usize = 64 * 1024;
    let Some((&selector, payload)) = bytes.split_first() else {
        return;
    };
    if payload.len() > FUZZ_INPUT_BYTES_MAX {
        return;
    }
    match selector % 3 {
        0 => {
            let _ = parse_process_start_time_ticks(payload);
            let _ = parse_process_group_id(payload);
        }
        1 => {
            if let Ok(text) = std::str::from_utf8(payload) {
                let _ = parse_process_status(text);
            }
        }
        2 => {
            if let Ok(text) = std::str::from_utf8(payload) {
                for (protocol, address_family) in [
                    (Protocol::Tcp, AddressFamily::Ipv4),
                    (Protocol::Tcp, AddressFamily::Ipv6),
                    (Protocol::Udp, AddressFamily::Ipv4),
                    (Protocol::Udp, AddressFamily::Ipv6),
                ] {
                    let _ = parse_socket_table(text, protocol, address_family, Some(100), 64);
                }
            }
        }
        _ => unreachable!("selector modulo three must be in 0..3"),
    }
}

fn trimmed_non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn read_cmdline(path: &Path) -> std::io::Result<(Option<String>, bool)> {
    read_cmdline_bounded(path, MAX_CMDLINE_BYTES)
}

fn read_cmdline_bounded(path: &Path, max_bytes: usize) -> std::io::Result<(Option<String>, bool)> {
    let file = File::open(path)?;
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "cmdline limit is too large"))?
        .checked_add(1)
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "cmdline limit is too large")
        })?;
    let mut reader = file.take(read_limit);
    let capacity = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "cmdline limit is too large")
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;

    let truncated = bytes.len() > max_bytes;
    if truncated {
        return Ok((None, true));
    }

    Ok(decode_cmdline(&bytes, max_bytes))
}

fn decode_cmdline(bytes: &[u8], max_bytes: usize) -> (Option<String>, bool) {
    let mut output_len = 0usize;
    let mut argument_count = 0usize;
    for argument in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        let Some(argument_len) = crate::observation::lossy_utf8_len(argument) else {
            return (None, true);
        };
        let separator_len = usize::from(argument_count != 0);
        let Some(next_len) = output_len
            .checked_add(separator_len)
            .and_then(|length| length.checked_add(argument_len))
        else {
            return (None, true);
        };
        if next_len > max_bytes {
            return (None, true);
        }
        output_len = next_len;
        argument_count += 1;
    }

    if argument_count == 0 {
        return (None, false);
    }

    let mut output = String::with_capacity(output_len);
    for argument in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        if !output.is_empty() {
            output.push(' ');
        }
        crate::observation::push_utf8_lossy(&mut output, argument);
    }
    debug_assert_eq!(output.len(), output_len);
    (Some(output), false)
}

#[cfg(test)]
mod tests;
