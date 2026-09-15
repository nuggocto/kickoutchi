//! Native macOS socket collection through libproc.
//!
//! macOS does not have Linux's `/proc/net` tables or Windows' IP Helper owner
//! tables. Collection is process-first: list PIDs, read descriptors with
//! `proc_pidinfo`, then inspect sockets with `proc_pidfdinfo`. Darwin FFI layouts
//! remain inside this module.

#![allow(
    clippy::struct_field_names,
    reason = "Darwin FFI structs mirror the C header names exactly"
)]

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::{CStr, OsStr, c_void};
use std::mem::{MaybeUninit, align_of, offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, ProcessContext, Protocol, RelatedProcessHint,
};
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact,
    FILE_DESCRIPTOR_ENTRIES_MAX, Ipv6Scope, MetadataCompleteness, MetadataOmission,
    MetadataProfile, NATIVE_RESIZE_ATTEMPTS_MAX, NativeSocketObservation, NativeSocketRow,
    NetworkSnapshot, ObservationScope, ObservationScopeKind, OwnerCompleteness,
    PlatformSocketToken, ProcessIdentity, ProcessObservation, ProcessRead, ProcessReadBatch,
    ProcessStartMarker, ScopeLimitation, SocketState as ObservationSocketState,
    UnverifiedOwnerReason,
};
use crate::observation::{OWNER_EDGES_MAX, SOCKET_OBSERVATIONS_MAX};
use crate::process::{tree_cont, tree_deliver_by_pid, tree_prepare_delivery_probe, tree_stop};
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};
use crate::tree::{
    MAX_TREE_PROCESSES, TreeProcessInfo, TreeProcessOps, TreeSignalResult, TreeSnapshotScope,
    TreeStopResult,
};

use super::{MAX_CHILD_PROCESSES, MAX_PROCESS_ANCESTORS, MAX_RELATED_PROCESS_HINTS};

const PROCESS_LIST_GROWTH_MARGIN: usize = 64;
const FD_LIST_GROWTH_MARGIN: usize = 16;
const MAX_PROCESS_FDS: usize = 65_536;

const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const SOCKINFO_IN: libc::c_int = 1;
const SOCKINFO_TCP: libc::c_int = 2;
const TSI_S_CLOSED: libc::c_int = 0;
const TSI_S_LISTEN: libc::c_int = 1;
const TSI_S_SYN_SENT: libc::c_int = 2;
const TSI_S_SYN_RECEIVED: libc::c_int = 3;
const TSI_S_ESTABLISHED: libc::c_int = 4;
const TSI_S_CLOSE_WAIT: libc::c_int = 5;
const TSI_S_FIN_WAIT_1: libc::c_int = 6;
const TSI_S_CLOSING: libc::c_int = 7;
const TSI_S_LAST_ACK: libc::c_int = 8;
const TSI_S_FIN_WAIT_2: libc::c_int = 9;
const TSI_S_TIME_WAIT: libc::c_int = 10;
const SOCK_MAXADDRLEN: usize = 255;
const MAX_KCTL_NAME: usize = 96;

pub(crate) struct MacosCollector;

impl Collector for MacosCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        let scope = ObservationScope::new(
            ObservationScopeKind::CurrentHostProcessVisibleSockets,
            None,
            [
                ScopeLimitation::ProcessFirstSocketVisibilityLimited,
                ScopeLimitation::Ipv6ScopeUnavailable,
                ScopeLimitation::ScopedIpv6ExactMatchingUnavailable,
            ],
        )?;
        crate::collector::collect_native_snapshot(
            profile,
            scope,
            |_profile| Self::collect_native_pass(),
            Self::read_native_processes,
        )
    }
}

impl MacosCollector {
    fn read_native_processes(
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
                Ok(Self::read_native_process(
                    pid,
                    profile,
                    remaining,
                    &mut parent_names,
                ))
            },
        )
    }

    fn collect_native_pass() -> Result<crate::observation::NativeObservationPass, CollectorError> {
        Self::collect_native_pass_with(process_ids, collect_pid_socket_records)
    }

    fn collect_native_pass_with<ListProcesses, ScanProcess>(
        mut list_processes: ListProcesses,
        mut scan_process: ScanProcess,
    ) -> Result<crate::observation::NativeObservationPass, CollectorError>
    where
        ListProcesses: FnMut() -> Result<Vec<u32>, CollectorError>,
        ScanProcess: FnMut(
            u32,
            &mut usize,
        )
            -> Result<(Vec<SocketRecord>, BTreeSet<SocketScanLoss>), std::io::Error>,
    {
        let mut grouped_records = Vec::<GroupedSocketRecord>::new();
        let mut socket_indexes = HashMap::<u64, usize>::new();
        let mut socket_set_losses = BTreeSet::new();
        let mut omitted_socket_set_loss_count = 0u64;
        let pids = list_processes()?;
        let mut aggregate_fd_entries = 0usize;
        let mut owner_edges = 0usize;
        for pid in pids {
            let (records, pid_losses) = match scan_process(pid, &mut aggregate_fd_entries) {
                Ok(scan) => scan,
                Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
                    return Err(
                        crate::observation::ObservationError::OwnerAttributionLimitExceeded.into(),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::OutOfMemory => {
                    return Err(platform_error(
                        "proc_pidinfo(PROC_PIDLISTFDS)",
                        error.to_string(),
                    ));
                }
                Err(error) => {
                    retain_socket_scan_loss(
                        &mut socket_set_losses,
                        &mut omitted_socket_set_loss_count,
                        socket_scan_loss(pid, &error),
                    );
                    continue;
                }
            };
            for loss in pid_losses {
                retain_socket_scan_loss(
                    &mut socket_set_losses,
                    &mut omitted_socket_set_loss_count,
                    loss,
                );
            }
            for record in records {
                retain_socket_record(
                    &mut grouped_records,
                    &mut socket_indexes,
                    &mut owner_edges,
                    &mut socket_set_losses,
                    &mut omitted_socket_set_loss_count,
                    record,
                    pid,
                )?;
            }
        }
        native_pass_from_records(
            grouped_records,
            socket_set_losses,
            omitted_socket_set_loss_count,
        )
    }

    fn read_native_process(
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
        parent_names: &mut HashMap<ProcessIdentity, ParentNameRead>,
    ) -> ProcessRead {
        let info = match read_process_bsdinfo(pid) {
            Ok(info) => info,
            Err(error) => return ProcessRead::Unverified(unverified_reason_for_io(&error)),
        };
        let Ok(microseconds) = u32::try_from(info.pbi_start_tvusec) else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        let Ok(marker) = ProcessStartMarker::macos(info.pbi_start_tvsec, microseconds) else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        if profile == MetadataProfile::IdentityOnly {
            return ProcessRead::Verified {
                marker,
                observation: ProcessObservation::identity_only(),
            };
        }
        let metadata = if optional_metadata_bytes_remaining == 0 {
            ProcessMetadata {
                partial: true,
                budget_omitted: true,
                ..ProcessMetadata::default()
            }
        } else {
            read_process_metadata_bounded(
                pid,
                profile,
                optional_metadata_bytes_remaining,
                parent_names,
            )
        };
        let after = match read_process_bsdinfo(pid) {
            Ok(info) => info,
            Err(error) => return ProcessRead::Unverified(unverified_reason_for_io(&error)),
        };
        let Ok(after_microseconds) = u32::try_from(after.pbi_start_tvusec) else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        let Ok(marker_after) = ProcessStartMarker::macos(after.pbi_start_tvsec, after_microseconds)
        else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        if marker_after != marker {
            return ProcessRead::Unverified(UnverifiedOwnerReason::Raced);
        }
        ProcessRead::Verified {
            marker: marker_after,
            observation: process_observation_from_metadata(metadata),
        }
    }
}

fn retain_socket_record(
    grouped_records: &mut Vec<GroupedSocketRecord>,
    socket_indexes: &mut HashMap<u64, usize>,
    owner_edges: &mut usize,
    socket_set_losses: &mut BTreeSet<SocketScanLoss>,
    omitted_socket_set_loss_count: &mut u64,
    record: SocketRecord,
    pid: u32,
) -> Result<(), CollectorError> {
    let socket_token = (record.socket_id != 0).then_some(record.socket_id);
    if let Some(token) = socket_token
        && let Some(index) = socket_indexes.get(&token).copied()
    {
        if !grouped_records[index].socket.same_non_owner_facts(&record) {
            retain_socket_scan_loss(
                socket_set_losses,
                omitted_socket_set_loss_count,
                SocketScanLoss::TokenConflict,
            );
            return Ok(());
        }
        if sorted_owner_is_new(&grouped_records[index].owner_pids, pid) {
            if *owner_edges >= OWNER_EDGES_MAX {
                return Err(
                    crate::observation::ObservationError::OwnerAttributionLimitExceeded.into(),
                );
            }
            grouped_records[index].owner_pids.push(pid);
            *owner_edges += 1;
        }
        return Ok(());
    }
    if grouped_records.len() >= SOCKET_OBSERVATIONS_MAX {
        return Err(crate::observation::ObservationError::SocketObservationLimitExceeded.into());
    }
    if *owner_edges >= OWNER_EDGES_MAX {
        return Err(crate::observation::ObservationError::OwnerAttributionLimitExceeded.into());
    }
    if let Some(token) = socket_token {
        socket_indexes.insert(token, grouped_records.len());
    }
    grouped_records.push(GroupedSocketRecord {
        socket: record,
        owner_pids: vec![pid],
    });
    *owner_edges += 1;
    Ok(())
}

fn sorted_owner_is_new(owners: &[u32], pid: u32) -> bool {
    owners.last().copied() != Some(pid)
}

pub(crate) fn fresh_process_evidence(
    pid: u32,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    let before =
        read_process_bsdinfo(pid).map_err(|error| process_evidence_io_error(pid, &error))?;
    let name = read_process_name(pid)
        .map_err(|error| process_evidence_io_error(pid, &error))?
        .or_else(|| process_name_from_bsd_info(&before))
        .ok_or(ProcessEvidenceError::NameMissing { pid })?;
    let after =
        read_process_bsdinfo(pid).map_err(|error| process_evidence_io_error(pid, &error))?;
    fresh_process_evidence_from_reads(pid, &before, name, &after)
}

fn fresh_process_evidence_from_reads(
    pid: u32,
    before: &libc::proc_bsdinfo,
    name: String,
    after: &libc::proc_bsdinfo,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    if name.is_empty() {
        return Err(ProcessEvidenceError::NameMissing { pid });
    }
    let before_marker = process_start_time_marker_from_bsd_info(before)
        .map_err(|_| ProcessEvidenceError::IdentityChanged { pid })?;
    let after_marker = process_start_time_marker_from_bsd_info(after)
        .map_err(|_| ProcessEvidenceError::IdentityChanged { pid })?;
    if before_marker != after_marker {
        return Err(ProcessEvidenceError::IdentityChanged { pid });
    }
    if name.len() > crate::observation::PROTECTION_NAME_MAX_BYTES {
        return Err(ProcessEvidenceError::NameOversized {
            pid,
            bytes: name.len(),
        });
    }
    Ok(FreshProcessEvidence {
        pid,
        start_marker: after_marker,
        name,
    })
}

fn process_evidence_io_error(pid: u32, error: &std::io::Error) -> ProcessEvidenceError {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => ProcessEvidenceError::PermissionDenied { pid },
        _ => ProcessEvidenceError::Missing { pid },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SocketRecordKey {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    socket_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    state: ObservationSocketState,
    socket_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupedSocketRecord {
    socket: SocketRecord,
    owner_pids: Vec<u32>,
}

impl SocketRecord {
    fn key(&self) -> SocketRecordKey {
        SocketRecordKey {
            protocol: self.protocol,
            local_addr: self.local_addr,
            local_port: self.local_port,
            socket_id: self.socket_id,
        }
    }

    fn same_non_owner_facts(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.local_addr == other.local_addr
            && self.local_port == other.local_port
            && self.state == other.state
            && self.socket_id == other.socket_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SocketScanLoss {
    TokenConflict,
    PermissionDenied(u32),
    Disappeared(u32),
    Malformed(u32),
    Unavailable(u32),
}

fn native_pass_from_records(
    records: Vec<GroupedSocketRecord>,
    losses: BTreeSet<SocketScanLoss>,
    mut omitted_evidence_gap_count: u64,
) -> Result<crate::observation::NativeObservationPass, CollectorError> {
    let rows = records
        .into_iter()
        .map(|record| {
            let GroupedSocketRecord { socket, owner_pids } = record;
            let ipv6_scope = socket
                .local_addr
                .is_ipv6()
                .then_some(Ipv6Scope::Unavailable);
            let endpoint = EndpointIdentity::new(
                socket.protocol,
                socket.local_addr,
                u32::from(socket.local_port),
                ipv6_scope,
            )
            .map_err(|error| {
                CollectorError::Observation(
                    crate::observation::ObservationError::PlatformApiFailed(error.to_string()),
                )
            })?;
            Ok(NativeSocketRow {
                socket: NativeSocketObservation {
                    endpoint,
                    state: socket.state,
                    timer: None,
                    token: PlatformSocketToken::macos_socket_id(socket.socket_id),
                },
                owner_pids,
                owner_completeness: OwnerCompleteness::Complete,
            })
        })
        .collect::<Result<Vec<_>, CollectorError>>()?;

    let mut evidence_gaps = Vec::with_capacity(losses.len());
    for loss in losses {
        let (pid, code, message) = match loss {
            SocketScanLoss::TokenConflict => (
                None,
                EvidenceGapCode::NativeFieldUnavailable,
                "conflicting facts for one native socket token made the socket set ambiguous",
            ),
            SocketScanLoss::PermissionDenied(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerPermissionDenied,
                "permission denied before the PID's socket descriptors could be enumerated",
            ),
            SocketScanLoss::Disappeared(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerDisappeared,
                "PID or socket descriptor disappeared during socket enumeration",
            ),
            SocketScanLoss::Malformed(pid) => (
                Some(pid),
                EvidenceGapCode::NativeFieldUnavailable,
                "malformed socket descriptor information could have hidden a socket",
            ),
            SocketScanLoss::Unavailable(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerAttributionIncomplete,
                "a PID socket scan failed before its socket set could be enumerated",
            ),
        };
        evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            code,
            None,
            pid,
            message,
        ));
    }
    if rows
        .iter()
        .any(|row| row.socket.endpoint.ipv6_scope == Some(Ipv6Scope::Unavailable))
    {
        if evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
            evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::Scope,
                EvidenceGapCode::NativeFieldUnavailable,
                None,
                None,
                "IPv6 scope identifiers are unavailable from macOS socket descriptor rows",
            ));
        } else {
            omitted_evidence_gap_count = omitted_evidence_gap_count.saturating_add(1);
        }
    }
    Ok(crate::observation::NativeObservationPass {
        rows,
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps,
        omitted_evidence_gap_count,
    })
}

fn socket_scan_loss(pid: u32, error: &std::io::Error) -> SocketScanLoss {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => SocketScanLoss::PermissionDenied(pid),
        Some(libc::ESRCH | libc::ENOENT) => SocketScanLoss::Disappeared(pid),
        _ if error.kind() == std::io::ErrorKind::InvalidData => SocketScanLoss::Malformed(pid),
        _ => SocketScanLoss::Unavailable(pid),
    }
}

fn retain_socket_scan_loss(
    losses: &mut BTreeSet<SocketScanLoss>,
    omitted: &mut u64,
    loss: SocketScanLoss,
) {
    if losses.contains(&loss) {
        return;
    }
    if losses.len() < crate::observation::EVIDENCE_GAPS_MAX {
        losses.insert(loss);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn process_observation_from_metadata(mut metadata: ProcessMetadata) -> ProcessObservation {
    if metadata
        .executable_path
        .as_ref()
        .is_some_and(|path| path.to_str().is_none())
    {
        metadata.executable_path = None;
        metadata.partial = true;
    }
    ProcessObservation {
        name: metadata.process_name.map(Into::into),
        executable_path: metadata.executable_path.map(Into::into),
        command_line: metadata.command_line.map(Into::into),
        parent_pid: metadata.parent_pid,
        parent_process_name: metadata.parent_process_name.map(Into::into),
        metadata_omission: metadata
            .budget_omitted
            .then_some(MetadataOmission::BudgetExceeded),
        metadata_completeness: if metadata.partial {
            MetadataCompleteness::Partial
        } else {
            MetadataCompleteness::Complete
        },
    }
}

fn unverified_reason_for_io(error: &std::io::Error) -> UnverifiedOwnerReason {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => UnverifiedOwnerReason::PermissionDenied,
        Some(libc::ESRCH | libc::ENOENT) => UnverifiedOwnerReason::Disappeared,
        _ => UnverifiedOwnerReason::IdentityUnavailable,
    }
}

#[derive(Debug, Clone, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    partial: bool,
    budget_omitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParentNameRead {
    Value(String),
    Unavailable,
    BudgetExceeded,
}

#[derive(Debug, PartialEq, Eq)]
enum CommandLineRead {
    Missing,
    Value(String),
    Omitted,
}

#[repr(C)]
struct ProcFileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: libc::off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct In4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: libc::in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
union InSocketAddress {
    ina_46: In4In6Addr,
    ina_6: libc::in6_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfo {
    insi_fport: libc::c_int,
    insi_lport: libc::c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: InSocketAddress,
    insi_laddr: InSocketAddress,
    insi_v4: InSockinfoV4,
    insi_v6: InSockinfoV6,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfoV4 {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfoV6 {
    in6_hlim: u8,
    in6_cksum: libc::c_int,
    in6_ifindex: u16,
    in6_hops: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: libc::c_int,
    tcpsi_timer: [libc::c_int; 4],
    tcpsi_mss: libc::c_int,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnSockinfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: [u8; SOCK_MAXADDRLEN],
    unsi_caddr: [u8; SOCK_MAXADDRLEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NdrvInfo {
    ndrvsi_if_family: u32,
    ndrvsi_if_unit: u32,
    ndrvsi_if_name: [libc::c_char; libc::IF_NAMESIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernCtlInfo {
    kcsi_id: u32,
    kcsi_reg_unit: u32,
    kcsi_flags: u32,
    kcsi_recvbufsize: u32,
    kcsi_sendbufsize: u32,
    kcsi_unit: u32,
    kcsi_name: [libc::c_char; MAX_KCTL_NAME],
}

#[repr(C)]
#[derive(Clone, Copy)]
union SocketProtocolInfo {
    pri_in: InSockinfo,
    pri_tcp: TcpSockinfo,
    pri_un: UnSockinfo,
    pri_ndrv: NdrvInfo,
    pri_kern_ctl: KernCtlInfo,
}

#[repr(C)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
struct SocketInfo {
    soi_stat: libc::vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: libc::c_int,
    soi_protocol: libc::c_int,
    soi_family: libc::c_int,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: libc::c_int,
    rfu_1: u32,
    soi_proto: SocketProtocolInfo,
}

#[repr(C)]
struct SocketFdinfo {
    pfi: ProcFileinfo,
    psi: SocketInfo,
}

// These layouts are the public 64-bit Darwin ABI from <sys/proc_info.h>.
// Both supported macOS targets use the same LP64 layout. Keeping the checks in
// production source makes both cross-target builds reject ABI drift even when
// target tests cannot execute on the build host.
const _: () = {
    assert!(libc::PROX_FDTYPE_SOCKET == 2);

    assert!(size_of::<ProcFileinfo>() == 24);
    assert!(align_of::<ProcFileinfo>() == 8);
    assert!(offset_of!(ProcFileinfo, fi_openflags) == 0);
    assert!(offset_of!(ProcFileinfo, fi_status) == 4);
    assert!(offset_of!(ProcFileinfo, fi_offset) == 8);
    assert!(offset_of!(ProcFileinfo, fi_type) == 16);
    assert!(offset_of!(ProcFileinfo, fi_guardflags) == 20);

    assert!(size_of::<In4In6Addr>() == 16);
    assert!(align_of::<In4In6Addr>() == 4);
    assert!(size_of::<InSocketAddress>() == 16);
    assert!(align_of::<InSocketAddress>() == 4);
    assert!(size_of::<InSockinfo>() == 80);
    assert!(align_of::<InSockinfo>() == 8);
    assert!(offset_of!(InSockinfo, insi_fport) == 0);
    assert!(offset_of!(InSockinfo, insi_lport) == 4);
    assert!(offset_of!(InSockinfo, insi_gencnt) == 8);
    assert!(offset_of!(InSockinfo, insi_flags) == 16);
    assert!(offset_of!(InSockinfo, insi_flow) == 20);
    assert!(offset_of!(InSockinfo, insi_vflag) == 24);
    assert!(offset_of!(InSockinfo, insi_ip_ttl) == 25);
    assert!(offset_of!(InSockinfo, rfu_1) == 28);
    assert!(offset_of!(InSockinfo, insi_faddr) == 32);
    assert!(offset_of!(InSockinfo, insi_laddr) == 48);
    assert!(offset_of!(InSockinfo, insi_v4) == 64);
    assert!(offset_of!(InSockinfo, insi_v6) == 68);
    assert!(offset_of!(InSockinfoV6, in6_ifindex) == 8);

    assert!(size_of::<TcpSockinfo>() == 120);
    assert!(align_of::<TcpSockinfo>() == 8);
    assert!(offset_of!(TcpSockinfo, tcpsi_ini) == 0);
    assert!(offset_of!(TcpSockinfo, tcpsi_state) == 80);
    assert!(offset_of!(TcpSockinfo, tcpsi_timer) == 84);
    assert!(offset_of!(TcpSockinfo, tcpsi_mss) == 100);
    assert!(offset_of!(TcpSockinfo, tcpsi_flags) == 104);
    assert!(offset_of!(TcpSockinfo, rfu_1) == 108);
    assert!(offset_of!(TcpSockinfo, tcpsi_tp) == 112);

    assert!(size_of::<UnSockinfo>() == 528);
    assert!(align_of::<UnSockinfo>() == 8);
    assert!(size_of::<SocketProtocolInfo>() == 528);
    assert!(align_of::<SocketProtocolInfo>() == 8);
    assert!(size_of::<SockbufInfo>() == 24);
    assert!(align_of::<SockbufInfo>() == 4);

    assert!(size_of::<libc::vinfo_stat>() == 136);
    assert!(align_of::<libc::vinfo_stat>() == 8);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(align_of::<SocketInfo>() == 8);
    assert!(offset_of!(SocketInfo, soi_stat) == 0);
    assert!(offset_of!(SocketInfo, soi_so) == 136);
    assert!(offset_of!(SocketInfo, soi_pcb) == 144);
    assert!(offset_of!(SocketInfo, soi_type) == 152);
    assert!(offset_of!(SocketInfo, soi_protocol) == 156);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_options) == 164);
    assert!(offset_of!(SocketInfo, soi_state) == 168);
    assert!(offset_of!(SocketInfo, soi_oobmark) == 180);
    assert!(offset_of!(SocketInfo, soi_rcv) == 184);
    assert!(offset_of!(SocketInfo, soi_snd) == 208);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, rfu_1) == 236);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);

    assert!(size_of::<SocketFdinfo>() == 792);
    assert!(align_of::<SocketFdinfo>() == 8);
    assert!(offset_of!(SocketFdinfo, pfi) == 0);
    assert!(offset_of!(SocketFdinfo, psi) == 24);
};

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    let bsd_info = read_process_bsdinfo(pid).ok();
    ProcessContext {
        owner_uid: bsd_info.as_ref().map(|info| info.pbi_uid),
        process_start_time_marker: bsd_info
            .as_ref()
            .and_then(|info| process_start_time_marker_from_bsd_info(info).ok()),
        children: collect_child_processes(pid),
        docker: None,
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<ProcessStartMarker> {
    process_start_time_marker_result(pid).ok()
}

pub(crate) fn process_start_time_marker_result(pid: u32) -> std::io::Result<ProcessStartMarker> {
    let info = read_process_bsdinfo(pid)?;
    process_start_time_marker_from_bsd_info(&info)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Best-effort command line for one PID, for the read-only inspect view.
/// `None` covers vanished, restricted, and kernel processes alike. Inspect
/// renders it as unknown rather than failing the report.
pub(crate) fn process_command_line(pid: u32) -> Option<String> {
    read_command_line(pid).ok().flatten()
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    let Ok(pids) = process_ids() else {
        return Vec::new();
    };
    let excluded_pids = process_ancestor_pids(std::process::id());
    let mut hints = Vec::new();
    let mut command_reads = 0usize;

    for pid in pids.into_iter().rev() {
        if excluded_pids.contains(&pid) {
            continue;
        }
        if command_reads == diagnostic::RELATED_PROCESS_COMMAND_READS_MAX {
            break;
        }
        command_reads += 1;
        let Ok(Some(command_line)) = read_command_line(pid) else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }
        hints.push(RelatedProcessHint {
            pid,
            process_name: read_process_name(pid).ok().flatten(),
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }

    hints
}

/// The macOS end of the process-tree I/O contract.
///
/// Snapshots come from one `proc_listallpids` walk with a `proc_bsdinfo` read
/// per PID; signal delivery goes through the `process` module's shared `kill(2)`
/// boundary. Darwin has no pidfd, so delivery cannot be pinned to a process
/// object the way Linux pins it. The stop-verify gate narrows the gap because a
/// stopped process cannot fork, exec, or exit on its own. An external
/// `SIGKILL` can still remove a stopped process, and for a member whose parent
/// is running (the root, and group members with parents outside the group) the
/// zombie can be reaped and the PID recycled before our raw-PID signal lands.
/// To shrink that window, `prepare_delivery` records each member's verified
/// start marker and every subsequent raw-PID signal re-reads and compares the
/// marker immediately before `kill(2)`. The residual race is the few
/// instructions between that read and the signal; without a pidfd equivalent
/// it cannot be closed completely.
pub(crate) struct MacosTreeOps {
    verified_markers: std::collections::HashMap<u32, ProcessStartMarker>,
    snapshot_scope: TreeSnapshotScope,
}

impl MacosTreeOps {
    pub(crate) fn new() -> Self {
        Self {
            verified_markers: std::collections::HashMap::new(),
            snapshot_scope: TreeSnapshotScope::Full,
        }
    }

    /// Whether `pid` still carries the start marker the pipeline verified.
    ///
    /// `Ok(())` only when a recorded marker still matches; `Err` when identity
    /// is unavailable, the process is gone, or the PID was recycled.
    fn recheck_marker(&self, pid: u32) -> Result<(), TreeSignalResult> {
        self.recheck_marker_with(pid, |pid| {
            read_process_bsdinfo(pid)
                .map(|info| process_start_time_marker_from_bsd_info(&info).ok())
        })
    }

    fn recheck_marker_with<Read>(&self, pid: u32, read_marker: Read) -> Result<(), TreeSignalResult>
    where
        Read: FnOnce(u32) -> std::io::Result<Option<ProcessStartMarker>>,
    {
        let Some(expected) = self.verified_markers.get(&pid) else {
            return Err(TreeSignalResult::Denied);
        };
        match read_marker(pid) {
            Ok(Some(actual)) if actual == *expected => Ok(()),
            // A different marker means the verified process is gone and the
            // PID now belongs to someone else: report the member as exited
            // rather than signalling the stranger.
            Ok(_) => Err(TreeSignalResult::NotFound),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                Err(TreeSignalResult::NotFound)
            }
            // An unreadable marker cannot prove identity; fail closed.
            Err(_) => Err(TreeSignalResult::Denied),
        }
    }

    fn rollback_identity_after_stop_with<Read>(
        pid: u32,
        read_marker: Read,
    ) -> Option<ProcessStartMarker>
    where
        Read: FnOnce(u32) -> std::io::Result<Option<ProcessStartMarker>>,
    {
        read_marker(pid).ok().flatten()
    }
}

impl TreeProcessOps for MacosTreeOps {
    fn set_snapshot_scope(&mut self, scope: TreeSnapshotScope) {
        self.snapshot_scope = scope;
    }

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        collect_tree_process_infos(self.snapshot_scope).map_err(|error| error.to_string())
    }

    fn stop(&mut self, pid: u32, deadline: std::time::Instant) -> TreeStopResult {
        tree_stop(pid, deadline)
    }

    fn rollback_identity_after_stop(
        &mut self,
        pid: u32,
        _prior_marker: Option<ProcessStartMarker>,
    ) -> Option<ProcessStartMarker> {
        Self::rollback_identity_after_stop_with(pid, |pid| {
            read_process_bsdinfo(pid)
                .map(|info| process_start_time_marker_from_bsd_info(&info).ok())
        })
    }

    fn cont(&mut self, pid: u32) -> TreeSignalResult {
        match self.recheck_marker(pid) {
            Ok(()) => tree_cont(pid),
            Err(TreeSignalResult::NotFound) => TreeSignalResult::NotFound,
            Err(TreeSignalResult::Denied) => TreeSignalResult::Denied,
            Err(TreeSignalResult::Delivered) => unreachable!("recheck_marker never delivers"),
        }
    }

    fn prepare_thaw(&mut self, pid: u32, marker: Option<ProcessStartMarker>) {
        // This is the identity observed after SIGSTOP, which can differ from
        // the identity authorized for termination after PID reuse. Missing
        // rollback evidence must also clear any earlier delivery marker.
        match marker {
            Some(marker) => {
                self.verified_markers.insert(pid, marker);
            }
            None => {
                self.verified_markers.remove(&pid);
            }
        }
    }

    fn prepare_delivery(
        &mut self,
        pid: u32,
        verified_start_marker: Option<ProcessStartMarker>,
    ) -> TreeSignalResult {
        // Post-stop verification guarantees a marker for every member; a
        // missing one here is a pipeline invariant break, so refuse delivery
        // rather than proceed without a reuse check.
        let Some(marker) = verified_start_marker else {
            return TreeSignalResult::Denied;
        };
        self.verified_markers.insert(pid, marker);
        tree_prepare_delivery_probe(pid)
    }

    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        fresh_process_evidence(pid)
    }

    fn deliver(&mut self, pid: u32, mode: crate::process::KillMode) -> TreeSignalResult {
        if let Err(result) = self.recheck_marker(pid) {
            return result;
        }
        tree_deliver_by_pid(pid, mode)
    }
}

/// Read one snapshot of the process table for scoped tree execution.
///
/// Process snapshots skip rows that vanished mid-scan (`ESRCH`) and rows macOS
/// explicitly hides from this non-root process (`EPERM`). GitHub's macOS runner
/// exposes protected system PIDs in `proc_listallpids` but denies their BSD info;
/// aborting on those unrelated rows would make user-owned tree/group kills and
/// read-only inspect unusable. Other metadata failures still fail closed.
fn collect_tree_process_infos(
    scope: TreeSnapshotScope,
) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    match scope {
        TreeSnapshotScope::Full => collect_full_tree_process_infos(),
        TreeSnapshotScope::Tree { root_pid } => collect_scoped_tree_process_infos(root_pid),
        TreeSnapshotScope::Group { root_pid, pgid } => {
            collect_scoped_group_process_infos(root_pid, pgid)
        }
    }
}

fn collect_full_tree_process_infos() -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let pids = process_ids()?;

    let mut infos = Vec::with_capacity(pids.len());
    for pid in pids {
        let Some(info) = read_tree_process_info(pid, true)? else {
            continue;
        };
        infos.push(info);
    }
    Ok(infos)
}

fn collect_scoped_tree_process_infos(
    root_pid: u32,
) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let mut infos = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root_pid]);

    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid) {
            continue;
        }
        let Some(info) = read_tree_process_info(pid, false)? else {
            continue;
        };
        infos.push(info);
        if infos.len() > MAX_TREE_PROCESSES {
            return Ok(infos);
        }
        for child_pid in child_process_ids(pid)? {
            if !seen.contains(&child_pid) {
                queue.push_back(child_pid);
            }
        }
    }

    Ok(infos)
}

fn collect_scoped_group_process_infos(
    root_pid: u32,
    pgid: u32,
) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let pids = process_ids()?;
    let mut infos = Vec::new();

    for pid in pids {
        match read_process_bsdinfo(pid) {
            Ok(info) => {
                let row = tree_process_info_from_readable_bsd(pid, &info)?;
                if pid == root_pid || row.process_group == Some(pgid) {
                    infos.push(row);
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                if pid == root_pid || process_group_for_pid(pid)? == Some(pgid) {
                    return Err(platform_error(
                        "proc_pidinfo(PROC_PIDTBSDINFO)",
                        format!("PID {pid}: process group member metadata is unreadable: {error}"),
                    ));
                }
            }
            Err(error) => {
                return Err(platform_error(
                    "proc_pidinfo(PROC_PIDTBSDINFO)",
                    format!("PID {pid}: {error}"),
                ));
            }
        }
    }

    Ok(infos)
}

fn read_tree_process_info(
    pid: u32,
    skip_restricted: bool,
) -> Result<Option<TreeProcessInfo>, CollectorError> {
    let info = match read_process_bsdinfo(pid) {
        Ok(info) => info,
        Err(error) if skip_restricted && should_skip_unreadable_snapshot_error(&error) => {
            return Ok(None);
        }
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
        Err(error) => {
            return Err(platform_error(
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                format!("PID {pid}: {error}"),
            ));
        }
    };
    tree_process_info_from_readable_bsd(pid, &info).map(Some)
}

fn tree_process_info_from_readable_bsd(
    pid: u32,
    info: &libc::proc_bsdinfo,
) -> Result<TreeProcessInfo, CollectorError> {
    // proc_name can be narrower than bsdinfo for other users' processes, so
    // fall back to the comm carried inside the bsdinfo we already read; a
    // readable process with no name at all fails the scan closed.
    let Some(name) = read_process_name(pid)
        .ok()
        .flatten()
        .or_else(|| process_name_from_bsd_info(info))
    else {
        return Err(platform_error(
            "proc_name",
            format!("PID {pid}: process name is unreadable"),
        ));
    };
    tree_process_info_from_bsd(pid, info, name)
}

fn should_skip_unreadable_snapshot_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ESRCH | libc::EPERM))
}

fn child_process_ids(parent_pid: u32) -> Result<Vec<u32>, CollectorError> {
    let parent_pid = pid_to_c_int(parent_pid).map_err(|error| {
        platform_error(
            "proc_listchildpids",
            format!("parent PID is invalid: {error}"),
        )
    })?;
    let capacity = MAX_TREE_PROCESSES + 1;
    let buffer_bytes = checked_buffer_len::<libc::pid_t>(capacity, "proc_listchildpids")?;
    let mut raw_pids = vec![0 as libc::pid_t; capacity];
    child_process_ids_with_reader(&mut raw_pids, buffer_bytes, |buffer, buffer_bytes| {
        call_count_api(|| unsafe {
            // SAFETY: buffer owns buffer_bytes bytes and proc_listchildpids writes
            // at most that many bytes, or `buffer.len()` pid_t elements, into it.
            // The count is capped at one past the tree limit; that is enough for
            // the shared cap refusal.
            libc::proc_listchildpids(
                parent_pid,
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer_bytes,
            )
        })
    })
}

fn child_process_ids_with_reader<Read>(
    raw_pids: &mut Vec<libc::pid_t>,
    buffer_bytes: libc::c_int,
    mut read: Read,
) -> Result<Vec<u32>, CollectorError>
where
    Read: FnMut(&mut [libc::pid_t], libc::c_int) -> std::io::Result<libc::c_int>,
{
    let count = match read(raw_pids, buffer_bytes) {
        Ok(count) => count,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(Vec::new()),
        Err(error) => return Err(platform_error("proc_listchildpids", error.to_string())),
    };
    if count < 0 {
        return Err(platform_error(
            "proc_listchildpids",
            "negative child process count".to_owned(),
        ));
    }

    let count = usize::try_from(count).expect("non-negative child PID count must fit usize");
    raw_pids.truncate(count.min(raw_pids.len()));
    let mut pids = std::mem::take(raw_pids)
        .into_iter()
        .filter_map(valid_pid)
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn process_group_for_pid(target_pid: u32) -> Result<Option<u32>, CollectorError> {
    let target_pid = pid_to_c_int(target_pid)
        .map_err(|error| platform_error("getpgid", format!("PID is invalid: {error}")))?;
    let process_group = unsafe {
        // SAFETY: getpgid takes a PID value and writes no Rust-owned memory.
        libc::getpgid(target_pid)
    };
    if process_group < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(platform_error(
            "getpgid",
            format!("PID {target_pid}: {error}"),
        ));
    }
    Ok(valid_pid(process_group))
}

/// Pure conversion from one Darwin BSD info read to a tree snapshot row.
///
/// `pbi_ppid` of `0` maps to no parent for kernel and launchd roots. `pbi_pgid`
/// of `0` maps to no targetable process group. Both values come from the same
/// fail-closed `proc_bsdinfo` read used to prove group membership.
fn tree_process_info_from_bsd(
    pid: u32,
    info: &libc::proc_bsdinfo,
    process_name: String,
) -> Result<TreeProcessInfo, CollectorError> {
    let start_time_marker = process_start_time_marker_from_bsd_info(info).map_err(|error| {
        platform_error(
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            format!("PID {pid}: invalid process start marker: {error}"),
        )
    })?;
    Ok(TreeProcessInfo {
        pid,
        parent_pid: nonzero_pid(info.pbi_ppid),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some(process_name),
        start_time_marker: Some(start_time_marker),
        owner_uid: Some(info.pbi_uid),
        process_group: nonzero_pid(info.pbi_pgid),
    })
}

fn collect_pid_socket_records(
    pid: u32,
    aggregate_fd_entries: &mut usize,
) -> Result<(Vec<SocketRecord>, BTreeSet<SocketScanLoss>), std::io::Error> {
    let remaining = FILE_DESCRIPTOR_ENTRIES_MAX.saturating_sub(*aggregate_fd_entries);
    let fds = list_process_fds(pid, remaining)?;
    collect_pid_socket_records_from_fds(
        pid,
        &fds,
        aggregate_fd_entries,
        FILE_DESCRIPTOR_ENTRIES_MAX,
        |fd| socket_record_for_fd(pid, fd),
    )
}

fn collect_pid_socket_records_from_fds<ReadFd>(
    pid: u32,
    fds: &[libc::proc_fdinfo],
    aggregate_fd_entries: &mut usize,
    max_aggregate_fds: usize,
    mut read_fd: ReadFd,
) -> Result<(Vec<SocketRecord>, BTreeSet<SocketScanLoss>), std::io::Error>
where
    ReadFd: FnMut(libc::c_int) -> std::io::Result<Option<SocketRecord>>,
{
    *aggregate_fd_entries = aggregate_fd_entries.checked_add(fds.len()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::FileTooLarge, "FD count overflow")
    })?;
    if *aggregate_fd_entries > max_aggregate_fds {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("aggregate FD traversal exceeds {max_aggregate_fds} entries"),
        ));
    }
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut losses = BTreeSet::new();
    for fd in fds {
        if fd.proc_fdtype
            != u32::try_from(libc::PROX_FDTYPE_SOCKET).expect("Darwin socket fd type must fit u32")
        {
            continue;
        }
        let record = match read_fd(fd.proc_fd) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(error) => {
                losses.insert(socket_scan_loss(pid, &error));
                continue;
            }
        };
        if record.socket_id == 0 || seen.insert(record.key()) {
            records.push(record);
        }
    }
    Ok((records, losses))
}

fn read_process_metadata_bounded(
    pid: u32,
    profile: MetadataProfile,
    aggregate_remaining: usize,
    parent_names: &mut HashMap<ProcessIdentity, ParentNameRead>,
) -> ProcessMetadata {
    if profile == MetadataProfile::IdentityOnly {
        return ProcessMetadata::default();
    }
    let bsd_info = read_process_bsdinfo(pid).ok();
    let name_budget = aggregate_remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES);
    let process_name = read_process_name_bounded(pid, name_budget)
        .ok()
        .flatten()
        .or_else(|| {
            bsd_info
                .as_ref()
                .and_then(|info| process_name_from_bsd_info_bounded(info, name_budget))
        });
    let mut metadata = ProcessMetadata {
        process_name,
        ..ProcessMetadata::default()
    };
    metadata.budget_omitted =
        metadata.process_name.is_none() && name_budget < crate::observation::PROCESS_NAME_MAX_BYTES;
    metadata.partial |= metadata.process_name.is_none();
    let mut remaining =
        aggregate_remaining.saturating_sub(metadata.process_name.as_ref().map_or(0, String::len));

    match read_executable_path_bounded(
        pid,
        remaining.min(crate::observation::EXECUTABLE_PATH_MAX_BYTES),
    ) {
        Ok(Some(path)) => {
            remaining = remaining.saturating_sub(path.as_os_str().as_bytes().len());
            metadata.executable_path = Some(path);
        }
        Ok(None) => metadata.partial = true,
        Err(_) => {
            metadata.partial = true;
            metadata.budget_omitted |= remaining < crate::observation::EXECUTABLE_PATH_MAX_BYTES;
        }
    }

    if let Some(info) = &bsd_info {
        metadata.parent_pid = nonzero_pid(info.pbi_ppid);
        if let Some(parent_pid) = metadata.parent_pid {
            let parent = read_process_bsdinfo(parent_pid)
                .ok()
                .and_then(|parent_info| {
                    let start_marker =
                        process_start_time_marker_from_bsd_info(&parent_info).ok()?;
                    let identity = ProcessIdentity {
                        pid: parent_pid,
                        start_marker,
                    };
                    if let Some(name) = parent_names.get(&identity) {
                        return Some(parent_name_for_budget(name, remaining));
                    }
                    let name = read_process_name_budgeted(
                        parent_pid,
                        remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES),
                    )
                    .unwrap_or(ParentNameRead::Unavailable);
                    read_process_bsdinfo(parent_pid)
                        .ok()
                        .and_then(|after| process_start_time_marker_from_bsd_info(&after).ok())
                        .filter(|after| *after == start_marker)?;
                    parent_names.insert(identity, name.clone());
                    Some(name)
                });
            retain_parent_process_name(&mut metadata, parent);
            remaining = remaining
                .saturating_sub(metadata.parent_process_name.as_ref().map_or(0, String::len));
        }
    } else {
        metadata.partial = true;
    }

    if profile == MetadataProfile::LegacyList {
        let command_line = read_command_line_bounded(
            pid,
            remaining.min(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES),
        );
        apply_command_line_read(&mut metadata, command_line, remaining);
    }

    metadata
}

fn retain_parent_process_name(metadata: &mut ProcessMetadata, parent_name: Option<ParentNameRead>) {
    match parent_name {
        Some(ParentNameRead::Value(name)) => metadata.parent_process_name = Some(name),
        Some(ParentNameRead::BudgetExceeded) => {
            metadata.partial = true;
            metadata.budget_omitted = true;
        }
        Some(ParentNameRead::Unavailable) | None => metadata.partial = true,
    }
}

fn parent_name_for_budget(parent_name: &ParentNameRead, max_bytes: usize) -> ParentNameRead {
    match parent_name {
        ParentNameRead::Value(name) if name.len() > max_bytes => ParentNameRead::BudgetExceeded,
        _ => parent_name.clone(),
    }
}

fn apply_command_line_read(
    metadata: &mut ProcessMetadata,
    read: std::io::Result<CommandLineRead>,
    remaining: usize,
) {
    match read {
        Ok(CommandLineRead::Value(command_line)) => {
            metadata.command_line = Some(command_line);
        }
        Ok(CommandLineRead::Omitted) => {
            metadata.partial = true;
            metadata.budget_omitted = true;
        }
        Ok(CommandLineRead::Missing) | Err(_) => {
            metadata.partial = true;
            metadata.budget_omitted |=
                remaining < crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
        }
    }
}

fn collect_child_processes(parent_pid: u32) -> ChildProcessSnapshot {
    let Ok(pids) = process_ids() else {
        return ChildProcessSnapshot::default();
    };

    let mut children = Vec::new();
    let mut truncated = false;
    for pid in pids {
        if pid == parent_pid {
            continue;
        }
        let Ok(info) = read_process_bsdinfo(pid) else {
            continue;
        };
        if nonzero_pid(info.pbi_ppid) != Some(parent_pid) {
            continue;
        }

        if children.len() == MAX_CHILD_PROCESSES {
            truncated = true;
            break;
        }
        children.push(ChildProcess {
            pid,
            process_name: read_process_name(pid)
                .ok()
                .flatten()
                .or_else(|| process_name_from_bsd_info(&info)),
        });
    }

    ChildProcessSnapshot {
        children,
        truncated,
    }
}

fn process_ancestor_pids(pid: u32) -> HashSet<u32> {
    let mut ancestors = HashSet::from([pid]);
    let mut current = pid;
    for _ in 0..MAX_PROCESS_ANCESTORS {
        let Some(parent_pid) = read_process_bsdinfo(current)
            .ok()
            .and_then(|info| nonzero_pid(info.pbi_ppid))
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

fn process_ids() -> Result<Vec<u32>, CollectorError> {
    process_ids_with_reader(|buffer, buffer_bytes| {
        let (buffer, buffer_bytes) = buffer.map_or((std::ptr::null_mut(), 0), |buffer| {
            (buffer.as_mut_ptr().cast::<c_void>(), buffer_bytes)
        });
        match call_count_api(|| unsafe {
            // SAFETY: a null buffer and zero size is the documented sizing call.
            // Otherwise buffer owns buffer_bytes bytes and libproc does not retain it.
            libc::proc_listallpids(buffer, buffer_bytes)
        }) {
            Err(error) => {
                if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
                    Err(crate::observation::ObservationError::SocketTablePermissionDenied.into())
                } else {
                    Err(platform_error("proc_listallpids", error.to_string()))
                }
            }
            Ok(count) => Ok(count),
        }
    })
}

fn call_count_api<Call>(call: Call) -> std::io::Result<libc::c_int>
where
    Call: FnOnce() -> libc::c_int,
{
    unsafe {
        // SAFETY: __error returns this thread's valid errno slot. libproc uses
        // zero for both an empty result and failure, so stale errno must be gone.
        *libc::__error() = 0;
    }
    let count = call();
    let errno = if count <= 0 {
        unsafe {
            // SAFETY: __error returns this thread's valid errno slot.
            *libc::__error()
        }
    } else {
        0
    };
    count_result(count, errno)
}

fn count_result(count: libc::c_int, errno: libc::c_int) -> std::io::Result<libc::c_int> {
    if count < 0 || (count == 0 && errno != 0) {
        Err(std::io::Error::from_raw_os_error(errno))
    } else {
        Ok(count)
    }
}

fn process_ids_with_reader<Read>(mut read: Read) -> Result<Vec<u32>, CollectorError>
where
    Read: FnMut(Option<&mut [libc::pid_t]>, libc::c_int) -> Result<libc::c_int, CollectorError>,
{
    let initial_count = read(None, 0)?;
    if initial_count < 0 {
        return Err(platform_error(
            "proc_listallpids",
            "negative process count".to_owned(),
        ));
    }
    if initial_count == 0 {
        return Ok(Vec::new());
    }

    let initial_count =
        usize::try_from(initial_count).expect("non-negative proc_listallpids count must fit usize");
    if initial_count > CANDIDATE_PROCESS_IDS_MAX {
        return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
    }
    let sentinel_capacity = CANDIDATE_PROCESS_IDS_MAX.saturating_add(1);
    let mut capacity = initial_count
        .saturating_add(PROCESS_LIST_GROWTH_MARGIN)
        .min(sentinel_capacity);

    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        if capacity > sentinel_capacity {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        let buffer_bytes = checked_buffer_len::<libc::pid_t>(capacity, "proc_listallpids")?;
        let mut raw_pids = vec![0 as libc::pid_t; capacity];
        let count = read(Some(&mut raw_pids), buffer_bytes)?;
        if count < 0 {
            return Err(platform_error(
                "proc_listallpids",
                "negative process count".to_owned(),
            ));
        }

        let count =
            usize::try_from(count).expect("non-negative proc_listallpids count must fit usize");
        if count > CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        if count < raw_pids.len() {
            raw_pids.truncate(count);
            let mut pids = raw_pids
                .into_iter()
                .filter_map(valid_pid)
                .collect::<Vec<_>>();
            pids.sort_unstable();
            pids.dedup();
            return Ok(pids);
        }

        capacity = capacity.saturating_mul(2).min(sentinel_capacity);
    }

    Err(platform_error(
        "proc_listallpids",
        "process list kept growing while being read".to_owned(),
    ))
}

fn list_process_fds(pid: u32, max_entries: usize) -> std::io::Result<Vec<libc::proc_fdinfo>> {
    let pid = pid_to_c_int(pid)?;
    list_process_fds_with_reader(
        |buffer, buffer_bytes| {
            let buffer = if let Some(buffer) = buffer {
                buffer.as_mut_ptr().cast::<c_void>()
            } else {
                std::ptr::null_mut()
            };
            unsafe {
                // SAFETY: __error returns this thread's valid errno slot. Clearing
                // it distinguishes a successful zero-byte result from libproc's
                // zero-on-error convention for both sizing and data calls.
                *libc::__error() = 0;
            }
            let written_bytes = unsafe {
                // SAFETY: a null buffer is the sizing call. Otherwise buffer owns
                // buffer_bytes bytes and libproc does not retain the pointer.
                libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buffer, buffer_bytes)
            };
            match written_bytes.cmp(&0) {
                std::cmp::Ordering::Less => Err(std::io::Error::last_os_error()),
                std::cmp::Ordering::Equal => {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(0) {
                        Ok(0)
                    } else {
                        Err(error)
                    }
                }
                std::cmp::Ordering::Greater => Ok(written_bytes),
            }
        },
        max_entries,
        max_entries < MAX_PROCESS_FDS,
    )
}

fn list_process_fds_with_reader<Read>(
    mut read: Read,
    max_entries: usize,
    aggregate_allowance: bool,
) -> std::io::Result<Vec<libc::proc_fdinfo>>
where
    Read: FnMut(Option<&mut [libc::proc_fdinfo]>, libc::c_int) -> std::io::Result<libc::c_int>,
{
    let needed_bytes = read(None, 0)?;
    if needed_bytes < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "negative fd list byte count",
        ));
    }
    if needed_bytes == 0 {
        return Ok(Vec::new());
    }

    let needed_bytes =
        usize::try_from(needed_bytes).expect("non-negative proc_pidinfo byte count must fit usize");
    let initial_count = fd_record_count(needed_bytes, usize::MAX)?;
    let max_entries = max_entries.min(MAX_PROCESS_FDS);
    if initial_count > max_entries {
        return Err(std::io::Error::new(
            if aggregate_allowance {
                std::io::ErrorKind::FileTooLarge
            } else {
                std::io::ErrorKind::InvalidData
            },
            format!("fd list exceeds {max_entries} descriptor allowance"),
        ));
    }
    let sentinel_capacity = max_entries.saturating_add(1);
    let mut capacity = initial_count
        .saturating_add(FD_LIST_GROWTH_MARGIN)
        .min(sentinel_capacity);

    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        if capacity > sentinel_capacity {
            return Err(std::io::Error::new(
                if aggregate_allowance {
                    std::io::ErrorKind::FileTooLarge
                } else {
                    std::io::ErrorKind::InvalidData
                },
                format!("fd list exceeds {max_entries} descriptor allowance"),
            ));
        }
        let buffer_bytes = checked_io_buffer_len::<libc::proc_fdinfo>(capacity)?;
        let mut fds = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            capacity
        ];
        let written_bytes = read(Some(&mut fds), buffer_bytes)?;
        if written_bytes < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "negative fd list byte count",
            ));
        }

        let written_bytes = usize::try_from(written_bytes)
            .expect("non-negative proc_pidinfo byte count must fit usize");
        let count = fd_record_count(
            written_bytes,
            usize::try_from(buffer_bytes).expect("positive c_int fits usize"),
        )?;
        if count > max_entries {
            return Err(std::io::Error::new(
                if aggregate_allowance {
                    std::io::ErrorKind::FileTooLarge
                } else {
                    std::io::ErrorKind::InvalidData
                },
                format!("fd list exceeds {max_entries} descriptor allowance"),
            ));
        }
        if fd_list_is_complete(count, fds.len()) {
            fds.truncate(count);
            return Ok(fds);
        }

        capacity = capacity.saturating_mul(2).min(sentinel_capacity);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "fd list kept growing while being read",
    ))
}

fn fd_record_count(bytes: usize, max_bytes: usize) -> std::io::Result<usize> {
    if bytes > max_bytes || !bytes.is_multiple_of(size_of::<libc::proc_fdinfo>()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fd list result is oversized or not record-aligned",
        ));
    }
    Ok(bytes / size_of::<libc::proc_fdinfo>())
}

const fn fd_list_is_complete(count: usize, capacity: usize) -> bool {
    count < capacity
}

fn socket_record_for_fd(pid: u32, fd: libc::c_int) -> std::io::Result<Option<SocketRecord>> {
    let info = read_socket_fdinfo(pid, fd)?;
    socket_record_from_info(&info)
}

fn read_socket_fdinfo(pid: u32, fd: libc::c_int) -> std::io::Result<SocketFdinfo> {
    let pid = pid_to_c_int(pid)?;
    let expected_bytes = checked_io_buffer_len::<SocketFdinfo>(1)?;
    let mut info = MaybeUninit::<SocketFdinfo>::zeroed();
    let written_bytes = unsafe {
        // SAFETY: info points to one zeroed SocketFdinfo-sized out buffer. The
        // flavor asks libproc to fill exactly that layout for this PID/fd pair.
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast::<c_void>(),
            expected_bytes,
        )
    };
    if written_bytes <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written_bytes != expected_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("socket fd info returned {written_bytes} bytes, expected {expected_bytes}"),
        ));
    }

    let info = unsafe {
        // SAFETY: proc_pidfdinfo reported it initialized the full SocketFdinfo.
        info.assume_init()
    };
    Ok(info)
}

fn socket_record_from_info(info: &SocketFdinfo) -> std::io::Result<Option<SocketRecord>> {
    let socket = &info.psi;
    match socket.soi_protocol {
        protocol if protocol == libc::IPPROTO_TCP && socket.soi_kind == SOCKINFO_TCP => {
            let tcp = unsafe {
                // SAFETY: soi_kind == SOCKINFO_TCP names pri_tcp as the active
                // protocol payload in Darwin's socket_info union.
                socket.soi_proto.pri_tcp
            };
            let state = darwin_tcp_state(tcp.tcpsi_state)?;
            socket_record_from_in_sockinfo(
                Protocol::Tcp,
                state,
                socket.soi_family,
                socket.soi_so,
                &tcp.tcpsi_ini,
            )
        }
        protocol if protocol == libc::IPPROTO_UDP && socket.soi_kind == SOCKINFO_IN => {
            let udp = unsafe {
                // SAFETY: soi_kind == SOCKINFO_IN names pri_in as the active
                // protocol payload for UDP sockets.
                socket.soi_proto.pri_in
            };
            socket_record_from_in_sockinfo(
                Protocol::Udp,
                ObservationSocketState::Bound,
                socket.soi_family,
                socket.soi_so,
                &udp,
            )
        }
        protocol if protocol == libc::IPPROTO_TCP || protocol == libc::IPPROTO_UDP => Err(
            malformed_socket_fdinfo("IP socket has an incompatible info kind"),
        ),
        _ => Ok(None),
    }
}

fn darwin_tcp_state(native: libc::c_int) -> std::io::Result<ObservationSocketState> {
    let state = match native {
        TSI_S_CLOSED => ObservationSocketState::Closed,
        TSI_S_LISTEN => ObservationSocketState::Listen,
        TSI_S_SYN_SENT => ObservationSocketState::SynSent,
        TSI_S_SYN_RECEIVED => ObservationSocketState::SynReceived,
        TSI_S_ESTABLISHED => ObservationSocketState::Established,
        TSI_S_CLOSE_WAIT => ObservationSocketState::CloseWait,
        TSI_S_FIN_WAIT_1 => ObservationSocketState::FinWait1,
        TSI_S_CLOSING => ObservationSocketState::Closing,
        TSI_S_LAST_ACK => ObservationSocketState::LastAck,
        TSI_S_FIN_WAIT_2 => ObservationSocketState::FinWait2,
        TSI_S_TIME_WAIT => ObservationSocketState::TimeWait,
        code if code >= 0 => ObservationSocketState::Unknown(
            u32::try_from(code).expect("nonnegative Darwin c_int must fit u32"),
        ),
        _ => return Err(malformed_socket_fdinfo("negative TCP state")),
    };
    Ok(state)
}

fn socket_record_from_in_sockinfo(
    protocol: Protocol,
    state: ObservationSocketState,
    family: libc::c_int,
    socket_id: u64,
    info: &InSockinfo,
) -> std::io::Result<Option<SocketRecord>> {
    let Some(local_port) = decode_port(info.insi_lport) else {
        if info.insi_lport == 0 {
            return Ok(None);
        }
        return Err(malformed_socket_fdinfo(
            "IP socket has an invalid local port",
        ));
    };
    let local_addr = decode_local_addr(info, family)
        .ok_or_else(|| malformed_socket_fdinfo("IP socket has an invalid local address"))?;
    Ok(Some(SocketRecord {
        protocol,
        local_addr,
        local_port,
        state,
        socket_id,
    }))
}

fn malformed_socket_fdinfo(detail: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, detail)
}

fn decode_port(raw: libc::c_int) -> Option<u16> {
    let port = u16::try_from(raw).ok()?;
    let port = u16::from_be(port);
    (port != 0).then_some(port)
}

fn decode_local_addr(info: &InSockinfo, family: libc::c_int) -> Option<IpAddr> {
    let flags = info.insi_vflag & (INI_IPV4 | INI_IPV6);
    let decode_v4 = || {
        let raw = unsafe {
            // SAFETY: the caller selected the IPv4 view from the socket family
            // and INI_IPV4 capability flag.
            info.insi_laddr.ina_46.i46a_addr4.s_addr
        };
        IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
    };
    let decode_v6 = || {
        let raw = unsafe {
            // SAFETY: the caller selected the IPv6 view from the socket family
            // and INI_IPV6 capability flag.
            info.insi_laddr.ina_6.s6_addr
        };
        let addr = Ipv6Addr::from(raw);
        addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4)
    };

    match family {
        libc::AF_INET if flags & INI_IPV4 != 0 => Some(decode_v4()),
        libc::AF_INET6 if flags & INI_IPV6 != 0 => Some(decode_v6()),
        _ if flags == INI_IPV4 => Some(decode_v4()),
        _ if flags == INI_IPV6 => Some(decode_v6()),
        _ => None,
    }
}

fn read_process_bsdinfo(pid: u32) -> std::io::Result<libc::proc_bsdinfo> {
    let pid = pid_to_c_int(pid)?;
    let expected_bytes = checked_io_buffer_len::<libc::proc_bsdinfo>(1)?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let written_bytes = unsafe {
        // SAFETY: info points to one proc_bsdinfo out buffer; libproc writes at
        // most expected_bytes bytes and does not retain the pointer.
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            expected_bytes,
        )
    };
    if written_bytes <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written_bytes != expected_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("process bsd info returned {written_bytes} bytes, expected {expected_bytes}"),
        ));
    }

    let info = unsafe {
        // SAFETY: proc_pidinfo reported it initialized the full proc_bsdinfo.
        info.assume_init()
    };
    Ok(info)
}

fn read_process_name(pid: u32) -> std::io::Result<Option<String>> {
    read_process_name_bounded(pid, crate::observation::PROCESS_NAME_MAX_BYTES)
}

fn read_process_name_bounded(pid: u32, max_bytes: usize) -> std::io::Result<Option<String>> {
    Ok(match read_process_name_budgeted(pid, max_bytes)? {
        ParentNameRead::Value(name) => Some(name),
        ParentNameRead::Unavailable | ParentNameRead::BudgetExceeded => None,
    })
}

fn read_process_name_budgeted(pid: u32, max_bytes: usize) -> std::io::Result<ParentNameRead> {
    if max_bytes == 0 {
        return Ok(ParentNameRead::BudgetExceeded);
    }
    let pid = pid_to_c_int(pid)?;
    let mut buffer = [0 as libc::c_char; 64];
    let written_bytes = unsafe {
        // SAFETY: buffer is valid for one proc_name write and is not retained.
        libc::proc_name(
            pid,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).expect("process-name buffer length fits u32"),
        )
    };
    if written_bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(c_char_slice_to_parent_name(&buffer, max_bytes))
}

fn read_executable_path_bounded(pid: u32, max_bytes: usize) -> std::io::Result<Option<PathBuf>> {
    let pid = pid_to_c_int(pid)?;
    let buffer_len = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE)
        .expect("PROC_PIDPATHINFO_MAXSIZE must fit usize")
        .min(max_bytes);
    if buffer_len == 0 {
        return Ok(None);
    }
    let mut buffer = vec![0_u8; buffer_len];
    let written_bytes = unsafe {
        // SAFETY: buffer is valid for one proc_pidpath write and is not retained.
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).expect("path buffer length fits u32"),
        )
    };
    if written_bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written_bytes == 0 {
        return Ok(None);
    }

    let written_bytes = usize::try_from(written_bytes)
        .expect("non-negative proc_pidpath byte count must fit usize");
    let written_bytes = checked_returned_buffer_len(written_bytes, buffer.len(), "proc_pidpath")?;
    buffer.truncate(written_bytes);
    Ok(Some(PathBuf::from(OsStr::from_bytes(&buffer))))
}

fn read_command_line(pid: u32) -> std::io::Result<Option<String>> {
    read_command_line_bounded(pid, crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES).map(|read| {
        match read {
            CommandLineRead::Value(value) => Some(value),
            CommandLineRead::Missing | CommandLineRead::Omitted => None,
        }
    })
}

fn read_command_line_bounded(pid: u32, max_bytes: usize) -> std::io::Result<CommandLineRead> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid_to_c_int(pid)?];
    let final_max = max_bytes.min(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES);
    let native_max = final_max
        .checked_add(crate::observation::EXECUTABLE_PATH_MAX_BYTES)
        .and_then(|value| value.checked_add(size_of::<libc::c_int>() + 2))
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "argument size overflow")
        })?;
    let buffer = read_changing_native_buffer(native_max, "KERN_PROCARGS2", |buffer| {
        let (oldp, mut buffer_len) = buffer.map_or((std::ptr::null_mut(), 0), |buffer| {
            (buffer.as_mut_ptr().cast::<c_void>(), buffer.len())
        });
        let result = unsafe {
            // SAFETY: mib is a live three-element KERN_PROCARGS2 name. oldp is
            // either null for sizing or points to buffer_len writable bytes;
            // buffer_len is a live out parameter and sysctl retains no pointer.
            libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).expect("sysctl MIB length fits u32"),
                oldp,
                &raw mut buffer_len,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            Ok(buffer_len)
        } else {
            Err(std::io::Error::last_os_error())
        }
    })?;
    if buffer.is_empty() {
        return Ok(CommandLineRead::Missing);
    }
    match decode_procargs2_bounded(&buffer, final_max) {
        Ok(value) => Ok(CommandLineRead::Value(value)),
        Err(ProcArgsDecodeError::OverLimit) => Ok(CommandLineRead::Omitted),
        Err(ProcArgsDecodeError::Missing) => Ok(CommandLineRead::Missing),
        Err(ProcArgsDecodeError::Malformed) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_PROCARGS2 returned malformed process arguments",
        )),
    }
}

fn read_changing_native_buffer<Read>(
    max_bytes: usize,
    api: &'static str,
    mut read: Read,
) -> std::io::Result<Vec<u8>>
where
    Read: FnMut(Option<&mut [u8]>) -> std::io::Result<usize>,
{
    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        let required = read(None)?;
        if required == 0 {
            return Ok(Vec::new());
        }
        if required > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{api} result exceeds its {max_bytes} byte allowance"),
            ));
        }

        let mut buffer = vec![0_u8; required];
        let returned = match read(Some(&mut buffer)) {
            Ok(returned) => returned,
            Err(error) if error.raw_os_error() == Some(libc::ENOMEM) => continue,
            Err(error) => return Err(error),
        };
        let returned = checked_returned_buffer_len(returned, buffer.len(), api)?;
        buffer.truncate(returned);
        return Ok(buffer);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{api} kept growing while being read"),
    ))
}

fn checked_returned_buffer_len(
    returned: usize,
    capacity: usize,
    api: &'static str,
) -> std::io::Result<usize> {
    if returned > capacity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{api} returned more bytes than its supplied buffer"),
        ));
    }
    Ok(returned)
}

#[cfg(test)]
fn decode_procargs2(bytes: &[u8]) -> Option<String> {
    decode_procargs2_bounded(bytes, crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcArgsDecodeError {
    Missing,
    OverLimit,
    Malformed,
}

fn decode_procargs2_bounded(bytes: &[u8], final_max: usize) -> Result<String, ProcArgsDecodeError> {
    let argc_bytes = bytes
        .get(..size_of::<libc::c_int>())
        .ok_or(ProcArgsDecodeError::Malformed)?;
    let argument_count = libc::c_int::from_ne_bytes(
        argc_bytes
            .try_into()
            .expect("argc slice length is exactly c_int size"),
    );
    if argument_count <= 0 {
        return Err(ProcArgsDecodeError::Missing);
    }

    let mut data = &bytes[size_of::<libc::c_int>()..];
    let exe_end = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ProcArgsDecodeError::Malformed)?;
    data = &data[exe_end + 1..];
    while data.first() == Some(&0) {
        data = &data[1..];
    }

    let mut final_bytes = 0usize;
    let mut accepted_arguments = 0usize;
    let argv_data = data;
    for _ in 0..argument_count {
        if data.is_empty() {
            return Err(ProcArgsDecodeError::Malformed);
        }
        let end = data
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ProcArgsDecodeError::Malformed)?;
        let arg = &data[..end];
        if !arg.is_empty() {
            let argument_bytes =
                crate::observation::lossy_utf8_len(arg).ok_or(ProcArgsDecodeError::OverLimit)?;
            final_bytes = final_bytes
                .checked_add(usize::from(accepted_arguments != 0))
                .and_then(|value| value.checked_add(argument_bytes))
                .ok_or(ProcArgsDecodeError::OverLimit)?;
            if final_bytes > final_max {
                return Err(ProcArgsDecodeError::OverLimit);
            }
            accepted_arguments = accepted_arguments
                .checked_add(1)
                .ok_or(ProcArgsDecodeError::OverLimit)?;
        }
        data = &data[end + 1..];
    }

    if accepted_arguments == 0 {
        Err(ProcArgsDecodeError::Missing)
    } else {
        let mut value = String::new();
        value
            .try_reserve_exact(final_bytes)
            .map_err(|_| ProcArgsDecodeError::OverLimit)?;
        let mut data = argv_data;
        let mut written_arguments = 0usize;
        for _ in 0..argument_count {
            if data.is_empty() {
                return Err(ProcArgsDecodeError::Malformed);
            }
            let end = data
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(ProcArgsDecodeError::Malformed)?;
            let argument = &data[..end];
            if !argument.is_empty() {
                if written_arguments != 0 {
                    value.push(' ');
                }
                crate::observation::push_utf8_lossy(&mut value, argument);
                written_arguments += 1;
            }
            data = &data[end + 1..];
        }
        debug_assert_eq!(written_arguments, accepted_arguments);
        debug_assert_eq!(value.len(), final_bytes);
        Ok(value)
    }
}

fn process_name_from_bsd_info(info: &libc::proc_bsdinfo) -> Option<String> {
    c_char_slice_to_string(&info.pbi_name).or_else(|| c_char_slice_to_string(&info.pbi_comm))
}

fn process_name_from_bsd_info_bounded(
    info: &libc::proc_bsdinfo,
    max_bytes: usize,
) -> Option<String> {
    c_char_slice_to_string_bounded(&info.pbi_name, max_bytes)
        .or_else(|| c_char_slice_to_string_bounded(&info.pbi_comm, max_bytes))
}

fn process_start_time_marker_from_bsd_info(
    info: &libc::proc_bsdinfo,
) -> Result<ProcessStartMarker, crate::observation::ProcessMarkerError> {
    let microseconds = u32::try_from(info.pbi_start_tvusec)
        .map_err(|_| crate::observation::ProcessMarkerError::InvalidMicroseconds)?;
    ProcessStartMarker::macos(info.pbi_start_tvsec, microseconds)
}

fn c_char_slice_to_string(bytes: &[libc::c_char]) -> Option<String> {
    c_char_slice_to_string_bounded(bytes, usize::MAX)
}

fn c_char_slice_to_string_bounded(bytes: &[libc::c_char], max_bytes: usize) -> Option<String> {
    match c_char_slice_to_parent_name(bytes, max_bytes) {
        ParentNameRead::Value(value) => Some(value),
        ParentNameRead::Unavailable | ParentNameRead::BudgetExceeded => None,
    }
}

fn c_char_slice_to_parent_name(bytes: &[libc::c_char], max_bytes: usize) -> ParentNameRead {
    let Some(nul_index) = bytes.iter().position(|byte| *byte == 0) else {
        return ParentNameRead::Unavailable;
    };
    if nul_index == 0 {
        return ParentNameRead::Unavailable;
    }
    let text = unsafe {
        // SAFETY: nul_index proves there is a NUL terminator inside bytes, and
        // as_ptr points to the start of that same live buffer.
        CStr::from_ptr(bytes.as_ptr())
    };
    let bytes = text.to_bytes();
    let Some(decoded_len) = crate::observation::lossy_utf8_len(bytes) else {
        return ParentNameRead::Unavailable;
    };
    if decoded_len == 0 {
        return ParentNameRead::Unavailable;
    }
    if decoded_len > max_bytes {
        return ParentNameRead::BudgetExceeded;
    }
    let mut text = String::with_capacity(decoded_len);
    crate::observation::push_utf8_lossy(&mut text, bytes);
    ParentNameRead::Value(text)
}

fn nonzero_pid(pid: u32) -> Option<u32> {
    (pid != 0).then_some(pid)
}

fn valid_pid(pid: libc::pid_t) -> Option<u32> {
    u32::try_from(pid).ok().filter(|pid| *pid != 0)
}

fn pid_to_c_int(pid: u32) -> std::io::Result<libc::c_int> {
    libc::c_int::try_from(pid).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PID does not fit platform c_int",
        )
    })
}

fn checked_buffer_len<T>(
    count: usize,
    operation: &'static str,
) -> Result<libc::c_int, CollectorError> {
    let bytes = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        platform_error(operation, "buffer byte length overflows usize".to_owned())
    })?;
    libc::c_int::try_from(bytes).map_err(|_| {
        platform_error(
            operation,
            "buffer byte length does not fit platform c_int".to_owned(),
        )
    })
}

fn checked_io_buffer_len<T>(count: usize) -> std::io::Result<libc::c_int> {
    let bytes = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "buffer byte length overflows usize",
        )
    })?;
    libc::c_int::try_from(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "buffer byte length does not fit platform c_int",
        )
    })
}

fn platform_error(operation: &'static str, detail: String) -> CollectorError {
    CollectorError::Platform { operation, detail }
}

#[cfg(test)]
mod tests;
