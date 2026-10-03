//! Native Windows socket collection through IP Helper.
//!
//! No `netstat` scraping: IP Helper tells us which sockets exist and which PID
//! owns each one. Process metadata is read natively for all sorted owner PIDs in
//! one bounded batch bracketed by at most two Toolhelp relation snapshots. Open
//! process handles retain high-resolution creation markers across that bracket,
//! because PID reuse can otherwise attach metadata to the wrong process.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsString, c_void};
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NO_DATA,
    ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME, INVALID_HANDLE_VALUE, STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSED,
    MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, ProcessContext, Protocol, RelatedProcessHint,
};
use crate::observation::NativeObservationPass;
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, EXECUTABLE_PATH_MAX_BYTES, EvidenceGap, EvidenceGapCode,
    EvidenceImpact, Ipv6Scope, MetadataCompleteness, MetadataOmission, MetadataProfile,
    NATIVE_RESIZE_ATTEMPTS_MAX, NATIVE_SOCKET_TABLE_MAX_BYTES, NativeSocketObservation,
    NativeSocketRow, NetworkSnapshot, OPTIONAL_METADATA_MAX_BYTES, ObservationScope,
    ObservationScopeKind, OwnerCompleteness, PROCESS_COMMAND_LINE_MAX_BYTES,
    PROCESS_NAME_MAX_BYTES, ProcessIdentity, ProcessObservation, ProcessRead, ProcessReadBatch,
    ProcessStartMarker, SOCKET_OBSERVATIONS_MAX, ScopeLimitation, SocketState,
    UnverifiedOwnerReason,
};
use crate::tree::TreeProcessInfo;

use super::{MAX_CHILD_PROCESSES, MAX_PROCESS_ANCESTORS, MAX_RELATED_PROCESS_HINTS};

const WINDOWS_PROCESS_PATH_CODE_UNITS_MAX: usize = 32 * 1024;

pub(crate) struct WindowsCollector;

impl Collector for WindowsCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        let scope = ObservationScope::new(
            ObservationScopeKind::CurrentHostNetworkStack,
            None,
            [ScopeLimitation::WslNetworkStackExcluded],
        )?;
        crate::collector::collect_native_snapshot(
            profile,
            scope,
            |_profile| Self::collect_native_pass(),
            read_process_observations,
        )
    }
}

impl WindowsCollector {
    fn collect_native_pass() -> Result<NativeObservationPass, CollectorError> {
        native_pass_from_records(collect_socket_records()?)
    }
}

fn native_pass_from_records(
    records: Vec<SocketRecord>,
) -> Result<NativeObservationPass, CollectorError> {
    let mut owner_pids = HashSet::new();
    for record in &records {
        let Some(pid) = record.pid else {
            continue;
        };
        if !owner_pids.contains(&pid) && owner_pids.len() >= CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        owner_pids.insert(pid);
    }
    let mut rows = Vec::with_capacity(records.len());
    let mut evidence_gaps = Vec::new();
    let mut omitted_evidence_gap_count = 0_u64;
    let mut ownership_partial = false;
    for record in records {
        let endpoint = crate::observation::EndpointIdentity::new(
            record.protocol,
            record.local_addr,
            u32::from(record.local_port),
            record.ipv6_scope,
        )
        .map_err(|_| crate::observation::ObservationError::NativeDataMalformed)?;
        let (owner_pids, owner_completeness) = if let Some(pid) = record.pid {
            (vec![pid], OwnerCompleteness::Complete)
        } else {
            ownership_partial = true;
            if evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
                evidence_gaps.push(EvidenceGap::new(
                    EvidenceImpact::Ownership,
                    EvidenceGapCode::OwnerAttributionIncomplete,
                    Some(endpoint.clone()),
                    None,
                    "IP Helper reported that the endpoint owner is unavailable",
                ));
            } else {
                omitted_evidence_gap_count = omitted_evidence_gap_count.saturating_add(1);
            }
            (
                Vec::new(),
                OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])?,
            )
        };
        rows.push(NativeSocketRow {
            socket: NativeSocketObservation {
                endpoint,
                state: record.state,
                timer: None,
                token: None,
                local_uid: None,
            },
            owner_pids,
            owner_completeness,
        });
    }
    Ok(NativeObservationPass {
        rows,
        global_owner_completeness: if ownership_partial {
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])?
        } else {
            OwnerCompleteness::Complete
        },
        evidence_gaps,
        omitted_evidence_gap_count,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    ipv6_scope: Option<Ipv6Scope>,
    state: SocketState,
    pid: Option<u32>,
}

#[derive(Debug, Clone, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    unverified_parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    start_time_marker: Option<ProcessStartMarker>,
    identity_reason: Option<UnverifiedOwnerReason>,
    partial: bool,
    budget_omitted: bool,
}

#[derive(Debug, Default)]
struct ProcessSnapshot {
    processes: HashMap<u32, ProcessMetadata>,
}

const PROCESS_HANDLE_CHUNK_MAX: usize = 256;
const RETAINED_PROCESS_HANDLES_MAX: usize = PROCESS_HANDLE_CHUNK_MAX + 1;

#[derive(Clone, Copy)]
enum ProcessSelection<'a> {
    All,
    Exact(&'a [u32]),
    ExactWithDirectChildren(&'a [u32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessOpenError {
    PermissionDenied,
    Disappeared,
    IdentityUnavailable,
}

trait ProcessApi {
    type Handle;

    fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError>;
    fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError>;
    fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker>;
    fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker>;
    fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String>;
    fn name_exceeds_budget(&mut self, pid: u32, max_bytes: usize) -> bool;
    fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf>;
    fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String>;
    #[cfg(test)]
    fn observe_retained_handle_count(&mut self, _count: usize) {}
}

struct RelationFailureTrackingApi<'a, Api> {
    inner: &'a mut Api,
    relation_failed: bool,
}

impl<Api: ProcessApi> ProcessApi for RelationFailureTrackingApi<'_, Api> {
    type Handle = Api::Handle;

    fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
        let result = self.inner.enumerate_relations();
        self.relation_failed |= result.is_err();
        result
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError> {
        self.inner.open_process(pid)
    }

    fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker> {
        self.inner.marker_from_handle(handle)
    }

    fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker> {
        self.inner.marker_for_pid(pid)
    }

    fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String> {
        self.inner.name(pid, max_bytes)
    }

    fn name_exceeds_budget(&mut self, pid: u32, max_bytes: usize) -> bool {
        self.inner.name_exceeds_budget(pid, max_bytes)
    }

    fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf> {
        self.inner.path(handle, max_bytes)
    }

    fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String> {
        self.inner.command_line(handle, max_bytes)
    }

    #[cfg(test)]
    fn observe_retained_handle_count(&mut self, count: usize) {
        self.inner.observe_retained_handle_count(count);
    }
}

#[derive(Default)]
struct RealProcessApi {
    names: HashMap<u32, [u16; 260]>,
}

impl ProcessApi for RealProcessApi {
    type Handle = OwnedHandle;

    fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
        enumerate_process_relations(&mut self.names)
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError> {
        open_query_process(pid)
    }

    fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker> {
        process_start_time_marker_from_handle(handle)
    }

    fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker> {
        process_start_time_marker(pid)
    }

    fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String> {
        decode_toolhelp_name(self.names.get(&pid)?, max_bytes)
    }

    fn name_exceeds_budget(&mut self, pid: u32, max_bytes: usize) -> bool {
        self.names
            .get(&pid)
            .and_then(toolhelp_name_utf8_len)
            .is_some_and(|length| length > max_bytes)
    }

    fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf> {
        query_process_path(handle, max_bytes)
    }

    fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String> {
        query_process_command_line(handle, max_bytes)
    }
}

impl ProcessSnapshot {
    fn collect(
        profile: MetadataProfile,
        selection: ProcessSelection<'_>,
    ) -> Result<Self, CollectorError> {
        Self::collect_with(
            &mut RealProcessApi::default(),
            profile,
            selection,
            OPTIONAL_METADATA_MAX_BYTES,
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "creation-handle bracketing and deterministic metadata budgeting are one safety transaction"
    )]
    fn collect_with<Api: ProcessApi>(
        api: &mut Api,
        profile: MetadataProfile,
        selection: ProcessSelection<'_>,
        metadata_budget: usize,
    ) -> Result<Self, CollectorError> {
        if profile == MetadataProfile::IdentityOnly {
            return Ok(Self::default());
        }
        let first_relations = api.enumerate_relations()?;
        let mut selected = selected_process_ids(&first_relations, selection);
        if selected.len() > CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        selected.sort_unstable();
        selected.dedup();
        // Creation markers tie each first-snapshot PID to the process opened in
        // its later bounded chunk. This retains scalar identities, not every OS
        // handle, while still rejecting a recycled PID before metadata or a
        // parent edge can be accepted.
        let markers_before = selected
            .iter()
            .copied()
            .map(|pid| (pid, api.marker_for_pid(pid)))
            .collect::<HashMap<_, _>>();
        let relations = api.enumerate_relations()?;
        let mut snapshot = Self::default();
        let mut retained_bytes = 0usize;
        let mut parent_names = HashMap::new();
        for chunk in selected.chunks(PROCESS_HANDLE_CHUNK_MAX) {
            let mut handles = chunk
                .iter()
                .copied()
                .map(|pid| (pid, api.open_process(pid)))
                .collect::<HashMap<_, _>>();
            debug_assert!(handles.len() < RETAINED_PROCESS_HANDLES_MAX);
            #[cfg(test)]
            api.observe_retained_handle_count(handles.len());
            let retained_chunk_handles = handles.len();
            for &pid in chunk {
                let handle = match handles.remove(&pid) {
                    Some(Ok(handle)) => handle,
                    Some(Err(error)) => {
                        snapshot.processes.insert(
                            pid,
                            ProcessMetadata {
                                identity_reason: Some(unverified_reason_for_open(error)),
                                partial: true,
                                ..ProcessMetadata::default()
                            },
                        );
                        continue;
                    }
                    None => {
                        return Err(
                            crate::observation::ObservationError::NativeDataMalformed.into()
                        );
                    }
                };
                let Some(before) = markers_before.get(&pid).copied().flatten() else {
                    snapshot.processes.insert(
                        pid,
                        ProcessMetadata {
                            identity_reason: Some(UnverifiedOwnerReason::IdentityUnavailable),
                            partial: true,
                            ..ProcessMetadata::default()
                        },
                    );
                    continue;
                };
                let handle_marker = api.marker_from_handle(&handle);
                if handle_marker != Some(before) {
                    snapshot.processes.insert(
                        pid,
                        ProcessMetadata {
                            identity_reason: Some(UnverifiedOwnerReason::Raced),
                            partial: true,
                            ..ProcessMetadata::default()
                        },
                    );
                    continue;
                }
                let remaining = metadata_budget.saturating_sub(retained_bytes);
                let name_budget = remaining.min(PROCESS_NAME_MAX_BYTES);
                let mut process_name = (name_budget != 0)
                    .then(|| api.name(pid, name_budget))
                    .flatten();
                let mut budget_omitted =
                    process_name.is_none() && name_budget < PROCESS_NAME_MAX_BYTES;
                retain_string_field(
                    &mut process_name,
                    &mut retained_bytes,
                    PROCESS_NAME_MAX_BYTES,
                    metadata_budget,
                );
                let path_budget = metadata_budget
                    .saturating_sub(retained_bytes)
                    .min(EXECUTABLE_PATH_MAX_BYTES);
                let mut path = (path_budget != 0)
                    .then(|| api.path(&handle, path_budget))
                    .flatten();
                budget_omitted |= path.is_none() && path_budget < EXECUTABLE_PATH_MAX_BYTES;
                retain_path_field(&mut path, &mut retained_bytes, metadata_budget);
                let first_parent_pid = first_relations.get(&pid).copied().flatten();
                let second_parent_pid = relations.get(&pid).copied().flatten();
                let parent_relation_changed = first_parent_pid != second_parent_pid;
                let parent_pid = (!parent_relation_changed)
                    .then_some(second_parent_pid)
                    .flatten();
                // Only the latest relation can be reported as unverified. A
                // parent seen solely in the first snapshot may already be stale.
                let recorded_parent_pid = second_parent_pid;
                let parent_name_budget = metadata_budget.saturating_sub(retained_bytes);
                let (parent_pid, parent_process_name) = parent_pid
                    .and_then(|parent_pid| {
                        query_verified_parent(
                            api,
                            parent_pid,
                            before,
                            parent_name_budget,
                            retained_chunk_handles,
                            &mut parent_names,
                        )
                        .map(|parent| (Some(parent_pid), Some(parent)))
                    })
                    .unwrap_or((None, None));
                budget_omitted |= parent_process_name
                    .as_ref()
                    .is_some_and(|parent| parent.name_budget_exceeded);
                let mut metadata = ProcessMetadata {
                    process_name,
                    executable_path: path.take(),
                    command_line: None,
                    parent_pid,
                    unverified_parent_pid: recorded_parent_pid.filter(|_| parent_pid.is_none()),
                    parent_process_name: parent_process_name.and_then(|parent| parent.name),
                    start_time_marker: Some(before),
                    identity_reason: None,
                    partial: false,
                    budget_omitted,
                };
                retain_string_field(
                    &mut metadata.parent_process_name,
                    &mut retained_bytes,
                    PROCESS_NAME_MAX_BYTES,
                    metadata_budget,
                );
                let command_line_budget = metadata_budget.saturating_sub(retained_bytes);
                metadata.command_line = (profile == MetadataProfile::LegacyList
                    && command_line_budget != 0)
                    .then(|| api.command_line(&handle, command_line_budget))
                    .flatten();
                metadata.budget_omitted |= profile == MetadataProfile::LegacyList
                    && metadata.command_line.is_none()
                    && command_line_budget < PROCESS_COMMAND_LINE_MAX_BYTES;
                retain_string_field(
                    &mut metadata.command_line,
                    &mut retained_bytes,
                    PROCESS_COMMAND_LINE_MAX_BYTES,
                    metadata_budget,
                );
                metadata.partial |= metadata.process_name.is_none()
                    || metadata.executable_path.is_none()
                    || parent_relation_changed
                    || metadata.unverified_parent_pid.is_some()
                    || (metadata.parent_pid.is_some() && metadata.parent_process_name.is_none())
                    || (profile == MetadataProfile::LegacyList && metadata.command_line.is_none());
                let after = api.marker_from_handle(&handle);
                let current = api.marker_for_pid(pid);
                snapshot.processes.insert(
                    pid,
                    finish_bracketed_metadata(metadata, before, after, current),
                );
            }
        }

        Ok(snapshot)
    }

    fn metadata(&self, pid: u32) -> Option<&ProcessMetadata> {
        self.processes.get(&pid)
    }

    /// Direct children of `pid`, resolved on demand from the process map.
    ///
    /// Scans `processes` on demand because only the details view requests
    /// children. Excludes self-parent edges.
    fn children(&self, pid: u32) -> ChildProcessSnapshot {
        let mut children = self
            .processes
            .iter()
            .filter(|&(&child_pid, metadata)| child_pid != pid && metadata.parent_pid == Some(pid))
            .map(|(&child_pid, metadata)| ChildProcess {
                pid: child_pid,
                process_name: metadata.process_name.clone(),
            })
            .collect::<Vec<_>>();
        children.sort_by_key(|child| child.pid);

        let truncated = children.len() > MAX_CHILD_PROCESSES;
        children.truncate(MAX_CHILD_PROCESSES);
        ChildProcessSnapshot {
            children,
            truncated,
        }
    }

    fn ancestor_pids(&self, pid: u32) -> HashSet<u32> {
        let mut ancestors = HashSet::from([pid]);
        let mut current = pid;
        for _ in 0..MAX_PROCESS_ANCESTORS {
            let Some(parent_pid) = self
                .processes
                .get(&current)
                .and_then(|metadata| metadata.parent_pid)
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
}

fn selected_process_ids(
    relations: &HashMap<u32, Option<u32>>,
    selection: ProcessSelection<'_>,
) -> Vec<u32> {
    match selection {
        ProcessSelection::All => relations.keys().copied().collect(),
        ProcessSelection::Exact(pids) => pids.to_vec(),
        ProcessSelection::ExactWithDirectChildren(pids) => {
            let selected = pids.iter().copied().collect::<HashSet<_>>();
            relations
                .iter()
                .filter_map(|(pid, parent_pid)| {
                    (selected.contains(pid)
                        || parent_pid.is_some_and(|parent| selected.contains(&parent)))
                    .then_some(*pid)
                })
                .chain(pids.iter().copied())
                .collect()
        }
    }
}

const fn unverified_reason_for_open(error: ProcessOpenError) -> UnverifiedOwnerReason {
    match error {
        ProcessOpenError::PermissionDenied => UnverifiedOwnerReason::PermissionDenied,
        ProcessOpenError::Disappeared => UnverifiedOwnerReason::Disappeared,
        ProcessOpenError::IdentityUnavailable => UnverifiedOwnerReason::IdentityUnavailable,
    }
}

fn finish_bracketed_metadata(
    metadata: ProcessMetadata,
    before: ProcessStartMarker,
    after: Option<ProcessStartMarker>,
    current: Option<ProcessStartMarker>,
) -> ProcessMetadata {
    if after == Some(before) && current == Some(before) {
        metadata
    } else {
        ProcessMetadata {
            identity_reason: Some(UnverifiedOwnerReason::Raced),
            partial: true,
            ..ProcessMetadata::default()
        }
    }
}

fn enumerate_process_relations(
    names: &mut HashMap<u32, [u16; 260]>,
) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
    let raw_snapshot = unsafe {
        // SAFETY: process ID is ignored for TH32CS_SNAPPROCESS.
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(CollectorError::Platform {
            operation: "CreateToolhelp32Snapshot",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    let snapshot = unsafe {
        // SAFETY: Toolhelp returned one owned non-sentinel handle.
        OwnedHandle::from_raw_handle(raw_snapshot)
    };
    let mut rows = HashMap::new();
    names.clear();
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).expect("entry size fits u32"),
        ..PROCESSENTRY32W::default()
    };
    let first_present = unsafe {
        // SAFETY: entry has the required size and is writable.
        Process32FirstW(snapshot.as_raw_handle(), &raw mut entry)
    } != 0;
    if !first_present {
        let error = std::io::Error::last_os_error();
        if windows_io_error_code(&error) == Some(ERROR_NO_MORE_FILES) {
            return Ok(rows);
        }
        return Err(CollectorError::Platform {
            operation: "Process32FirstW",
            detail: error.to_string(),
        });
    }
    loop {
        if rows.len() >= CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        rows.insert(
            entry.th32ProcessID,
            (entry.th32ParentProcessID != 0).then_some(entry.th32ParentProcessID),
        );
        names.insert(entry.th32ProcessID, entry.szExeFile);
        let present = unsafe {
            // SAFETY: entry remains valid for the next API write.
            Process32NextW(snapshot.as_raw_handle(), &raw mut entry)
        } != 0;
        if !present {
            break;
        }
    }
    let error = std::io::Error::last_os_error();
    if windows_io_error_code(&error) != Some(ERROR_NO_MORE_FILES) {
        return Err(CollectorError::Platform {
            operation: "Process32NextW",
            detail: error.to_string(),
        });
    }
    Ok(rows)
}

fn open_query_process(pid: u32) -> Result<OwnedHandle, ProcessOpenError> {
    let handle = unsafe {
        // SAFETY: OpenProcess receives only value arguments and is checked.
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    if handle.is_null() {
        // Capture GetLastError before any formatting, allocation, or helper call
        // can overwrite this thread's Windows error slot.
        let error = std::io::Error::last_os_error();
        return Err(match windows_io_error_code(&error) {
            Some(ERROR_ACCESS_DENIED) => ProcessOpenError::PermissionDenied,
            Some(ERROR_INVALID_PARAMETER) => ProcessOpenError::Disappeared,
            _ => ProcessOpenError::IdentityUnavailable,
        });
    }
    Ok(unsafe {
        // SAFETY: the successful OpenProcess handle is owned by this scope.
        OwnedHandle::from_raw_handle(handle)
    })
}

#[derive(Clone)]
struct VerifiedParent {
    name: Option<String>,
    name_budget_exceeded: bool,
}

fn query_verified_parent<Api: ProcessApi>(
    api: &mut Api,
    parent_pid: u32,
    child_marker: ProcessStartMarker,
    max_bytes: usize,
    retained_chunk_handles: usize,
    names: &mut HashMap<ProcessIdentity, VerifiedParent>,
) -> Option<VerifiedParent> {
    let marker = api.marker_for_pid(parent_pid)?;
    if marker >= child_marker {
        return None;
    }
    let identity = ProcessIdentity {
        pid: parent_pid,
        start_marker: marker,
    };
    if let Some(name) = names.get(&identity) {
        return Some(verified_parent_for_budget(name, max_bytes));
    }
    let handle = api.open_process(parent_pid).ok()?;
    debug_assert!(retained_chunk_handles < RETAINED_PROCESS_HANDLES_MAX);
    #[cfg(test)]
    api.observe_retained_handle_count(retained_chunk_handles + 1);
    let before = api.marker_from_handle(&handle)?;
    if before != marker {
        return None;
    }
    let name_budget = max_bytes.min(PROCESS_NAME_MAX_BYTES);
    let name = (name_budget != 0)
        .then(|| api.name(parent_pid, name_budget))
        .flatten();
    let name_budget_exceeded = name.is_none()
        && name_budget < PROCESS_NAME_MAX_BYTES
        && api.name_exceeds_budget(parent_pid, name_budget);
    let after = api.marker_from_handle(&handle)?;
    let current = api.marker_for_pid(parent_pid)?;
    (before == after && after == current).then(|| {
        let parent = VerifiedParent {
            name,
            name_budget_exceeded,
        };
        names.insert(identity, parent.clone());
        parent
    })
}

fn verified_parent_for_budget(parent: &VerifiedParent, max_bytes: usize) -> VerifiedParent {
    if parent
        .name
        .as_ref()
        .is_some_and(|name| name.len() > max_bytes)
    {
        VerifiedParent {
            name: None,
            name_budget_exceeded: true,
        }
    } else {
        parent.clone()
    }
}

fn query_process_path(handle: &OwnedHandle, max_bytes: usize) -> Option<PathBuf> {
    let code_units = process_path_buffer_code_units(max_bytes);
    if code_units == 0 {
        return None;
    }
    let mut buffer = vec![0u16; code_units];
    let mut length = u32::try_from(buffer.len()).ok()?;
    let result = unsafe {
        // SAFETY: buffer owns `length` writable UTF-16 code units and the API
        // writes the resulting count through a valid pointer.
        QueryFullProcessImageNameW(
            handle.as_raw_handle(),
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    };
    if result == 0 {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    decode_utf16_bounded(
        buffer.get(..length)?,
        max_bytes.min(EXECUTABLE_PATH_MAX_BYTES),
    )
    .map(PathBuf::from)
}

/// File name of an open process's executable image.
///
/// The UTF-16 buffer grows from `MAX_PATH` to the long-path maximum, so a short
/// executable name in a deep install directory still resolves. Callers bound
/// the returned name for their own policy. `Ok(None)` means the image path has
/// no file-name component.
pub(crate) fn process_image_file_name(handle: &OwnedHandle) -> std::io::Result<Option<String>> {
    process_image_file_name_with(|buffer, length| {
        let result = unsafe {
            // SAFETY: the handle has query access, `buffer` is initialized and
            // writable for `*length` code units, and no pointer is retained.
            QueryFullProcessImageNameW(
                handle.as_raw_handle(),
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                length,
            )
        };
        if result == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

fn process_image_file_name_with(
    mut query: impl FnMut(&mut [u16], &mut u32) -> std::io::Result<()>,
) -> std::io::Result<Option<String>> {
    let mut capacity = 260usize;
    loop {
        let mut path = vec![0u16; capacity];
        let mut length = u32::try_from(path.len()).expect("bounded image path fits u32");
        match query(&mut path, &mut length) {
            Ok(()) => {
                let length = usize::try_from(length).unwrap_or(usize::MAX);
                let path = path.get(..length).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "QueryFullProcessImageNameW reported more code units than its buffer",
                    )
                })?;
                let path = OsString::from_wide(path);
                return Ok(Path::new(&path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()));
            }
            Err(error)
                if windows_io_error_code(&error) == Some(ERROR_INSUFFICIENT_BUFFER)
                    && capacity < WINDOWS_PROCESS_PATH_CODE_UNITS_MAX =>
            {
                capacity = capacity
                    .saturating_mul(2)
                    .min(WINDOWS_PROCESS_PATH_CODE_UNITS_MAX);
            }
            Err(error) => return Err(error),
        }
    }
}

fn process_path_buffer_code_units(max_bytes: usize) -> usize {
    // A UTF-16 code unit contributes at least one byte to the decoded WTF-8/UTF-8
    // path, so the final byte budget is also a safe code-unit bound. Capping at
    // Windows' long-path buffer maximum avoids a needlessly larger allocation.
    max_bytes
        .min(EXECUTABLE_PATH_MAX_BYTES)
        .min(WINDOWS_PROCESS_PATH_CODE_UNITS_MAX)
}

fn query_process_command_line(handle: &OwnedHandle, max_bytes: usize) -> Option<String> {
    query_process_command_line_with(max_bytes, |buffer, capacity, required| unsafe {
        // SAFETY: the caller supplies either a null probe or a writable buffer of
        // `capacity` bytes, plus a valid required-length output pointer.
        NtQueryInformationProcess(
            handle.as_raw_handle(),
            ProcessCommandLineInformation,
            buffer,
            capacity,
            required,
        )
    })
}

fn query_process_command_line_with(
    max_bytes: usize,
    mut query: impl FnMut(*mut c_void, u32, *mut u32) -> i32,
) -> Option<String> {
    let final_max = max_bytes.min(PROCESS_COMMAND_LINE_MAX_BYTES);
    let native_max = size_of::<UNICODE_STRING>().checked_add(final_max.checked_mul(2)?)?;
    let mut required_bytes = 0u32;
    let probe_status = query(std::ptr::null_mut(), 0, &raw mut required_bytes);
    if probe_status >= 0 || !is_resize_status(probe_status) {
        return None;
    }
    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        let required = usize::try_from(required_bytes).ok()?;
        if required < size_of::<UNICODE_STRING>() || required > native_max {
            return None;
        }

        // UNICODE_STRING contains a pointer and therefore needs pointer
        // alignment; a u16 allocation is insufficient on 64-bit Windows.
        let words = required.div_ceil(size_of::<u64>());
        let mut buffer = Vec::<u64>::new();
        buffer.try_reserve_exact(words).ok()?;
        buffer.resize(words, 0);
        let allocated_bytes = buffer.len().checked_mul(size_of::<u64>())?;
        let capacity = u32::try_from(allocated_bytes).ok()?;
        let status = query(
            buffer.as_mut_ptr().cast(),
            capacity,
            &raw mut required_bytes,
        );
        if status >= 0 {
            let returned_bytes = usize::try_from(required_bytes).ok()?;
            if returned_bytes < size_of::<UNICODE_STRING>() || returned_bytes > allocated_bytes {
                return None;
            }
            return decode_command_line_buffer(&buffer, returned_bytes, final_max);
        }
        if !is_resize_status(status) {
            return None;
        }
    }
    None
}

const fn is_resize_status(status: i32) -> bool {
    status == STATUS_BUFFER_OVERFLOW
        || status == STATUS_BUFFER_TOO_SMALL
        || status == STATUS_INFO_LENGTH_MISMATCH
}

fn decode_command_line_buffer(
    buffer: &[u64],
    returned_bytes: usize,
    final_max: usize,
) -> Option<String> {
    if returned_bytes < size_of::<UNICODE_STRING>() {
        return None;
    }
    let unicode = unsafe {
        // SAFETY: u64 storage satisfies UNICODE_STRING alignment, and the caller
        // established that the initialized prefix contains the complete header.
        &*buffer.as_ptr().cast::<UNICODE_STRING>()
    };
    let byte_length = usize::from(unicode.Length);
    if byte_length == 0 || byte_length % 2 != 0 || byte_length > final_max.checked_mul(2)? {
        return None;
    }
    let buffer_start = buffer.as_ptr() as usize;
    let start = (unicode.Buffer as usize).checked_sub(buffer_start)?;
    let end = start.checked_add(byte_length)?;
    if start % align_of::<u16>() != 0 || end > returned_bytes {
        return None;
    }
    let code_units = unsafe {
        // SAFETY: the returned pointer lies in the aligned u16 buffer, and both
        // offset and byte length were validated as even and in bounds.
        std::slice::from_raw_parts(unicode.Buffer, byte_length / 2)
    };
    decode_utf16_bounded(code_units, final_max)
}

fn decode_toolhelp_name(code_units: &[u16; 260], final_max: usize) -> Option<String> {
    let end = code_units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(code_units.len());
    if end == 0 {
        return None;
    }
    decode_utf16_bounded(&code_units[..end], final_max)
}

fn toolhelp_name_utf8_len(code_units: &[u16; 260]) -> Option<usize> {
    let end = code_units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(code_units.len());
    if end == 0 {
        return None;
    }
    std::char::decode_utf16(code_units[..end].iter().copied()).try_fold(
        0usize,
        |length, decoded| {
            length.checked_add(decoded.unwrap_or(char::REPLACEMENT_CHARACTER).len_utf8())
        },
    )
}

fn decode_utf16_bounded(code_units: &[u16], final_max: usize) -> Option<String> {
    let mut final_bytes = 0usize;
    for decoded in std::char::decode_utf16(code_units.iter().copied()) {
        final_bytes =
            final_bytes.checked_add(decoded.unwrap_or(char::REPLACEMENT_CHARACTER).len_utf8())?;
        if final_bytes > final_max {
            return None;
        }
    }
    let mut value = String::new();
    value.try_reserve_exact(final_bytes).ok()?;
    value.extend(
        std::char::decode_utf16(code_units.iter().copied())
            .map(|decoded| decoded.unwrap_or(char::REPLACEMENT_CHARACTER)),
    );
    Some(value)
}

fn retain_string_field(
    field: &mut Option<String>,
    retained: &mut usize,
    per_value_max: usize,
    aggregate_max: usize,
) {
    let Some(length) = field.as_ref().map(String::len) else {
        return;
    };
    let Some(next) = retained.checked_add(length) else {
        *field = None;
        return;
    };
    if length > per_value_max || next > aggregate_max {
        *field = None;
    } else {
        *retained = next;
    }
}

fn retain_path_field(field: &mut Option<PathBuf>, retained: &mut usize, aggregate_max: usize) {
    let Some(length) = field.as_ref().map(|path| path.as_os_str().len()) else {
        return;
    };
    let Some(next) = retained.checked_add(length) else {
        *field = None;
        return;
    };
    if length > EXECUTABLE_PATH_MAX_BYTES || next > aggregate_max {
        *field = None;
    } else {
        *retained = next;
    }
}

fn read_process_observations(
    sorted_pids: &[u32],
    profile: MetadataProfile,
    optional_metadata_bytes_remaining: usize,
) -> Result<ProcessReadBatch, CollectorError> {
    read_process_observations_with(
        &mut RealProcessApi::default(),
        sorted_pids,
        profile,
        optional_metadata_bytes_remaining,
    )
}

fn read_process_observations_with<Api: ProcessApi>(
    api: &mut Api,
    sorted_pids: &[u32],
    profile: MetadataProfile,
    optional_metadata_bytes_remaining: usize,
) -> Result<ProcessReadBatch, CollectorError> {
    if sorted_pids.len() > CANDIDATE_PROCESS_IDS_MAX {
        return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
    }
    if profile == MetadataProfile::IdentityOnly {
        return Ok(sorted_pids
            .iter()
            .copied()
            .map(|pid| {
                let read = match api.open_process(pid) {
                    Ok(handle) => api.marker_from_handle(&handle).map_or(
                        ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
                        |marker| ProcessRead::Verified {
                            marker,
                            observation: ProcessObservation::identity_only(),
                        },
                    ),
                    Err(error) => ProcessRead::Unverified(unverified_reason_for_open(error)),
                };
                (pid, read)
            })
            .collect());
    }

    let (snapshot, relation_failed) = {
        let mut tracking_api = RelationFailureTrackingApi {
            inner: api,
            relation_failed: false,
        };
        let snapshot = ProcessSnapshot::collect_with(
            &mut tracking_api,
            profile,
            ProcessSelection::Exact(sorted_pids),
            optional_metadata_bytes_remaining,
        );
        (snapshot, tracking_api.relation_failed)
    };
    let mut snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(_) if relation_failed => return Ok(direct_partial_process_reads(api, sorted_pids)),
        Err(error) => return Err(error),
    };
    Ok(sorted_pids
        .iter()
        .copied()
        .map(|pid| {
            let read = snapshot.processes.remove(&pid).map_or(
                ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
                process_read_from_metadata,
            );
            (pid, read)
        })
        .collect())
}

fn direct_partial_process_reads<Api: ProcessApi>(
    api: &mut Api,
    sorted_pids: &[u32],
) -> ProcessReadBatch {
    // The sole caller, read_process_observations_with, already enforces the
    // CANDIDATE_PROCESS_IDS_MAX bound before delegating here.
    sorted_pids
        .iter()
        .copied()
        .map(|pid| {
            let read = match api.open_process(pid) {
                Ok(handle) => api.marker_from_handle(&handle).map_or(
                    ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
                    |marker| ProcessRead::Verified {
                        marker,
                        observation: ProcessObservation {
                            name: None,
                            executable_path: None,
                            command_line: None,
                            parent_pid: None,
                            parent_process_name: None,
                            metadata_omission: None,
                            metadata_completeness: MetadataCompleteness::Partial,
                        },
                    },
                ),
                Err(error) => ProcessRead::Unverified(unverified_reason_for_open(error)),
            };
            (pid, read)
        })
        .collect()
}

fn process_read_from_metadata(metadata: ProcessMetadata) -> ProcessRead {
    if let Some(reason) = metadata.identity_reason {
        return ProcessRead::Unverified(reason);
    }
    let Some(marker) = metadata.start_time_marker else {
        return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
    };
    ProcessRead::Verified {
        marker,
        observation: ProcessObservation {
            name: metadata.process_name.map(Arc::from),
            executable_path: metadata
                .executable_path
                .map(|path| Arc::<Path>::from(path.into_boxed_path())),
            command_line: metadata.command_line.map(Arc::from),
            parent_pid: metadata.parent_pid,
            parent_process_name: metadata.parent_process_name.map(Arc::from),
            metadata_omission: metadata
                .budget_omitted
                .then_some(MetadataOmission::BudgetExceeded),
            metadata_completeness: if metadata.partial {
                MetadataCompleteness::Partial
            } else {
                MetadataCompleteness::Complete
            },
        },
    }
}

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    let referenced = [pid];
    let processes = ProcessSnapshot::collect(
        MetadataProfile::Display,
        ProcessSelection::ExactWithDirectChildren(&referenced),
    )
    .unwrap_or_else(|_| ProcessSnapshot::default());
    ProcessContext {
        owner_uid: None,
        process_start_time_marker: process_start_time_marker(pid),
        children: processes.children(pid),
        docker: None,
    }
}

pub(crate) fn process_command_line_reader(
    identities: &[crate::observation::ProcessIdentity],
) -> impl FnMut(u32) -> Option<String> {
    let expected = identities
        .iter()
        .map(|identity| (identity.pid, identity.start_marker))
        .collect::<HashMap<_, _>>();
    let pids = expected.keys().copied().collect::<Vec<_>>();
    let processes =
        ProcessSnapshot::collect(MetadataProfile::LegacyList, ProcessSelection::Exact(&pids))
            .unwrap_or_else(|_| ProcessSnapshot::default());
    move |pid| {
        processes
            .metadata(pid)
            .filter(|metadata| metadata.start_time_marker == expected.get(&pid).copied())
            .and_then(|metadata| metadata.command_line.clone())
    }
}

pub(crate) fn collect_tree_process_infos() -> Result<Vec<TreeProcessInfo>, CollectorError> {
    ProcessSnapshot::collect(MetadataProfile::Display, ProcessSelection::All)
        .map(|snapshot| tree_process_infos_from_snapshot(&snapshot))
}

fn tree_process_infos_from_snapshot(processes: &ProcessSnapshot) -> Vec<TreeProcessInfo> {
    tree_process_infos_from_snapshot_with(processes, |pid| {
        processes
            .processes
            .get(&pid)
            .and_then(|metadata| metadata.start_time_marker)
    })
}

fn tree_process_infos_from_snapshot_with(
    processes: &ProcessSnapshot,
    mut marker_for_pid: impl FnMut(u32) -> Option<ProcessStartMarker>,
) -> Vec<TreeProcessInfo> {
    let markers = processes
        .processes
        .keys()
        .map(|pid| (*pid, marker_for_pid(*pid)))
        .collect::<HashMap<_, _>>();
    let names = processes
        .processes
        .iter()
        .filter_map(|(pid, metadata)| Some((*pid, metadata.process_name.clone()?)))
        .collect::<HashMap<_, _>>();

    let mut rows = processes
        .processes
        .iter()
        .map(|(pid, metadata)| {
            let parent_edge = accepted_parent_edge(*pid, metadata.parent_pid, &markers);
            TreeProcessInfo {
                pid: *pid,
                parent_pid: parent_edge.verified,
                unverified_parent_pid: metadata.unverified_parent_pid.or(parent_edge.unverified),
                parent_process_name: parent_edge
                    .verified
                    .and_then(|parent_pid| names.get(&parent_pid).cloned()),
                process_name: metadata.process_name.clone(),
                executable_name: None,
                start_time_marker: markers.get(pid).copied().flatten(),
                owner_uid: None,
                process_group: None,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|info| info.pid);
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptedParentEdge {
    verified: Option<u32>,
    unverified: Option<u32>,
}

fn accepted_parent_edge(
    child_pid: u32,
    parent_pid: Option<u32>,
    markers: &HashMap<u32, Option<ProcessStartMarker>>,
) -> AcceptedParentEdge {
    let Some(parent_pid) = parent_pid else {
        return AcceptedParentEdge {
            verified: None,
            unverified: None,
        };
    };
    if parent_pid == child_pid {
        return AcceptedParentEdge {
            verified: None,
            unverified: None,
        };
    }
    let Some(child_start) = markers.get(&child_pid).copied().flatten() else {
        return AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        };
    };
    let Some(parent_start) = markers.get(&parent_pid).copied().flatten() else {
        return AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        };
    };
    match child_start.cmp(&parent_start) {
        std::cmp::Ordering::Greater => AcceptedParentEdge {
            verified: Some(parent_pid),
            unverified: None,
        },
        std::cmp::Ordering::Equal => AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        },
        std::cmp::Ordering::Less => AcceptedParentEdge {
            verified: None,
            unverified: None,
        },
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<ProcessStartMarker> {
    let process_handle = open_query_process(pid).ok()?;
    process_start_time_marker_from_handle(&process_handle)
}

pub(crate) fn process_start_time_marker_from_handle(
    handle: &OwnedHandle,
) -> Option<ProcessStartMarker> {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    let result = unsafe {
        // SAFETY: all FILETIME pointers are valid for one write, and `handle` is
        // an owned process handle with query access.
        GetProcessTimes(
            handle.as_raw_handle(),
            &raw mut creation_time,
            &raw mut exit_time,
            &raw mut kernel_time,
            &raw mut user_time,
        )
    };
    (result != 0)
        .then(|| filetime_to_u64(creation_time))
        .and_then(|ticks| ProcessStartMarker::windows(ticks).ok())
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    let current_pid = std::process::id();
    let processes = ProcessSnapshot::collect(MetadataProfile::LegacyList, ProcessSelection::All)
        .unwrap_or_else(|_| ProcessSnapshot::default());
    let excluded_pids = processes.ancestor_pids(current_pid);
    let mut rows = processes.processes.into_iter().collect::<Vec<_>>();
    rows.sort_by_key(|(pid, _metadata)| *pid);

    let mut hints = Vec::new();
    for (pid, metadata) in rows {
        if excluded_pids.contains(&pid) {
            continue;
        }
        let Some(command_line) = metadata.command_line else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }
        hints.push(RelatedProcessHint {
            pid,
            process_name: metadata.process_name,
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }
    hints
}

type SocketTableCollector = fn(&mut Vec<SocketRecord>) -> Result<(), CollectorError>;
const SOCKET_TABLE_COLLECTORS: [SocketTableCollector; 4] = [
    collect_tcp4_records,
    collect_tcp6_records,
    collect_udp4_records,
    collect_udp6_records,
];

fn collect_socket_records() -> Result<Vec<SocketRecord>, CollectorError> {
    collect_socket_records_with(&SOCKET_TABLE_COLLECTORS)
}

fn collect_socket_records_with(
    collectors: &[SocketTableCollector],
) -> Result<Vec<SocketRecord>, CollectorError> {
    let mut records = Vec::new();
    for collector in collectors {
        collector(&mut records)?;
    }
    Ok(records)
}

fn collect_tcp4_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedTcpTable(AF_INET)", |buffer, size| unsafe {
        // SAFETY: IP Helper writes at most `*size` bytes to the caller-owned buffer.
        // The buffer is u32-aligned and `size` is its byte length.
        GetExtendedTcpTable(
            buffer,
            size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    append_tcp4_table(records, &table)
}

fn collect_tcp6_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedTcpTable(AF_INET6)", |buffer, size| unsafe {
        // SAFETY: see the IPv4 call above; only the address family changes.
        GetExtendedTcpTable(
            buffer,
            size,
            0,
            u32::from(AF_INET6),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    append_tcp6_table(records, &table)
}

fn collect_udp4_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedUdpTable(AF_INET)", |buffer, size| unsafe {
        // SAFETY: IP Helper writes at most `*size` bytes to the caller-owned buffer.
        GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)
    })?;
    append_udp4_table(records, &table)
}

fn collect_udp6_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedUdpTable(AF_INET6)", |buffer, size| unsafe {
        // SAFETY: see the IPv4 UDP call above; only the address family changes.
        GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0)
    })?;
    append_udp6_table(records, &table)
}

fn append_tcp4_table(records: &mut Vec<SocketRecord>, table: &[u32]) -> Result<(), CollectorError> {
    if table.is_empty() {
        return Ok(());
    }
    extend_socket_records(records, tcp4_rows(table)?.iter().map(tcp4_record))
}

fn append_tcp6_table(records: &mut Vec<SocketRecord>, table: &[u32]) -> Result<(), CollectorError> {
    if table.is_empty() {
        return Ok(());
    }
    extend_socket_records(records, tcp6_rows(table)?.iter().map(tcp6_record))
}

fn append_udp4_table(records: &mut Vec<SocketRecord>, table: &[u32]) -> Result<(), CollectorError> {
    if table.is_empty() {
        return Ok(());
    }
    extend_socket_records(records, udp4_rows(table)?.iter().map(udp4_record))
}

fn append_udp6_table(records: &mut Vec<SocketRecord>, table: &[u32]) -> Result<(), CollectorError> {
    if table.is_empty() {
        return Ok(());
    }
    extend_socket_records(records, udp6_rows(table)?.iter().map(udp6_record))
}

fn extend_socket_records(
    records: &mut Vec<SocketRecord>,
    incoming: impl IntoIterator<Item = Result<SocketRecord, CollectorError>>,
) -> Result<(), CollectorError> {
    extend_socket_records_with_limit(records, incoming, SOCKET_OBSERVATIONS_MAX)
}

fn extend_socket_records_with_limit(
    records: &mut Vec<SocketRecord>,
    incoming: impl IntoIterator<Item = Result<SocketRecord, CollectorError>>,
    limit: usize,
) -> Result<(), CollectorError> {
    for record in incoming {
        let record = record?;
        if records.len() >= limit {
            return Err(
                crate::observation::ObservationError::SocketObservationLimitExceeded.into(),
            );
        }
        records.push(record);
    }
    Ok(())
}

fn read_iphelper_table<F>(operation: &'static str, mut call: F) -> Result<Vec<u32>, CollectorError>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
{
    read_iphelper_table_with(operation, &mut call, |words| vec![0_u32; words])
}

fn read_iphelper_table_with<F, A>(
    operation: &'static str,
    mut call: F,
    mut allocate: A,
) -> Result<Vec<u32>, CollectorError>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
    A: FnMut(usize) -> Vec<u32>,
{
    let mut size = 0_u32;
    let mut code = call(std::ptr::null_mut(), &raw mut size);
    if code == ERROR_NO_DATA {
        return Ok(Vec::new());
    }
    if code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_SUCCESS {
        return Err(windows_api_error(operation, code));
    }

    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        if size == 0 {
            return Ok(Vec::new());
        }
        if size
            > u32::try_from(NATIVE_SOCKET_TABLE_MAX_BYTES)
                .expect("native socket-table byte limit fits the Windows API")
        {
            return Err(crate::observation::ObservationError::NativeDataOversized.into());
        }

        let words = usize::try_from(size)
            .expect("Windows table size must fit usize")
            .div_ceil(size_of::<u32>());
        let mut buffer = allocate(words);
        let mut buffer_size = u32::try_from(buffer.len() * size_of::<u32>())
            .expect("bounded Windows table buffer must fit u32");
        code = call(buffer.as_mut_ptr().cast::<c_void>(), &raw mut buffer_size);
        match code {
            ERROR_SUCCESS => {
                let returned_bytes =
                    usize::try_from(buffer_size).expect("Windows table size must fit usize");
                let allocated_bytes = std::mem::size_of_val(buffer.as_slice());
                if returned_bytes > allocated_bytes || returned_bytes % size_of::<u32>() != 0 {
                    return Err(CollectorError::Platform {
                        operation,
                        detail: "table returned an invalid byte length".to_owned(),
                    });
                }
                buffer.truncate(returned_bytes / size_of::<u32>());
                return Ok(buffer);
            }
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_INSUFFICIENT_BUFFER => size = buffer_size,
            code => return Err(windows_api_error(operation, code)),
        }
    }

    Err(CollectorError::Platform {
        operation,
        detail: "table kept growing while being read".to_owned(),
    })
}

fn tcp4_rows(buffer: &[u32]) -> Result<&[MIB_TCPROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_TCPTABLE_OWNER_PID",
        std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
    )
}

fn tcp6_rows(buffer: &[u32]) -> Result<&[MIB_TCP6ROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_TCP6TABLE_OWNER_PID",
        std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
    )
}

fn udp4_rows(buffer: &[u32]) -> Result<&[MIB_UDPROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_UDPTABLE_OWNER_PID",
        std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
    )
}

fn udp6_rows(buffer: &[u32]) -> Result<&[MIB_UDP6ROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_UDP6TABLE_OWNER_PID",
        std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
    )
}

fn table_rows<'a, Row>(
    buffer: &'a [u32],
    operation: &'static str,
    row_offset_bytes: usize,
) -> Result<&'a [Row], CollectorError> {
    let buffer_bytes = std::mem::size_of_val(buffer);
    if buffer_bytes < size_of::<u32>() {
        return Err(CollectorError::Platform {
            operation,
            detail: "table buffer is smaller than its row count".to_owned(),
        });
    }

    let count = usize::try_from(buffer[0]).expect("Windows table row count must fit usize");
    if count > SOCKET_OBSERVATIONS_MAX {
        return Err(crate::observation::ObservationError::SocketObservationLimitExceeded.into());
    }
    let row_address = (buffer.as_ptr() as usize)
        .checked_add(row_offset_bytes)
        .ok_or_else(|| CollectorError::Platform {
            operation,
            detail: "table row address overflows usize".to_owned(),
        })?;
    if row_offset_bytes < size_of::<u32>() || row_address % align_of::<Row>() != 0 {
        return Err(CollectorError::Platform {
            operation,
            detail: "table row payload is misaligned".to_owned(),
        });
    }
    let required = checked_table_byte_len(operation, count, size_of::<Row>(), row_offset_bytes)?;
    if required > buffer_bytes {
        return Err(CollectorError::Platform {
            operation,
            detail: "table row count exceeds returned buffer".to_owned(),
        });
    }

    let rows = unsafe {
        // SAFETY: the bounds check above proves the flexible array payload fits in
        // the returned u32-aligned buffer. IP Helper table rows are u32-aligned.
        let row_ptr = buffer
            .as_ptr()
            .cast::<u8>()
            .add(row_offset_bytes)
            .cast::<Row>();
        std::slice::from_raw_parts(row_ptr, count)
    };
    Ok(rows)
}

fn checked_table_byte_len(
    operation: &'static str,
    count: usize,
    row_size: usize,
    row_offset_bytes: usize,
) -> Result<usize, CollectorError> {
    let row_bytes = count
        .checked_mul(row_size)
        .ok_or_else(|| CollectorError::Platform {
            operation,
            detail: "table row count overflows usize".to_owned(),
        })?;
    row_offset_bytes
        .checked_add(row_bytes)
        .ok_or_else(|| CollectorError::Platform {
            operation,
            detail: "table byte length overflows usize".to_owned(),
        })
}

fn tcp4_record(row: &MIB_TCPROW_OWNER_PID) -> Result<SocketRecord, CollectorError> {
    Ok(SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(ipv4_addr(row.dwLocalAddr)),
        local_port: decode_port(row.dwLocalPort)?,
        ipv6_scope: None,
        state: mib_tcp_state(row.dwState),
        pid: (row.dwOwningPid != 0).then_some(row.dwOwningPid),
    })
}

fn tcp6_record(row: &MIB_TCP6ROW_OWNER_PID) -> Result<SocketRecord, CollectorError> {
    let (local_addr, ipv6_scope) = canonicalize_ipv6_local(
        Ipv6Addr::from(row.ucLocalAddr),
        ipv6_scope(u32::from_be(row.dwLocalScopeId)),
    );
    Ok(SocketRecord {
        protocol: Protocol::Tcp,
        local_addr,
        local_port: decode_port(row.dwLocalPort)?,
        ipv6_scope,
        state: mib_tcp_state(row.dwState),
        pid: (row.dwOwningPid != 0).then_some(row.dwOwningPid),
    })
}

fn mib_tcp_state(native: u32) -> SocketState {
    match i32::try_from(native).ok() {
        Some(MIB_TCP_STATE_CLOSED) => SocketState::Closed,
        Some(MIB_TCP_STATE_LISTEN) => SocketState::Listen,
        Some(MIB_TCP_STATE_SYN_SENT) => SocketState::SynSent,
        Some(MIB_TCP_STATE_SYN_RCVD) => SocketState::SynReceived,
        Some(MIB_TCP_STATE_ESTAB) => SocketState::Established,
        Some(MIB_TCP_STATE_FIN_WAIT1) => SocketState::FinWait1,
        Some(MIB_TCP_STATE_FIN_WAIT2) => SocketState::FinWait2,
        Some(MIB_TCP_STATE_CLOSE_WAIT) => SocketState::CloseWait,
        Some(MIB_TCP_STATE_CLOSING) => SocketState::Closing,
        Some(MIB_TCP_STATE_LAST_ACK) => SocketState::LastAck,
        Some(MIB_TCP_STATE_TIME_WAIT) => SocketState::TimeWait,
        Some(MIB_TCP_STATE_DELETE_TCB) => SocketState::DeleteTcb,
        _ => SocketState::Unknown(native),
    }
}

fn udp4_record(row: &MIB_UDPROW_OWNER_PID) -> Result<SocketRecord, CollectorError> {
    Ok(SocketRecord {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(ipv4_addr(row.dwLocalAddr)),
        local_port: decode_port(row.dwLocalPort)?,
        ipv6_scope: None,
        state: SocketState::Bound,
        pid: (row.dwOwningPid != 0).then_some(row.dwOwningPid),
    })
}

fn udp6_record(row: &MIB_UDP6ROW_OWNER_PID) -> Result<SocketRecord, CollectorError> {
    let (local_addr, ipv6_scope) = canonicalize_ipv6_local(
        Ipv6Addr::from(row.ucLocalAddr),
        ipv6_scope(u32::from_be(row.dwLocalScopeId)),
    );
    Ok(SocketRecord {
        protocol: Protocol::Udp,
        local_addr,
        local_port: decode_port(row.dwLocalPort)?,
        ipv6_scope,
        state: SocketState::Bound,
        pid: (row.dwOwningPid != 0).then_some(row.dwOwningPid),
    })
}

fn canonicalize_ipv6_local(address: Ipv6Addr, scope: Ipv6Scope) -> (IpAddr, Option<Ipv6Scope>) {
    address.to_ipv4_mapped().map_or_else(
        || (IpAddr::V6(address), Some(scope)),
        |address| (IpAddr::V4(address), None),
    )
}

const fn ipv6_scope(scope_id: u32) -> Ipv6Scope {
    match std::num::NonZeroU32::new(scope_id) {
        Some(scope_id) => Ipv6Scope::InterfaceIndex(scope_id),
        None => Ipv6Scope::Unscoped,
    }
}

fn ipv4_addr(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

#[cfg(test)]
fn encode_port_for_tests(port: u16) -> u32 {
    u32::from(port.to_be())
}

fn decode_port(raw: u32) -> Result<u16, CollectorError> {
    // IP Helper documents this DWORD as a network-order port consumed with
    // ntohs, whose input is the low 16 bits; the upper bits are unspecified.
    let port = u16::from_be(
        u16::try_from(raw & u32::from(u16::MAX)).expect("masked IP Helper port value must fit u16"),
    );
    if port == 0 {
        return Err(crate::observation::ObservationError::NativeDataMalformed.into());
    }
    Ok(port)
}

fn windows_api_error(operation: &'static str, code: u32) -> CollectorError {
    CollectorError::Platform {
        operation,
        detail: format!("Windows error {code}"),
    }
}

fn windows_io_error_code(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

#[cfg(test)]
mod tests;
