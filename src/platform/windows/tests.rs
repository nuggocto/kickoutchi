use super::{
    AcceptedParentEdge, MAX_CHILD_PROCESSES, ProcessApi, ProcessMetadata, ProcessOpenError,
    ProcessSelection, ProcessSnapshot, accepted_parent_edge, append_tcp4_table, append_tcp6_table,
    append_udp4_table, append_udp6_table, checked_table_byte_len, collect_socket_records_with,
    decode_port, decode_utf16_bounded, encode_port_for_tests, extend_socket_records_with_limit,
    filetime_to_u64, finish_bracketed_metadata, mib_tcp_state, native_pass_from_records,
    process_image_file_name_with, process_path_buffer_code_units, process_read_from_metadata,
    query_process_command_line_with, read_iphelper_table_with, read_process_observations_with,
    tcp4_record, tcp4_rows, tcp6_record, tcp6_rows, tree_process_infos_from_snapshot_with,
    udp4_record, udp4_rows, udp6_record, udp6_rows,
};
use crate::collector::CollectorError;
use crate::model::Protocol;
use crate::observation::{
    EvidenceGapCode, EvidenceImpact, Ipv6Scope, MetadataCompleteness, MetadataOmission,
    MetadataProfile, ObservationScope, ObservationScopeKind, OwnerCompleteness, OwnerObservation,
    ProcessRead, ProcessStartMarker, ScopeLimitation, SocketState, UnverifiedOwnerReason,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
#[expect(
    clippy::unnecessary_wraps,
    reason = "four typed collector seams stay visible in one production-wiring test"
)]
fn socket_collection_orchestration_runs_all_four_tables_in_order() {
    fn push_record(
        records: &mut Vec<super::SocketRecord>,
        protocol: Protocol,
        local_addr: IpAddr,
        local_port: u16,
        state: SocketState,
        pid: u32,
    ) {
        let ipv6_scope = local_addr.is_ipv6().then_some(Ipv6Scope::Unscoped);
        records.push(super::SocketRecord {
            protocol,
            local_addr,
            local_port,
            ipv6_scope,
            state,
            pid: Some(pid),
        });
    }

    fn tcp4(records: &mut Vec<super::SocketRecord>) -> Result<(), CollectorError> {
        push_record(
            records,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            3000,
            SocketState::Listen,
            1,
        );
        Ok(())
    }

    fn tcp6(records: &mut Vec<super::SocketRecord>) -> Result<(), CollectorError> {
        push_record(
            records,
            Protocol::Tcp,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            3001,
            SocketState::Established,
            2,
        );
        Ok(())
    }

    fn udp4(records: &mut Vec<super::SocketRecord>) -> Result<(), CollectorError> {
        push_record(
            records,
            Protocol::Udp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3002,
            SocketState::Bound,
            3,
        );
        Ok(())
    }

    fn udp6(records: &mut Vec<super::SocketRecord>) -> Result<(), CollectorError> {
        push_record(
            records,
            Protocol::Udp,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            3003,
            SocketState::Bound,
            4,
        );
        Ok(())
    }

    let records =
        collect_socket_records_with(&[tcp4, tcp6, udp4, udp6]).expect("all table readers succeed");

    assert_eq!(
        records
            .iter()
            .map(|record| (record.protocol, record.local_port))
            .collect::<Vec<_>>(),
        [
            (Protocol::Tcp, 3000),
            (Protocol::Tcp, 3001),
            (Protocol::Udp, 3002),
            (Protocol::Udp, 3003),
        ]
    );

    let mut aggregate = vec![records[0]];
    let error =
        extend_socket_records_with_limit(&mut aggregate, records[1..3].iter().copied().map(Ok), 2)
            .expect_err("first row beyond the aggregate limit is refused");
    assert!(matches!(
        error,
        CollectorError::Observation(
            crate::observation::ObservationError::SocketObservationLimitExceeded
        )
    ));
    assert_eq!(aggregate, records[..2]);
}
use std::path::PathBuf;
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_PID,
};

fn full_process_metadata() -> ProcessMetadata {
    ProcessMetadata {
        process_name: Some("python.exe".to_owned()),
        executable_path: Some("C:/Python/python.exe".into()),
        command_line: Some("python.exe -m http.server 3000".to_owned()),
        parent_pid: Some(42),
        unverified_parent_pid: None,
        parent_process_name: Some("WindowsTerminal.exe".to_owned()),
        start_time_marker: ProcessStartMarker::windows(100).ok(),
        identity_reason: None,
        partial: false,
        budget_omitted: false,
    }
}

#[derive(Default)]
struct FakeProcessApi {
    relations: Vec<HashMap<u32, Option<u32>>>,
    enumeration_count: usize,
    failed_enumerations: HashSet<usize>,
    refused_enumerations: HashSet<usize>,
    open_errors: HashMap<u32, ProcessOpenError>,
    markers: HashMap<u32, u64>,
    marker_reads: HashMap<u32, VecDeque<u64>>,
    paths: HashMap<u32, PathBuf>,
    names: HashMap<u32, String>,
    path_budgets: Vec<usize>,
    metadata_reads: Vec<(&'static str, u32, usize)>,
    max_retained_handles: usize,
}

impl FakeProcessApi {
    fn stable(relations: HashMap<u32, Option<u32>>) -> Self {
        let markers = relations
            .keys()
            .copied()
            .map(|pid| (pid, u64::from(pid) + 100))
            .collect();
        let paths = relations
            .keys()
            .copied()
            .map(|pid| (pid, PathBuf::from(format!("C:/fake/p{pid}.exe"))))
            .collect();
        let names = relations
            .keys()
            .copied()
            .map(|pid| (pid, format!("p{pid}.exe")))
            .collect();
        Self {
            relations: vec![relations.clone(), relations],
            markers,
            paths,
            names,
            ..Self::default()
        }
    }
}

impl ProcessApi for FakeProcessApi {
    type Handle = u32;

    fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
        let call = self.enumeration_count;
        self.enumeration_count += 1;
        if self.failed_enumerations.contains(&call) {
            return Err(CollectorError::Platform {
                operation: "CreateToolhelp32Snapshot",
                detail: "injected failure".to_owned(),
            });
        }
        if self.refused_enumerations.contains(&call) {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        let index = self
            .enumeration_count
            .saturating_sub(1)
            .min(self.relations.len().saturating_sub(1));
        Ok(self.relations.get(index).cloned().unwrap_or_default())
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError> {
        self.open_errors.get(&pid).copied().map_or(Ok(pid), Err)
    }

    fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker> {
        self.marker_reads
            .get_mut(handle)
            .and_then(VecDeque::pop_front)
            .or_else(|| self.markers.get(handle).copied())
            .and_then(|marker| ProcessStartMarker::windows(marker).ok())
    }

    fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker> {
        self.markers
            .get(&pid)
            .copied()
            .and_then(|marker| ProcessStartMarker::windows(marker).ok())
    }

    fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String> {
        self.metadata_reads.push(("name", pid, max_bytes));
        let name = self.names.get(&pid)?;
        (name.len() <= max_bytes).then(|| name.clone())
    }

    fn name_exceeds_budget(&mut self, pid: u32, max_bytes: usize) -> bool {
        self.names
            .get(&pid)
            .is_some_and(|name| name.len() > max_bytes)
    }

    fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf> {
        self.metadata_reads.push(("path", *handle, max_bytes));
        self.path_budgets.push(max_bytes);
        let path = self.paths.get(handle)?;
        (path.as_os_str().len() <= max_bytes).then(|| path.clone())
    }

    fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String> {
        self.metadata_reads
            .push(("command_line", *handle, max_bytes));
        let command = format!("p{handle}.exe --serve");
        (command.len() <= max_bytes).then_some(command)
    }

    fn observe_retained_handle_count(&mut self, count: usize) {
        self.max_retained_handles = self.max_retained_handles.max(count);
    }
}

struct RawTableFixture {
    storage: Vec<u64>,
    word_len: usize,
}

impl RawTableFixture {
    fn words(&self) -> &[u32] {
        unsafe {
            // SAFETY: `storage` is initialized u64 memory, hence is aligned
            // for u32. `word_len` was derived from its initialized byte span.
            std::slice::from_raw_parts(self.storage.as_ptr().cast::<u32>(), self.word_len)
        }
    }
}

fn raw_table_fixture(
    row_offset: usize,
    row_size: usize,
    row_align: usize,
    write_row: impl FnOnce(*mut u32),
) -> RawTableFixture {
    assert_eq!(row_offset % size_of::<u32>(), 0);
    let byte_len = row_offset.checked_add(row_size).unwrap();
    assert_eq!(byte_len % size_of::<u32>(), 0);
    let word_len = byte_len / size_of::<u32>();
    let mut storage = vec![0_u64; byte_len.div_ceil(size_of::<u64>())];
    let words = storage.as_mut_ptr().cast::<u32>();
    unsafe {
        // SAFETY: every concrete table has at least its u32 count header.
        words.write(1);
    }
    let row_words = unsafe {
        // SAFETY: `row_offset` is u32-aligned and falls within the allocation
        // sized for the complete concrete row.
        words.add(row_offset / size_of::<u32>())
    };
    assert_eq!((row_words as usize) % row_align, 0);
    write_row(row_words);
    RawTableFixture { storage, word_len }
}

#[test]
fn iphelper_zero_row_tables_are_legal() {
    let table = [0_u32];
    let mut records = Vec::new();

    assert!(tcp4_rows(&table).unwrap().is_empty());
    assert!(tcp6_rows(&table).unwrap().is_empty());
    assert!(udp4_rows(&table).unwrap().is_empty());
    assert!(udp6_rows(&table).unwrap().is_empty());
    append_tcp4_table(&mut records, &table).unwrap();
    append_tcp6_table(&mut records, &table).unwrap();
    append_udp4_table(&mut records, &table).unwrap();
    append_udp6_table(&mut records, &table).unwrap();
    assert!(records.is_empty());
}

#[test]
fn raw_tcp4_table_parses_and_converts_complete_row() {
    let row = MIB_TCPROW_OWNER_PID {
        dwState: 8,
        dwLocalAddr: u32::from_ne_bytes([192, 0, 2, 17]),
        dwLocalPort: encode_port_for_tests(44_321),
        dwRemoteAddr: 0,
        dwRemotePort: 0,
        dwOwningPid: 1_001,
    };
    let offset = std::mem::offset_of!(super::MIB_TCPTABLE_OWNER_PID, table);
    let fixture = raw_table_fixture(
        offset,
        size_of::<MIB_TCPROW_OWNER_PID>(),
        std::mem::align_of::<MIB_TCPROW_OWNER_PID>(),
        |row_words| unsafe {
            // SAFETY: the helper checked alignment and reserved one complete
            // MIB_TCPROW_OWNER_PID at this address.
            row_words.cast::<MIB_TCPROW_OWNER_PID>().write(row);
        },
    );

    let mut records = Vec::new();
    append_tcp4_table(&mut records, fixture.words()).expect("valid TCPv4 table");
    let pass = native_pass_from_records(records).expect("valid native pass");

    assert_eq!(pass.rows.len(), 1);
    assert_eq!(pass.rows[0].socket.endpoint.protocol, Protocol::Tcp);
    assert_eq!(
        pass.rows[0].socket.endpoint.address,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17))
    );
    assert_eq!(pass.rows[0].socket.endpoint.port.get(), 44_321);
    assert_eq!(pass.rows[0].socket.endpoint.ipv6_scope, None);
    assert_eq!(pass.rows[0].socket.state, SocketState::CloseWait);
    assert_eq!(pass.rows[0].owner_pids, [1_001]);
    assert!(
        append_tcp4_table(
            &mut Vec::new(),
            &fixture.words()[..fixture.words().len() - 1]
        )
        .is_err()
    );
}

#[test]
fn raw_tcp6_table_parses_and_converts_complete_row() {
    let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0, 0, 1);
    let row = MIB_TCP6ROW_OWNER_PID {
        ucLocalAddr: address.octets(),
        dwLocalScopeId: 19_u32.to_be(),
        dwLocalPort: encode_port_for_tests(65_535),
        ucRemoteAddr: [0; 16],
        dwRemoteScopeId: 0,
        dwRemotePort: 0,
        dwState: 11,
        dwOwningPid: 2_002,
    };
    let offset = std::mem::offset_of!(super::MIB_TCP6TABLE_OWNER_PID, table);
    let fixture = raw_table_fixture(
        offset,
        size_of::<MIB_TCP6ROW_OWNER_PID>(),
        std::mem::align_of::<MIB_TCP6ROW_OWNER_PID>(),
        |row_words| unsafe {
            // SAFETY: the helper checked alignment and reserved one complete
            // MIB_TCP6ROW_OWNER_PID at this address.
            row_words.cast::<MIB_TCP6ROW_OWNER_PID>().write(row);
        },
    );

    let mut records = Vec::new();
    append_tcp6_table(&mut records, fixture.words()).expect("valid TCPv6 table");
    let pass = native_pass_from_records(records).expect("valid native pass");

    assert_eq!(pass.rows.len(), 1);
    assert_eq!(pass.rows[0].socket.endpoint.protocol, Protocol::Tcp);
    assert_eq!(pass.rows[0].socket.endpoint.address, IpAddr::V6(address));
    assert_eq!(pass.rows[0].socket.endpoint.port.get(), 65_535);
    assert_eq!(
        pass.rows[0].socket.endpoint.ipv6_scope,
        Some(Ipv6Scope::InterfaceIndex(
            std::num::NonZeroU32::new(19).unwrap()
        ))
    );
    assert_eq!(pass.rows[0].socket.state, SocketState::TimeWait);
    assert_eq!(pass.rows[0].owner_pids, [2_002]);
    assert!(
        append_tcp6_table(
            &mut Vec::new(),
            &fixture.words()[..fixture.words().len() - 1]
        )
        .is_err()
    );
}

#[test]
fn raw_udp4_table_retains_row_when_owner_is_unavailable() {
    let row = MIB_UDPROW_OWNER_PID {
        dwLocalAddr: u32::from_ne_bytes([198, 51, 100, 23]),
        dwLocalPort: encode_port_for_tests(53),
        dwOwningPid: 0,
    };
    let offset = std::mem::offset_of!(super::MIB_UDPTABLE_OWNER_PID, table);
    let fixture = raw_table_fixture(
        offset,
        size_of::<MIB_UDPROW_OWNER_PID>(),
        std::mem::align_of::<MIB_UDPROW_OWNER_PID>(),
        |row_words| unsafe {
            // SAFETY: the helper checked alignment and reserved one complete
            // MIB_UDPROW_OWNER_PID at this address.
            row_words.cast::<MIB_UDPROW_OWNER_PID>().write(row);
        },
    );

    let mut records = Vec::new();
    append_udp4_table(&mut records, fixture.words()).expect("valid UDPv4 table");
    let pass = native_pass_from_records(records).expect("valid native pass");

    assert_eq!(pass.rows.len(), 1);
    assert_eq!(pass.rows[0].socket.endpoint.protocol, Protocol::Udp);
    assert_eq!(
        pass.rows[0].socket.endpoint.address,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23))
    );
    assert_eq!(pass.rows[0].socket.endpoint.port.get(), 53);
    assert_eq!(pass.rows[0].socket.endpoint.ipv6_scope, None);
    assert_eq!(pass.rows[0].socket.state, SocketState::Bound);
    assert!(pass.rows[0].owner_pids.is_empty());
    assert!(matches!(
        &pass.rows[0].owner_completeness,
        OwnerCompleteness::Partial { reasons }
            if reasons == &[EvidenceGapCode::OwnerAttributionIncomplete]
    ));
    assert!(
        append_udp4_table(
            &mut Vec::new(),
            &fixture.words()[..fixture.words().len() - 1]
        )
        .is_err()
    );
}

#[test]
fn raw_udp6_table_retains_row_when_owner_is_unavailable() {
    let address = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
    let row = MIB_UDP6ROW_OWNER_PID {
        ucLocalAddr: address.octets(),
        dwLocalScopeId: 7_u32.to_be(),
        dwLocalPort: encode_port_for_tests(5_353),
        dwOwningPid: 0,
    };
    let offset = std::mem::offset_of!(super::MIB_UDP6TABLE_OWNER_PID, table);
    let fixture = raw_table_fixture(
        offset,
        size_of::<MIB_UDP6ROW_OWNER_PID>(),
        std::mem::align_of::<MIB_UDP6ROW_OWNER_PID>(),
        |row_words| unsafe {
            // SAFETY: the helper checked alignment and reserved one complete
            // MIB_UDP6ROW_OWNER_PID at this address.
            row_words.cast::<MIB_UDP6ROW_OWNER_PID>().write(row);
        },
    );

    let mut records = Vec::new();
    append_udp6_table(&mut records, fixture.words()).expect("valid UDPv6 table");
    let pass = native_pass_from_records(records).expect("valid native pass");

    assert_eq!(pass.rows.len(), 1);
    assert_eq!(pass.rows[0].socket.endpoint.protocol, Protocol::Udp);
    assert_eq!(pass.rows[0].socket.endpoint.address, IpAddr::V6(address));
    assert_eq!(pass.rows[0].socket.endpoint.port.get(), 5_353);
    assert_eq!(
        pass.rows[0].socket.endpoint.ipv6_scope,
        Some(Ipv6Scope::InterfaceIndex(
            std::num::NonZeroU32::new(7).unwrap()
        ))
    );
    assert_eq!(pass.rows[0].socket.state, SocketState::Bound);
    assert!(pass.rows[0].owner_pids.is_empty());
    assert_eq!(pass.evidence_gaps.len(), 1);
    assert_eq!(
        pass.evidence_gaps[0].code,
        EvidenceGapCode::OwnerAttributionIncomplete
    );
    assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::Ownership);
    assert!(
        append_udp6_table(
            &mut Vec::new(),
            &fixture.words()[..fixture.words().len() - 1]
        )
        .is_err()
    );
}

#[test]
fn iphelper_accepts_exact_byte_limit_without_oversized_allocation() {
    let limit = super::NATIVE_SOCKET_TABLE_MAX_BYTES;
    let mut calls = 0;
    let mut allocations = Vec::new();
    let table = read_iphelper_table_with(
        "test",
        |buffer, size| {
            calls += 1;
            if buffer.is_null() {
                unsafe {
                    // SAFETY: the reader supplies a valid size output pointer.
                    *size = u32::try_from(limit).unwrap();
                }
                super::ERROR_INSUFFICIENT_BUFFER
            } else {
                super::ERROR_SUCCESS
            }
        },
        |words| {
            allocations.push(words);
            vec![0_u32; words]
        },
    )
    .expect("the exact table byte limit is accepted");

    assert_eq!(calls, 2);
    assert_eq!(allocations, [limit / size_of::<u32>()]);
    assert_eq!(std::mem::size_of_val(table.as_slice()), limit);
}

#[test]
fn iphelper_refuses_over_limit_before_allocation_or_data_call() {
    let mut calls = 0;
    let mut allocations = 0;
    let result = read_iphelper_table_with(
        "test",
        |_buffer, size| {
            calls += 1;
            unsafe {
                // SAFETY: the reader supplies a valid size output pointer.
                *size = u32::try_from(super::NATIVE_SOCKET_TABLE_MAX_BYTES + 1).unwrap();
            }
            super::ERROR_INSUFFICIENT_BUFFER
        },
        |words| {
            allocations += 1;
            vec![0_u32; words]
        },
    );

    assert!(matches!(
        result,
        Err(crate::collector::CollectorError::Observation(
            crate::observation::ObservationError::NativeDataOversized
        ))
    ));
    assert_eq!(calls, 1, "only the size probe may reach IP Helper");
    assert_eq!(allocations, 0);
}

#[test]
fn iphelper_can_succeed_on_third_resize_attempt() {
    let mut calls = 0;
    let table = read_iphelper_table_with(
        "test",
        |buffer, size| {
            calls += 1;
            unsafe {
                // SAFETY: the reader supplies a valid size output pointer.
                *size = u32::try_from(size_of::<u32>()).unwrap();
                if calls == 4 {
                    buffer.cast::<u32>().write(0);
                }
            }
            if calls == 4 {
                super::ERROR_SUCCESS
            } else {
                super::ERROR_INSUFFICIENT_BUFFER
            }
        },
        |words| vec![0_u32; words],
    )
    .expect("the third bounded resize attempt may succeed");

    assert_eq!(calls, 4, "one probe plus three data calls");
    assert_eq!(table, [0]);
}

#[test]
fn iphelper_never_makes_a_fourth_resize_attempt() {
    let mut calls = 0;
    let result = read_iphelper_table_with(
        "test",
        |_buffer, size| {
            calls += 1;
            unsafe {
                // SAFETY: the reader supplies a valid size output pointer.
                *size = u32::try_from(size_of::<u32>()).unwrap();
            }
            super::ERROR_INSUFFICIENT_BUFFER
        },
        |words| vec![0_u32; words],
    );

    assert!(result.is_err());
    assert_eq!(calls, 4, "one probe plus exactly three data calls");
}

#[test]
fn iphelper_truncates_to_successful_returned_byte_size() {
    let mut calls = 0;
    let table = read_iphelper_table_with(
        "test",
        |buffer: *mut c_void, size| {
            calls += 1;
            unsafe {
                // SAFETY: the reader supplies a valid size output pointer and,
                // on the data call, a buffer of the probed size.
                if buffer.is_null() {
                    *size = 4 * u32::try_from(size_of::<u32>()).unwrap();
                    return super::ERROR_INSUFFICIENT_BUFFER;
                }
                buffer.cast::<u32>().write(0);
                *size = u32::try_from(size_of::<u32>()).unwrap();
            }
            super::ERROR_SUCCESS
        },
        |words| vec![u32::MAX; words],
    )
    .expect("a shorter successful return is valid");

    assert_eq!(calls, 2);
    assert_eq!(table, [0]);
}

#[test]
fn iphelper_rejects_successful_return_length_overclaim() {
    let mut calls = 0;
    let result = read_iphelper_table_with(
        "test",
        |buffer, size| {
            calls += 1;
            unsafe {
                // SAFETY: the reader supplies a valid size output pointer.
                *size = if buffer.is_null() { 4 } else { 8 };
            }
            if buffer.is_null() {
                super::ERROR_INSUFFICIENT_BUFFER
            } else {
                super::ERROR_SUCCESS
            }
        },
        |words| vec![0_u32; words],
    );

    assert!(result.is_err());
    assert_eq!(calls, 2);
}

#[test]
fn table_rows_reject_malicious_count_and_checked_arithmetic_overflow() {
    let malicious = [u32::MAX];
    assert!(tcp4_rows(&malicious).is_err());
    assert!(tcp6_rows(&malicious).is_err());
    assert!(udp4_rows(&malicious).is_err());
    assert!(udp6_rows(&malicious).is_err());

    assert!(checked_table_byte_len("test", usize::MAX, 2, 0).is_err());
    assert!(checked_table_byte_len("test", 1, 2, usize::MAX).is_err());
}

#[test]
fn all_iphelper_layouts_reject_truncated_one_row_fixtures() {
    let truncated = [1_u32];

    assert!(tcp4_rows(&truncated).is_err());
    assert!(tcp6_rows(&truncated).is_err());
    assert!(udp4_rows(&truncated).is_err());
    assert!(udp6_rows(&truncated).is_err());
}

fn assert_socket_relation_fallback(failed_call: usize, row_bound_refusal: bool) {
    let record = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 443,
        ipv6_scope: None,
        state: SocketState::Listen,
        pid: Some(7),
    };
    let pass = native_pass_from_records(vec![record]).expect("valid socket pass");
    let scope = ObservationScope::new(
        ObservationScopeKind::CurrentHostNetworkStack,
        None,
        [ScopeLimitation::WslNetworkStackExcluded],
    )
    .unwrap();
    let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
    if row_bound_refusal {
        api.refused_enumerations.insert(failed_call);
    } else {
        api.failed_enumerations.insert(failed_call);
    }

    let snapshot = crate::collector::collect_native_snapshot(
        MetadataProfile::Display,
        scope,
        |_| Ok(pass.clone()),
        |pids, profile, budget| read_process_observations_with(&mut api, pids, profile, budget),
    )
    .expect("relation loss is metadata-local");

    assert_eq!(snapshot.sockets.len(), 1);
    assert!(matches!(
        snapshot.sockets[0].owners.as_slice(),
        [OwnerObservation::Verified(identity)] if identity.pid == 7
    ));
    assert_eq!(snapshot.processes.len(), 1);
    let metadata = snapshot.processes.values().next().unwrap();
    assert_eq!(
        metadata.metadata_completeness,
        MetadataCompleteness::Partial
    );
    assert_eq!(metadata.name, None);
    assert_eq!(metadata.executable_path, None);
    assert_eq!(metadata.command_line, None);
    assert_eq!(metadata.parent_pid, None);
    assert_eq!(metadata.parent_process_name, None);
    assert_eq!(metadata.metadata_omission, None);
    assert_eq!(api.enumeration_count, failed_call + 1);
}

#[test]
fn first_relation_enumeration_failure_keeps_authoritative_socket_rows() {
    assert_socket_relation_fallback(0, false);
}

#[test]
fn second_relation_row_bound_refusal_keeps_authoritative_socket_rows() {
    assert_socket_relation_fallback(1, true);
}

#[test]
fn tree_style_snapshot_keeps_toolhelp_enumeration_failure_fatal() {
    let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
    api.failed_enumerations.insert(0);

    let error = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::All,
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect_err("shared process snapshots must remain fail-closed");

    assert!(matches!(
        error,
        CollectorError::Platform {
            operation: "CreateToolhelp32Snapshot",
            ..
        }
    ));
    assert_eq!(api.enumeration_count, 1);
}

#[test]
fn socket_relation_fallback_preserves_per_pid_failure_reason() {
    let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
    api.failed_enumerations.insert(0);
    api.open_errors
        .insert(7, ProcessOpenError::PermissionDenied);

    let reads = read_process_observations_with(
        &mut api,
        &[7],
        MetadataProfile::Display,
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("relation failure uses direct PID reads");

    let [(pid, read)] = reads.as_slice() else {
        panic!("one requested PID must produce one read");
    };
    assert_eq!(*pid, 7);
    assert_eq!(
        *read,
        ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied),
    );
}

#[test]
fn process_handles_are_retained_in_bounded_chunks() {
    let count = u32::try_from(super::PROCESS_HANDLE_CHUNK_MAX + 1).unwrap();
    let relations = (1..=count)
        .map(|pid| (pid, (pid != 1).then_some(1)))
        .collect::<HashMap<_, _>>();
    let pids = (1..=count).collect::<Vec<_>>();
    let mut api = FakeProcessApi::stable(relations);

    let snapshot = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&pids),
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("chunked collection succeeds");

    assert_eq!(snapshot.processes.len(), pids.len());
    assert_eq!(api.enumeration_count, 2);
    assert_eq!(
        api.max_retained_handles,
        super::RETAINED_PROCESS_HANDLES_MAX
    );
}

#[test]
fn parent_name_reads_are_capped_by_each_low_aggregate_remainder() {
    let relations = (1..=64)
        .map(|pid| (pid, (pid != 1).then_some(1)))
        .collect::<HashMap<_, _>>();
    let pids = (2..=64).collect::<Vec<_>>();
    let mut api = FakeProcessApi::stable(relations);

    ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&pids),
        7,
    )
    .expect("low-budget metadata collection remains bounded");

    assert!(!api.path_budgets.is_empty());
    assert!(api.path_budgets.iter().all(|budget| *budget <= 7));
}

#[test]
fn changed_parent_relation_never_reports_the_stale_first_parent() {
    let first = HashMap::from([(1, None), (7, Some(1))]);
    let second = HashMap::from([(1, None), (7, None)]);
    let mut api = FakeProcessApi::stable(first);
    api.relations[1] = second;

    let metadata = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&[7]),
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("changed relation remains row-local")
    .processes
    .remove(&7)
    .unwrap();

    assert_eq!(metadata.parent_pid, None);
    assert_eq!(metadata.unverified_parent_pid, None);
    assert!(metadata.partial);
}

#[test]
fn executable_path_native_capacity_tracks_final_byte_budget() {
    assert_eq!(process_path_buffer_code_units(0), 0);
    assert_eq!(process_path_buffer_code_units(9), 9);
    assert_eq!(
        process_path_buffer_code_units(usize::MAX),
        super::WINDOWS_PROCESS_PATH_CODE_UNITS_MAX
    );
}

#[test]
fn parent_name_budget_marks_exact_fit_and_first_excess_truthfully() {
    fn collect_with_parent_budget(budget: usize) -> ProcessMetadata {
        let relations = HashMap::from([(1, None), (7, Some(1))]);
        let mut api = FakeProcessApi::stable(relations);
        api.names.insert(7, String::new());
        api.paths.insert(7, PathBuf::new());
        api.names.insert(1, "parent".to_owned());
        ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::Display,
            ProcessSelection::Exact(&[7]),
            budget,
        )
        .expect("parent metadata collection succeeds")
        .processes
        .remove(&7)
        .unwrap()
    }

    let exact = collect_with_parent_budget("parent".len());
    assert_eq!(exact.parent_process_name.as_deref(), Some("parent"));
    assert!(!exact.budget_omitted);

    for budget in ["parent".len() - 1, 0] {
        let omitted = process_read_from_metadata(collect_with_parent_budget(budget));
        let ProcessRead::Verified { observation, .. } = omitted else {
            panic!("stable identity remains verified");
        };
        assert_eq!(observation.parent_process_name, None);
        assert_eq!(
            observation.metadata_omission,
            Some(MetadataOmission::BudgetExceeded)
        );
    }
}

#[test]
fn genuine_parent_lookup_failure_is_not_reported_as_budget_exhaustion() {
    let relations = HashMap::from([(1, None), (7, Some(1))]);
    let mut api = FakeProcessApi::stable(relations);
    api.open_errors
        .insert(1, ProcessOpenError::PermissionDenied);

    let metadata = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&[7]),
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("parent lookup failure remains row-local")
    .processes
    .remove(&7)
    .unwrap();
    let ProcessRead::Verified { observation, .. } = process_read_from_metadata(metadata) else {
        panic!("child identity remains verified");
    };

    assert_eq!(observation.parent_pid, None);
    assert_eq!(observation.parent_process_name, None);
    assert_eq!(observation.metadata_omission, None);
    assert_eq!(
        observation.metadata_completeness,
        MetadataCompleteness::Partial
    );
}

#[test]
fn unavailable_parent_name_under_low_budget_is_not_budget_exhaustion() {
    let relations = HashMap::from([(1, None), (7, Some(1))]);
    let mut api = FakeProcessApi::stable(relations);
    api.names.insert(7, String::new());
    api.paths.insert(7, PathBuf::new());
    api.names.remove(&1);

    let metadata = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&[7]),
        1,
    )
    .expect("unavailable parent name remains row-local")
    .processes
    .remove(&7)
    .unwrap();
    let ProcessRead::Verified { observation, .. } = process_read_from_metadata(metadata) else {
        panic!("child identity remains verified");
    };

    assert_eq!(observation.parent_pid, Some(1));
    assert_eq!(observation.parent_process_name, None);
    assert_eq!(observation.metadata_omission, None);
    assert_eq!(
        observation.metadata_completeness,
        MetadataCompleteness::Partial
    );
}

#[test]
fn cached_parent_name_respects_each_childs_remaining_budget() {
    let cached = super::VerifiedParent {
        name: Some("parent".to_owned()),
        name_budget_exceeded: false,
    };

    let exact = super::verified_parent_for_budget(&cached, 6);
    assert_eq!(exact.name.as_deref(), Some("parent"));
    assert!(!exact.name_budget_exceeded);

    for budget in [5, 0] {
        let omitted = super::verified_parent_for_budget(&cached, budget);
        assert_eq!(omitted.name, None);
        assert!(omitted.name_budget_exceeded);
    }
}

#[test]
fn metadata_reads_use_toolhelp_name_source_and_deterministic_field_order() {
    let relations = HashMap::from([(7, Some(1)), (1, None)]);
    let mut api = FakeProcessApi::stable(relations);
    api.markers.insert(1, 1);
    api.markers.insert(7, 107);
    api.names.insert(7, "toolhelp.exe".to_owned());
    api.paths.insert(7, PathBuf::from("C:/different/path.exe"));

    let snapshot = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::LegacyList,
        ProcessSelection::Exact(&[7]),
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("fake collection succeeds");

    assert_eq!(
        snapshot.processes[&7].process_name.as_deref(),
        Some("toolhelp.exe")
    );
    let fields = api
        .metadata_reads
        .iter()
        .map(|(field, _, _)| *field)
        .collect::<Vec<_>>();
    assert_eq!(fields, ["name", "path", "name", "command_line"]);
}

#[test]
fn low_aggregate_budget_is_reserved_in_name_then_path_order() {
    let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
    api.names.insert(7, "seven.exe".to_owned());

    let snapshot = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::LegacyList,
        ProcessSelection::Exact(&[7]),
        9,
    )
    .expect("low-budget collection succeeds");

    assert_eq!(
        snapshot.processes[&7].process_name.as_deref(),
        Some("seven.exe")
    );
    assert_eq!(snapshot.processes[&7].executable_path, None);
    assert_eq!(
        api.metadata_reads,
        vec![("name", 7, 9)],
        "no later field allocates after the name consumes the reserve",
    );
}

#[test]
fn command_line_utf16_seam_enforces_final_utf8_boundary() {
    let exact = vec![u16::from(b'x'); super::PROCESS_COMMAND_LINE_MAX_BYTES];
    assert_eq!(
        decode_utf16_bounded(&exact, super::PROCESS_COMMAND_LINE_MAX_BYTES)
            .as_deref()
            .map(str::len),
        Some(super::PROCESS_COMMAND_LINE_MAX_BYTES)
    );

    let oversized = vec![u16::from(b'x'); super::PROCESS_COMMAND_LINE_MAX_BYTES + 1];
    assert_eq!(
        decode_utf16_bounded(&oversized, super::PROCESS_COMMAND_LINE_MAX_BYTES),
        None
    );
}

#[test]
fn command_line_native_read_succeeds_after_bounded_resize_retry() {
    let header = size_of::<super::UNICODE_STRING>();
    let final_bytes = header + 4;
    let mut calls = 0;
    let command_line = query_process_command_line_with(32, |buffer, _capacity, required| {
        calls += 1;
        unsafe {
            // SAFETY: the seam provides a valid required-length pointer and
            // the successful call provides the requested writable storage.
            if buffer.is_null() {
                *required = u32::try_from(header + 2).unwrap();
                return super::STATUS_INFO_LENGTH_MISMATCH;
            }
            if calls <= 3 {
                *required = u32::try_from(final_bytes).unwrap();
                return super::STATUS_BUFFER_TOO_SMALL;
            }
            let text = buffer
                .cast::<u64>()
                .add(header / size_of::<u64>())
                .cast::<u16>();
            text.write(u16::from(b'o'));
            text.add(1).write(u16::from(b'k'));
            buffer
                .cast::<super::UNICODE_STRING>()
                .write(super::UNICODE_STRING {
                    Length: 4,
                    MaximumLength: 4,
                    Buffer: text,
                });
            *required = u32::try_from(final_bytes).unwrap();
        }
        0
    });

    assert_eq!(command_line.as_deref(), Some("ok"));
    assert_eq!(calls, 4, "one probe plus three data attempts");
}

#[test]
fn command_line_native_read_never_makes_a_fourth_data_attempt() {
    let mut calls = 0;
    let result = query_process_command_line_with(32, |_buffer, _capacity, required| {
        calls += 1;
        unsafe {
            // SAFETY: the seam provides a valid required-length pointer.
            *required = u32::try_from(size_of::<super::UNICODE_STRING>() + 2).unwrap();
        }
        super::STATUS_INFO_LENGTH_MISMATCH
    });

    assert_eq!(result, None);
    assert_eq!(calls, 4, "one probe plus exactly three data attempts");
}

#[test]
fn batch_refuses_reused_pid_and_discards_its_metadata() {
    let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
    api.marker_reads.insert(7, VecDeque::from([107, 108]));
    api.markers.insert(7, 108);

    let snapshot = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&[7]),
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("fake batch collection succeeds");

    assert_eq!(
        process_read_from_metadata(snapshot.processes[&7].clone()),
        ProcessRead::Unverified(UnverifiedOwnerReason::Raced)
    );
}

#[test]
fn selected_process_context_batch_keeps_direct_children() {
    let relations = HashMap::from([(100, None), (101, Some(100)), (200, Some(1))]);
    let mut api = FakeProcessApi::stable(relations);
    api.markers.insert(100, 100);
    api.markers.insert(101, 200);

    let snapshot = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::ExactWithDirectChildren(&[100]),
        0,
    )
    .expect("fake context collection succeeds");

    assert_eq!(
        snapshot.processes.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([100, 101])
    );
    assert_eq!(snapshot.children(100).children[0].pid, 101);
    assert_eq!(snapshot.children(100).children[0].process_name, None);
    assert_eq!(api.enumeration_count, 2);
}

#[test]
fn process_open_permission_denial_remains_distinct() {
    let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
    api.open_errors
        .insert(7, ProcessOpenError::PermissionDenied);

    let snapshot = ProcessSnapshot::collect_with(
        &mut api,
        MetadataProfile::Display,
        ProcessSelection::Exact(&[7]),
        super::OPTIONAL_METADATA_MAX_BYTES,
    )
    .expect("permission denial remains row-local");

    assert_eq!(
        process_read_from_metadata(snapshot.processes[&7].clone()),
        ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied)
    );
}

#[test]
fn process_snapshot_tracks_current_process_ancestors() {
    let snapshot = ProcessSnapshot {
        processes: HashMap::from([
            (
                10,
                ProcessMetadata {
                    parent_pid: Some(5),
                    ..ProcessMetadata::default()
                },
            ),
            (
                5,
                ProcessMetadata {
                    parent_pid: Some(1),
                    ..ProcessMetadata::default()
                },
            ),
            (
                1,
                ProcessMetadata {
                    parent_pid: Some(1),
                    ..ProcessMetadata::default()
                },
            ),
        ]),
    };

    let ancestors = snapshot.ancestor_pids(10);

    assert!(ancestors.contains(&10));
    assert!(ancestors.contains(&5));
    assert!(ancestors.contains(&1));
    assert_eq!(ancestors.len(), 3);
}

#[test]
fn children_are_resolved_on_demand_sorted_and_self_excluded() {
    let snapshot = ProcessSnapshot {
        processes: HashMap::from([
            (
                100,
                ProcessMetadata {
                    parent_pid: Some(100),
                    ..ProcessMetadata::default()
                },
            ),
            (
                102,
                ProcessMetadata {
                    process_name: Some("worker-b".to_owned()),
                    parent_pid: Some(100),
                    ..ProcessMetadata::default()
                },
            ),
            (
                101,
                ProcessMetadata {
                    process_name: Some("worker-a".to_owned()),
                    parent_pid: Some(100),
                    ..ProcessMetadata::default()
                },
            ),
            (
                200,
                ProcessMetadata {
                    parent_pid: Some(1),
                    ..ProcessMetadata::default()
                },
            ),
        ]),
    };

    let children = snapshot.children(100);

    let listed: Vec<(u32, Option<&str>)> = children
        .children
        .iter()
        .map(|child| (child.pid, child.process_name.as_deref()))
        .collect();
    assert_eq!(
        listed,
        vec![(101, Some("worker-a")), (102, Some("worker-b"))]
    );
    assert!(!children.truncated);
}

#[test]
fn children_resolution_is_bounded() {
    let mut processes = HashMap::from([(100, ProcessMetadata::default())]);
    let max = u32::try_from(MAX_CHILD_PROCESSES).expect("child cap fits u32 test PIDs");
    for offset in 0..=max {
        processes.insert(
            1_000 + offset,
            ProcessMetadata {
                parent_pid: Some(100),
                ..ProcessMetadata::default()
            },
        );
    }
    let snapshot = ProcessSnapshot { processes };

    let children = snapshot.children(100);

    assert_eq!(children.children.len(), MAX_CHILD_PROCESSES);
    assert!(children.truncated);
}

#[test]
fn tcp4_listen_row_becomes_socket_record() {
    let row = MIB_TCPROW_OWNER_PID {
        dwState: u32::try_from(MIB_TCP_STATE_LISTEN).expect("listen state fits u32"),
        dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
        dwLocalPort: encode_port_for_tests(3000),
        dwRemoteAddr: 0,
        dwRemotePort: 0,
        dwOwningPid: 18422,
    };

    let record = tcp4_record(&row).expect("valid TCP row");

    assert_eq!(record.protocol, Protocol::Tcp);
    assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(record.local_port, 3000);
    assert_eq!(record.state, SocketState::Listen);
    assert_eq!(record.pid, Some(18422));
}

#[test]
fn tcp6_listen_row_keeps_ipv6_address() {
    let row = MIB_TCP6ROW_OWNER_PID {
        ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
        dwLocalScopeId: 0,
        dwLocalPort: encode_port_for_tests(8080),
        ucRemoteAddr: [0; 16],
        dwRemoteScopeId: 0,
        dwRemotePort: 0,
        dwState: u32::try_from(MIB_TCP_STATE_LISTEN).expect("listen state fits u32"),
        dwOwningPid: 77,
    };

    let record = tcp6_record(&row).expect("valid TCP row");

    assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(record.local_port, 8080);
    assert_eq!(record.ipv6_scope, Some(Ipv6Scope::Unscoped));
    assert_eq!(record.pid, Some(77));
}

#[test]
fn tcp6_row_preserves_nonzero_scope_id() {
    let row = MIB_TCP6ROW_OWNER_PID {
        ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
        dwLocalScopeId: u32::MAX.to_be(),
        dwLocalPort: encode_port_for_tests(8080),
        ucRemoteAddr: [0; 16],
        dwRemoteScopeId: 0,
        dwRemotePort: 0,
        dwState: u32::try_from(MIB_TCP_STATE_LISTEN).unwrap(),
        dwOwningPid: 77,
    };

    assert_eq!(
        tcp6_record(&row).expect("valid TCP row").ipv6_scope,
        Some(Ipv6Scope::InterfaceIndex(
            std::num::NonZeroU32::new(u32::MAX).unwrap()
        ))
    );
}

#[test]
fn ipv4_mapped_ipv6_rows_become_unscoped_ipv4_endpoints() {
    let mapped = Ipv4Addr::new(192, 0, 2, 44).to_ipv6_mapped();
    let tcp = MIB_TCP6ROW_OWNER_PID {
        ucLocalAddr: mapped.octets(),
        dwLocalScopeId: 12_u32.to_be(),
        dwLocalPort: encode_port_for_tests(8080),
        ucRemoteAddr: [0; 16],
        dwRemoteScopeId: 0,
        dwRemotePort: 0,
        dwState: u32::try_from(MIB_TCP_STATE_LISTEN).unwrap(),
        dwOwningPid: 77,
    };
    let udp = MIB_UDP6ROW_OWNER_PID {
        ucLocalAddr: mapped.octets(),
        dwLocalScopeId: 13_u32.to_be(),
        dwLocalPort: encode_port_for_tests(8081),
        dwOwningPid: 78,
    };

    let tcp = tcp6_record(&tcp).expect("valid mapped TCPv6 row");
    let udp = udp6_record(&udp).expect("valid mapped UDPv6 row");

    assert_eq!(tcp.local_addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
    assert_eq!(tcp.ipv6_scope, None);
    assert_eq!(udp.local_addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
    assert_eq!(udp.ipv6_scope, None);
}

#[test]
fn every_documented_mib_tcp_state_maps_to_shared_state() {
    let cases = [
        (1, SocketState::Closed),
        (2, SocketState::Listen),
        (3, SocketState::SynSent),
        (4, SocketState::SynReceived),
        (5, SocketState::Established),
        (6, SocketState::FinWait1),
        (7, SocketState::FinWait2),
        (8, SocketState::CloseWait),
        (9, SocketState::Closing),
        (10, SocketState::LastAck),
        (11, SocketState::TimeWait),
        (12, SocketState::DeleteTcb),
    ];

    for (native, expected) in cases {
        assert_eq!(mib_tcp_state(native), expected, "native state {native}");
    }
}

#[test]
fn every_other_mib_tcp_state_preserves_its_native_code() {
    for native in [0, 13, 100, i32::MAX as u32 + 1, u32::MAX] {
        assert_eq!(mib_tcp_state(native), SocketState::Unknown(native));
    }
}

#[test]
fn owner_table_row_survives_without_process_enrichment() {
    let record = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 443,
        ipv6_scope: None,
        state: SocketState::Established,
        pid: Some(77),
    };

    let pass = native_pass_from_records(vec![record]).expect("owner row is authoritative");

    assert_eq!(pass.rows.len(), 1);
    assert_eq!(pass.rows[0].socket.state, SocketState::Established);
    assert_eq!(pass.rows[0].socket.timer, None);
    assert_eq!(pass.rows[0].owner_pids, [77]);
}

#[test]
fn owner_table_row_survives_process_identity_failure_in_snapshot() {
    let record = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 443,
        ipv6_scope: None,
        state: SocketState::Established,
        pid: Some(77),
    };
    let pass = native_pass_from_records(vec![record]).expect("owner row is authoritative");
    let scope = ObservationScope::new(
        ObservationScopeKind::CurrentHostNetworkStack,
        None,
        [ScopeLimitation::WslNetworkStackExcluded],
    )
    .unwrap();

    let snapshot = crate::collector::collect_native_snapshot(
        MetadataProfile::Display,
        scope,
        |_| Ok(pass.clone()),
        |pids, _, _| {
            Ok(pids
                .iter()
                .copied()
                .map(|pid| {
                    (
                        pid,
                        ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied),
                    )
                })
                .collect())
        },
    )
    .expect("identity failure is row-local");

    assert_eq!(snapshot.sockets.len(), 1);
    assert_eq!(snapshot.sockets[0].state, SocketState::Established);
    assert_eq!(
        snapshot.sockets[0].owners,
        vec![OwnerObservation::UnverifiedPid {
            pid: 77,
            reason: UnverifiedOwnerReason::PermissionDenied,
        }]
    );
    assert!(snapshot.processes.is_empty());
}

#[test]
fn ownerless_windows_snapshot_retains_endpoints_without_reading_pid_zero() {
    let tcp4 = tcp4_record(&MIB_TCPROW_OWNER_PID {
        dwState: u32::try_from(MIB_TCP_STATE_LISTEN).unwrap(),
        dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
        dwLocalPort: encode_port_for_tests(5351),
        dwRemoteAddr: 0,
        dwRemotePort: 0,
        dwOwningPid: 0,
    })
    .expect("valid ownerless TCPv4 row");
    let tcp6 = tcp6_record(&MIB_TCP6ROW_OWNER_PID {
        ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
        dwLocalScopeId: 0,
        dwLocalPort: encode_port_for_tests(5352),
        ucRemoteAddr: [0; 16],
        dwRemoteScopeId: 0,
        dwRemotePort: 0,
        dwState: u32::try_from(MIB_TCP_STATE_LISTEN).unwrap(),
        dwOwningPid: 0,
    })
    .expect("valid ownerless TCPv6 row");
    let udp4 = udp4_record(&MIB_UDPROW_OWNER_PID {
        dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
        dwLocalPort: encode_port_for_tests(5353),
        dwOwningPid: 0,
    })
    .expect("valid ownerless UDPv4 row");
    let udp6 = udp6_record(&MIB_UDP6ROW_OWNER_PID {
        ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
        dwLocalScopeId: 0,
        dwLocalPort: encode_port_for_tests(5355),
        dwOwningPid: 0,
    })
    .expect("valid ownerless UDPv6 row");
    let pass = native_pass_from_records(vec![tcp4, tcp6, udp4, udp6])
        .expect("ownerless Windows rows are retained");
    let scope = ObservationScope::new(
        ObservationScopeKind::CurrentHostNetworkStack,
        None,
        [ScopeLimitation::WslNetworkStackExcluded],
    )
    .unwrap();
    let mut process_reads = 0;

    let snapshot = crate::collector::collect_native_snapshot(
        MetadataProfile::Display,
        scope,
        |_| Ok(pass.clone()),
        |pids, _, _| {
            process_reads += 1;
            assert!(pids.is_empty(), "PID 0 must not become an owner edge");
            Ok(Vec::new())
        },
    )
    .expect("ownerless Windows snapshot remains valid");

    assert_eq!(process_reads, 2);
    assert_eq!(snapshot.sockets.len(), 4);
    assert!(
        snapshot
            .sockets
            .iter()
            .all(|socket| socket.owners.is_empty())
    );
    assert!(
        snapshot
            .sockets
            .iter()
            .all(|socket| matches!(socket.owner_completeness, OwnerCompleteness::Partial { .. }))
    );
    assert!(
        snapshot
            .sockets
            .iter()
            .all(|socket| snapshot.evidence_gaps.iter().any(|gap| {
                gap.code == EvidenceGapCode::OwnerAttributionIncomplete
                    && gap.impact == EvidenceImpact::Ownership
                    && gap.endpoint.as_ref() == Some(&socket.local_endpoint)
                    && gap.pid.is_none()
            }))
    );
    assert!(snapshot.processes.is_empty());
}

#[test]
fn udp_rows_are_bound_sockets() {
    let udp4 = MIB_UDPROW_OWNER_PID {
        dwLocalAddr: u32::from_ne_bytes([0, 0, 0, 0]),
        dwLocalPort: encode_port_for_tests(5353),
        dwOwningPid: 902,
    };
    let udp6 = MIB_UDP6ROW_OWNER_PID {
        ucLocalAddr: Ipv6Addr::UNSPECIFIED.octets(),
        dwLocalScopeId: 0,
        dwLocalPort: encode_port_for_tests(5355),
        dwOwningPid: 903,
    };

    let udp4 = udp4_record(&udp4).expect("valid UDP row");
    let udp6 = udp6_record(&udp6).expect("valid UDP row");
    assert_eq!(udp4.state, SocketState::Bound);
    assert_eq!(udp4.local_port, 5353);
    assert_eq!(udp6.state, SocketState::Bound);
    assert_eq!(udp6.local_port, 5355);
}

#[test]
fn port_decoding_uses_documented_low_word_and_rejects_zero() {
    assert_eq!(decode_port(encode_port_for_tests(3000)).unwrap(), 3000);
    assert_eq!(
        decode_port(0xDEAD_0000 | encode_port_for_tests(3000)).unwrap(),
        3000
    );
    assert!(decode_port(0).is_err());
}

#[test]
fn filetime_marker_keeps_full_windows_creation_time_precision() {
    let marker = filetime_to_u64(FILETIME {
        dwLowDateTime: 0x89AB_CDEF,
        dwHighDateTime: 0x0123_4567,
    });

    assert_eq!(marker, 0x0123_4567_89AB_CDEF);
}

#[test]
fn parent_edges_require_child_to_start_after_parent() {
    let markers = HashMap::from([
        (10, ProcessStartMarker::windows(100).ok()),
        (20, ProcessStartMarker::windows(200).ok()),
        (30, ProcessStartMarker::windows(50).ok()),
        (40, None),
    ]);

    assert_eq!(
        accepted_parent_edge(20, Some(10), &markers),
        AcceptedParentEdge {
            verified: Some(10),
            unverified: None,
        },
    );
    assert_eq!(
        accepted_parent_edge(10, Some(20), &markers),
        AcceptedParentEdge {
            verified: None,
            unverified: None,
        },
    );
    assert_eq!(
        accepted_parent_edge(30, Some(10), &markers),
        AcceptedParentEdge {
            verified: None,
            unverified: None,
        },
    );
    assert_eq!(
        accepted_parent_edge(20, Some(20), &markers),
        AcceptedParentEdge {
            verified: None,
            unverified: None,
        },
    );
}

#[test]
fn missing_creation_time_keeps_parent_edge_unverified() {
    let markers = HashMap::from([
        (10, ProcessStartMarker::windows(100).ok()),
        (20, ProcessStartMarker::windows(200).ok()),
        (40, None),
    ]);

    assert_eq!(
        accepted_parent_edge(20, Some(99), &markers),
        AcceptedParentEdge {
            verified: None,
            unverified: Some(99),
        },
    );
    assert_eq!(
        accepted_parent_edge(40, Some(10), &markers),
        AcceptedParentEdge {
            verified: None,
            unverified: Some(10),
        },
    );
}

#[test]
fn equal_creation_times_keep_parent_edge_unverified() {
    let snapshot = ProcessSnapshot {
        processes: HashMap::from([
            (10, ProcessMetadata::default()),
            (
                20,
                ProcessMetadata {
                    parent_pid: Some(10),
                    ..ProcessMetadata::default()
                },
            ),
        ]),
    };

    let rows =
        tree_process_infos_from_snapshot_with(&snapshot, |_| ProcessStartMarker::windows(100).ok());
    let child = rows.iter().find(|row| row.pid == 20).expect("child row");

    assert_eq!(child.parent_pid, None);
    assert_eq!(child.unverified_parent_pid, Some(10));
}

#[test]
fn process_read_uses_the_marker_that_bracketed_its_metadata() {
    let read = process_read_from_metadata(full_process_metadata());

    let ProcessRead::Verified {
        marker,
        observation,
    } = read
    else {
        panic!("identity-bracketed metadata must be verified");
    };
    assert_eq!(marker, ProcessStartMarker::windows(100).unwrap());
    assert_eq!(observation.name.as_deref(), Some("python.exe"));
    assert_eq!(
        observation.parent_process_name.as_deref(),
        Some("WindowsTerminal.exe")
    );
}

#[test]
fn pid_reuse_marker_mismatch_is_unverified_and_discards_metadata() {
    let metadata = finish_bracketed_metadata(
        full_process_metadata(),
        ProcessStartMarker::windows(100).unwrap(),
        ProcessStartMarker::windows(101).ok(),
        ProcessStartMarker::windows(101).ok(),
    );

    assert_eq!(
        process_read_from_metadata(metadata),
        ProcessRead::Unverified(UnverifiedOwnerReason::Raced)
    );
}

#[test]
fn image_file_name_reader_grows_for_long_paths_and_bounds_reported_lengths() {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER};

    let directory = "D:\\".to_owned() + &"deep\\".repeat(800);
    let long_path = format!("{directory}service.exe")
        .encode_utf16()
        .collect::<Vec<_>>();
    assert!(long_path.len() > 2_048);
    let mut capacities = Vec::new();
    let name = process_image_file_name_with(|buffer, length| {
        capacities.push(buffer.len());
        if buffer.len() < long_path.len() + 1 {
            return Err(std::io::Error::from_raw_os_error(
                i32::try_from(ERROR_INSUFFICIENT_BUFFER).unwrap(),
            ));
        }
        buffer[..long_path.len()].copy_from_slice(&long_path);
        *length = u32::try_from(long_path.len()).unwrap();
        Ok(())
    })
    .expect("a long image path is readable");
    assert_eq!(name.as_deref(), Some("service.exe"));
    assert_eq!(capacities.first(), Some(&260));
    assert!(capacities.windows(2).all(|pair| pair[1] > pair[0]));

    let malformed = process_image_file_name_with(|buffer, length| {
        *length = u32::try_from(buffer.len() + 1).unwrap();
        Ok(())
    });
    assert_eq!(
        malformed
            .expect_err("an impossible length must fail closed")
            .kind(),
        std::io::ErrorKind::InvalidData
    );

    let mut calls = 0;
    let denied = process_image_file_name_with(|_, _| {
        calls += 1;
        Err(std::io::Error::from_raw_os_error(
            i32::try_from(ERROR_ACCESS_DENIED).unwrap(),
        ))
    });
    assert!(denied.is_err());
    assert_eq!(calls, 1, "only an undersized buffer is retried");

    let mut oversized_calls = 0;
    let oversized = process_image_file_name_with(|_, _| {
        oversized_calls += 1;
        Err(std::io::Error::from_raw_os_error(
            i32::try_from(ERROR_INSUFFICIENT_BUFFER).unwrap(),
        ))
    });
    assert!(oversized.is_err());
    assert!(
        oversized_calls <= 8,
        "growth stops at the long-path maximum"
    );
}
