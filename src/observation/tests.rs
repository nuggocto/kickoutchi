use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use super::*;

#[test]
fn macos_executable_protection_agrees_between_borrowed_and_owned_rows() {
    let protected_names = vec!["postgres".to_owned()];
    for (name, path, expected) in [
        (Some("worker"), "/opt/postgres", true),
        (None, "/opt/postgres", true),
        (Some("worker"), "/opt/postgres-backup-helper", false),
    ] {
        let mut row = crate::test_support::port_entry(5432, Some(42), Protocol::Tcp, "worker");
        row.platform = Platform::Macos;
        row.process_name = name.map(Arc::from);
        row.executable_path = Some(Arc::from(Path::new(path)));
        row.process_identity = Some(ProcessIdentity {
            pid: 42,
            start_marker: ProcessStartMarker::macos(10, 1).unwrap(),
        });
        let snapshot = snapshot_from_test_rows(vec![row]);

        let descriptors = snapshot.port_entry_descriptors(&protected_names).unwrap();
        let mut owned = project_legacy(&snapshot).unwrap();
        crate::protection::mark_protected(&mut owned, &protected_names);

        assert_eq!(owned[0].protected, expected, "{name:?}: {path}");
        assert_eq!(
            snapshot.port_entry_view(&descriptors[0]).protected,
            expected,
            "{name:?}: {path}",
        );
    }
}

#[test]
fn scoped_ipv6_identity_survives_borrowed_and_owned_projection() {
    let mut snapshot = crate::collector::Collector::collect(
        &crate::collector::FakeCollector,
        MetadataProfile::Display,
    )
    .expect("fake snapshot is valid");
    let scope = Ipv6Scope::interface_index(7).expect("test scope is valid");
    let socket = snapshot.sockets.first_mut().expect("fixture has a socket");
    socket.local_endpoint.address = IpAddr::V6(Ipv6Addr::LOCALHOST);
    socket.local_endpoint.ipv6_scope = Some(scope);

    let descriptors = snapshot
        .port_entry_descriptors(&[])
        .expect("projection descriptors fit");
    assert_eq!(
        snapshot.port_entry_view(&descriptors[0]).ipv6_scope,
        Some(scope)
    );
    assert_eq!(
        project_legacy(&snapshot).expect("owned projection fits")[0].ipv6_scope,
        Some(scope)
    );
}

#[test]
fn legacy_permission_partial_does_not_imply_permission_denial() {
    let mut snapshot = crate::collector::Collector::collect(
        &crate::collector::FakeCollector,
        MetadataProfile::Display,
    )
    .expect("fake snapshot is valid");
    let socket = snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has the selected socket");
    socket.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).expect("one reason fits");

    let rows = project_legacy(&snapshot).expect("legacy projection fits");
    let row = rows
        .iter()
        .find(|row| row.local_port == 3000)
        .expect("selected row is projected");

    assert_eq!(row.permission, PermissionStatus::Partial);
}

#[test]
fn lossy_utf8_length_matches_conversion() {
    for bytes in [
        b"a\xffb\xf0\x80\x80\x80c".as_slice(),
        b"trailing\xf0\x9f".as_slice(),
    ] {
        let expected = String::from_utf8_lossy(bytes);
        let len = lossy_utf8_len(bytes).expect("small decoded length fits");
        assert_eq!(len, expected.len());

        let mut actual = String::with_capacity(len);
        push_utf8_lossy(&mut actual, bytes);
        assert_eq!(actual, expected);
    }
}

#[derive(Debug, Clone)]
enum Step {
    Clock(u64),
    Pass(NativeObservationPass),
    Process(u32, MetadataProfile, ProcessRead),
    ProcessBatch(ProcessReadBatch),
    Error(ObservationError),
}

struct FakeSource {
    steps: VecDeque<Step>,
    calls: Vec<String>,
    process_budgets: Vec<(u32, usize)>,
    process_batch_calls: usize,
}

impl FakeSource {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            calls: Vec::new(),
            process_budgets: Vec::new(),
            process_batch_calls: 0,
        }
    }

    fn next(&mut self) -> Result<Step, ObservationError> {
        match self.steps.pop_front().expect("test source exhausted") {
            Step::Error(error) => Err(error),
            step => Ok(step),
        }
    }

    fn read_process(
        &mut self,
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessRead, ObservationError> {
        self.calls.push(format!("process:{pid}:{profile:?}"));
        self.process_budgets
            .push((pid, optional_metadata_bytes_remaining));
        match self.next()? {
            Step::Process(expected_pid, expected_profile, read) => {
                assert_eq!(pid, expected_pid);
                assert_eq!(profile, expected_profile);
                Ok(read)
            }
            step => panic!("expected process, got {step:?}"),
        }
    }
}

impl ObservationSource for FakeSource {
    fn wall_clock(&mut self) -> Result<SystemTime, ObservationError> {
        self.calls.push("clock".to_owned());
        match self.next()? {
            Step::Clock(milliseconds) => Ok(UNIX_EPOCH + Duration::from_millis(milliseconds)),
            step => panic!("expected clock, got {step:?}"),
        }
    }

    fn collect_native_pass(
        &mut self,
        _profile: MetadataProfile,
    ) -> Result<NativeObservationPass, ObservationError> {
        self.calls.push("pass".to_owned());
        match self.next()? {
            Step::Pass(pass) => Ok(pass),
            step => panic!("expected native pass, got {step:?}"),
        }
    }

    fn read_processes(
        &mut self,
        sorted_pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessReadBatch, ObservationError> {
        self.process_batch_calls += 1;
        if matches!(self.steps.front(), Some(Step::ProcessBatch(_))) {
            return match self.next()? {
                Step::ProcessBatch(reads) => Ok(reads),
                step => panic!("expected process batch, got {step:?}"),
            };
        }
        let mut retained_bytes = 0usize;
        let mut reads = Vec::with_capacity(sorted_pids.len());
        for &pid in sorted_pids {
            let remaining = optional_metadata_bytes_remaining.saturating_sub(retained_bytes);
            let read = self.read_process(pid, profile, remaining)?;
            retained_bytes = retained_bytes.saturating_add(process_read_metadata_bytes(&read));
            reads.push((pid, read));
        }
        Ok(reads)
    }
}

fn endpoint(port: u32) -> EndpointIdentity {
    EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
        .expect("fixture endpoint is valid")
}

fn socket(port: u32) -> NativeSocketObservation {
    NativeSocketObservation {
        endpoint: endpoint(port),
        state: SocketState::Listen,
        timer: None,
        token: PlatformSocketToken::linux_inode(u64::from(port)),
    }
}

fn native_pass(sockets: Vec<NativeSocketObservation>, pids: &[&[u32]]) -> NativeObservationPass {
    assert_eq!(
        sockets.len(),
        pids.len(),
        "every socket fixture needs owners"
    );
    NativeObservationPass {
        rows: sockets
            .into_iter()
            .zip(pids)
            .map(|(socket, owner_pids)| NativeSocketRow {
                socket,
                owner_pids: owner_pids.to_vec(),
                owner_completeness: OwnerCompleteness::Complete,
            })
            .collect(),
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
    }
}

fn verified(marker: u64, name: Option<&str>) -> ProcessRead {
    ProcessRead::Verified {
        marker: ProcessStartMarker::linux(marker).expect("fixture marker is nonzero"),
        observation: ProcessObservation {
            name: name.map(Arc::from),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            metadata_omission: None,
            metadata_completeness: MetadataCompleteness::Complete,
        },
    }
}

fn scope() -> ObservationScope {
    ObservationScope::new(
        ObservationScopeKind::CurrentNetworkNamespace,
        Some("net:[1]"),
        [ScopeLimitation::OtherNetworkNamespacesExcluded],
    )
    .expect("fixture scope is valid")
}

fn limits(max: usize) -> ObservationLimits {
    ObservationLimits {
        sockets: max,
        candidate_pids: max,
        owner_edges: max,
        identity_reads_per_attempt: max.saturating_mul(2),
        identity_reads_total: max.saturating_mul(4),
        evidence_gaps: max,
        optional_metadata_bytes: max,
    }
}

fn stable_steps(rows: Vec<NativeSocketObservation>, pids: &[&[u32]]) -> Vec<Step> {
    let unique: BTreeSet<u32> = pids.iter().flat_map(|pids| pids.iter().copied()).collect();
    let mut steps = vec![Step::Clock(10), Step::Pass(native_pass(rows.clone(), pids))];
    for pid in &unique {
        steps.push(Step::Process(
            *pid,
            MetadataProfile::IdentityOnly,
            verified(7, None),
        ));
    }
    steps.push(Step::Pass(native_pass(rows, pids)));
    for pid in unique {
        steps.push(Step::Process(
            pid,
            MetadataProfile::Display,
            verified(7, Some("p")),
        ));
    }
    steps.push(Step::Clock(20));
    steps
}

#[expect(
    clippy::too_many_arguments,
    reason = "the test helper names both complete consistency passes explicitly"
)]
fn append_attempt(
    steps: &mut Vec<Step>,
    started: u64,
    rows_a: Vec<NativeSocketObservation>,
    pids_a: &[&[u32]],
    reads_a: &[(u32, ProcessRead)],
    rows_b: Vec<NativeSocketObservation>,
    pids_b: &[&[u32]],
    reads_b: &[(u32, ProcessRead)],
) {
    steps.push(Step::Clock(started));
    steps.push(Step::Pass(native_pass(rows_a, pids_a)));
    steps.extend(
        reads_a
            .iter()
            .map(|(pid, read)| Step::Process(*pid, MetadataProfile::IdentityOnly, read.clone())),
    );
    steps.push(Step::Pass(native_pass(rows_b, pids_b)));
    steps.extend(
        reads_b
            .iter()
            .map(|(pid, read)| Step::Process(*pid, MetadataProfile::Display, read.clone())),
    );
    steps.push(Step::Clock(started + 1));
}

#[test]
fn owner_reason_and_scope_boundaries_use_the_contract_limits() {
    let reasons = [
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::OwnerAttributionIncomplete,
        EvidenceGapCode::OwnerDisappeared,
        EvidenceGapCode::ProcessIdentityUnavailable,
        EvidenceGapCode::ProcessMetadataUnavailable,
        EvidenceGapCode::NativeFieldUnavailable,
        EvidenceGapCode::ScopeExcluded,
        EvidenceGapCode::NoncriticalEvidenceTruncated,
        EvidenceGapCode::ObservationRaced,
    ];
    assert_eq!(
        OwnerCompleteness::partial([]).unwrap(),
        OwnerCompleteness::Complete
    );
    let exact =
        OwnerCompleteness::partial(reasons[..OWNER_COMPLETENESS_REASONS_MAX].iter().copied())
            .expect("eight distinct owner reasons fit");
    assert!(matches!(exact, OwnerCompleteness::Partial { reasons } if reasons.len() == 8));
    assert_eq!(
        OwnerCompleteness::partial(reasons),
        Err(ObservationError::OwnerReasonLimitExceeded)
    );

    assert!(ObservationScope::new(ObservationScopeKind::CurrentHostNetworkStack, None, []).is_ok());
    let identifier = "s".repeat(SCOPE_IDENTIFIER_MAX_BYTES);
    assert_eq!(
        ObservationScope::new(
            ObservationScopeKind::CurrentHostNetworkStack,
            Some(&identifier),
            [
                ScopeLimitation::OtherNetworkNamespacesExcluded,
                ScopeLimitation::ProcessFirstSocketVisibilityLimited,
                ScopeLimitation::WslNetworkStackExcluded,
                ScopeLimitation::ProcessMetadataPermissionLimited,
                ScopeLimitation::Ipv6ScopeUnavailable,
                ScopeLimitation::ScopedIpv6ExactMatchingUnavailable,
                ScopeLimitation::NativeFieldUnavailable,
                ScopeLimitation::PollingIntervalBlindSpot,
            ],
        )
        .expect("exact scope bounds")
        .limitations
        .len(),
        SCOPE_LIMITATIONS_MAX
    );
    let oversized = "s".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1);
    assert_eq!(
        ObservationScope::new(
            ObservationScopeKind::CurrentHostNetworkStack,
            Some(&oversized),
            []
        ),
        Err(ObservationError::ScopeIdentifierOversized)
    );
}

#[test]
fn owner_reasons_are_deduplicated_in_public_name_order() {
    let completeness = OwnerCompleteness::partial([
        EvidenceGapCode::ScopeExcluded,
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::NativeFieldUnavailable,
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::ObservationRaced,
    ])
    .expect("distinct reasons fit");
    let OwnerCompleteness::Partial { reasons } = completeness else {
        panic!("nonempty reasons must remain partial");
    };

    assert_eq!(
        owner_reason_names(&reasons).collect::<Vec<_>>(),
        [
            "native_field_unavailable",
            "observation_raced",
            "owner_permission_denied",
            "scope_excluded",
        ]
    );
}

#[test]
fn ninth_scope_limitation_is_rejected() {
    assert_eq!(
        super::bounded_scope_limitations(0..=SCOPE_LIMITATIONS_MAX),
        Err(ObservationError::ScopeLimitationLimitExceeded),
    );
}

#[test]
fn process_name_path_and_command_boundaries_use_actual_limits() {
    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: 7,
            start_marker: ProcessStartMarker::linux(7).unwrap(),
        }
    }

    let cases = [
        (PROCESS_NAME_MAX_BYTES, 0, 0),
        (0, EXECUTABLE_PATH_MAX_BYTES, 0),
        (0, 0, PROCESS_COMMAND_LINE_MAX_BYTES),
    ];
    for (name_bytes, path_bytes, command_bytes) in cases {
        let mut processes = HashMap::from([(
            identity(),
            ProcessObservation {
                name: Some(Arc::from("n".repeat(name_bytes))),
                executable_path: Some(Arc::from(Path::new(&"p".repeat(path_bytes)))),
                command_line: Some(Arc::from("c".repeat(command_bytes))),
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        )]);
        let mut gaps = Vec::new();
        let mut omitted = 0;
        apply_metadata_budget(
            &mut processes,
            &mut gaps,
            &mut omitted,
            ObservationLimits::PRODUCTION,
        );
        let process = processes.get(&identity()).unwrap();
        assert_eq!(
            process.name.as_ref().map(|value| value.len()),
            Some(name_bytes)
        );
        assert_eq!(
            process
                .executable_path
                .as_ref()
                .map(|value| value.as_os_str().as_encoded_bytes().len()),
            Some(path_bytes)
        );
        assert_eq!(
            process.command_line.as_ref().map(|value| value.len()),
            Some(command_bytes)
        );
        assert!(gaps.is_empty());
    }

    // Each over-limit case pins exactly which field the budget must drop,
    // as a literal expectation rather than re-deriving it from the limits.
    let over_cases = [
        (PROCESS_NAME_MAX_BYTES + 1, 0, 0, true, false, false),
        (0, EXECUTABLE_PATH_MAX_BYTES + 1, 0, false, true, false),
        (0, 0, PROCESS_COMMAND_LINE_MAX_BYTES + 1, false, false, true),
    ];
    for (name_bytes, path_bytes, command_bytes, name_dropped, path_dropped, command_dropped) in
        over_cases
    {
        let mut processes = HashMap::from([(
            identity(),
            ProcessObservation {
                name: Some(Arc::from("n".repeat(name_bytes))),
                executable_path: Some(Arc::from(Path::new(&"p".repeat(path_bytes)))),
                command_line: Some(Arc::from("c".repeat(command_bytes))),
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        )]);
        let mut gaps = Vec::new();
        let mut omitted = 0;
        apply_metadata_budget(
            &mut processes,
            &mut gaps,
            &mut omitted,
            ObservationLimits::PRODUCTION,
        );
        let process = processes.get(&identity()).unwrap();
        assert_eq!(process.name.is_none(), name_dropped);
        assert_eq!(process.executable_path.is_none(), path_dropped);
        assert_eq!(process.command_line.is_none(), command_dropped);
        assert_eq!(process.metadata_completeness, MetadataCompleteness::Partial);
        assert_eq!(gaps.len(), 1);
    }
}

#[test]
fn endpoints_reject_zero_and_overflow_and_accept_exact_maxima() {
    assert_eq!(
        EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 0, None),
        Err(EndpointIdentityError::InvalidPort)
    );
    assert!(
        EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            u32::from(u16::MAX),
            None
        )
        .is_ok()
    );
    assert_eq!(
        EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            u32::from(u16::MAX) + 1,
            None
        ),
        Err(EndpointIdentityError::InvalidPort)
    );
    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let maximum_scope =
        Ipv6Scope::interface_index(u64::from(u32::MAX)).expect("maximum interface index is valid");
    assert_eq!(
        EndpointIdentity::new(Protocol::Tcp, ipv6, 1, Some(maximum_scope))
            .expect("maximum interface index is valid")
            .ipv6_scope,
        Some(Ipv6Scope::InterfaceIndex(NonZeroU32::MAX))
    );
    assert_eq!(
        Ipv6Scope::interface_index(u64::from(u32::MAX) + 1),
        Err(EndpointIdentityError::InvalidInterfaceIndex)
    );
    assert_eq!(
        EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            1,
            Some(maximum_scope),
        ),
        Err(EndpointIdentityError::Ipv4WithScope)
    );
    let mapped = EndpointIdentity::new(
        Protocol::Tcp,
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        1,
        Some(Ipv6Scope::Unavailable),
    )
    .expect("mapped IPv6 canonicalizes to IPv4");
    assert_eq!(mapped.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(mapped.ipv6_scope, None);
}

#[test]
fn typed_markers_and_tokens_reject_zero() {
    assert_eq!(ProcessStartMarker::linux(0), Err(ProcessMarkerError::Zero));
    assert_eq!(
        ProcessStartMarker::windows(0),
        Err(ProcessMarkerError::Zero)
    );
    assert_eq!(
        ProcessStartMarker::macos(0, 0),
        Err(ProcessMarkerError::Zero)
    );
    assert_eq!(
        ProcessStartMarker::macos(1, 1_000_000),
        Err(ProcessMarkerError::InvalidMicroseconds)
    );
    assert!(ProcessStartMarker::macos(u64::MAX, 999_999).is_ok());
    assert_eq!(PlatformSocketToken::linux_inode(0), None);
    assert!(PlatformSocketToken::macos_socket_id(u64::MAX).is_some());
}

#[test]
fn socket_state_order_is_frozen_and_unknown_retains_native_code() {
    let mut states = vec![
        SocketState::Unknown(9),
        SocketState::Bound,
        SocketState::Closed,
        SocketState::Unknown(2),
        SocketState::NewSynReceived,
        SocketState::DeleteTcb,
        SocketState::TimeWait,
        SocketState::LastAck,
        SocketState::Closing,
        SocketState::CloseWait,
        SocketState::FinWait2,
        SocketState::FinWait1,
        SocketState::Established,
        SocketState::SynReceived,
        SocketState::SynSent,
        SocketState::Listen,
    ];
    states.sort();
    assert_eq!(
        states,
        vec![
            SocketState::Closed,
            SocketState::Listen,
            SocketState::SynSent,
            SocketState::SynReceived,
            SocketState::Established,
            SocketState::FinWait1,
            SocketState::FinWait2,
            SocketState::CloseWait,
            SocketState::Closing,
            SocketState::LastAck,
            SocketState::TimeWait,
            SocketState::DeleteTcb,
            SocketState::NewSynReceived,
            SocketState::Bound,
            SocketState::Unknown(2),
            SocketState::Unknown(9)
        ]
    );
}

#[test]
fn linux_tcp_timer_mapping_and_ceiling_conversion_are_frozen() {
    let expected = [
        TcpTimerKind::None,
        TcpTimerKind::Retransmit,
        TcpTimerKind::Other,
        TcpTimerKind::TimeWait,
        TcpTimerKind::ZeroWindowProbe,
    ];
    for (native, expected) in expected.into_iter().enumerate() {
        assert_eq!(
            TcpTimerKind::from_linux_native(u32::try_from(native).expect("small code")),
            expected
        );
    }
    assert_eq!(
        TcpTimerKind::from_linux_native(255),
        TcpTimerKind::Unknown(255)
    );

    let timer = TcpTimerObservation::from_linux_native(1, 1, Some(128));
    assert_eq!(timer.kind, TcpTimerKind::Retransmit);
    assert_eq!(timer.native_code, None);
    assert_eq!(timer.raw_ticks, 1);
    assert_eq!(timer.estimated_remaining_milliseconds, Some(8));
    assert_eq!(
        TcpTimerObservation::from_linux_native(255, 1, Some(100)).native_code,
        Some(255)
    );
    assert_eq!(
        TcpTimerObservation::from_linux_native(3, u64::MAX, Some(1))
            .estimated_remaining_milliseconds,
        None
    );
    assert_eq!(
        TcpTimerObservation::from_linux_native(0, 0, None).estimated_remaining_milliseconds,
        None
    );
}

#[test]
fn stable_collection_returns_pass_b_and_exact_call_order() {
    let row = socket(80);
    let mut source = FakeSource::new(stable_steps(vec![row], &[&[42]]));
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("stable observation succeeds");
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
    assert_eq!(
        snapshot
            .processes
            .values()
            .next()
            .and_then(|p| p.name.as_deref()),
        Some("p")
    );
    assert_eq!(
        source.calls,
        [
            "clock",
            "pass",
            "process:42:IdentityOnly",
            "pass",
            "process:42:Display",
            "clock"
        ]
    );
    assert!(source.steps.is_empty());
    assert_eq!(source.process_batch_calls, 2);
}

#[test]
fn process_read_table_accepts_only_the_exact_sorted_pid_batch() {
    let expected = [1, 2];
    let valid = ProcessReadTable::from_expected(
        &expected,
        vec![(1, verified(1, None)), (2, verified(2, None))],
    )
    .expect("the exact sorted batch is valid");
    assert_eq!(valid.len(), 2);
    assert!(valid.get(1).is_some());
    assert!(valid.get(2).is_some());
    assert!(valid.get(3).is_none());

    let malformed_batches = [
        vec![(1, verified(1, None))],
        vec![
            (1, verified(1, None)),
            (2, verified(2, None)),
            (3, verified(3, None)),
        ],
        vec![(1, verified(1, None)), (1, verified(1, None))],
        vec![(2, verified(2, None)), (1, verified(1, None))],
        vec![(1, verified(1, None)), (3, verified(3, None))],
    ];
    for batch in malformed_batches {
        assert_eq!(
            ProcessReadTable::from_expected(&expected, batch)
                .expect_err("missing, extra, duplicate, unordered, or wrong PIDs are malformed"),
            ObservationError::NativeDataMalformed
        );
    }
}

#[test]
fn collection_rejects_an_unordered_process_read_batch() {
    let mut source = FakeSource::new(vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![socket(80)], &[&[1, 2]])),
        Step::ProcessBatch(vec![(2, verified(2, None)), (1, verified(1, None))]),
    ]);

    assert_eq!(
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(4)),
        Err(ObservationError::NativeDataMalformed)
    );
    assert_eq!(source.process_batch_calls, 1);
}

#[test]
fn canonicalization_keeps_each_socket_owner_completeness_and_timer_bundled() {
    let mut socket_80 = socket(80);
    socket_80.timer = Some(TcpTimerObservation::from_linux_native(1, 8, Some(100)));
    let mut socket_81 = socket(81);
    socket_81.timer = Some(TcpTimerObservation::from_linux_native(1, 9, Some(100)));
    let partial = OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
        .expect("one reason fits");
    let row_80 = NativeSocketRow {
        socket: socket_80,
        owner_pids: vec![1],
        owner_completeness: OwnerCompleteness::Complete,
    };
    let row_81 = NativeSocketRow {
        socket: socket_81,
        owner_pids: vec![2],
        owner_completeness: partial.clone(),
    };
    let pass = |rows| NativeObservationPass {
        rows,
        global_owner_completeness: partial.clone(),
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
    };
    let steps = vec![
        Step::Clock(1),
        Step::Pass(pass(vec![row_81.clone(), row_80.clone()])),
        Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
        Step::Process(2, MetadataProfile::IdentityOnly, verified(2, None)),
        Step::Pass(pass(vec![row_80, row_81])),
        Step::Process(1, MetadataProfile::Display, verified(1, Some("one"))),
        Step::Process(2, MetadataProfile::Display, verified(2, Some("two"))),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("bundled rows canonicalize without detaching per-socket facts");

    assert_eq!(snapshot.sockets[0].local_endpoint.port.get(), 80);
    assert_eq!(
        snapshot.sockets[0].timer.map(|timer| timer.raw_ticks),
        Some(8)
    );
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::Complete
    );
    assert!(matches!(
        snapshot.sockets[0].owners.as_slice(),
        [OwnerObservation::Verified(identity)] if identity.pid == 1
    ));
    assert_eq!(snapshot.sockets[1].local_endpoint.port.get(), 81);
    assert_eq!(
        snapshot.sockets[1].timer.map(|timer| timer.raw_ticks),
        Some(9)
    );
    assert_eq!(snapshot.sockets[1].owner_completeness, partial);
    assert!(matches!(
        snapshot.sockets[1].owners.as_slice(),
        [OwnerObservation::Verified(identity)] if identity.pid == 2
    ));
}

#[test]
fn timer_changes_do_not_create_socket_races_and_pass_b_is_retained() {
    let mut pass_a = socket(80);
    pass_a.timer = Some(TcpTimerObservation::from_linux_native(1, 20, Some(100)));
    let mut pass_b = pass_a.clone();
    pass_b.timer = Some(TcpTimerObservation::from_linux_native(1, 10, Some(100)));
    let mut source = FakeSource::new(vec![
        Step::Clock(10),
        Step::Pass(native_pass(vec![pass_a], &[&[]])),
        Step::Pass(native_pass(vec![pass_b], &[&[]])),
        Step::Clock(20),
    ]);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(1))
            .expect("timer-only movement remains a stable socket observation");

    assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
    assert_eq!(
        snapshot.sockets[0].timer,
        Some(TcpTimerObservation::from_linux_native(1, 10, Some(100)))
    );
}

#[test]
fn duplicate_timer_rows_have_deterministic_timer_order() {
    let mut earlier = socket(80);
    earlier.token = None;
    earlier.timer = Some(TcpTimerObservation::from_linux_native(1, 20, Some(100)));
    let mut later = earlier.clone();
    later.timer = Some(TcpTimerObservation::from_linux_native(1, 10, Some(100)));
    let mut source = FakeSource::new(stable_steps(vec![earlier, later], &[&[], &[]]));

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(2))
            .expect("duplicate timer rows collect deterministically");

    assert_eq!(
        snapshot
            .sockets
            .iter()
            .map(|socket| socket.timer.expect("fixture timer").raw_ticks)
            .collect::<Vec<_>>(),
        [10, 20]
    );
}

#[test]
fn platform_socket_tokens_survive_collection() {
    let linux = socket(80);
    let macos = NativeSocketObservation {
        endpoint: endpoint(81),
        state: SocketState::Listen,
        timer: None,
        token: PlatformSocketToken::macos_socket_id(0xCAFE),
    };
    let mut source = FakeSource::new(stable_steps(
        vec![linux.clone(), macos.clone()],
        &[&[], &[]],
    ));

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(4))
            .expect("typed socket tokens collect");

    assert_eq!(snapshot.sockets[0].socket_token, linux.token);
    assert_eq!(snapshot.sockets[1].socket_token, macos.token);
}

#[test]
fn complete_owner_scan_can_return_an_empty_owner_set() {
    let mut source = FakeSource::new(stable_steps(vec![socket(80)], &[&[]]));

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(2))
            .expect("an exhaustively ownerless socket is valid");

    assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::Complete
    );
    assert!(snapshot.sockets[0].owners.is_empty());
    assert!(snapshot.evidence_gaps.is_empty());
}

#[test]
fn attributable_vanished_pid_merges_into_global_completeness() {
    let row = socket(80);
    let steps = vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![row.clone()], &[&[42]])),
        Step::Process(
            42,
            MetadataProfile::IdentityOnly,
            ProcessRead::Unverified(UnverifiedOwnerReason::Disappeared),
        ),
        Step::Pass(native_pass(vec![row], &[&[42]])),
        Step::Process(
            42,
            MetadataProfile::Display,
            ProcessRead::Unverified(UnverifiedOwnerReason::Disappeared),
        ),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(4))
            .expect("a vanished attributed PID remains explicit");

    assert_eq!(
        snapshot.owner_completeness,
        OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap()
    );
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap()
    );
    assert!(snapshot.evidence_gaps.iter().any(|gap| {
        gap.code == EvidenceGapCode::OwnerDisappeared
            && gap.endpoint.as_ref() == Some(&endpoint(80))
            && gap.pid == Some(42)
    }));
}

#[test]
fn duplicate_rows_are_compared_as_a_multiset() {
    let row = socket(80);
    let mut source = FakeSource::new(stable_steps(vec![row.clone(), row], &[&[], &[]]));
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("equal duplicate multiplicity is stable");
    assert_eq!(snapshot.sockets.len(), 2);
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
}

#[test]
fn large_duplicate_group_merges_local_uncertainty_linearly() {
    const DUPLICATES: usize = 32_768;

    let row = socket(80);
    let disappeared = OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap();
    let denied = OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
    let mut local_a = vec![OwnerCompleteness::Complete; DUPLICATES];
    local_a[0] = disappeared;
    local_a[DUPLICATES - 1] = denied;
    let rows = |local_completeness: Vec<OwnerCompleteness>| {
        local_completeness
            .into_iter()
            .map(|owner_completeness| NativeSocketRow {
                socket: row.clone(),
                owner_pids: Vec::new(),
                owner_completeness,
            })
            .collect()
    };
    let mut pass_a = CollectedPass {
        rows: rows(local_a),
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        processes_by_pid: ProcessReadTable::default(),
        omitted_evidence_gap_count: 0,
    };
    let mut pass_b = CollectedPass {
        rows: rows(vec![OwnerCompleteness::Complete; DUPLICATES]),
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        processes_by_pid: ProcessReadTable::default(),
        omitted_evidence_gap_count: 0,
    };

    merge_attempt_uncertainty(&mut pass_a, &mut pass_b).expect("bounded reasons merge");

    let expected = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::OwnerDisappeared,
    ])
    .unwrap();
    assert!(
        pass_b
            .rows
            .iter()
            .all(|row| row.owner_completeness == expected)
    );
}

#[test]
fn attempt_merge_keeps_global_and_socket_local_owner_reasons_separate() {
    let global_a = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::OwnerPermissionDenied,
    ])
    .unwrap();
    let global_b = OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap();
    let local_a =
        OwnerCompleteness::partial([EvidenceGapCode::ProcessIdentityUnavailable]).unwrap();
    let local_b =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
    let rows = |owner_completeness| {
        vec![NativeSocketRow {
            socket: socket(80),
            owner_pids: Vec::new(),
            owner_completeness,
        }]
    };
    let mut pass_a = CollectedPass {
        rows: rows(local_a),
        global_owner_completeness: global_a,
        evidence_gaps: Vec::new(),
        processes_by_pid: ProcessReadTable::default(),
        omitted_evidence_gap_count: 0,
    };
    let mut pass_b = CollectedPass {
        rows: rows(local_b),
        global_owner_completeness: global_b,
        evidence_gaps: Vec::new(),
        processes_by_pid: ProcessReadTable::default(),
        omitted_evidence_gap_count: 0,
    };

    merge_attempt_uncertainty(&mut pass_a, &mut pass_b).expect("bounded reasons merge");

    assert_eq!(
        pass_b.global_owner_completeness,
        OwnerCompleteness::partial([
            EvidenceGapCode::OwnerDisappeared,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .unwrap()
    );
    assert_eq!(
        pass_b.rows[0].owner_completeness,
        OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::ProcessIdentityUnavailable,
        ])
        .unwrap()
    );
}

#[test]
fn merged_source_omission_counts_saturate() {
    let mut pass_a = CollectedPass {
        rows: Vec::new(),
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        processes_by_pid: ProcessReadTable::default(),
        omitted_evidence_gap_count: u64::MAX,
    };
    let mut pass_b = CollectedPass {
        rows: Vec::new(),
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        processes_by_pid: ProcessReadTable::default(),
        omitted_evidence_gap_count: 1,
    };

    merge_attempt_uncertainty(&mut pass_a, &mut pass_b).expect("empty passes merge");

    assert_eq!(pass_b.omitted_evidence_gap_count, u64::MAX);
}

#[test]
fn multiplicity_owner_edges_and_identity_races_are_independent() {
    let row = socket(80);
    let pass = |sockets: Vec<NativeSocketObservation>, pids: &[&[u32]], read: ProcessRead| {
        let unique = pids
            .iter()
            .flat_map(|pids| pids.iter().copied())
            .collect::<BTreeSet<_>>();
        CollectedPass {
            rows: native_pass(sockets, pids).rows,
            global_owner_completeness: OwnerCompleteness::Complete,
            evidence_gaps: Vec::new(),
            processes_by_pid: ProcessReadTable {
                entries: unique.into_iter().map(|pid| (pid, read.clone())).collect(),
            },
            omitted_evidence_gap_count: 0,
        }
    };

    let two = pass(
        vec![row.clone(), row.clone()],
        &[&[7], &[7]],
        verified(7, None),
    );
    let one = pass(vec![row.clone()], &[&[7]], verified(7, None));
    let change = compare_passes(&two, &one);
    assert!(change.socket_set);
    assert!(
        change.ownership,
        "duplicate owner-edge multiplicity also changed"
    );

    let owner_a = pass(vec![row.clone()], &[&[7]], verified(7, None));
    let owner_b = pass(vec![row.clone()], &[&[8]], verified(7, None));
    let change = compare_passes(&owner_a, &owner_b);
    assert!(!change.socket_set);
    assert!(change.ownership);

    let marker_a = pass(vec![row.clone()], &[&[7]], verified(7, None));
    let marker_b = pass(vec![row.clone()], &[&[7]], verified(8, None));
    let change = compare_passes(&marker_a, &marker_b);
    assert!(!change.socket_set);
    assert!(change.ownership);

    let unverified = pass(
        vec![row],
        &[&[7]],
        ProcessRead::Unverified(UnverifiedOwnerReason::Raced),
    );
    assert!(compare_passes(&marker_a, &unverified).ownership);
}

#[test]
fn orchestrator_reports_multiplicity_only_races() {
    let row = socket(80);
    let mut steps = Vec::new();
    for started in [1, 3] {
        append_attempt(
            &mut steps,
            started,
            vec![row.clone(), row.clone()],
            &[&[], &[]],
            &[],
            vec![row.clone()],
            &[&[]],
            &[],
        );
    }
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("bounded raced snapshot");

    assert_eq!(snapshot.completeness, SnapshotCompleteness::Raced);
    assert!(snapshot.evidence_gaps.iter().any(|gap| {
        gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::SocketSet
    }));
    assert!(!snapshot.evidence_gaps.iter().any(|gap| {
        gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::Ownership
    }));
    assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
}

#[test]
fn orchestrator_reports_owner_edge_only_races() {
    let row = socket(80);
    let mut steps = Vec::new();
    for started in [1, 3] {
        append_attempt(
            &mut steps,
            started,
            vec![row.clone()],
            &[&[1]],
            &[(1, verified(10, None))],
            vec![row.clone()],
            &[&[2]],
            &[(2, verified(20, Some("p")))],
        );
    }
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("bounded raced snapshot");

    assert_eq!(snapshot.sockets.len(), 1);
    assert!(snapshot.evidence_gaps.iter().any(|gap| {
        gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::Ownership
    }));
    assert!(!snapshot.evidence_gaps.iter().any(|gap| {
        gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::SocketSet
    }));
}

#[test]
fn orchestrator_reports_marker_only_races() {
    let row = socket(80);
    let mut steps = Vec::new();
    for started in [1, 3] {
        append_attempt(
            &mut steps,
            started,
            vec![row.clone()],
            &[&[1]],
            &[(1, verified(10, None))],
            vec![row.clone()],
            &[&[1]],
            &[(1, verified(11, Some("p")))],
        );
    }
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("bounded raced snapshot");

    assert_eq!(snapshot.completeness, SnapshotCompleteness::Raced);
    assert!(matches!(
        snapshot.sockets[0].owners[0],
        OwnerObservation::Verified(ProcessIdentity {
            start_marker: ProcessStartMarker::LinuxStartTicks(marker),
            ..
        }) if marker.get() == 11
    ));
}

#[test]
fn orchestrator_reports_verified_to_unverified_races() {
    let row = socket(80);
    let mut steps = Vec::new();
    for started in [1, 3] {
        append_attempt(
            &mut steps,
            started,
            vec![row.clone()],
            &[&[1]],
            &[(1, verified(10, None))],
            vec![row.clone()],
            &[&[1]],
            &[(
                1,
                ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
            )],
        );
    }
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("bounded raced snapshot");

    assert!(matches!(
        snapshot.sockets[0].owners[0],
        OwnerObservation::UnverifiedPid {
            pid: 1,
            reason: UnverifiedOwnerReason::IdentityUnavailable
        }
    ));
    assert!(snapshot.processes.is_empty());
}

#[test]
fn orchestrator_treats_one_pass_only_pids_as_races() {
    let row = socket(80);
    let mut steps = Vec::new();
    for started in [1, 3] {
        append_attempt(
            &mut steps,
            started,
            vec![row.clone()],
            &[&[1]],
            &[(1, verified(10, None))],
            vec![row.clone()],
            &[&[]],
            &[],
        );
    }
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("bounded raced snapshot");

    assert!(snapshot.sockets[0].owners.is_empty());
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::Raced
    );
    assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Raced);
}

#[test]
fn stable_output_is_independent_of_native_source_order() {
    let rows_a = vec![socket(81), socket(80)];
    let rows_b = vec![socket(80), socket(81)];
    let mut source_a = FakeSource::new(stable_steps(rows_a, &[&[2, 1], &[3]]));
    let mut source_b = FakeSource::new(stable_steps(rows_b, &[&[3], &[1, 2]]));
    let snapshot_a =
        collect_consistent_with_limits(&mut source_a, scope(), MetadataProfile::Display, limits(8))
            .expect("first ordering collects");
    let snapshot_b =
        collect_consistent_with_limits(&mut source_b, scope(), MetadataProfile::Display, limits(8))
            .expect("second ordering collects");
    assert_eq!(snapshot_a.sockets, snapshot_b.sockets);
    assert_eq!(snapshot_a.processes, snapshot_b.processes);
}

#[test]
fn evidence_gaps_and_projected_rows_have_deterministic_order() {
    let gap = |port| {
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            Some(endpoint(port)),
            Some(port),
            "missing",
        )
    };
    let mut pass_a = native_pass(vec![socket(81), socket(80)], &[&[2], &[1]]);
    pass_a.evidence_gaps = vec![gap(81), gap(80)];
    let mut pass_b = native_pass(vec![socket(80), socket(81)], &[&[1], &[2]]);
    pass_b.evidence_gaps = vec![gap(80), gap(81)];
    let steps = vec![
        Step::Clock(1),
        Step::Pass(pass_a),
        Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
        Step::Process(2, MetadataProfile::IdentityOnly, verified(2, None)),
        Step::Pass(pass_b),
        Step::Process(1, MetadataProfile::Display, verified(1, Some("one"))),
        Step::Process(2, MetadataProfile::Display, verified(2, Some("two"))),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(16))
            .expect("stable deterministic snapshot");
    let gap_ports = snapshot
        .evidence_gaps
        .iter()
        .map(|gap| gap.endpoint.as_ref().unwrap().port.get())
        .collect::<Vec<_>>();
    // Both passes report the same two gaps in opposite orders. The result
    // is that pair once, in canonical order: reporting order does not
    // reach the snapshot, and observing one gap twice does not make it two.
    assert_eq!(gap_ports, vec![80, 81]);

    let projected = project_legacy(&snapshot).expect("legacy projection");
    assert_eq!(
        projected
            .iter()
            .map(|row| (row.local_port, row.pid))
            .collect::<Vec<_>>(),
        vec![(80, Some(1)), (81, Some(2))]
    );
}

#[test]
fn evidence_gap_order_uses_public_code_names() {
    let mut gaps = [
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            None,
            None,
            "process",
        ),
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            None,
            "native",
        ),
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::NoncriticalEvidenceTruncated,
            None,
            None,
            "truncated",
        ),
    ];

    gaps.sort();

    assert_eq!(
        gaps.iter().map(|gap| gap.code.name()).collect::<Vec<_>>(),
        [
            "native_field_unavailable",
            "noncritical_evidence_truncated",
            "process_metadata_unavailable",
        ]
    );
}

#[test]
fn evidence_gap_endpoint_order_uses_scope_before_port() {
    let address = IpAddr::V6("fe80::1".parse().unwrap());
    let scope_two = Ipv6Scope::interface_index(2).unwrap();
    let scope_three = Ipv6Scope::interface_index(3).unwrap();
    let mut gaps = [
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            Some(EndpointIdentity::new(Protocol::Tcp, address, 8_000, Some(scope_three)).unwrap()),
            None,
            "scope three",
        ),
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            Some(EndpointIdentity::new(Protocol::Tcp, address, 9_000, Some(scope_two)).unwrap()),
            None,
            "scope two",
        ),
    ];

    gaps.sort();

    assert_eq!(
        gaps[0].endpoint.as_ref().unwrap().ipv6_scope,
        Some(scope_two)
    );
    assert_eq!(gaps[0].endpoint.as_ref().unwrap().port.get(), 9_000);
    assert_eq!(
        gaps[1].endpoint.as_ref().unwrap().ipv6_scope,
        Some(scope_three)
    );
    assert_eq!(gaps[1].endpoint.as_ref().unwrap().port.get(), 8_000);
}

#[test]
fn partial_and_denied_ownership_remain_explicit() {
    let row = socket(80);
    let gap = EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        Some(row.endpoint.clone()),
        Some(42),
        "denied",
    );
    let partial = OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
        .expect("one reason fits");
    let pass = NativeObservationPass {
        rows: vec![NativeSocketRow {
            socket: row.clone(),
            owner_pids: vec![42],
            owner_completeness: partial.clone(),
        }],
        global_owner_completeness: partial,
        evidence_gaps: vec![gap.clone()],
        omitted_evidence_gap_count: 0,
    };
    let steps = vec![
        Step::Clock(1),
        Step::Pass(pass.clone()),
        Step::Process(
            42,
            MetadataProfile::IdentityOnly,
            ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied),
        ),
        Step::Pass(pass),
        Step::Process(
            42,
            MetadataProfile::Display,
            ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied),
        ),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("permission loss is a partial snapshot, not an error");
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
    assert!(snapshot.evidence_gaps.contains(&gap));
    assert!(
        snapshot
            .evidence_gaps
            .iter()
            .all(|gap| gap.code == EvidenceGapCode::OwnerPermissionDenied)
    );
    assert!(matches!(
        snapshot.sockets[0].owners[0],
        OwnerObservation::UnverifiedPid {
            reason: UnverifiedOwnerReason::PermissionDenied,
            ..
        }
    ));
    assert!(snapshot.processes.is_empty());
}

#[test]
fn second_unstable_attempt_returns_its_pass_b_without_a_third_attempt() {
    let a1 = socket(80);
    let b1 = socket(81);
    let a2 = socket(82);
    let b2 = socket(83);
    let steps = vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![a1], &[&[]])),
        Step::Pass(native_pass(vec![b1], &[&[]])),
        Step::Clock(2),
        Step::Clock(3),
        Step::Pass(native_pass(vec![a2], &[&[]])),
        Step::Pass(native_pass(vec![b2.clone()], &[&[]])),
        Step::Clock(4),
    ];
    let mut source = FakeSource::new(steps);
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("the second raced pass B is returned");
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Raced);
    assert_eq!(snapshot.sockets[0].local_endpoint, b2.endpoint);
    assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::Raced
    );
    assert_eq!(
        source.calls.iter().filter(|call| *call == "pass").count(),
        4
    );
    assert!(source.steps.is_empty(), "no third attempt may be consumed");
}

#[test]
fn stable_retry_is_accepted_on_attempt_two() {
    let mut steps = vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![socket(80)], &[&[]])),
        Step::Pass(native_pass(vec![socket(81)], &[&[]])),
        Step::Clock(2),
    ];
    steps.extend(stable_steps(vec![socket(82)], &[&[]]));
    let mut source = FakeSource::new(steps);
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("stable retry succeeds");
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
    assert_eq!(snapshot.sockets[0].local_endpoint, endpoint(82));
    assert_eq!(
        source.calls.iter().filter(|call| *call == "pass").count(),
        4
    );
}

#[test]
fn injectable_limits_cover_zero_max_and_max_plus_one() {
    let mut empty = FakeSource::new(stable_steps(Vec::new(), &[]));
    let snapshot =
        collect_consistent_with_limits(&mut empty, scope(), MetadataProfile::Display, limits(2))
            .expect("zero rows are valid");
    assert!(snapshot.sockets.is_empty());

    let rows = vec![socket(80), socket(81)];
    let mut maximum = FakeSource::new(stable_steps(rows, &[&[], &[]]));
    assert!(
        collect_consistent_with_limits(&mut maximum, scope(), MetadataProfile::Display, limits(2))
            .is_ok()
    );

    let mut over = FakeSource::new(vec![
        Step::Clock(1),
        Step::Pass(native_pass(
            vec![socket(80), socket(81), socket(82)],
            &[&[], &[], &[]],
        )),
    ]);
    assert_eq!(
        collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, limits(2)),
        Err(ObservationError::SocketObservationLimitExceeded)
    );
    assert_eq!(over.calls, ["clock", "pass"]);
}

#[test]
fn legacy_projection_preserves_owner_metadata_and_checks_projection_bounds() {
    let mut empty_source = FakeSource::new(stable_steps(Vec::new(), &[]));
    let empty = collect_consistent_with_limits(
        &mut empty_source,
        scope(),
        MetadataProfile::Display,
        limits(4),
    )
    .expect("empty snapshot is valid");
    assert!(
        project_legacy_with_limit(&empty, 0, None, None)
            .expect("zero rows fit a zero limit")
            .is_empty()
    );

    let mut source = FakeSource::new(stable_steps(vec![socket(80)], &[&[1, 1]]));
    let mut snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(4))
            .expect("duplicate owner edges remain countable");
    let process = snapshot
        .processes
        .values_mut()
        .next()
        .expect("shared owner has process metadata");
    process.name = Some(Arc::from("process"));
    process.executable_path = Some(Arc::from(Path::new("/usr/bin/process")));
    process.command_line = Some(Arc::from("process --serve"));
    process.parent_process_name = Some(Arc::from("parent"));
    let projected = project_legacy_with_limit(&snapshot, 2, None, None)
        .expect("exact projection maximum is accepted");
    assert_eq!(projected.len(), 2);
    for entry in &projected {
        assert_eq!(entry.process_name.as_deref(), Some("process"));
        assert_eq!(
            entry.executable_path.as_deref(),
            Some(Path::new("/usr/bin/process"))
        );
        assert_eq!(entry.command_line.as_deref(), Some("process --serve"));
        assert_eq!(entry.parent_process_name.as_deref(), Some("parent"));
        assert!(!entry.protected);
    }
    assert_eq!(
        project_legacy_with_limit(&snapshot, 1, None, None),
        Err(ObservationError::LegacyProjectionLimitExceeded)
    );
}

#[test]
fn targeted_descriptors_ignore_unrelated_rows_over_global_projection_limit() {
    let mut source = FakeSource::new(stable_steps(vec![socket(80)], &[&[1]]));
    let mut snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(4))
            .expect("target fixture collects");
    let mut unrelated = snapshot.sockets[0].clone();
    unrelated.local_endpoint = endpoint(81);
    unrelated.owners = vec![snapshot.sockets[0].owners[0].clone(); DERIVED_PORT_ENTRIES_MAX + 1];
    snapshot.sockets.push(unrelated);

    assert_eq!(
        snapshot
            .port_entry_descriptors_matching(None, Some(80), &[])
            .expect("unrelated rows do not consume the targeted limit")
            .len(),
        1,
    );
    assert_eq!(
        snapshot.port_entry_descriptors(&[]),
        Err(ObservationError::LegacyProjectionLimitExceeded),
    );
}

#[test]
fn many_sockets_for_one_owner_use_one_process_record() {
    let rows = vec![socket(80), socket(81), socket(82)];
    let mut source = FakeSource::new(stable_steps(rows, &[&[7], &[7], &[7]]));
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("shared owner snapshot");

    assert_eq!(snapshot.processes.len(), 1);
    let process = snapshot.processes.values().next().unwrap();
    assert_eq!(process.name.as_ref().map(|name| name.len()), Some(1));
    let rows = project_legacy(&snapshot).expect("legacy rows");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.process_name.as_deref(), Some("p"));
    }
}

#[test]
fn identity_limit_refuses_before_any_process_read() {
    let mut small = limits(3);
    small.owner_edges = 3;
    small.candidate_pids = 2;
    let mut source = FakeSource::new(vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![socket(80)], &[&[1, 2, 3]])),
    ]);
    assert_eq!(
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small),
        Err(ObservationError::ProcessIdentityLimitExceeded)
    );
    assert!(!source.calls.iter().any(|call| call.starts_with("process:")));
}

#[test]
fn owner_edge_limit_accepts_max_and_refuses_max_plus_one_before_identity_reads() {
    let row = socket(80);
    let exact_pids: &[&[u32]] = &[&[1, 1]];
    let mut exact = FakeSource::new(stable_steps(vec![row.clone()], exact_pids));
    let mut small = limits(8);
    small.owner_edges = 2;
    assert!(
        collect_consistent_with_limits(&mut exact, scope(), MetadataProfile::Display, small)
            .is_ok()
    );

    let mut over = FakeSource::new(vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![row], &[&[1, 1, 1]])),
    ]);
    assert_eq!(
        collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, small),
        Err(ObservationError::OwnerAttributionLimitExceeded)
    );
    assert!(!over.calls.iter().any(|call| call.starts_with("process:")));
}

#[test]
fn identity_reads_are_bounded_across_both_passes_of_an_attempt() {
    let row = socket(80);
    let mut small = limits(8);
    small.identity_reads_per_attempt = 2;
    let mut exact = FakeSource::new(stable_steps(vec![row.clone()], &[&[1]]));
    assert!(
        collect_consistent_with_limits(&mut exact, scope(), MetadataProfile::Display, small)
            .is_ok()
    );

    let mut over = FakeSource::new(vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![row.clone()], &[&[1]])),
        Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
        Step::Pass(native_pass(vec![row], &[&[1, 2]])),
    ]);
    assert_eq!(
        collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, small),
        Err(ObservationError::ProcessIdentityLimitExceeded)
    );
    assert_eq!(
        over.calls
            .iter()
            .filter(|call| call.starts_with("process:"))
            .count(),
        1
    );
}

#[test]
fn total_identity_bound_is_exact_and_refuses_before_excess_read() {
    let row = socket(80);
    let mut exact_limits = limits(4);
    exact_limits.identity_reads_total = 2;
    let mut exact = FakeSource::new(stable_steps(vec![row.clone()], &[&[1]]));
    assert!(
            collect_consistent_with_limits(
                &mut exact,
                scope(),
                MetadataProfile::Display,
                exact_limits,
            )
            .is_ok()
        );
    assert_eq!(exact.process_budgets.len(), 2);

    let mut over_limits = exact_limits;
    over_limits.identity_reads_total = 1;
    let mut over = FakeSource::new(vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![row.clone()], &[&[1]])),
        Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
        Step::Pass(native_pass(vec![row], &[&[1]])),
    ]);
    assert_eq!(
        collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, over_limits,),
        Err(ObservationError::ProcessIdentityLimitExceeded)
    );
    assert_eq!(
        over.process_budgets,
        [(1, over_limits.optional_metadata_bytes)]
    );
}

#[test]
fn readers_receive_remaining_metadata_budget_in_pid_order() {
    let rows = vec![socket(80), socket(81)];
    let mut small = limits(4);
    small.optional_metadata_bytes = 3;
    let mut source = FakeSource::new(stable_steps(rows, &[&[2], &[1]]));

    collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small)
        .expect("bounded metadata collection succeeds");

    assert_eq!(source.process_budgets, [(1, 3), (2, 3), (1, 3), (2, 2)]);
}

#[test]
fn omitted_metadata_truncation_gaps_are_counted() {
    let row = socket(80);
    let steps = vec![
        Step::Clock(1),
        Step::Pass(native_pass(vec![row.clone()], &[&[1]])),
        Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
        Step::Pass(native_pass(vec![row], &[&[1]])),
        Step::Process(1, MetadataProfile::Display, verified(1, Some("xx"))),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);
    let mut small = limits(2);
    small.evidence_gaps = 0;
    small.optional_metadata_bytes = 1;

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small)
            .expect("metadata truncation retains the snapshot");

    assert!(snapshot.evidence_gaps.is_empty());
    assert_eq!(snapshot.omitted_evidence_gap_count, 1);
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
}

#[test]
fn evidence_gap_overflow_is_counted_and_forces_partial() {
    let row = socket(80);
    // Four gaps that differ by PID. Overflow accounting has to be driven
    // by evidence that genuinely differs, because repeating one gap is
    // merged down to a single retained gap rather than filling the budget.
    let gap = |pid| {
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            None,
            Some(pid),
            "missing",
        )
    };
    let mut pass = native_pass(vec![row], &[&[]]);
    pass.evidence_gaps = vec![gap(1), gap(2), gap(3), gap(4)];
    let steps = vec![
        Step::Clock(1),
        Step::Pass(pass.clone()),
        Step::Pass(pass),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);
    let mut small = limits(8);
    small.evidence_gaps = 1;
    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small)
            .expect("gap truncation retains the snapshot");
    assert_eq!(snapshot.evidence_gaps.len(), 1);
    assert_eq!(snapshot.omitted_evidence_gap_count, 3);
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
}

/// Both consistency passes read the same host, so a real collector reports
/// the same per-PID gaps in each one. Retaining both copies would spend
/// half the gap budget on evidence already recorded, and the resulting
/// overflow would make an otherwise usable observation refuse a watch diff
/// and a kill.
#[test]
fn a_gap_observed_in_both_passes_is_retained_once_and_costs_one_budget_slot() {
    let row = socket(80);
    let gap = |pid| {
        EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(pid),
            "denied",
        )
    };
    let mut pass = native_pass(vec![row], &[&[]]);
    pass.evidence_gaps = vec![gap(1), gap(2)];
    let steps = vec![
        Step::Clock(1),
        Step::Pass(pass.clone()),
        Step::Pass(pass),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);
    // A budget of exactly two: the distinct pair fits, a doubled pair
    // would not, so this also pins that the copies never reach the budget.
    let mut exact = limits(8);
    exact.evidence_gaps = 2;

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, exact)
            .expect("duplicate gaps do not fail collection");

    assert_eq!(
        snapshot
            .evidence_gaps
            .iter()
            .map(|gap| gap.pid)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2)],
    );
    assert_eq!(snapshot.omitted_evidence_gap_count, 0);
}

#[test]
fn aggregate_gap_counts_merge_by_max_without_inventing_a_cross_pass_union() {
    let row = socket(80);
    let aggregate = |count| {
        EvidenceGap::aggregate_for_pids(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            NonZeroU64::new(count).expect("fixture count is nonzero"),
            "at least the reported number of PIDs were denied",
        )
    };
    let pass = |count| {
        let mut pass = native_pass(vec![row.clone()], &[&[]]);
        pass.global_owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                .expect("one reason fits");
        pass.evidence_gaps = vec![aggregate(count)];
        pass
    };
    let steps = vec![
        Step::Clock(1),
        Step::Pass(pass(4_096)),
        Step::Pass(pass(4_100)),
        Step::Clock(2),
    ];
    let mut source = FakeSource::new(steps);

    let snapshot =
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(8))
            .expect("aggregate gaps merge within one slot");

    assert_eq!(snapshot.evidence_gaps.len(), 1);
    assert_eq!(snapshot.evidence_gaps[0].affected_pid_count(), Some(4_100));
    assert_eq!(snapshot.omitted_evidence_gap_count, 0);
}

#[test]
fn metadata_budget_is_pid_then_field_order_and_omits_before_overflow() {
    let mut processes = HashMap::from([
        (
            ProcessIdentity {
                pid: 2,
                start_marker: ProcessStartMarker::linux(2).unwrap(),
            },
            ProcessObservation {
                name: Some(Arc::from("bb")),
                executable_path: None,
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        ),
        (
            ProcessIdentity {
                pid: 1,
                start_marker: ProcessStartMarker::linux(1).unwrap(),
            },
            ProcessObservation {
                name: Some(Arc::from("aa")),
                executable_path: Some(Arc::from(Path::new("x"))),
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        ),
    ]);
    let mut gaps = Vec::new();
    let mut omitted = 0;
    let mut small = limits(8);
    small.optional_metadata_bytes = 3;
    apply_metadata_budget(&mut processes, &mut gaps, &mut omitted, small);
    let pid1 = processes
        .iter()
        .find(|(identity, _)| identity.pid == 1)
        .unwrap()
        .1;
    let pid2 = processes
        .iter()
        .find(|(identity, _)| identity.pid == 2)
        .unwrap()
        .1;
    assert_eq!(pid1.name.as_deref(), Some("aa"));
    assert_eq!(pid1.executable_path.as_deref(), Some(Path::new("x")));
    assert_eq!(pid2.name, None);
    assert_eq!(
        pid2.metadata_omission,
        Some(MetadataOmission::BudgetExceeded)
    );
    assert_eq!(pid2.metadata_completeness, MetadataCompleteness::Partial);
    assert_eq!(
        gaps.iter().map(|gap| gap.code).collect::<Vec<_>>(),
        [EvidenceGapCode::NoncriticalEvidenceTruncated]
    );
    assert_eq!(omitted, 0);
}

#[test]
fn metadata_budget_omits_fields_in_order_without_changing_identity_or_socket() {
    let expected_fields = [
        (None, None, None, None),
        (Some("n"), None, None, None),
        (Some("n"), Some(Path::new("x")), None, None),
        (Some("n"), Some(Path::new("x")), Some("p"), None),
        (Some("n"), Some(Path::new("x")), Some("p"), Some("c")),
    ];

    for (budget, expected) in expected_fields.into_iter().enumerate() {
        let row = socket(80);
        let token = row.token;
        let full = ProcessRead::Verified {
            marker: ProcessStartMarker::linux(7).unwrap(),
            observation: ProcessObservation {
                name: Some(Arc::from("n")),
                executable_path: Some(Arc::from(Path::new("x"))),
                command_line: Some(Arc::from("c")),
                parent_pid: Some(99),
                parent_process_name: Some(Arc::from("p")),
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        };
        let steps = vec![
            Step::Clock(1),
            Step::Pass(native_pass(vec![row.clone()], &[&[42]])),
            Step::Process(42, MetadataProfile::IdentityOnly, verified(7, None)),
            Step::Pass(native_pass(vec![row], &[&[42]])),
            Step::Process(42, MetadataProfile::Display, full),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);
        let mut test_limits = limits(8);
        test_limits.optional_metadata_bytes = budget;

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            test_limits,
        )
        .expect("metadata omission retains authoritative identity");
        let owner = snapshot.sockets[0].owners[0].clone();
        let OwnerObservation::Verified(identity) = owner else {
            panic!("owner identity must remain verified");
        };
        let process = snapshot.processes.get(&identity).unwrap();

        assert_eq!(identity.pid, 42);
        assert_eq!(identity.start_marker, ProcessStartMarker::linux(7).unwrap());
        assert_eq!(snapshot.sockets[0].local_endpoint, endpoint(80));
        assert_eq!(snapshot.sockets[0].socket_token, token);
        assert_eq!(process.name.as_deref(), expected.0);
        assert_eq!(process.executable_path.as_deref(), expected.1);
        assert_eq!(process.parent_process_name.as_deref(), expected.2);
        assert_eq!(process.command_line.as_deref(), expected.3);
        assert_eq!(process.parent_pid, Some(99));
        assert_eq!(
            process.metadata_omission,
            (budget < 4).then_some(MetadataOmission::BudgetExceeded)
        );
    }
}

#[test]
fn clock_errors_are_operational_and_reverse_intervals_are_rejected() {
    assert_eq!(
        validate_wall_clock_interval(
            UNIX_EPOCH + Duration::from_secs(2),
            UNIX_EPOCH + Duration::from_secs(1)
        ),
        Err(ObservationError::InvalidWallClockInterval)
    );
    let mut source = FakeSource::new(vec![Step::Error(ObservationError::ClockUnavailable)]);
    assert_eq!(
        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, limits(2)),
        Err(ObservationError::ClockUnavailable)
    );
}
