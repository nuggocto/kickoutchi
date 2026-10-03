use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::SystemTime;

use super::*;
use crate::model::Protocol;
use crate::observation::{
    EvidenceGapCode, EvidenceImpact, ObservationScope, ObservationScopeKind, OwnerCompleteness,
    ProcessIdentity, ProcessObservation, ProcessStartMarker, TcpTimerObservation,
};

fn endpoint(protocol: Protocol, address: IpAddr) -> EndpointIdentity {
    let scope = address.is_ipv6().then_some(Ipv6Scope::Unscoped);
    EndpointIdentity::new(protocol, address, 3000, scope).expect("test endpoint is valid")
}

fn ipv6_endpoint(address: Ipv6Addr, scope: Ipv6Scope) -> EndpointIdentity {
    EndpointIdentity::new(Protocol::Tcp, IpAddr::V6(address), 3000, Some(scope))
        .expect("test IPv6 endpoint is valid")
}

fn snapshot(sockets: Vec<SocketObservation>) -> NetworkSnapshot {
    NetworkSnapshot {
        capture_started_at: SystemTime::UNIX_EPOCH,
        capture_completed_at: SystemTime::UNIX_EPOCH,
        scope: ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
            Some("net:[1]"),
            [],
        )
        .expect("test scope is valid"),
        completeness: SnapshotCompleteness::Complete,
        owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
        sockets,
        processes: HashMap::new(),
    }
}

fn socket(
    endpoint: EndpointIdentity,
    state: SocketState,
    owners: Vec<OwnerObservation>,
    owner_completeness: OwnerCompleteness,
) -> SocketObservation {
    SocketObservation {
        local_endpoint: endpoint,
        state,
        timer: None,
        owners,
        owner_completeness,
        socket_token: None,
        local_uid: None,
    }
}

fn probe_result(outcome: ProbeOutcome) -> ProbeResult {
    ProbeResult {
        outcome,
        raw_os_error: None,
        os_error_message: None,
    }
}

#[test]
fn relationship_matrix_distinguishes_authoritative_and_supporting_overlap() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let exact = target.clone();
    let observed_wildcard = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let target_wildcard = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let observed_exact = target.clone();
    let unrelated = endpoint(Protocol::Udp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let ipv6_wildcard = ipv6_endpoint(Ipv6Addr::UNSPECIFIED, Ipv6Scope::Unscoped);

    assert_eq!(
        relationship(&exact, &target, Ipv6Mode::SystemDefault),
        EndpointRelationship::Exact
    );
    assert_eq!(
        relationship(&observed_wildcard, &target, Ipv6Mode::SystemDefault),
        EndpointRelationship::ObservedWildcardCoversTarget
    );
    assert_eq!(
        relationship(&observed_exact, &target_wildcard, Ipv6Mode::SystemDefault),
        EndpointRelationship::TargetWildcardCoversObserved
    );
    assert_eq!(
        relationship(&ipv6_wildcard, &target, Ipv6Mode::DualStack),
        EndpointRelationship::PotentialDualStackOverlap
    );
    assert_eq!(
        relationship(&ipv6_wildcard, &target, Ipv6Mode::V6Only),
        EndpointRelationship::Unrelated
    );
    assert_eq!(
        relationship(&unrelated, &target, Ipv6Mode::SystemDefault),
        EndpointRelationship::Unrelated
    );
}

#[test]
fn same_family_wildcard_relationships_are_identical_for_tcp_and_udp() {
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let exact = endpoint(protocol, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let wildcard = endpoint(protocol, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            relationship(&exact, &exact, Ipv6Mode::SystemDefault),
            EndpointRelationship::Exact
        );
        assert_eq!(
            relationship(&wildcard, &exact, Ipv6Mode::SystemDefault),
            EndpointRelationship::ObservedWildcardCoversTarget
        );
        assert_eq!(
            relationship(&exact, &wildcard, Ipv6Mode::SystemDefault),
            EndpointRelationship::TargetWildcardCoversObserved
        );
    }
}

#[test]
fn ipv6_relationship_requires_known_equal_scopes() {
    let address = "fe80::1".parse::<Ipv6Addr>().expect("literal is valid");
    let scope_three = Ipv6Scope::InterfaceIndex(NonZeroU32::new(3).expect("nonzero"));
    let scope_four = Ipv6Scope::InterfaceIndex(NonZeroU32::new(4).expect("nonzero"));
    let target = ipv6_endpoint(address, scope_three);

    assert_eq!(
        relationship(
            &ipv6_endpoint(address, scope_three),
            &target,
            Ipv6Mode::SystemDefault
        ),
        EndpointRelationship::Exact
    );
    assert_eq!(
        relationship(
            &ipv6_endpoint(address, scope_four),
            &target,
            Ipv6Mode::SystemDefault
        ),
        EndpointRelationship::PotentialScopeOverlap
    );
    assert_eq!(
        relationship(
            &ipv6_endpoint(address, Ipv6Scope::Unavailable),
            &target,
            Ipv6Mode::SystemDefault
        ),
        EndpointRelationship::PotentialScopeOverlap
    );
}

#[test]
fn probe_first_rows_select_the_documented_verdicts() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let clean = snapshot(Vec::new());
    let cases = [
        (ProbeOutcome::BindableNow, Verdict::BindableNow),
        (
            ProbeOutcome::AddressUnavailable,
            Verdict::AddressUnavailable,
        ),
        (ProbeOutcome::Unsupported, Verdict::Unsupported),
        (ProbeOutcome::PermissionDenied, Verdict::PermissionDenied),
        (ProbeOutcome::Other, Verdict::Indeterminate),
        (
            ProbeOutcome::AddressInUse,
            Verdict::ReservationOrPolicyUnknown,
        ),
    ];

    for (outcome, expected) in cases {
        let result = analyze(
            &target,
            Ipv6Mode::SystemDefault,
            &clean,
            &probe_result(outcome),
            None,
        );
        assert_eq!(result.verdict, expected, "outcome {outcome:?}");
        assert_eq!(result.certainty, expected.certainty());
    }

    let mut raced = clean;
    raced.completeness = SnapshotCompleteness::Raced;
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &raced,
        &probe_result(ProbeOutcome::Other),
        None,
    );
    assert_eq!(result.verdict, Verdict::ObservationRaced);
}

#[test]
fn every_probe_outcome_is_total_across_snapshot_completeness() {
    for completeness in [
        SnapshotCompleteness::Complete,
        SnapshotCompleteness::Partial,
        SnapshotCompleteness::Raced,
    ] {
        for outcome in [
            ProbeOutcome::BindableNow,
            ProbeOutcome::AddressInUse,
            ProbeOutcome::PermissionDenied,
            ProbeOutcome::AddressUnavailable,
            ProbeOutcome::Unsupported,
            ProbeOutcome::Other,
        ] {
            let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut observed = snapshot(Vec::new());
            observed.completeness = completeness;
            let result = analyze(
                &target,
                Ipv6Mode::SystemDefault,
                &observed,
                &probe_result(outcome),
                None,
            );
            let expected = match outcome {
                ProbeOutcome::BindableNow => Verdict::BindableNow,
                ProbeOutcome::AddressInUse => Verdict::ReservationOrPolicyUnknown,
                ProbeOutcome::PermissionDenied => Verdict::PermissionDenied,
                ProbeOutcome::AddressUnavailable => Verdict::AddressUnavailable,
                ProbeOutcome::Unsupported => Verdict::Unsupported,
                ProbeOutcome::Other if completeness == SnapshotCompleteness::Raced => {
                    Verdict::ObservationRaced
                }
                ProbeOutcome::Other => Verdict::Indeterminate,
            };
            assert_eq!(
                result.verdict, expected,
                "outcome {outcome:?}, completeness {completeness:?}"
            );
            assert_eq!(result.certainty, expected.certainty());
            assert!(!result.evidence.is_empty());
        }
    }
}

#[test]
fn address_in_use_prefers_verified_then_hidden_then_ownerless_evidence() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let identity = ProcessIdentity {
        pid: 42,
        start_marker: ProcessStartMarker::linux(7).expect("marker is valid"),
    };
    let verified = snapshot(vec![socket(
        target.clone(),
        SocketState::Listen,
        vec![OwnerObservation::Verified(identity)],
        OwnerCompleteness::Complete,
    )]);
    let hidden = snapshot(vec![socket(
        target.clone(),
        SocketState::Listen,
        vec![OwnerObservation::UnverifiedPid {
            pid: 42,
            reason: crate::observation::UnverifiedOwnerReason::PermissionDenied,
        }],
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
            .expect("one reason fits"),
    )]);
    let ownerless = snapshot(vec![socket(
        target.clone(),
        SocketState::Listen,
        Vec::new(),
        OwnerCompleteness::Complete,
    )]);

    for (snapshot, expected) in [
        (verified, Verdict::Owned),
        (hidden, Verdict::OwnerHidden),
        (ownerless, Verdict::KernelStateObserved),
    ] {
        let result = analyze(
            &target,
            Ipv6Mode::SystemDefault,
            &snapshot,
            &probe_result(ProbeOutcome::AddressInUse),
            None,
        );
        assert_eq!(result.verdict, expected);
    }
}

#[test]
fn verified_owner_evidence_precedes_hidden_owner_evidence_across_sockets() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let wildcard = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let identity = ProcessIdentity {
        pid: 42,
        start_marker: ProcessStartMarker::linux(7).expect("marker is valid"),
    };
    let observed = snapshot(vec![
        socket(
            wildcard,
            SocketState::Listen,
            vec![OwnerObservation::UnverifiedPid {
                pid: 41,
                reason: crate::observation::UnverifiedOwnerReason::PermissionDenied,
            }],
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                .expect("one reason fits"),
        ),
        socket(
            target.clone(),
            SocketState::Listen,
            vec![OwnerObservation::Verified(identity)],
            OwnerCompleteness::Complete,
        ),
    ]);

    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );

    assert_eq!(result.verdict, Verdict::Owned);
    assert_eq!(result.evidence[0].code, EvidenceCode::VisibleVerifiedOwner);
    assert_eq!(
        result.evidence[1].code,
        EvidenceCode::VisibleUnreadableOwner
    );
}

#[test]
fn ownerless_socket_retains_pid_scoped_global_attribution_gap() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut observed = snapshot(vec![socket(
        target.clone(),
        SocketState::Listen,
        Vec::new(),
        OwnerCompleteness::Complete,
    )]);
    observed.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
            .expect("one reason fits");
    observed.completeness = SnapshotCompleteness::Partial;
    observed.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerAttributionIncomplete,
        None,
        Some(99),
        "a process could not be inspected",
    ));
    observed.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Metadata,
        EvidenceGapCode::ProcessMetadataUnavailable,
        None,
        Some(100),
        "unrelated process metadata is unavailable",
    ));

    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );

    // Incomplete snapshot-wide attribution means the empty owner set does not
    // prove that no process holds the socket.
    assert_eq!(result.verdict, Verdict::OwnerHidden);
    assert_eq!(result.evidence_gaps.len(), 1);
    assert_eq!(result.evidence_gaps[0].pid, Some(99));
}

#[test]
fn ownerless_socket_is_kernel_state_only_when_attribution_was_complete() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut ownerless = socket(
        target.clone(),
        SocketState::Listen,
        Vec::new(),
        OwnerCompleteness::Complete,
    );
    ownerless.local_uid = Some(970);
    let complete = snapshot(vec![ownerless]);
    let mut incomplete = complete.clone();
    incomplete.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
            .expect("one reason fits");
    let has_unreadable_owner = |evidence: &[Evidence]| {
        evidence
            .iter()
            .any(|item| item.code == EvidenceCode::VisibleUnreadableOwner)
    };

    let proven = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &complete,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );
    let hidden = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &incomplete,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );

    assert_eq!(proven.verdict, Verdict::KernelStateObserved);
    assert_eq!(proven.certainty, Certainty::Proven);
    assert!(!has_unreadable_owner(&proven.evidence));

    assert_eq!(hidden.verdict, Verdict::OwnerHidden);
    assert_eq!(hidden.certainty, Certainty::Unknown);
    let unreadable = hidden
        .evidence
        .iter()
        .find(|item| item.code == EvidenceCode::VisibleUnreadableOwner)
        .expect("hidden owners carry unreadable-owner evidence");
    assert_eq!(unreadable.certainty, Certainty::Unknown);
    assert!(unreadable.message.ends_with("uid 970 created the socket"));
}

#[test]
fn pid_scoped_global_socket_set_gap_applies_without_an_observed_owner() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut observed = snapshot(Vec::new());
    observed.completeness = SnapshotCompleteness::Partial;
    observed.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        None,
        Some(99),
        "a process socket scan failed",
    ));

    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );

    assert_eq!(result.verdict, Verdict::ReservationOrPolicyUnknown);
    assert_eq!(result.evidence_gaps.len(), 1);
    assert_eq!(result.evidence_gaps[0].pid, Some(99));
}

#[test]
fn permission_denial_separates_proven_failure_from_unknown_bindability() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &snapshot(Vec::new()),
        &probe_result(ProbeOutcome::PermissionDenied),
        None,
    );
    let permission = result
        .evidence
        .iter()
        .filter(|item| item.code == EvidenceCode::ExactBindPermissionDenied)
        .collect::<Vec<_>>();

    assert_eq!(result.verdict, Verdict::PermissionDenied);
    assert_eq!(permission.len(), 2);
    assert_eq!(permission[0].certainty, Certainty::Proven);
    assert_eq!(permission[1].certainty, Certainty::Unknown);
    assert!(permission[1].message.contains("bindability unknown"));
}

#[test]
fn non_listening_state_explains_address_in_use_but_unstable_socket_set_does_not() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut observed = snapshot(vec![socket(
        target.clone(),
        SocketState::TimeWait,
        Vec::new(),
        OwnerCompleteness::Complete,
    )]);
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );
    assert_eq!(result.verdict, Verdict::KernelStateObserved);

    observed.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::ObservationRaced,
        Some(target.clone()),
        None,
        "socket set changed",
    ));
    observed.completeness = SnapshotCompleteness::Partial;
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );
    assert_eq!(result.verdict, Verdict::ReservationOrPolicyUnknown);
}

#[test]
fn closed_and_unknown_tcp_states_do_not_claim_to_explain_a_failed_bind() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    for state in [SocketState::Closed, SocketState::Unknown(99)] {
        let observed = snapshot(vec![socket(
            target.clone(),
            state,
            Vec::new(),
            OwnerCompleteness::Complete,
        )]);
        let result = analyze(
            &target,
            Ipv6Mode::SystemDefault,
            &observed,
            &probe_result(ProbeOutcome::AddressInUse),
            None,
        );
        assert_eq!(result.verdict, Verdict::ReservationOrPolicyUnknown);
        assert!(
            result
                .evidence
                .iter()
                .all(|item| item.code != EvidenceCode::NonListeningKernelState)
        );
    }
}

#[test]
fn successful_probe_wins_and_retains_conflicting_observation() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let observed = snapshot(vec![socket(
        target.clone(),
        SocketState::Listen,
        Vec::new(),
        OwnerCompleteness::Complete,
    )]);
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::BindableNow),
        Some("web"),
    );

    assert_eq!(result.verdict, Verdict::BindableNow);
    assert_eq!(result.label.as_deref(), Some("web"));
    assert!(
        result
            .evidence
            .iter()
            .any(|item| { item.code == EvidenceCode::ObservationProbeConflict })
    );
}

#[test]
fn evidence_and_gap_retention_are_bounded_with_exact_omitted_counts() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut owners = Vec::new();
    let mut processes = HashMap::new();
    for pid in 1..=17 {
        let identity = ProcessIdentity {
            pid,
            start_marker: ProcessStartMarker::linux(u64::from(pid)).expect("marker is valid"),
        };
        owners.push(OwnerObservation::Verified(identity));
        processes.insert(identity, ProcessObservation::identity_only());
    }
    let mut observed = snapshot(vec![socket(
        target.clone(),
        SocketState::Listen,
        owners,
        OwnerCompleteness::Complete,
    )]);
    observed.processes = processes;
    observed.evidence_gaps = (0..17)
        .map(|index| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                None,
                &format!("gap {index:02}"),
            )
        })
        .collect();
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );

    assert_eq!(result.evidence.len(), WHY_EVIDENCE_MAX);
    assert_eq!(result.omitted_evidence_count, 2);
    assert_eq!(result.evidence_gaps.len(), WHY_EVIDENCE_GAPS_MAX);
    assert_eq!(result.omitted_evidence_gap_count, 1);
}

#[test]
fn evidence_retention_handles_zero_maximum_and_first_omitted_item() {
    let item = || Evidence {
        code: EvidenceCode::ExactBindOtherError,
        source: EvidenceSource::Analysis,
        certainty: Certainty::Unknown,
        message: "bounded evidence".to_owned(),
    };

    for (count, retained, omitted) in [
        (0, 0, 0),
        (WHY_EVIDENCE_MAX, WHY_EVIDENCE_MAX, 0),
        (WHY_EVIDENCE_MAX + 1, WHY_EVIDENCE_MAX, 1),
    ] {
        let mut evidence = BoundedEvidence::default();
        for _ in 0..count {
            evidence.push_with(item);
        }
        assert_eq!(evidence.items.len(), retained, "count={count}");
        assert_eq!(evidence.omitted, omitted, "count={count}");
    }
}

#[test]
fn time_wait_timer_is_estimated_and_never_promises_future_bindability() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut observed_socket = socket(
        target.clone(),
        SocketState::TimeWait,
        Vec::new(),
        OwnerCompleteness::Complete,
    );
    observed_socket.timer = Some(TcpTimerObservation::from_linux_native(3, 25, Some(100)));
    let observed = snapshot(vec![observed_socket]);
    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::AddressInUse),
        None,
    );
    let timer = result
        .evidence
        .iter()
        .find(|item| item.code == EvidenceCode::LinuxTimerEstimate)
        .expect("timer evidence is retained");

    assert_eq!(timer.certainty, Certainty::Estimated);
    assert!(!timer.message.contains("will"));
    assert!(!timer.message.contains("succeed"));
}

#[test]
fn evidence_phases_are_pinned_owner_kernel_probe_timer_supporting_then_gaps() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let identity = ProcessIdentity {
        pid: 42,
        start_marker: ProcessStartMarker::linux(7).expect("marker is valid"),
    };
    let mut timer_socket = socket(
        target.clone(),
        SocketState::TimeWait,
        Vec::new(),
        OwnerCompleteness::Complete,
    );
    timer_socket.timer = Some(TcpTimerObservation::from_linux_native(3, 25, Some(100)));
    let mut observed = snapshot(vec![
        socket(
            target.clone(),
            SocketState::Listen,
            vec![OwnerObservation::Verified(identity)],
            OwnerCompleteness::Complete,
        ),
        timer_socket,
        socket(
            ipv6_endpoint(Ipv6Addr::UNSPECIFIED, Ipv6Scope::Unscoped),
            SocketState::Listen,
            Vec::new(),
            OwnerCompleteness::Complete,
        ),
    ]);
    observed
        .scope
        .limitations
        .push(ScopeLimitation::NativeFieldUnavailable);
    observed.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Metadata,
        EvidenceGapCode::ProcessMetadataUnavailable,
        Some(target.clone()),
        None,
        "metadata unavailable",
    ));

    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::BindableNow),
        None,
    );

    assert_eq!(
        result
            .evidence
            .iter()
            .map(|item| item.code)
            .collect::<Vec<_>>(),
        vec![
            EvidenceCode::VisibleVerifiedOwner,
            EvidenceCode::NonListeningKernelState,
            EvidenceCode::ExactBindSucceeded,
            EvidenceCode::LinuxTimerEstimate,
            EvidenceCode::ScopeLimitation,
            EvidenceCode::ObservationProbeConflict,
            EvidenceCode::ScopeLimitation,
        ]
    );
    assert_eq!(result.evidence_gaps.len(), 1);
    assert_eq!(
        result.evidence_gaps[0].code,
        EvidenceGapCode::ProcessMetadataUnavailable
    );
}

#[test]
fn unrelated_endpoint_gaps_are_excluded() {
    let target = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let unrelated = endpoint(Protocol::Tcp, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    let mut observed = snapshot(vec![socket(
        unrelated.clone(),
        SocketState::Listen,
        Vec::new(),
        OwnerCompleteness::Complete,
    )]);
    observed.evidence_gaps = vec![EvidenceGap::new(
        EvidenceImpact::Metadata,
        EvidenceGapCode::ProcessMetadataUnavailable,
        Some(unrelated),
        Some(7),
        "unrelated metadata",
    )];

    let result = analyze(
        &target,
        Ipv6Mode::SystemDefault,
        &observed,
        &probe_result(ProbeOutcome::BindableNow),
        None,
    );

    assert!(result.evidence_gaps.is_empty());
}
