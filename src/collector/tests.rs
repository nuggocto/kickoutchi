use super::NativeObservationSource;
use super::{Collector, FakeCollector, kill_ports_from_snapshot};
use crate::model::SocketState;
use crate::observation::{
    EvidenceGap, EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot,
    ObservationError, OwnerCompleteness, OwnerObservation, ProcessIdentity, SnapshotCompleteness,
    UnverifiedOwnerReason, project_legacy, project_legacy_identities, project_legacy_pids,
};
use crate::observation::{NativeObservationPass, ObservationSource};
use crate::test_support::permission_denied_owner_snapshot;

fn socket_limit_pass(
    _profile: MetadataProfile,
) -> Result<NativeObservationPass, super::CollectorError> {
    Err(super::CollectorError::Observation(
        ObservationError::SocketObservationLimitExceeded,
    ))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "function pointer must match the fallible native adapter seam"
)]
fn empty_process_reads(
    _pids: &[u32],
    _profile: MetadataProfile,
    _remaining: usize,
) -> Result<crate::observation::ProcessReadBatch, super::CollectorError> {
    Ok(Vec::new())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "function pointer must match the fallible native adapter seam"
)]
fn empty_native_pass(
    _profile: MetadataProfile,
) -> Result<NativeObservationPass, super::CollectorError> {
    Ok(NativeObservationPass {
        rows: Vec::new(),
        global_owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
    })
}

fn process_limit_reads(
    _pids: &[u32],
    _profile: MetadataProfile,
    _remaining: usize,
) -> Result<crate::observation::ProcessReadBatch, super::CollectorError> {
    Err(super::CollectorError::Observation(
        ObservationError::ProcessIdentityLimitExceeded,
    ))
}

#[test]
fn native_adapter_preserves_typed_observation_errors() {
    let mut pass_error = NativeObservationSource {
        collect_pass: socket_limit_pass,
        read_processes: empty_process_reads,
    };
    assert_eq!(
        ObservationSource::collect_native_pass(&mut pass_error, MetadataProfile::IdentityOnly),
        Err(ObservationError::SocketObservationLimitExceeded)
    );

    let mut process_error = NativeObservationSource {
        collect_pass: empty_native_pass,
        read_processes: process_limit_reads,
    };
    assert_eq!(
        ObservationSource::read_processes(
            &mut process_error,
            &[],
            MetadataProfile::IdentityOnly,
            0,
        ),
        Err(ObservationError::ProcessIdentityLimitExceeded)
    );
}

fn verified_owner_permission_snapshot() -> NetworkSnapshot {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let endpoint = {
        let socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has target socket");
        socket.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                .expect("one reason fits");
        socket.local_endpoint.clone()
    };
    snapshot.owner_completeness = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerAttributionIncomplete,
        EvidenceGapCode::OwnerPermissionDenied,
    ])
    .expect("fixture reasons fit");
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        Some(endpoint),
        None,
        "native ownership attribution was permission denied",
    ));
    snapshot
}

#[test]
fn identity_projection_excludes_recycled_and_unverified_pid_owners() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let matching = snapshot
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has target listener")
        .clone();
    let identity = matching
        .owners
        .iter()
        .find_map(|owner| match owner {
            OwnerObservation::Verified(identity) => Some(*identity),
            OwnerObservation::UnverifiedPid { .. } => None,
        })
        .expect("fixture listener has a verified owner");
    let mut recycled = matching.clone();
    recycled.owners = vec![OwnerObservation::Verified(ProcessIdentity {
        pid: identity.pid,
        start_marker: crate::observation::ProcessStartMarker::linux(999)
            .expect("test marker is nonzero"),
    })];
    let mut unverified = matching.clone();
    unverified.owners = vec![OwnerObservation::UnverifiedPid {
        pid: identity.pid,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    }];
    snapshot.sockets = vec![matching, recycled, unverified];

    let entries =
        project_legacy_identities(&snapshot, &std::collections::BTreeSet::from([identity]))
            .expect("identity projection succeeds");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].process_identity, Some(identity));
}

#[test]
fn destructive_authority_ignores_non_legacy_socket_states() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let template = snapshot
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has target listener")
        .clone();
    let non_legacy_states = [
        crate::observation::SocketState::Closed,
        crate::observation::SocketState::SynSent,
        crate::observation::SocketState::SynReceived,
        crate::observation::SocketState::Established,
        crate::observation::SocketState::FinWait1,
        crate::observation::SocketState::FinWait2,
        crate::observation::SocketState::CloseWait,
        crate::observation::SocketState::Closing,
        crate::observation::SocketState::LastAck,
        crate::observation::SocketState::TimeWait,
        crate::observation::SocketState::DeleteTcb,
        crate::observation::SocketState::NewSynReceived,
        crate::observation::SocketState::Unknown(255),
    ];
    for state in non_legacy_states {
        let mut socket = template.clone();
        socket.state = state;
        socket.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                .expect("one reason fits");
        socket.owners = vec![OwnerObservation::UnverifiedPid {
            pid: 29_999,
            reason: UnverifiedOwnerReason::PermissionDenied,
        }];
        snapshot.sockets.push(socket);
    }

    let rows = kill_ports_from_snapshot(&snapshot, None, Some(3000))
        .expect("non-legacy states cannot invalidate listener authority");
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| row.state == SocketState::Listen));
    assert!(
        kill_ports_from_snapshot(&snapshot, Some(29_999), None)
            .expect("non-legacy states cannot become PID kill targets")
            .is_empty()
    );
    assert!(
        project_legacy(&snapshot)
            .expect("legacy projection")
            .iter()
            .all(|row| matches!(row.state, SocketState::Listen | SocketState::Bound))
    );
    let pids = std::collections::BTreeSet::from([29_999]);
    assert!(
        project_legacy_pids(&snapshot, &pids)
            .expect("PID projection")
            .is_empty()
    );
}

#[test]
fn destructive_authority_distinguishes_pid_and_port_targets() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    snapshot.owner_completeness = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerAttributionIncomplete,
        EvidenceGapCode::OwnerPermissionDenied,
    ])
    .expect("fixture reasons fit");
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        Some(99_999),
        "unrelated PID ownership denied",
    ));
    assert!(kill_ports_from_snapshot(&snapshot, Some(18_422), None).is_ok());
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));

    snapshot.evidence_gaps.clear();
    snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
            .expect("one reason fits");
    let selected_socket = snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has selected endpoint");
    selected_socket.owner_completeness = snapshot.owner_completeness.clone();
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));

    snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has selected endpoint")
        .owner_completeness = OwnerCompleteness::Complete;
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerAttributionIncomplete,
        None,
        Some(99_999),
        "unrelated global owner loss",
    ));
    assert!(kill_ports_from_snapshot(&snapshot, Some(18_422), None).is_ok());

    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerAttributionIncomplete,
        None,
        Some(18_422),
        "target PID owner loss",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));
}

#[test]
fn aggregate_owner_scan_loss_blocks_port_but_not_unrelated_pid_target() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
            .expect("one reason fits");
    snapshot.evidence_gaps.push(EvidenceGap::aggregate_for_pids(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        std::num::NonZeroU64::new(4_097).expect("fixture count is nonzero"),
        "unrelated PIDs could not be inspected",
    ));

    assert!(kill_ports_from_snapshot(&snapshot, Some(18_422), None).is_ok());
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));

    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        Some(18_422),
        "the target PID could not be inspected",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
}

#[test]
fn destructive_projection_contains_only_rows_matching_the_target_mode() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    snapshot.owner_completeness = OwnerCompleteness::Complete;
    snapshot.evidence_gaps.clear();
    snapshot.omitted_evidence_gap_count = 0;
    for socket in &mut snapshot.sockets {
        socket.owner_completeness = OwnerCompleteness::Complete;
    }
    let co_owner = snapshot
        .processes
        .keys()
        .find(|identity| identity.pid == 21_988)
        .copied()
        .expect("fixture co-owner identity");
    snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture target socket")
        .owners
        .push(OwnerObservation::Verified(co_owner));

    let by_pid = kill_ports_from_snapshot(&snapshot, Some(18_422), None)
        .expect("verified PID remains the selected identity");
    assert!(!by_pid.is_empty());
    assert!(by_pid.iter().all(|row| row.pid == Some(18_422)));

    let by_port = kill_ports_from_snapshot(&snapshot, None, Some(3000))
        .expect("globally complete port ownership projects all candidates");
    assert_eq!(
        by_port
            .iter()
            .filter_map(|row| row.pid)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([18_422, 21_988])
    );
    assert!(by_port.iter().all(|row| row.local_port == 3000));
}

#[test]
fn port_authority_requires_complete_local_evidence_and_verified_owners() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    snapshot.owner_completeness = OwnerCompleteness::Complete;
    snapshot.evidence_gaps.clear();
    let socket = snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture target socket");
    socket.owner_completeness = OwnerCompleteness::Complete;
    socket.owners.push(OwnerObservation::UnverifiedPid {
        pid: 99_999,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    });

    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));
}

#[test]
fn matching_permission_denied_unverified_pid_preserves_authority_loss() {
    let snapshot = permission_denied_owner_snapshot();

    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
}

#[test]
fn matching_socket_local_permission_gap_preserves_authority_loss() {
    let snapshot = verified_owner_permission_snapshot();

    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
}

#[test]
fn endpointless_target_ownership_permission_gap_blocks_pid_and_port() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    snapshot.owner_completeness = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerAttributionIncomplete,
        EvidenceGapCode::OwnerPermissionDenied,
    ])
    .expect("fixture reasons fit");
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        Some(18_422),
        "target PID ownership denied without an endpoint",
    ));

    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
}

#[test]
fn applicable_socket_set_permission_gaps_preserve_authority_loss() {
    let base = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let target_endpoint = base
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture target socket")
        .local_endpoint
        .clone();

    let mut global = base.clone();
    global.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        Some(18_422),
        "target PID socket set denied",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&global, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&global, None, Some(3000)),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));

    let mut local = base;
    local.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::OwnerPermissionDenied,
        Some(target_endpoint),
        None,
        "selected endpoint socket set denied",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&local, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));

    let unrelated_endpoint = local
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 5173)
        .expect("fixture unrelated socket")
        .local_endpoint
        .clone();
    let mut target_pid_on_other_endpoint = local;
    target_pid_on_other_endpoint.evidence_gaps.clear();
    target_pid_on_other_endpoint
        .evidence_gaps
        .push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(unrelated_endpoint),
            Some(18_422),
            "target PID socket set denied on another endpoint",
        ));
    assert!(matches!(
        kill_ports_from_snapshot(&target_pid_on_other_endpoint, Some(18_422), None),
        Err(super::CollectorError::OwnershipPermissionDenied)
    ));
}

#[test]
fn raced_refusal_never_masquerades_as_permission_denial() {
    for (pid, port) in [(Some(18_422), None), (None, Some(3000))] {
        let mut snapshot = permission_denied_owner_snapshot();
        snapshot.completeness = SnapshotCompleteness::Raced;
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ObservationRaced,
            None,
            None,
            "socket table changed during collection",
        ));

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, pid, port),
            Err(super::CollectorError::Observation(
                ObservationError::ObservationRaced
            ))
        ));
    }
}

#[test]
fn permission_refusal_precedes_omitted_evidence_for_pid_and_port() {
    for (pid, port) in [(Some(18_422), None), (None, Some(3000))] {
        let mut snapshot = permission_denied_owner_snapshot();
        snapshot.omitted_evidence_gap_count = 1;

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, pid, port),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
    }
}

#[test]
fn empty_owner_port_gate_remains_generic_fail_closed() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let socket = snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture target socket");
    socket.owners.clear();
    socket.owner_completeness = OwnerCompleteness::Complete;

    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));
}

#[test]
fn pid_socket_set_gaps_require_proven_unrelated_provenance() {
    let base = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let target_pid = 18_422;

    for pid in [None, Some(target_pid)] {
        let mut snapshot = base.clone();
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::OwnerAttributionIncomplete,
            None,
            pid,
            "socket set provenance is not unrelated",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(target_pid), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
    }

    let mut unrelated = base.clone();
    unrelated.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::OwnerAttributionIncomplete,
        None,
        Some(99_999),
        "known unrelated PID socket scan loss",
    ));
    assert!(kill_ports_from_snapshot(&unrelated, Some(target_pid), None).is_ok());
    assert!(matches!(
        kill_ports_from_snapshot(&unrelated, None, Some(3000)),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));

    let selected_endpoint = base
        .sockets
        .iter()
        .find(|socket| {
            socket.owners.iter().any(|owner| {
                matches!(
                    owner,
                    crate::observation::OwnerObservation::Verified(identity)
                        if identity.pid == target_pid
                )
            })
        })
        .expect("target endpoint")
        .local_endpoint
        .clone();
    let mut matching_endpoint = base;
    matching_endpoint.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        Some(selected_endpoint),
        Some(99_999),
        "matching endpoint remains relevant despite unrelated PID",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&matching_endpoint, Some(target_pid), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));

    let unrelated_endpoint = matching_endpoint
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 5173)
        .expect("unrelated endpoint")
        .local_endpoint
        .clone();
    for pid in [None, Some(99_999)] {
        let mut unrelated = matching_endpoint.clone();
        unrelated.evidence_gaps.clear();
        unrelated.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            Some(unrelated_endpoint.clone()),
            pid,
            "nonmatching endpoint has no target provenance",
        ));
        assert!(kill_ports_from_snapshot(&unrelated, Some(target_pid), None).is_ok());
    }
}

#[test]
fn port_socket_and_ownership_gaps_apply_only_globally_or_to_the_selected_port() {
    let base = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let selected_endpoint = base
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("selected endpoint")
        .local_endpoint
        .clone();
    let unrelated_endpoint = base
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 5173)
        .expect("unrelated endpoint")
        .local_endpoint
        .clone();

    for impact in [EvidenceImpact::SocketSet, EvidenceImpact::Ownership] {
        let mut unrelated = base.clone();
        unrelated.evidence_gaps.push(EvidenceGap::new(
            impact,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(unrelated_endpoint.clone()),
            None,
            "another port was permission denied",
        ));
        assert!(kill_ports_from_snapshot(&unrelated, None, Some(3000)).is_ok());

        for endpoint in [None, Some(selected_endpoint.clone())] {
            let mut applicable = base.clone();
            applicable.evidence_gaps.push(EvidenceGap::new(
                impact,
                EvidenceGapCode::NativeFieldUnavailable,
                endpoint,
                Some(99_999),
                "selected port evidence is partial",
            ));
            assert!(matches!(
                kill_ports_from_snapshot(&applicable, None, Some(3000)),
                Err(super::CollectorError::Observation(
                    ObservationError::PartialSocketSet
                ))
            ));
        }
    }
}

#[test]
fn kill_collection_exhaustively_validates_snapshot_authority() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");

    let selected_endpoint = snapshot
        .sockets
        .iter()
        .find(|socket| {
            socket.owners.iter().any(|owner| {
                matches!(
                    owner,
                    crate::observation::OwnerObservation::Verified(identity)
                        if identity.pid == 18_422
                )
            })
        })
        .expect("selected owner has an endpoint")
        .local_endpoint
        .clone();
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerAttributionIncomplete,
        Some(selected_endpoint),
        Some(18_422),
        "selected endpoint owner loss",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));

    let mut raced = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    raced.completeness = SnapshotCompleteness::Raced;
    raced
        .evidence_gaps
        .retain(|gap| gap.code != EvidenceGapCode::ObservationRaced);
    assert!(matches!(
        kill_ports_from_snapshot(&raced, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::ObservationRaced
        ))
    ));
    snapshot.evidence_gaps.retain(|gap| gap.endpoint.is_none());

    snapshot.completeness = SnapshotCompleteness::Partial;
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        None,
        None,
        "injected partial socket authority",
    ));
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));
}

#[test]
fn naturally_unverified_attributable_owner_refuses_kill_projection() {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let socket = snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture target socket");
    socket.owners = vec![OwnerObservation::UnverifiedPid {
        pid: 18_422,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    }];
    socket.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::ProcessIdentityUnavailable])
            .expect("one reason fits");
    snapshot.owner_completeness = socket.owner_completeness.clone();

    assert!(!snapshot.owner_completeness.is_complete());
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));

    snapshot.owner_completeness = OwnerCompleteness::Raced;
    assert!(matches!(
        kill_ports_from_snapshot(&snapshot, Some(18_422), None),
        Err(super::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));
}
