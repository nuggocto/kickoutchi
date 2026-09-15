//! Narrow, invariant-preserving fixtures shared across unit-test modules.
//!
//! Keep only exact cross-module setup here. Module-specific fields stay at
//! their call sites so tests continue to show the behavior they exercise.

use std::net::{IpAddr, Ipv4Addr};

use crate::collector::{Collector, FakeCollector};
use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};
use crate::observation::{
    EvidenceGap, EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot,
    OwnerCompleteness, OwnerObservation, UnverifiedOwnerReason,
};

#[path = "../tests/support/command.rs"]
pub(crate) mod command;

pub(crate) fn port_entry(port: u16, pid: Option<u32>, protocol: Protocol, name: &str) -> PortEntry {
    PortEntry {
        protocol,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: port,
        state: match protocol {
            Protocol::Tcp => SocketState::Listen,
            Protocol::Udp => SocketState::Bound,
        },
        pid,
        process_name: Some(name.into()),
        executable_path: None,
        command_line: None,
        parent_pid: None,
        parent_process_name: None,
        protected: false,
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        process_identity: pid.map(|pid| crate::observation::ProcessIdentity {
            pid,
            start_marker: crate::observation::ProcessStartMarker::linux(55)
                .expect("test marker is nonzero"),
        }),
        ipv6_scope: None,
    }
}

pub(crate) fn permission_denied_owner_snapshot() -> NetworkSnapshot {
    let mut snapshot = FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake collection succeeds");
    let socket = snapshot
        .sockets
        .iter_mut()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("fixture has target socket");
    let endpoint = socket.local_endpoint.clone();
    socket.owners = vec![OwnerObservation::UnverifiedPid {
        pid: 18_422,
        reason: UnverifiedOwnerReason::PermissionDenied,
    }];
    socket.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
            .expect("one reason fits");
    snapshot
        .processes
        .retain(|identity, _| identity.pid != 18_422);
    snapshot.owner_completeness = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerAttributionIncomplete,
        EvidenceGapCode::OwnerPermissionDenied,
    ])
    .expect("fixture reasons fit");
    for _ in 0..2 {
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(endpoint.clone()),
            Some(18_422),
            "native owner PID could not be verified to a process start identity",
        ));
    }
    snapshot
}
