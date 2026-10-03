use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU64;

use super::{HiddenOwner, OwnerVisibility};
use crate::model::Protocol;
use crate::observation::{
    EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact, OwnerCompleteness,
    SocketObservation, SocketState, snapshot_from_test_rows,
};

const ME: u32 = 1000;

fn ownerless(port: u32, uid: Option<u32>) -> SocketObservation {
    SocketObservation {
        local_endpoint: EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            None,
        )
        .expect("valid fixture endpoint"),
        state: SocketState::Listen,
        timer: None,
        owners: Vec::new(),
        owner_completeness: OwnerCompleteness::Complete,
        socket_token: None,
        local_uid: uid,
    }
}

fn visibility(unreadable_processes: u64) -> OwnerVisibility {
    OwnerVisibility {
        unreadable_processes,
        current_uid: Some(ME),
    }
}

#[test]
fn classification_separates_permission_from_absence() {
    let cases = [
        // Nothing was unreadable: no readable process holds the socket.
        (0, Some(0), HiddenOwner::NoReadableHolder),
        (0, None, HiddenOwner::NoReadableHolder),
        // Unreadable processes and another user's socket.
        (496, Some(0), HiddenOwner::OtherUser { uid: 0 }),
        // Unreadable processes, but the socket is ours or has no UID.
        (496, Some(ME), HiddenOwner::Unattributed),
        (496, None, HiddenOwner::Unattributed),
    ];
    for (unreadable, uid, expected) in cases {
        assert_eq!(
            visibility(unreadable).classify(&ownerless(5432, uid)),
            expected,
            "unreadable={unreadable} uid={uid:?}"
        );
    }
}

#[test]
fn a_partial_local_owner_set_is_never_called_unheld() {
    // A nested PID namespace hides owners without any permission gap.
    let mut socket = ownerless(5432, Some(ME));
    socket.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
            .expect("one reason fits");

    assert_eq!(visibility(0).classify(&socket), HiddenOwner::Unattributed);
}

#[test]
fn unreadable_count_is_a_lower_bound_without_double_counting() {
    let mut snapshot = snapshot_from_test_rows(Vec::new());
    let gap = |pid| {
        EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(pid),
            "denied",
        )
    };
    // PID 7 repeats; PID 8 is distinct; a disappearance is not a denial.
    snapshot.evidence_gaps.extend([gap(7), gap(7), gap(8)]);
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerDisappeared,
        None,
        Some(9),
        "gone",
    ));
    assert_eq!(OwnerVisibility::of(&snapshot).unreadable_processes, 2);

    snapshot.evidence_gaps.push(EvidenceGap::aggregate_for_pids(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        NonZeroU64::new(496).expect("nonzero"),
        "denied",
    ));
    assert_eq!(OwnerVisibility::of(&snapshot).unreadable_processes, 496);
}

#[test]
fn table_notes_group_hidden_rows_by_reason() {
    let other = ownerless(5432, Some(4_000_000_001));
    let mine = ownerless(3000, Some(ME));
    let owned = ownerless(8080, Some(ME));

    let lines = visibility(496).table_notes([
        (false, false, &other),
        (false, false, &other),
        (false, false, &mine),
        (true, true, &owned),
        (true, false, &owned),
    ]);

    assert_eq!(
        lines,
        [
            "note: PID \"-\" means the socket's owner is not visible:",
            "  2 row(s) belong to other users (uid 4000000001: 2); at least 496 process(es) could not be read (permission denied). Rerun with sudo to see their owners.",
            "  1 row(s) have no attributed owner; at least 496 process(es) could not be read (permission denied).",
            "note: 1 row(s) show a PID but PROCESS \"-\": that process's name could not be read.",
        ]
    );
}

#[test]
fn table_notes_name_unheld_sockets_without_blaming_permissions() {
    let kernel = ownerless(53, Some(0));

    let lines = visibility(0).table_notes([(false, false, &kernel)]);

    assert_eq!(lines.len(), 2);
    assert!(
        lines[1].contains("no holder among readable processes"),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("permission")),
        "{lines:?}"
    );
}

#[test]
fn table_notes_are_silent_when_every_row_is_attributed() {
    let owned = ownerless(8080, Some(ME));

    assert!(
        visibility(496)
            .table_notes([(true, true, &owned)])
            .is_empty()
    );
}

#[test]
fn hidden_port_message_names_the_socket_user_and_the_cause() {
    let message =
        visibility(3).hidden_port_owner_message(5432, &ownerless(5432, Some(4_000_000_001)));

    assert_eq!(
        message,
        "port 5432 is visible, but its owner is hidden: the socket belongs to uid 4000000001 and at least 3 process(es) could not be read (permission denied); rerun with higher privileges, or pass --pid when known"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn uid_zero_resolves_to_root() {
    assert_eq!(super::user_name(0).as_deref(), Some("root"));
}
