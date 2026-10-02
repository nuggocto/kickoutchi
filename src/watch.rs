//! Deterministic, bounded comparison of complete network observations.

use std::cmp::Ordering;
use std::sync::Arc;

use thiserror::Error;

use crate::observation::{
    EndpointIdentity, EvidenceImpact, NetworkSnapshot, OwnerObservation, PlatformSocketToken,
    SOCKET_OBSERVATIONS_MAX, SocketObservation, compare_endpoint_identity,
    compare_owner_completeness,
};

const WATCH_EVENTS_PER_POLL_MAX: usize = match SOCKET_OBSERVATIONS_MAX.checked_mul(2) {
    Some(limit) => limit,
    None => panic!("socket observation limit cannot be doubled"),
};

pub(crate) const WATCH_EVENT_BATCH_MAX: usize = 4_096;
pub(crate) const WATCH_EVENT_EVIDENCE_MAX: usize = 8;
pub(crate) const WATCH_EVENT_GAPS_MAX: usize = 8;
pub(crate) const WATCH_FAILURES_MAX: u8 = 3;
pub(crate) const WATCH_RECORD_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EventKind {
    Release,
    Replacement,
    Bind,
    Baseline,
}

impl EventKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Bind => "bind",
            Self::Release => "release",
            Self::Replacement => "replacement",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Certainty {
    Proven,
    Estimated,
    Heuristic,
    Unknown,
}

impl Certainty {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Estimated => "estimated",
            Self::Heuristic => "heuristic",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WatchEvent<'a> {
    pub(crate) kind: EventKind,
    pub(crate) previous_snapshot: Option<&'a NetworkSnapshot>,
    pub(crate) current_snapshot: Option<&'a NetworkSnapshot>,
    pub(crate) previous_socket: Option<&'a SocketObservation>,
    pub(crate) current_socket: Option<&'a SocketObservation>,
    pub(crate) multiplicity: u32,
    pub(crate) certainty: Certainty,
}

impl<'a> WatchEvent<'a> {
    pub(crate) fn endpoint(self) -> &'a EndpointIdentity {
        self.current_socket
            .or(self.previous_socket)
            .map(|socket| &socket.local_endpoint)
            .expect("endpoint events always carry one socket side")
    }

    pub(crate) fn event_socket(self) -> &'a SocketObservation {
        match self.kind {
            EventKind::Release => self
                .previous_socket
                .expect("release events carry the previous socket"),
            EventKind::Baseline | EventKind::Bind => self
                .current_socket
                .expect("baseline and bind events carry the current socket"),
            EventKind::Replacement => self
                .current_socket
                .expect("replacement events carry the current socket"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum DiffError {
    #[error("snapshot is not safe for socket multiplicity comparison")]
    UnsafeSnapshot,
    #[error("watch event limit exceeded")]
    EventLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemainderSide {
    Release,
    Bind,
}

#[derive(Debug, Clone, Copy)]
struct RemainderCursor {
    side: RemainderSide,
    previous_position: usize,
    previous_end: usize,
    current_position: usize,
    current_end: usize,
    paired_to_skip: usize,
}

#[derive(Debug, Clone)]
struct ReplacementReadiness {
    globally_safe: bool,
    unsafe_endpoints: Vec<EndpointIdentity>,
}

impl ReplacementReadiness {
    fn new(snapshot: &NetworkSnapshot) -> Self {
        let mut globally_safe = snapshot.owner_completeness.is_complete();
        let mut unsafe_endpoints = Vec::new();
        for gap in &snapshot.evidence_gaps {
            if gap.impact != EvidenceImpact::Ownership {
                continue;
            }
            if let Some(endpoint) = &gap.endpoint {
                unsafe_endpoints.push(endpoint.clone());
            } else {
                globally_safe = false;
            }
        }
        for socket in &snapshot.sockets {
            if !socket.owner_completeness.is_complete() {
                unsafe_endpoints.push(socket.local_endpoint.clone());
            }
        }
        unsafe_endpoints.sort_unstable_by(compare_endpoint_identity);
        unsafe_endpoints
            .dedup_by(|left, right| compare_endpoint_identity(left, right) == Ordering::Equal);
        Self {
            globally_safe,
            unsafe_endpoints,
        }
    }

    fn allows(&self, endpoint: &EndpointIdentity) -> bool {
        self.globally_safe
            && self
                .unsafe_endpoints
                .binary_search_by(|candidate| compare_endpoint_identity(candidate, endpoint))
                .is_err()
    }
}

#[derive(Clone)]
pub(crate) struct SnapshotDiff<'a> {
    previous: &'a NetworkSnapshot,
    current: &'a NetworkSnapshot,
    previous_indices: Arc<[usize]>,
    current_indices: Arc<[usize]>,
    previous_replacement_readiness: Arc<ReplacementReadiness>,
    current_replacement_readiness: Arc<ReplacementReadiness>,
    previous_position: usize,
    current_position: usize,
    pending_replacement: Option<(usize, usize, Certainty)>,
    pending_remainder: Option<RemainderCursor>,
    yielded: usize,
    event_limit: usize,
}

pub(crate) fn diff_snapshots<'a>(
    previous: &'a NetworkSnapshot,
    current: &'a NetworkSnapshot,
) -> Result<SnapshotDiff<'a>, DiffError> {
    SnapshotDiff::with_limit(previous, current, WATCH_EVENTS_PER_POLL_MAX)
}

impl<'a> SnapshotDiff<'a> {
    fn with_limit(
        previous: &'a NetworkSnapshot,
        current: &'a NetworkSnapshot,
        event_limit: usize,
    ) -> Result<Self, DiffError> {
        if !previous.socket_set_diff_safe() || !current.socket_set_diff_safe() {
            return Err(DiffError::UnsafeSnapshot);
        }
        let mut previous_indices = (0..previous.sockets.len()).collect::<Vec<_>>();
        let mut current_indices = (0..current.sockets.len()).collect::<Vec<_>>();
        previous_indices.sort_unstable_by(|left, right| {
            compare_socket(&previous.sockets[*left], &previous.sockets[*right])
        });
        current_indices.sort_unstable_by(|left, right| {
            compare_socket(&current.sockets[*left], &current.sockets[*right])
        });
        let previous_replacement_readiness = ReplacementReadiness::new(previous);
        let current_replacement_readiness = ReplacementReadiness::new(current);
        Ok(Self {
            previous,
            current,
            previous_indices: previous_indices.into(),
            current_indices: current_indices.into(),
            previous_replacement_readiness: Arc::new(previous_replacement_readiness),
            current_replacement_readiness: Arc::new(current_replacement_readiness),
            previous_position: 0,
            current_position: 0,
            pending_replacement: None,
            pending_remainder: None,
            yielded: 0,
            event_limit,
        })
    }

    fn next_event(&mut self) -> Option<WatchEvent<'a>> {
        loop {
            if let Some((previous, current, certainty)) = self.pending_replacement.take() {
                return Some(WatchEvent {
                    kind: EventKind::Replacement,
                    previous_snapshot: Some(self.previous),
                    current_snapshot: Some(self.current),
                    previous_socket: Some(&self.previous.sockets[previous]),
                    current_socket: Some(&self.current.sockets[current]),
                    multiplicity: 1,
                    certainty,
                });
            }
            if let Some((side, index)) = self.next_remainder_index() {
                return Some(match side {
                    RemainderSide::Release => WatchEvent {
                        kind: EventKind::Release,
                        previous_snapshot: Some(self.previous),
                        current_snapshot: Some(self.current),
                        previous_socket: Some(&self.previous.sockets[index]),
                        current_socket: None,
                        multiplicity: 1,
                        certainty: Certainty::Proven,
                    },
                    RemainderSide::Bind => WatchEvent {
                        kind: EventKind::Bind,
                        previous_snapshot: Some(self.previous),
                        current_snapshot: Some(self.current),
                        previous_socket: None,
                        current_socket: Some(&self.current.sockets[index]),
                        multiplicity: 1,
                        certainty: Certainty::Proven,
                    },
                });
            }
            if !self.prepare_next_bucket() {
                return None;
            }
        }
    }

    fn next_remainder_index(&mut self) -> Option<(RemainderSide, usize)> {
        let cursor = self.pending_remainder.as_mut()?;
        loop {
            let next = match (
                self.previous_indices.get(cursor.previous_position),
                self.current_indices.get(cursor.current_position),
            ) {
                (Some(previous), Some(current))
                    if cursor.previous_position < cursor.previous_end
                        && cursor.current_position < cursor.current_end =>
                {
                    match compare_socket(
                        &self.previous.sockets[*previous],
                        &self.current.sockets[*current],
                    ) {
                        Ordering::Less => {
                            cursor.previous_position += 1;
                            (RemainderSide::Release, Some(*previous))
                        }
                        Ordering::Greater => {
                            cursor.current_position += 1;
                            (RemainderSide::Bind, Some(*current))
                        }
                        Ordering::Equal => {
                            cursor.previous_position += 1;
                            cursor.current_position += 1;
                            (cursor.side, None)
                        }
                    }
                }
                (Some(previous), _) if cursor.previous_position < cursor.previous_end => {
                    cursor.previous_position += 1;
                    (RemainderSide::Release, Some(*previous))
                }
                (_, Some(current)) if cursor.current_position < cursor.current_end => {
                    cursor.current_position += 1;
                    (RemainderSide::Bind, Some(*current))
                }
                _ => {
                    self.pending_remainder = None;
                    return None;
                }
            };
            let (side, Some(index)) = next else {
                continue;
            };
            if side != cursor.side {
                continue;
            }
            if cursor.paired_to_skip != 0 {
                cursor.paired_to_skip -= 1;
                continue;
            }
            return Some((side, index));
        }
    }

    fn prepare_next_bucket(&mut self) -> bool {
        while self.previous_position < self.previous_indices.len()
            || self.current_position < self.current_indices.len()
        {
            let ordering = match (
                self.previous_indices.get(self.previous_position),
                self.current_indices.get(self.current_position),
            ) {
                (Some(previous), Some(current)) => compare_bucket(
                    &self.previous.sockets[*previous],
                    &self.current.sockets[*current],
                ),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => return false,
            };
            let previous_end = if ordering == Ordering::Greater {
                self.previous_position
            } else {
                bucket_end(
                    &self.previous.sockets,
                    &self.previous_indices,
                    self.previous_position,
                )
            };
            let current_end = if ordering == Ordering::Less {
                self.current_position
            } else {
                bucket_end(
                    &self.current.sockets,
                    &self.current_indices,
                    self.current_position,
                )
            };

            self.reconcile_bucket(previous_end, current_end);
            self.previous_position = previous_end;
            self.current_position = current_end;
            if self.pending_replacement.is_some() || self.pending_remainder.is_some() {
                return true;
            }
        }
        false
    }

    fn reconcile_bucket(&mut self, previous_end: usize, current_end: usize) {
        self.pending_replacement = None;
        self.pending_remainder = None;

        let previous = &self.previous_indices[self.previous_position..previous_end];
        let current = &self.current_indices[self.current_position..current_end];
        if previous.len() == 1 && current.len() == 1 {
            let previous_index = previous[0];
            let current_index = current[0];
            if compare_socket(
                &self.previous.sockets[previous_index],
                &self.current.sockets[current_index],
            ) == Ordering::Equal
            {
                return;
            }
            if let Some(certainty) = replacement_certainty(
                &self.previous_replacement_readiness,
                &self.previous.sockets[previous_index],
                &self.current_replacement_readiness,
                &self.current.sockets[current_index],
            ) {
                self.pending_replacement = Some((previous_index, current_index, certainty));
                return;
            }
        }

        let (previous_remaining, current_remaining) = self.count_remaining(previous, current);
        let side = match previous_remaining.cmp(&current_remaining) {
            Ordering::Greater => RemainderSide::Release,
            Ordering::Less => RemainderSide::Bind,
            Ordering::Equal => return,
        };
        self.pending_remainder = Some(RemainderCursor {
            side,
            previous_position: self.previous_position,
            previous_end,
            current_position: self.current_position,
            current_end,
            paired_to_skip: previous_remaining.min(current_remaining),
        });
    }

    fn count_remaining(&self, previous: &[usize], current: &[usize]) -> (usize, usize) {
        let mut previous_remaining = 0usize;
        let mut current_remaining = 0usize;
        let mut previous_cursor = 0usize;
        let mut current_cursor = 0usize;
        while previous_cursor < previous.len() && current_cursor < current.len() {
            match compare_socket(
                &self.previous.sockets[previous[previous_cursor]],
                &self.current.sockets[current[current_cursor]],
            ) {
                Ordering::Less => {
                    previous_remaining += 1;
                    previous_cursor += 1;
                }
                Ordering::Greater => {
                    current_remaining += 1;
                    current_cursor += 1;
                }
                Ordering::Equal => {
                    previous_cursor += 1;
                    current_cursor += 1;
                }
            }
        }
        previous_remaining += previous.len() - previous_cursor;
        current_remaining += current.len() - current_cursor;
        (previous_remaining, current_remaining)
    }
}

impl<'a> Iterator for SnapshotDiff<'a> {
    type Item = Result<WatchEvent<'a>, DiffError>;

    fn next(&mut self) -> Option<Self::Item> {
        let event = self.next_event()?;
        let Some(yielded) = self.yielded.checked_add(1) else {
            return Some(Err(DiffError::EventLimitExceeded));
        };
        if yielded > self.event_limit {
            return Some(Err(DiffError::EventLimitExceeded));
        }
        self.yielded = yielded;
        Some(Ok(event))
    }
}

#[derive(Clone)]
pub(crate) struct BaselineEvents<'a> {
    snapshot: &'a NetworkSnapshot,
    indices: Arc<[usize]>,
    position: usize,
}

pub(crate) fn baseline_events(snapshot: &NetworkSnapshot) -> Result<BaselineEvents<'_>, DiffError> {
    if !snapshot.socket_set_diff_safe() {
        return Err(DiffError::UnsafeSnapshot);
    }
    let mut indices = (0..snapshot.sockets.len()).collect::<Vec<_>>();
    indices.sort_unstable_by(|left, right| {
        compare_socket(&snapshot.sockets[*left], &snapshot.sockets[*right])
    });
    Ok(BaselineEvents {
        snapshot,
        indices: indices.into(),
        position: 0,
    })
}

impl<'a> Iterator for BaselineEvents<'a> {
    type Item = WatchEvent<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = *self.indices.get(self.position)?;
        self.position += 1;
        Some(WatchEvent {
            kind: EventKind::Baseline,
            previous_snapshot: None,
            current_snapshot: Some(self.snapshot),
            previous_socket: None,
            current_socket: Some(&self.snapshot.sockets[index]),
            multiplicity: 1,
            certainty: Certainty::Proven,
        })
    }
}

fn bucket_end(sockets: &[SocketObservation], indices: &[usize], start: usize) -> usize {
    let Some(first) = indices.get(start) else {
        return start;
    };
    let mut end = start + 1;
    while end < indices.len()
        && compare_bucket(&sockets[*first], &sockets[indices[end]]) == Ordering::Equal
    {
        end += 1;
    }
    end
}

fn replacement_certainty(
    previous_readiness: &ReplacementReadiness,
    previous: &SocketObservation,
    current_readiness: &ReplacementReadiness,
    current: &SocketObservation,
) -> Option<Certainty> {
    if !previous_readiness.allows(&previous.local_endpoint)
        || !current_readiness.allows(&current.local_endpoint)
        || !previous.owner_completeness.is_complete()
        || !current.owner_completeness.is_complete()
    {
        return None;
    }
    let [OwnerObservation::Verified(previous_identity)] = previous.owners.as_slice() else {
        return None;
    };
    let [OwnerObservation::Verified(current_identity)] = current.owners.as_slice() else {
        return None;
    };
    if previous_identity == current_identity {
        return None;
    }
    Some(
        if previous_identity.pid == current_identity.pid
            && same_marker_kind(
                previous_identity.start_marker,
                current_identity.start_marker,
            )
        {
            Certainty::Proven
        } else {
            Certainty::Heuristic
        },
    )
}

const fn same_marker_kind(
    left: crate::observation::ProcessStartMarker,
    right: crate::observation::ProcessStartMarker,
) -> bool {
    matches!(
        (left, right),
        (
            crate::observation::ProcessStartMarker::LinuxStartTicks(_),
            crate::observation::ProcessStartMarker::LinuxStartTicks(_)
        ) | (
            crate::observation::ProcessStartMarker::MacOsStartTime(_),
            crate::observation::ProcessStartMarker::MacOsStartTime(_)
        ) | (
            crate::observation::ProcessStartMarker::WindowsCreationTime(_),
            crate::observation::ProcessStartMarker::WindowsCreationTime(_)
        )
    )
}

fn compare_socket(left: &SocketObservation, right: &SocketObservation) -> Ordering {
    compare_bucket(left, right)
        .then_with(|| compare_token(left.socket_token, right.socket_token))
        .then_with(|| compare_owner_set(left, right))
        .then_with(|| left.owners.cmp(&right.owners))
        .then_with(|| left.timer.cmp(&right.timer))
}

fn compare_bucket(left: &SocketObservation, right: &SocketObservation) -> Ordering {
    compare_endpoint_identity(&left.local_endpoint, &right.local_endpoint)
        .then_with(|| left.state.cmp(&right.state))
}

fn compare_token(
    left: Option<PlatformSocketToken>,
    right: Option<PlatformSocketToken>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn compare_owner_set(left: &SocketObservation, right: &SocketObservation) -> Ordering {
    let left_omitted = left
        .owners
        .len()
        .saturating_sub(crate::observation::SERIALIZED_OWNERS_MAX);
    let right_omitted = right
        .owners
        .len()
        .saturating_sub(crate::observation::SERIALIZED_OWNERS_MAX);
    compare_owner_completeness(&left.owner_completeness, &right.owner_completeness)
        .then_with(|| left_omitted.cmp(&right_omitted))
        .then_with(|| {
            left.owners[..left
                .owners
                .len()
                .min(crate::observation::SERIALIZED_OWNERS_MAX)]
                .cmp(
                    &right.owners[..right
                        .owners
                        .len()
                        .min(crate::observation::SERIALIZED_OWNERS_MAX)],
                )
        })
}

pub(crate) fn compare_event_prefix(left: WatchEvent<'_>, right: WatchEvent<'_>) -> Ordering {
    compare_endpoint_identity(left.endpoint(), right.endpoint())
        .then_with(|| left.event_socket().state.cmp(&right.event_socket().state))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| compare_event_tokens(left, right))
        .then_with(|| compare_event_owner_sets(left, right))
}

fn compare_event_tokens(left: WatchEvent<'_>, right: WatchEvent<'_>) -> Ordering {
    match (left.kind, right.kind) {
        (EventKind::Replacement, EventKind::Replacement) => compare_token(
            left.previous_socket.and_then(|socket| socket.socket_token),
            right.previous_socket.and_then(|socket| socket.socket_token),
        )
        .then_with(|| {
            compare_token(
                left.current_socket.and_then(|socket| socket.socket_token),
                right.current_socket.and_then(|socket| socket.socket_token),
            )
        }),
        _ => compare_token(
            left.event_socket().socket_token,
            right.event_socket().socket_token,
        ),
    }
}

fn compare_event_owner_sets(left: WatchEvent<'_>, right: WatchEvent<'_>) -> Ordering {
    match (left.kind, right.kind) {
        (EventKind::Replacement, EventKind::Replacement) => compare_owner_set(
            left.previous_socket
                .expect("replacement carries a previous socket"),
            right
                .previous_socket
                .expect("replacement carries a previous socket"),
        )
        .then_with(|| {
            compare_owner_set(
                left.current_socket
                    .expect("replacement carries a current socket"),
                right
                    .current_socket
                    .expect("replacement carries a current socket"),
            )
        }),
        _ => compare_owner_set(left.event_socket(), right.event_socket()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU64;
    use std::time::{Duration, SystemTime};

    use super::{Certainty, DiffError, EventKind, SnapshotDiff, baseline_events, diff_snapshots};
    use crate::model::Protocol;
    use crate::observation::{
        EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact, MetadataCompleteness,
        NetworkSnapshot, ObservationScope, ObservationScopeKind, OwnerCompleteness,
        OwnerObservation, PlatformSocketToken, ProcessIdentity, ProcessObservation,
        ProcessStartMarker, SnapshotCompleteness, SocketObservation, SocketState,
    };

    fn identity(pid: u32, marker: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_marker: ProcessStartMarker::linux(marker).unwrap(),
        }
    }

    fn socket(port: u32, owner: Option<ProcessIdentity>) -> SocketObservation {
        SocketObservation {
            local_endpoint: EndpointIdentity::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                None,
            )
            .unwrap(),
            state: SocketState::Listen,
            timer: None,
            owners: owner.map_or_else(Vec::new, |owner| vec![OwnerObservation::Verified(owner)]),
            owner_completeness: OwnerCompleteness::Complete,
            socket_token: None,
        }
    }

    fn snapshot(sockets: Vec<SocketObservation>) -> NetworkSnapshot {
        let mut processes = HashMap::new();
        for socket in &sockets {
            for owner in &socket.owners {
                if let OwnerObservation::Verified(identity) = owner {
                    processes.insert(
                        *identity,
                        ProcessObservation {
                            name: Some(format!("p{}", identity.pid).into()),
                            executable_path: None,
                            command_line: None,
                            parent_pid: None,
                            parent_process_name: None,
                            metadata_omission: None,
                            metadata_completeness: MetadataCompleteness::Complete,
                        },
                    );
                }
            }
        }
        NetworkSnapshot {
            capture_started_at: SystemTime::UNIX_EPOCH,
            capture_completed_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1),
            scope: ObservationScope::new(
                ObservationScopeKind::CurrentNetworkNamespace,
                Some("net:[1]"),
                [],
            )
            .unwrap(),
            completeness: SnapshotCompleteness::Complete,
            owner_completeness: OwnerCompleteness::Complete,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
            sockets,
            processes,
        }
    }

    fn events(previous: &NetworkSnapshot, current: &NetworkSnapshot) -> Vec<(EventKind, u16)> {
        diff_snapshots(previous, current)
            .unwrap()
            .map(|event| {
                let event = event.unwrap();
                (event.kind, event.endpoint().port.get())
            })
            .collect()
    }

    #[test]
    fn baseline_is_sorted_and_preserves_duplicate_observations() {
        let snapshot = snapshot(vec![
            socket(3001, None),
            socket(3000, None),
            socket(3000, None),
        ]);
        let ports = baseline_events(&snapshot)
            .unwrap()
            .map(|event| event.endpoint().port.get())
            .collect::<Vec<_>>();
        assert_eq!(ports, [3000, 3000, 3001]);
    }

    #[test]
    fn multiplicity_changes_emit_only_unpaired_sockets() {
        let previous = snapshot(vec![
            socket(3000, None),
            socket(3000, None),
            socket(4000, None),
        ]);
        let current = snapshot(vec![socket(3000, None), socket(5000, None)]);
        assert_eq!(
            events(&previous, &current),
            [
                (EventKind::Release, 3000),
                (EventKind::Release, 4000),
                (EventKind::Bind, 5000)
            ]
        );
    }

    #[test]
    fn same_pid_changed_marker_is_proven_replacement() {
        let previous = snapshot(vec![socket(3000, Some(identity(7, 10)))]);
        let current = snapshot(vec![socket(3000, Some(identity(7, 11)))]);
        let event = diff_snapshots(&previous, &current)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.kind, EventKind::Replacement);
        assert_eq!(event.certainty, Certainty::Proven);
    }

    #[test]
    fn different_pid_replacement_is_heuristic_without_tokens() {
        let previous = snapshot(vec![socket(3000, Some(identity(7, 10)))]);
        let current = snapshot(vec![socket(3000, Some(identity(8, 11)))]);
        let event = diff_snapshots(&previous, &current)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.kind, EventKind::Replacement);
        assert_eq!(event.certainty, Certainty::Heuristic);
    }

    #[test]
    fn different_marker_kinds_never_prove_replacement() {
        let previous = snapshot(vec![socket(3000, Some(identity(7, 10)))]);
        let current_identity = ProcessIdentity {
            pid: 7,
            start_marker: ProcessStartMarker::windows(11).unwrap(),
        };
        let current = snapshot(vec![socket(3000, Some(current_identity))]);
        let event = diff_snapshots(&previous, &current)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.kind, EventKind::Replacement);
        assert_eq!(event.certainty, Certainty::Heuristic);
    }

    #[test]
    fn equal_identity_token_change_is_silent() {
        let owner = identity(7, 10);
        let mut previous_socket = socket(3000, Some(owner));
        previous_socket.socket_token =
            Some(PlatformSocketToken::LinuxInode(NonZeroU64::new(1).unwrap()));
        let mut current_socket = socket(3000, Some(owner));
        current_socket.socket_token =
            Some(PlatformSocketToken::LinuxInode(NonZeroU64::new(2).unwrap()));
        assert!(
            events(
                &snapshot(vec![previous_socket]),
                &snapshot(vec![current_socket])
            )
            .is_empty()
        );
    }

    #[test]
    fn state_transition_is_release_then_bind_not_replacement() {
        let owner = identity(7, 10);
        let previous = snapshot(vec![socket(3000, Some(owner))]);
        let mut current_socket = socket(3000, Some(owner));
        current_socket.state = SocketState::Established;
        let current = snapshot(vec![current_socket]);
        let kinds = diff_snapshots(&previous, &current)
            .unwrap()
            .map(|event| event.unwrap().kind)
            .collect::<Vec<_>>();
        assert_eq!(kinds, [EventKind::Release, EventKind::Bind]);
    }

    #[test]
    fn shared_owner_only_changes_are_silent() {
        let first = identity(7, 10);
        let second = identity(8, 11);
        let previous = snapshot(vec![socket(3000, Some(first))]);
        let mut current_socket = socket(3000, Some(first));
        current_socket
            .owners
            .push(OwnerObservation::Verified(second));
        let current = snapshot(vec![current_socket]);
        assert!(events(&previous, &current).is_empty());

        let previous = snapshot(vec![current.sockets[0].clone()]);
        let current = snapshot(vec![socket(3000, Some(first))]);
        assert!(events(&previous, &current).is_empty());
    }

    #[test]
    fn incomplete_global_ownership_disables_replacement() {
        let mut previous = snapshot(vec![socket(3000, Some(identity(7, 10)))]);
        previous.completeness = SnapshotCompleteness::Partial;
        previous.owner_completeness = OwnerCompleteness::partial([
            crate::observation::EvidenceGapCode::OwnerAttributionIncomplete,
        ])
        .unwrap();
        let current = snapshot(vec![socket(3000, Some(identity(8, 11)))]);
        assert!(events(&previous, &current).is_empty());
    }

    #[test]
    fn aggregate_ownership_gap_allows_bind_release_but_not_replacement() {
        let add_aggregate_gap = |snapshot: &mut NetworkSnapshot| {
            snapshot.completeness = SnapshotCompleteness::Partial;
            snapshot.owner_completeness =
                OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
            snapshot.evidence_gaps.push(EvidenceGap::aggregate_for_pids(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerPermissionDenied,
                None,
                std::num::NonZeroU64::new(4_097).unwrap(),
                "unrelated PIDs could not be inspected",
            ));
        };

        let mut previous = snapshot(vec![socket(3_000, Some(identity(7, 10)))]);
        let mut current = snapshot(vec![socket(4_000, Some(identity(8, 11)))]);
        add_aggregate_gap(&mut previous);
        add_aggregate_gap(&mut current);
        assert_eq!(
            events(&previous, &current),
            [(EventKind::Release, 3_000), (EventKind::Bind, 4_000)]
        );

        let mut replacement = snapshot(vec![socket(3_000, Some(identity(8, 11)))]);
        add_aggregate_gap(&mut replacement);
        assert!(events(&previous, &replacement).is_empty());
    }

    #[test]
    fn event_order_is_independent_of_source_order() {
        let previous = snapshot(vec![socket(9000, None), socket(7000, None)]);
        let current = snapshot(vec![socket(8000, None), socket(6000, None)]);
        assert_eq!(
            events(&previous, &current),
            [
                (EventKind::Bind, 6000),
                (EventKind::Release, 7000),
                (EventKind::Bind, 8000),
                (EventKind::Release, 9000),
            ]
        );
    }

    #[test]
    fn one_bucket_emits_every_release_across_the_batch_boundary() {
        let previous = snapshot(vec![socket(3_000, None); super::WATCH_EVENT_BATCH_MAX + 1]);
        let current = snapshot(Vec::new());
        let events = diff_snapshots(&previous, &current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), super::WATCH_EVENT_BATCH_MAX + 1);
        assert!(events.iter().all(|event| event.kind == EventKind::Release));
    }

    #[test]
    fn local_incompleteness_and_duplicate_multiplicity_disable_replacement() {
        let mut previous_socket = socket(3_000, Some(identity(7, 10)));
        previous_socket.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        let current_socket = socket(3_000, Some(identity(8, 11)));
        let mut previous = snapshot(vec![previous_socket]);
        previous.completeness = SnapshotCompleteness::Partial;
        assert!(events(&previous, &snapshot(vec![current_socket.clone()])).is_empty());

        let previous = snapshot(vec![
            socket(3_000, Some(identity(7, 10))),
            socket(3_000, Some(identity(7, 10))),
        ]);
        let current = snapshot(vec![current_socket.clone(), current_socket]);
        assert!(events(&previous, &current).is_empty());
    }

    #[test]
    fn token_supported_identity_change_remains_heuristic() {
        let mut previous_socket = socket(3_000, Some(identity(7, 10)));
        previous_socket.socket_token =
            Some(PlatformSocketToken::LinuxInode(NonZeroU64::new(9).unwrap()));
        let mut current_socket = socket(3_000, Some(identity(8, 11)));
        current_socket.socket_token =
            Some(PlatformSocketToken::LinuxInode(NonZeroU64::new(9).unwrap()));
        let previous = snapshot(vec![previous_socket]);
        let current = snapshot(vec![current_socket]);
        let event = diff_snapshots(&previous, &current)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(event.kind, EventKind::Replacement);
        assert_eq!(event.certainty, Certainty::Heuristic);
    }

    #[test]
    fn canonical_cancellation_compares_owners_beyond_the_public_limit() {
        let common = (1..=crate::observation::SERIALIZED_OWNERS_MAX)
            .map(|pid| OwnerObservation::UnverifiedPid {
                pid: u32::try_from(pid).unwrap(),
                reason: crate::observation::UnverifiedOwnerReason::IdentityUnavailable,
            })
            .collect::<Vec<_>>();
        let mut hidden_100 = socket(3_000, None);
        hidden_100.owners = common.clone();
        hidden_100.owners.push(OwnerObservation::UnverifiedPid {
            pid: 100,
            reason: crate::observation::UnverifiedOwnerReason::IdentityUnavailable,
        });
        let mut hidden_101 = socket(3_000, None);
        hidden_101.owners = common;
        hidden_101.owners.push(OwnerObservation::UnverifiedPid {
            pid: 101,
            reason: crate::observation::UnverifiedOwnerReason::IdentityUnavailable,
        });
        let previous = snapshot(vec![hidden_101.clone(), hidden_100.clone()]);
        let current = snapshot(vec![hidden_100]);
        let events = diff_snapshots(&previous, &current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Release);
        assert_eq!(events[0].previous_socket.unwrap().owners, hidden_101.owners);
    }

    #[test]
    fn owner_set_order_uses_omitted_count_before_serialized_owners() {
        let mut fewer_omitted = socket(3000, None);
        fewer_omitted.owners = (100..165)
            .map(|pid| OwnerObservation::Verified(identity(pid, u64::from(pid) + 1)))
            .collect();
        let mut more_omitted = socket(3000, None);
        more_omitted.owners = (1..67)
            .map(|pid| OwnerObservation::Verified(identity(pid, u64::from(pid) + 1)))
            .collect();
        assert_eq!(
            super::compare_owner_set(&fewer_omitted, &more_omitted),
            std::cmp::Ordering::Less
        );

        let mut attribution = socket(3000, None);
        attribution.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        let mut permission = socket(3000, None);
        permission.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
        assert_eq!(
            super::compare_owner_set(&attribution, &permission),
            std::cmp::Ordering::Less
        );

        let mut attribution_permission = socket(3000, None);
        attribution_permission.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerAttributionIncomplete,
        ])
        .unwrap();
        let mut attribution_identity = socket(3000, None);
        attribution_identity.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::ProcessIdentityUnavailable,
            EvidenceGapCode::OwnerAttributionIncomplete,
        ])
        .unwrap();
        assert_eq!(
            super::compare_owner_set(&attribution_permission, &attribution_identity),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn iterator_refuses_the_first_event_over_its_limit() {
        let previous = snapshot(Vec::new());
        let current = snapshot(vec![socket(3000, None), socket(3001, None)]);
        let mut diff = SnapshotDiff::with_limit(&previous, &current, 1).unwrap();
        assert!(diff.next().unwrap().is_ok());
        assert!(matches!(
            diff.next(),
            Some(Err(DiffError::EventLimitExceeded))
        ));
    }
}
