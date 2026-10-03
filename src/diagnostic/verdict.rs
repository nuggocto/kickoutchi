//! Pure, bounded explanation of exact endpoint bind probes.

use std::net::IpAddr;

use crate::observation::{
    EndpointIdentity, EvidenceGap, Ipv6Scope, NetworkSnapshot, OwnerObservation, ScopeLimitation,
    SnapshotCompleteness, SocketObservation, SocketState, TcpTimerKind,
};
use crate::probe::{Ipv6Mode, ProbeOutcome, ProbeResult};
use crate::watch::Certainty;

pub(crate) const WHY_ENDPOINTS_MAX: usize = 8;
pub(crate) const WHY_EVIDENCE_MAX: usize = 16;
pub(crate) const WHY_EVIDENCE_GAPS_MAX: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    BindableNow,
    Owned,
    OwnerHidden,
    KernelStateObserved,
    PermissionDenied,
    AddressUnavailable,
    ReservationOrPolicyUnknown,
    ObservationRaced,
    Unsupported,
    Indeterminate,
}

impl Verdict {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::BindableNow => "bindable_now",
            Self::Owned => "owned",
            Self::OwnerHidden => "owner_hidden",
            Self::KernelStateObserved => "kernel_state_observed",
            Self::PermissionDenied => "permission_denied",
            Self::AddressUnavailable => "address_unavailable",
            Self::ReservationOrPolicyUnknown => "reservation_or_policy_unknown",
            Self::ObservationRaced => "observation_raced",
            Self::Unsupported => "unsupported",
            Self::Indeterminate => "indeterminate",
        }
    }

    const fn certainty(self) -> Certainty {
        match self {
            Self::BindableNow
            | Self::Owned
            | Self::KernelStateObserved
            | Self::PermissionDenied
            | Self::AddressUnavailable
            | Self::Unsupported => Certainty::Proven,
            Self::OwnerHidden
            | Self::ReservationOrPolicyUnknown
            | Self::ObservationRaced
            | Self::Indeterminate => Certainty::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointRelationship {
    Exact,
    ObservedWildcardCoversTarget,
    TargetWildcardCoversObserved,
    PotentialDualStackOverlap,
    PotentialScopeOverlap,
    Unrelated,
}

impl EndpointRelationship {
    const fn authoritative(self) -> bool {
        matches!(
            self,
            Self::Exact | Self::ObservedWildcardCoversTarget | Self::TargetWildcardCoversObserved
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceSource {
    LinuxProcfs,
    MacosLibproc,
    WindowsIpHelper,
    WindowsProcessApi,
    BindProbe,
    Analysis,
}

impl EvidenceSource {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::LinuxProcfs => "linux_procfs",
            Self::MacosLibproc => "macos_libproc",
            Self::WindowsIpHelper => "windows_ip_helper",
            Self::WindowsProcessApi => "windows_process_api",
            Self::BindProbe => "bind_probe",
            Self::Analysis => "analysis",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceCode {
    VisibleVerifiedOwner,
    VisibleUnreadableOwner,
    NonListeningKernelState,
    ExactBindSucceeded,
    ExactBindAddressInUse,
    ExactBindPermissionDenied,
    ExactBindAddressUnavailable,
    ExactBindUnsupported,
    ExactBindOtherError,
    LinuxTimerEstimate,
    ScopeLimitation,
    PotentialScopeOverlap,
    ObservationProbeConflict,
}

impl EvidenceCode {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::VisibleVerifiedOwner => "visible_verified_owner",
            Self::VisibleUnreadableOwner => "visible_unreadable_owner",
            Self::NonListeningKernelState => "non_listening_kernel_state",
            Self::ExactBindSucceeded => "exact_bind_succeeded",
            Self::ExactBindAddressInUse => "exact_bind_address_in_use",
            Self::ExactBindPermissionDenied => "exact_bind_permission_denied",
            Self::ExactBindAddressUnavailable => "exact_bind_address_unavailable",
            Self::ExactBindUnsupported => "exact_bind_unsupported",
            Self::ExactBindOtherError => "exact_bind_other_error",
            Self::LinuxTimerEstimate => "linux_timer_estimate",
            Self::ScopeLimitation => "scope_limitation",
            Self::PotentialScopeOverlap => "potential_scope_overlap",
            Self::ObservationProbeConflict => "observation_probe_conflict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) code: EvidenceCode,
    pub(crate) source: EvidenceSource,
    pub(crate) certainty: Certainty,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerdictResult {
    pub(crate) endpoint: EndpointIdentity,
    pub(crate) label: Option<String>,
    pub(crate) verdict: Verdict,
    pub(crate) certainty: Certainty,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) omitted_evidence_count: u64,
    pub(crate) evidence_gaps: Vec<EvidenceGap>,
    pub(crate) omitted_evidence_gap_count: u64,
}

pub(crate) fn analyze(
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
    probe: &ProbeResult,
    label: Option<&str>,
) -> VerdictResult {
    let source = native_source(snapshot);
    let verdict = select_verdict(endpoint, ipv6_mode, snapshot, probe.outcome);
    let mut evidence = BoundedEvidence::default();

    append_owner_evidence(&mut evidence, endpoint, ipv6_mode, snapshot);
    append_kernel_evidence(&mut evidence, endpoint, ipv6_mode, snapshot, source);
    append_probe_evidence(&mut evidence, probe.outcome);
    append_timer_evidence(&mut evidence, endpoint, ipv6_mode, snapshot, source);
    append_supporting_evidence(&mut evidence, endpoint, ipv6_mode, snapshot, probe.outcome);

    let (evidence_gaps, omitted_evidence_gap_count) =
        applicable_gaps(endpoint, ipv6_mode, snapshot);
    VerdictResult {
        endpoint: endpoint.clone(),
        label: label.map(str::to_owned),
        verdict,
        certainty: verdict.certainty(),
        evidence: evidence.items,
        omitted_evidence_count: evidence.omitted,
        evidence_gaps,
        omitted_evidence_gap_count,
    }
}

fn relationship(
    observed: &EndpointIdentity,
    target: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
) -> EndpointRelationship {
    if observed.protocol != target.protocol || observed.port != target.port {
        return EndpointRelationship::Unrelated;
    }

    match (observed.address, target.address) {
        (IpAddr::V4(observed_address), IpAddr::V4(target_address)) => address_relationship(
            observed_address.is_unspecified(),
            target_address.is_unspecified(),
            observed_address == target_address,
        ),
        (IpAddr::V6(observed_address), IpAddr::V6(target_address)) => {
            let base = address_relationship(
                observed_address.is_unspecified(),
                target_address.is_unspecified(),
                observed_address == target_address,
            );
            if base == EndpointRelationship::Unrelated {
                return base;
            }
            if authoritative_scopes_equal(observed.ipv6_scope, target.ipv6_scope) {
                base
            } else {
                EndpointRelationship::PotentialScopeOverlap
            }
        }
        (IpAddr::V6(observed_address), IpAddr::V4(_))
            if observed_address.is_unspecified() && ipv6_mode != Ipv6Mode::V6Only =>
        {
            EndpointRelationship::PotentialDualStackOverlap
        }
        (IpAddr::V4(_), IpAddr::V6(target_address))
            if target_address.is_unspecified() && ipv6_mode != Ipv6Mode::V6Only =>
        {
            EndpointRelationship::PotentialDualStackOverlap
        }
        _ => EndpointRelationship::Unrelated,
    }
}

fn authoritative_scopes_equal(observed: Option<Ipv6Scope>, target: Option<Ipv6Scope>) -> bool {
    observed == target && observed.is_some_and(|scope| scope != Ipv6Scope::Unavailable)
}

fn address_relationship(
    observed_wildcard: bool,
    target_wildcard: bool,
    equal: bool,
) -> EndpointRelationship {
    if equal {
        EndpointRelationship::Exact
    } else if observed_wildcard {
        EndpointRelationship::ObservedWildcardCoversTarget
    } else if target_wildcard {
        EndpointRelationship::TargetWildcardCoversObserved
    } else {
        EndpointRelationship::Unrelated
    }
}

fn select_verdict(
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
    outcome: ProbeOutcome,
) -> Verdict {
    match outcome {
        ProbeOutcome::BindableNow => Verdict::BindableNow,
        ProbeOutcome::AddressUnavailable => Verdict::AddressUnavailable,
        ProbeOutcome::Unsupported => Verdict::Unsupported,
        ProbeOutcome::PermissionDenied => Verdict::PermissionDenied,
        ProbeOutcome::Other if snapshot.completeness == SnapshotCompleteness::Raced => {
            Verdict::ObservationRaced
        }
        ProbeOutcome::Other => Verdict::Indeterminate,
        ProbeOutcome::AddressInUse => address_in_use_verdict(endpoint, ipv6_mode, snapshot),
    }
}

fn address_in_use_verdict(
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
) -> Verdict {
    if !snapshot.socket_set_diff_safe() {
        return Verdict::ReservationOrPolicyUnknown;
    }

    let mut hidden_owner = false;
    let mut ownerless_active = false;
    let mut kernel_state = false;
    for socket in authoritative_sockets(endpoint, ipv6_mode, snapshot) {
        if active_socket(socket) {
            if socket
                .owners
                .iter()
                .any(|owner| matches!(owner, OwnerObservation::Verified(_)))
            {
                return Verdict::Owned;
            }
            if owner_possibly_hidden(socket, snapshot) {
                hidden_owner = true;
            } else if socket.owners.is_empty() {
                ownerless_active = true;
            }
        } else if relevant_non_listening_tcp_state(socket) {
            kernel_state = true;
        }
    }
    if hidden_owner {
        Verdict::OwnerHidden
    } else if ownerless_active || kernel_state {
        Verdict::KernelStateObserved
    } else {
        Verdict::ReservationOrPolicyUnknown
    }
}

/// Whether an active socket without a verified owner may still have one
/// that this snapshot could not see.
///
/// An unverified owner PID or incomplete local attribution says so directly.
/// An empty owner set says so too when snapshot-wide attribution was
/// incomplete: an unreadable process anywhere on the host could hold the
/// socket, so an empty set is not proof that no process does. Kill authority
/// draws the same conclusion from the same snapshot gaps.
fn owner_possibly_hidden(socket: &SocketObservation, snapshot: &NetworkSnapshot) -> bool {
    socket
        .owners
        .iter()
        .any(|owner| matches!(owner, OwnerObservation::UnverifiedPid { .. }))
        || !socket.owner_completeness.is_complete()
        || (socket.owners.is_empty() && !snapshot.owner_completeness.is_complete())
}

fn authoritative_sockets<'a>(
    endpoint: &'a EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &'a NetworkSnapshot,
) -> impl Iterator<Item = &'a SocketObservation> {
    snapshot.sockets.iter().filter(move |socket| {
        relationship(&socket.local_endpoint, endpoint, ipv6_mode).authoritative()
    })
}

fn active_socket(socket: &SocketObservation) -> bool {
    matches!(
        (socket.local_endpoint.protocol, socket.state),
        (crate::model::Protocol::Tcp, SocketState::Listen)
            | (crate::model::Protocol::Udp, SocketState::Bound)
    )
}

fn relevant_non_listening_tcp_state(socket: &SocketObservation) -> bool {
    socket.local_endpoint.protocol == crate::model::Protocol::Tcp
        && !matches!(
            socket.state,
            SocketState::Closed | SocketState::Listen | SocketState::Unknown(_)
        )
}

#[derive(Default)]
struct BoundedEvidence {
    items: Vec<Evidence>,
    omitted: u64,
}

impl BoundedEvidence {
    fn push_with(&mut self, item: impl FnOnce() -> Evidence) {
        if self.items.len() < WHY_EVIDENCE_MAX {
            self.items.push(item());
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
}

/// Owner evidence names [`owner_source`], not the caller's native source: on
/// Windows the socket table comes from IP Helper while owner identity comes
/// from the process API, and attributing the owner fact to the wrong source
/// would misreport where the evidence came from.
fn append_owner_evidence(
    evidence: &mut BoundedEvidence,
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
) {
    let source = owner_source(snapshot);
    for socket in
        authoritative_sockets(endpoint, ipv6_mode, snapshot).filter(|socket| active_socket(socket))
    {
        for owner in &socket.owners {
            if let OwnerObservation::Verified(identity) = owner {
                evidence.push_with(|| {
                    let process = snapshot.processes.get(identity);
                    let name = process.and_then(|process| process.name.as_deref());
                    let message = name.map_or_else(
                        || {
                            format!(
                                "PID {} owned the endpoint at snapshot capture",
                                identity.pid
                            )
                        },
                        |name| {
                            format!(
                                "PID {} ({name}) owned the endpoint at snapshot capture",
                                identity.pid
                            )
                        },
                    );
                    Evidence {
                        code: EvidenceCode::VisibleVerifiedOwner,
                        source,
                        certainty: Certainty::Proven,
                        message,
                    }
                });
            }
        }
    }
    for socket in
        authoritative_sockets(endpoint, ipv6_mode, snapshot).filter(|socket| active_socket(socket))
    {
        let verified = socket
            .owners
            .iter()
            .any(|owner| matches!(owner, OwnerObservation::Verified(_)));
        if !verified && owner_possibly_hidden(socket, snapshot) {
            evidence.push_with(|| Evidence {
                code: EvidenceCode::VisibleUnreadableOwner,
                source,
                certainty: Certainty::Unknown,
                message: socket.local_uid.map_or_else(
                    || "the endpoint is visible but its owner is not verified".to_owned(),
                    |uid| {
                        format!(
                            "the endpoint is visible but its owner is not verified; uid {uid} created the socket"
                        )
                    },
                ),
            });
        }
    }
}

fn append_kernel_evidence(
    evidence: &mut BoundedEvidence,
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
    source: EvidenceSource,
) {
    for socket in authoritative_sockets(endpoint, ipv6_mode, snapshot) {
        if relevant_non_listening_tcp_state(socket) {
            evidence.push_with(|| Evidence {
                code: EvidenceCode::NonListeningKernelState,
                source,
                certainty: Certainty::Proven,
                message: format!("the kernel reports TCP state {}", socket.state.name()),
            });
        }
    }
}

fn append_timer_evidence(
    evidence: &mut BoundedEvidence,
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
    source: EvidenceSource,
) {
    for socket in authoritative_sockets(endpoint, ipv6_mode, snapshot) {
        if socket
            .timer
            .is_some_and(|timer| timer.kind == TcpTimerKind::TimeWait)
        {
            evidence.push_with(|| {
                let message = socket
                    .timer
                    .and_then(|timer| timer.estimated_remaining_milliseconds)
                    .map_or_else(
                        || "the kernel reports a TIME_WAIT timer".to_owned(),
                        |milliseconds| {
                            format!(
                                "the TIME_WAIT timer is estimated at {milliseconds} ms remaining"
                            )
                        },
                    );
                Evidence {
                    code: EvidenceCode::LinuxTimerEstimate,
                    source,
                    certainty: Certainty::Estimated,
                    message,
                }
            });
        }
    }
}

fn append_probe_evidence(evidence: &mut BoundedEvidence, outcome: ProbeOutcome) {
    let (code, message) = match outcome {
        ProbeOutcome::BindableNow => (
            EvidenceCode::ExactBindSucceeded,
            "the exact bind probe succeeded",
        ),
        ProbeOutcome::AddressInUse => (
            EvidenceCode::ExactBindAddressInUse,
            "the exact bind probe reported that the address is in use",
        ),
        ProbeOutcome::PermissionDenied => (
            EvidenceCode::ExactBindPermissionDenied,
            "the exact bind probe was denied permission",
        ),
        ProbeOutcome::AddressUnavailable => (
            EvidenceCode::ExactBindAddressUnavailable,
            "the exact bind probe reported that the address is unavailable",
        ),
        ProbeOutcome::Unsupported => (
            EvidenceCode::ExactBindUnsupported,
            "the requested address family or socket option is unsupported",
        ),
        ProbeOutcome::Other => (
            EvidenceCode::ExactBindOtherError,
            "the exact bind probe returned another operating-system error",
        ),
    };
    evidence.push_with(|| Evidence {
        code,
        source: EvidenceSource::BindProbe,
        certainty: Certainty::Proven,
        message: message.to_owned(),
    });
    if outcome == ProbeOutcome::PermissionDenied {
        evidence.push_with(|| Evidence {
            code: EvidenceCode::ExactBindPermissionDenied,
            source: EvidenceSource::Analysis,
            certainty: Certainty::Unknown,
            message: "permission denial leaves current bindability unknown".to_owned(),
        });
    }
}

fn append_supporting_evidence(
    evidence: &mut BoundedEvidence,
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
    outcome: ProbeOutcome,
) {
    let mut observed_socket = false;
    for socket in &snapshot.sockets {
        match relationship(&socket.local_endpoint, endpoint, ipv6_mode) {
            relationship if relationship.authoritative() => observed_socket = true,
            EndpointRelationship::PotentialScopeOverlap => evidence.push_with(|| Evidence {
                code: EvidenceCode::PotentialScopeOverlap,
                source: EvidenceSource::Analysis,
                certainty: Certainty::Unknown,
                message:
                    "an observed IPv6 endpoint may overlap, but scope evidence is insufficient"
                        .to_owned(),
            }),
            EndpointRelationship::PotentialDualStackOverlap => evidence.push_with(|| Evidence {
                code: EvidenceCode::ScopeLimitation,
                source: EvidenceSource::Analysis,
                certainty: Certainty::Unknown,
                message: "an IPv6 wildcard may overlap the IPv4 endpoint under dual-stack behavior"
                    .to_owned(),
            }),
            EndpointRelationship::Unrelated => {}
            _ => unreachable!("authoritative relationships are handled by the first arm"),
        }
    }
    if outcome == ProbeOutcome::BindableNow && observed_socket {
        evidence.push_with(|| Evidence {
            code: EvidenceCode::ObservationProbeConflict,
            source: EvidenceSource::Analysis,
            certainty: Certainty::Unknown,
            message: "the earlier snapshot observed a matching socket, but the later exact bind succeeded"
                .to_owned(),
        });
    }
    for limitation in &snapshot.scope.limitations {
        evidence.push_with(|| Evidence {
            code: EvidenceCode::ScopeLimitation,
            source: EvidenceSource::Analysis,
            certainty: Certainty::Unknown,
            message: scope_limitation_message(*limitation).to_owned(),
        });
    }
}

fn applicable_gaps(
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    snapshot: &NetworkSnapshot,
) -> (Vec<EvidenceGap>, u64) {
    let mut matching_owner_pids = std::collections::HashSet::new();
    let mut complete_ownerless_active = false;
    for socket in authoritative_sockets(endpoint, ipv6_mode, snapshot) {
        complete_ownerless_active |= active_socket(socket)
            && socket.owners.is_empty()
            && socket.owner_completeness.is_complete();
        for owner in &socket.owners {
            matching_owner_pids.insert(match owner {
                OwnerObservation::Verified(identity) => identity.pid,
                OwnerObservation::UnverifiedPid { pid, .. } => *pid,
            });
        }
    }
    let mut gaps = snapshot.evidence_gaps.iter().collect::<Vec<_>>();
    gaps.sort_unstable();
    let mut retained = Vec::with_capacity(WHY_EVIDENCE_GAPS_MAX);
    let mut omitted = snapshot.omitted_evidence_gap_count;
    for gap in gaps {
        if !gap_applies(
            gap,
            endpoint,
            ipv6_mode,
            &matching_owner_pids,
            complete_ownerless_active,
            &snapshot.owner_completeness,
        ) {
            continue;
        }
        if retained.len() < WHY_EVIDENCE_GAPS_MAX {
            retained.push(gap.clone());
        } else {
            omitted = omitted.saturating_add(1);
        }
    }
    (retained, omitted)
}

fn gap_applies(
    gap: &EvidenceGap,
    endpoint: &EndpointIdentity,
    ipv6_mode: Ipv6Mode,
    matching_owner_pids: &std::collections::HashSet<u32>,
    complete_ownerless_active: bool,
    global_owner_completeness: &crate::observation::OwnerCompleteness,
) -> bool {
    if let Some(affected) = &gap.endpoint
        && relationship(affected, endpoint, ipv6_mode) == EndpointRelationship::Unrelated
    {
        return false;
    }
    if gap.affected_pid_count().is_some()
        && gap.endpoint.is_none()
        && gap.impact == crate::observation::EvidenceImpact::Ownership
    {
        return complete_ownerless_active && !global_owner_completeness.is_complete();
    }
    let Some(pid) = gap.pid else {
        return true;
    };
    if gap.endpoint.is_none() && gap.impact == crate::observation::EvidenceImpact::SocketSet {
        return true;
    }
    if matching_owner_pids.contains(&pid) {
        return true;
    }
    gap.endpoint.is_none()
        && gap.impact == crate::observation::EvidenceImpact::Ownership
        && complete_ownerless_active
        && !global_owner_completeness.is_complete()
}

fn native_source(snapshot: &NetworkSnapshot) -> EvidenceSource {
    match snapshot.scope.kind {
        crate::observation::ObservationScopeKind::CurrentNetworkNamespace => {
            EvidenceSource::LinuxProcfs
        }
        crate::observation::ObservationScopeKind::CurrentHostProcessVisibleSockets => {
            EvidenceSource::MacosLibproc
        }
        crate::observation::ObservationScopeKind::CurrentHostNetworkStack => {
            EvidenceSource::WindowsIpHelper
        }
    }
}

fn owner_source(snapshot: &NetworkSnapshot) -> EvidenceSource {
    match snapshot.scope.kind {
        crate::observation::ObservationScopeKind::CurrentNetworkNamespace => {
            EvidenceSource::LinuxProcfs
        }
        crate::observation::ObservationScopeKind::CurrentHostProcessVisibleSockets => {
            EvidenceSource::MacosLibproc
        }
        crate::observation::ObservationScopeKind::CurrentHostNetworkStack => {
            EvidenceSource::WindowsProcessApi
        }
    }
}

fn scope_limitation_message(limitation: ScopeLimitation) -> &'static str {
    match limitation {
        ScopeLimitation::OtherNetworkNamespacesExcluded => {
            "other network namespaces are outside this observation"
        }
        ScopeLimitation::ProcessFirstSocketVisibilityLimited => {
            "socket visibility depends on visible processes"
        }
        ScopeLimitation::WslNetworkStackExcluded => {
            "the WSL network stack is outside this observation"
        }
        ScopeLimitation::ProcessMetadataPermissionLimited => {
            "process metadata may be limited by permissions"
        }
        ScopeLimitation::Ipv6ScopeUnavailable => "IPv6 scope information is unavailable",
        ScopeLimitation::ScopedIpv6ExactMatchingUnavailable => {
            "exact matching of scoped IPv6 endpoints is unavailable"
        }
        ScopeLimitation::NativeFieldUnavailable => {
            "the platform does not expose every native field"
        }
        ScopeLimitation::PollingIntervalBlindSpot => {
            "changes between observations may not be visible"
        }
    }
}

#[cfg(test)]
mod tests;
