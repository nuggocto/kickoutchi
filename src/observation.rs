//! Platform-neutral, bounded network observation domain.
//!
//! This module owns consistency and retention policy so every native adapter
//! has one contract to satisfy.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use thiserror::Error;

#[cfg(test)]
use crate::model::PortEntry;
pub(crate) use crate::model::Protocol;
use crate::model::{PermissionStatus, Platform, PortEntryView, SocketState as LegacySocketState};

mod limits;

#[allow(
    unused_imports,
    reason = "native-adapter bounds are consumed only on their supported target"
)]
pub(crate) use limits::{
    CANDIDATE_PROCESS_IDS_MAX, EVIDENCE_GAPS_MAX, EVIDENCE_MESSAGE_MAX_BYTES,
    EXECUTABLE_PATH_MAX_BYTES, FILE_DESCRIPTOR_ENTRIES_MAX, NATIVE_RESIZE_ATTEMPTS_MAX,
    NATIVE_SOCKET_TABLE_MAX_BYTES, OPTIONAL_METADATA_MAX_BYTES, OWNER_COMPLETENESS_REASONS_MAX,
    OWNER_EDGES_MAX, ObservationLimits, PROCESS_COMMAND_LINE_MAX_BYTES, PROCESS_NAME_MAX_BYTES,
    PROTECTION_NAME_MAX_BYTES, PROTECTION_SCOPE_MAX_BYTES, PROTECTION_SCOPE_MAX_MEMBERS,
    SCOPE_IDENTIFIER_MAX_BYTES, SCOPE_LIMITATIONS_MAX, SERIALIZED_OWNERS_MAX,
    SOCKET_OBSERVATIONS_MAX,
};
use limits::{CONSISTENCY_ATTEMPTS_MAX, DERIVED_PORT_ENTRIES_MAX};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "scope variants are host-specific")]
pub(crate) enum Ipv6Scope {
    Unscoped,
    InterfaceIndex(NonZeroU32),
    Unavailable,
}

#[cfg(test)]
impl Ipv6Scope {
    pub(crate) fn interface_index(value: u64) -> Result<Self, EndpointIdentityError> {
        u32::try_from(value)
            .ok()
            .and_then(NonZeroU32::new)
            .map(Self::InterfaceIndex)
            .ok_or(EndpointIdentityError::InvalidInterfaceIndex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[allow(dead_code, reason = "validation variants are host-specific")]
pub(crate) enum EndpointIdentityError {
    #[error("endpoint port must be in 1..=65535")]
    InvalidPort,
    #[error("IPv4 endpoints cannot carry an IPv6 scope")]
    Ipv4WithScope,
    #[error("IPv6 endpoints require an explicit scope state")]
    Ipv6WithoutScope,
    #[error("IPv6 interface index must be in 1..=4294967295")]
    InvalidInterfaceIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EndpointIdentity {
    pub(crate) protocol: Protocol,
    pub(crate) address: IpAddr,
    pub(crate) port: NonZeroU16,
    pub(crate) ipv6_scope: Option<Ipv6Scope>,
}

impl EndpointIdentity {
    pub(crate) fn new(
        protocol: Protocol,
        address: IpAddr,
        port: u32,
        ipv6_scope: Option<Ipv6Scope>,
    ) -> Result<Self, EndpointIdentityError> {
        let was_ipv4_mapped =
            matches!(address, IpAddr::V6(value) if value.to_ipv4_mapped().is_some());
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4),
            address @ IpAddr::V4(_) => address,
        };
        let port = u16::try_from(port)
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or(EndpointIdentityError::InvalidPort)?;
        let ipv6_scope = match (address, ipv6_scope) {
            (IpAddr::V4(_), None) => None,
            (IpAddr::V4(_), Some(_)) if was_ipv4_mapped => None,
            (IpAddr::V4(_), Some(_)) => return Err(EndpointIdentityError::Ipv4WithScope),
            (IpAddr::V6(_), None) => return Err(EndpointIdentityError::Ipv6WithoutScope),
            (IpAddr::V6(_), Some(scope)) => Some(scope),
        };
        Ok(Self {
            protocol,
            address,
            port,
            ipv6_scope,
        })
    }
}

pub(crate) fn compare_endpoint_identity(
    left: &EndpointIdentity,
    right: &EndpointIdentity,
) -> Ordering {
    left.protocol
        .cmp(&right.protocol)
        .then_with(|| match (left.address, right.address) {
            (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
            (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
            (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
            (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        })
        .then_with(|| left.ipv6_scope.cmp(&right.ipv6_scope))
        .then_with(|| left.port.cmp(&right.port))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MacOsProcessStartTime {
    seconds: u64,
    microseconds: u32,
}

#[allow(dead_code, reason = "constructed only on macOS")]
impl MacOsProcessStartTime {
    pub(crate) fn new(seconds: u64, microseconds: u32) -> Result<Self, ProcessMarkerError> {
        if microseconds > 999_999 {
            return Err(ProcessMarkerError::InvalidMicroseconds);
        }
        if seconds == 0 && microseconds == 0 {
            return Err(ProcessMarkerError::Zero);
        }
        Ok(Self {
            seconds,
            microseconds,
        })
    }

    pub(crate) const fn seconds(self) -> u64 {
        self.seconds
    }

    pub(crate) const fn microseconds(self) -> u32 {
        self.microseconds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[allow(dead_code, reason = "marker errors are host-specific")]
pub(crate) enum ProcessMarkerError {
    #[error("a process start marker cannot be zero")]
    Zero,
    #[error("macOS process-start microseconds must be in 0..=999999")]
    InvalidMicroseconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "marker variants are host-specific")]
pub(crate) enum ProcessStartMarker {
    LinuxStartTicks(NonZeroU64),
    MacOsStartTime(MacOsProcessStartTime),
    WindowsCreationTime(NonZeroU64),
}

#[allow(dead_code, reason = "marker constructors are host-specific")]
impl ProcessStartMarker {
    pub(crate) fn linux(ticks: u64) -> Result<Self, ProcessMarkerError> {
        NonZeroU64::new(ticks)
            .map(Self::LinuxStartTicks)
            .ok_or(ProcessMarkerError::Zero)
    }

    pub(crate) fn macos(seconds: u64, microseconds: u32) -> Result<Self, ProcessMarkerError> {
        MacOsProcessStartTime::new(seconds, microseconds).map(Self::MacOsStartTime)
    }

    pub(crate) fn windows(filetime_ticks: u64) -> Result<Self, ProcessMarkerError> {
        NonZeroU64::new(filetime_ticks)
            .map(Self::WindowsCreationTime)
            .ok_or(ProcessMarkerError::Zero)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    pub(crate) start_marker: ProcessStartMarker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "socket tokens are host-specific")]
pub(crate) enum PlatformSocketToken {
    LinuxInode(NonZeroU64),
    MacOsSocketId(NonZeroU64),
}

#[allow(dead_code, reason = "socket token constructors are host-specific")]
impl PlatformSocketToken {
    pub(crate) fn linux_inode(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self::LinuxInode)
    }

    pub(crate) fn macos_socket_id(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self::MacOsSocketId)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code, reason = "some native states are host-specific")]
pub(crate) enum SocketState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    NewSynReceived,
    Bound,
    Unknown(u32),
}

impl SocketState {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Listen => "listen",
            Self::SynSent => "syn_sent",
            Self::SynReceived => "syn_received",
            Self::Established => "established",
            Self::FinWait1 => "fin_wait1",
            Self::FinWait2 => "fin_wait2",
            Self::CloseWait => "close_wait",
            Self::Closing => "closing",
            Self::LastAck => "last_ack",
            Self::TimeWait => "time_wait",
            Self::DeleteTcb => "delete_tcb",
            Self::NewSynReceived => "new_syn_received",
            Self::Bound => "bound",
            Self::Unknown(_) => "unknown",
        }
    }

    pub(crate) const fn order_key(self) -> (u8, u32) {
        match self {
            Self::Closed => (0, 0),
            Self::Listen => (1, 0),
            Self::SynSent => (2, 0),
            Self::SynReceived => (3, 0),
            Self::Established => (4, 0),
            Self::FinWait1 => (5, 0),
            Self::FinWait2 => (6, 0),
            Self::CloseWait => (7, 0),
            Self::Closing => (8, 0),
            Self::LastAck => (9, 0),
            Self::TimeWait => (10, 0),
            Self::DeleteTcb => (11, 0),
            Self::NewSynReceived => (12, 0),
            Self::Bound => (13, 0),
            Self::Unknown(code) => (14, code),
        }
    }
}

impl Ord for SocketState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order_key().cmp(&other.order_key())
    }
}

impl PartialOrd for SocketState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "TCP timer kinds are Linux-specific")]
pub(crate) enum TcpTimerKind {
    None,
    Retransmit,
    Other,
    TimeWait,
    ZeroWindowProbe,
    Unknown(u32),
}

#[allow(dead_code, reason = "native timer mapping is Linux-specific")]
impl TcpTimerKind {
    pub(crate) const fn from_linux_native(native_code: u32) -> Self {
        match native_code {
            0 => Self::None,
            1 => Self::Retransmit,
            2 => Self::Other,
            3 => Self::TimeWait,
            4 => Self::ZeroWindowProbe,
            code => Self::Unknown(code),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TcpTimerObservation {
    pub(crate) kind: TcpTimerKind,
    pub(crate) native_code: Option<u32>,
    pub(crate) raw_ticks: u64,
    pub(crate) estimated_remaining_milliseconds: Option<u64>,
}

#[allow(dead_code, reason = "native timer fields are Linux-specific")]
impl TcpTimerObservation {
    pub(crate) fn from_linux_native(
        native_code: u32,
        raw_ticks: u64,
        clock_ticks_per_second: Option<u64>,
    ) -> Self {
        let estimated_remaining_milliseconds = clock_ticks_per_second
            .filter(|ticks| *ticks != 0)
            .and_then(|ticks| {
                let numerator = u128::from(raw_ticks)
                    .checked_mul(1_000)?
                    .checked_add(u128::from(ticks) - 1)?;
                u64::try_from(numerator / u128::from(ticks)).ok()
            });
        let kind = TcpTimerKind::from_linux_native(native_code);
        Self {
            native_code: matches!(kind, TcpTimerKind::Unknown(_)).then_some(native_code),
            kind,
            raw_ticks,
            estimated_remaining_milliseconds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "not every evidence code is emitted on every host")]
pub(crate) enum EvidenceGapCode {
    OwnerPermissionDenied,
    OwnerAttributionIncomplete,
    OwnerDisappeared,
    ProcessIdentityUnavailable,
    ProcessMetadataUnavailable,
    NativeFieldUnavailable,
    ScopeExcluded,
    NoncriticalEvidenceTruncated,
    ObservationRaced,
}

impl EvidenceGapCode {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::OwnerPermissionDenied => "owner_permission_denied",
            Self::OwnerAttributionIncomplete => "owner_attribution_incomplete",
            Self::OwnerDisappeared => "owner_disappeared",
            Self::ProcessIdentityUnavailable => "process_identity_unavailable",
            Self::ProcessMetadataUnavailable => "process_metadata_unavailable",
            Self::NativeFieldUnavailable => "native_field_unavailable",
            Self::ScopeExcluded => "scope_excluded",
            Self::NoncriticalEvidenceTruncated => "noncritical_evidence_truncated",
            Self::ObservationRaced => "observation_raced",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum EvidenceImpact {
    SocketSet,
    Ownership,
    Metadata,
    #[allow(
        dead_code,
        reason = "scope gaps are emitted by target-specific adapters"
    )]
    Scope,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EvidenceGap {
    pub(crate) impact: EvidenceImpact,
    pub(crate) code: EvidenceGapCode,
    pub(crate) endpoint: Option<EndpointIdentity>,
    pub(crate) pid: Option<u32>,
    affected_pid_count: Option<NonZeroU64>,
    message: String,
}

impl Ord for EvidenceGap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.impact
            .cmp(&other.impact)
            .then_with(|| self.code.name().cmp(other.code.name()))
            .then_with(|| match (&self.endpoint, &other.endpoint) {
                (Some(left), Some(right)) => compare_endpoint_identity(left, right),
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
            .then_with(|| self.pid.cmp(&other.pid))
            .then_with(|| self.affected_pid_count.cmp(&other.affected_pid_count))
            .then_with(|| self.message.cmp(&other.message))
    }
}

impl PartialOrd for EvidenceGap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl EvidenceGap {
    pub(crate) fn new(
        impact: EvidenceImpact,
        code: EvidenceGapCode,
        endpoint: Option<EndpointIdentity>,
        pid: Option<u32>,
        message: &str,
    ) -> Self {
        Self {
            impact,
            code,
            endpoint,
            pid,
            affected_pid_count: None,
            message: truncate_utf8(message, EVIDENCE_MESSAGE_MAX_BYTES).to_owned(),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn aggregate_for_pids(
        impact: EvidenceImpact,
        code: EvidenceGapCode,
        endpoint: Option<EndpointIdentity>,
        affected_pid_count: NonZeroU64,
        message: &str,
    ) -> Self {
        Self {
            impact,
            code,
            endpoint,
            pid: None,
            affected_pid_count: Some(affected_pid_count),
            message: truncate_utf8(message, EVIDENCE_MESSAGE_MAX_BYTES).to_owned(),
        }
    }

    pub(crate) const fn affected_pid_count(&self) -> Option<u64> {
        match self.affected_pid_count {
            Some(count) => Some(count.get()),
            None => None,
        }
    }

    fn same_aggregate_observation(&self, other: &Self) -> bool {
        self.affected_pid_count.is_some()
            && other.affected_pid_count.is_some()
            && self.impact == other.impact
            && self.code == other.code
            && self.endpoint == other.endpoint
            && self.pid == other.pid
            && self.message == other.message
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnerCompleteness {
    Complete,
    Partial { reasons: Vec<EvidenceGapCode> },
    Raced,
}

impl OwnerCompleteness {
    pub(crate) fn partial(
        reasons: impl IntoIterator<Item = EvidenceGapCode>,
    ) -> Result<Self, ObservationError> {
        let reasons: BTreeSet<_> = reasons.into_iter().collect();
        if reasons.len() > OWNER_COMPLETENESS_REASONS_MAX {
            return Err(ObservationError::OwnerReasonLimitExceeded);
        }
        if reasons.is_empty() {
            return Ok(Self::Complete);
        }
        let mut reasons = reasons.into_iter().collect::<Vec<_>>();
        reasons.sort_unstable_by_key(|reason| reason.name());
        Ok(Self::Partial { reasons })
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

pub(crate) fn owner_reason_names(
    reasons: &[EvidenceGapCode],
) -> impl ExactSizeIterator<Item = &'static str> + '_ {
    reasons.iter().map(|reason| reason.name())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "unverified reasons depend on the native platform")]
pub(crate) enum UnverifiedOwnerReason {
    PermissionDenied,
    Disappeared,
    IdentityUnavailable,
    Raced,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum OwnerObservation {
    Verified(ProcessIdentity),
    UnverifiedPid {
        pid: u32,
        reason: UnverifiedOwnerReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketObservation {
    pub(crate) local_endpoint: EndpointIdentity,
    pub(crate) state: SocketState,
    pub(crate) timer: Option<TcpTimerObservation>,
    pub(crate) owners: Vec<OwnerObservation>,
    pub(crate) owner_completeness: OwnerCompleteness,
    pub(crate) socket_token: Option<PlatformSocketToken>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotCompleteness {
    Complete,
    Partial,
    Raced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code, reason = "limitations are host and capability specific")]
pub(crate) enum ScopeLimitation {
    OtherNetworkNamespacesExcluded,
    ProcessFirstSocketVisibilityLimited,
    WslNetworkStackExcluded,
    ProcessMetadataPermissionLimited,
    Ipv6ScopeUnavailable,
    ScopedIpv6ExactMatchingUnavailable,
    NativeFieldUnavailable,
    PollingIntervalBlindSpot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "the Current* names are frozen observation-scope contract values"
)]
#[allow(dead_code, reason = "scope kinds are host-specific")]
pub(crate) enum ObservationScopeKind {
    CurrentNetworkNamespace,
    CurrentHostProcessVisibleSockets,
    CurrentHostNetworkStack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservationScope {
    pub(crate) kind: ObservationScopeKind,
    pub(crate) identifier: Option<String>,
    pub(crate) limitations: Vec<ScopeLimitation>,
}

impl ObservationScope {
    pub(crate) fn new(
        kind: ObservationScopeKind,
        identifier: Option<&str>,
        limitations: impl IntoIterator<Item = ScopeLimitation>,
    ) -> Result<Self, ObservationError> {
        let limitations = bounded_scope_limitations(limitations)?;
        let identifier = match identifier {
            Some(value) if value.len() > SCOPE_IDENTIFIER_MAX_BYTES => {
                return Err(ObservationError::ScopeIdentifierOversized);
            }
            Some(value) => Some(value.to_owned()),
            None => None,
        };
        Ok(Self {
            kind,
            identifier,
            limitations,
        })
    }
}

fn bounded_scope_limitations<T: Ord>(
    limitations: impl IntoIterator<Item = T>,
) -> Result<Vec<T>, ObservationError> {
    let limitations: BTreeSet<_> = limitations.into_iter().collect();
    if limitations.len() > SCOPE_LIMITATIONS_MAX {
        return Err(ObservationError::ScopeLimitationLimitExceeded);
    }
    Ok(limitations.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataProfile {
    IdentityOnly,
    Display,
    LegacyList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataCompleteness {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataOmission {
    BudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessObservation {
    pub(crate) name: Option<Arc<str>>,
    pub(crate) executable_path: Option<Arc<Path>>,
    pub(crate) command_line: Option<Arc<str>>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<Arc<str>>,
    pub(crate) metadata_omission: Option<MetadataOmission>,
    pub(crate) metadata_completeness: MetadataCompleteness,
}

impl ProcessObservation {
    pub(crate) const fn identity_only() -> Self {
        Self {
            name: None,
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            metadata_omission: None,
            metadata_completeness: MetadataCompleteness::Complete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkSnapshot {
    pub(crate) capture_started_at: SystemTime,
    pub(crate) capture_completed_at: SystemTime,
    pub(crate) scope: ObservationScope,
    pub(crate) completeness: SnapshotCompleteness,
    pub(crate) owner_completeness: OwnerCompleteness,
    pub(crate) evidence_gaps: Vec<EvidenceGap>,
    pub(crate) omitted_evidence_gap_count: u64,
    pub(crate) sockets: Vec<SocketObservation>,
    pub(crate) processes: HashMap<ProcessIdentity, ProcessObservation>,
}

#[cfg(test)]
pub(crate) fn snapshot_from_test_rows(rows: Vec<PortEntry>) -> NetworkSnapshot {
    let platform = rows.first().map_or(Platform::Linux, |row| row.platform);
    let scope_kind = match platform {
        Platform::Linux => ObservationScopeKind::CurrentNetworkNamespace,
        Platform::Macos => ObservationScopeKind::CurrentHostProcessVisibleSockets,
        Platform::Windows => ObservationScopeKind::CurrentHostNetworkStack,
    };
    let mut processes = HashMap::new();
    let mut sockets = Vec::with_capacity(rows.len());
    let mut ownership_partial = false;
    for row in rows {
        let ipv6_scope = row
            .local_addr
            .is_ipv6()
            .then_some(row.ipv6_scope.unwrap_or(Ipv6Scope::Unavailable));
        let endpoint = EndpointIdentity::new(
            row.protocol,
            row.local_addr,
            u32::from(row.local_port),
            ipv6_scope,
        )
        .expect("test rows use valid endpoints");
        let owners = row.pid.map_or_else(Vec::new, |pid| {
            let identity = row.process_identity.unwrap_or(ProcessIdentity {
                pid,
                start_marker: ProcessStartMarker::linux(u64::from(pid) + 1)
                    .expect("test PID produces a nonzero marker"),
            });
            processes.entry(identity).or_insert(ProcessObservation {
                name: row.process_name,
                executable_path: row.executable_path,
                command_line: row.command_line,
                parent_pid: row.parent_pid,
                parent_process_name: row.parent_process_name,
                metadata_omission: None,
                metadata_completeness: if row.permission == PermissionStatus::Full {
                    MetadataCompleteness::Complete
                } else {
                    MetadataCompleteness::Partial
                },
            });
            vec![OwnerObservation::Verified(identity)]
        });
        ownership_partial |= owners.is_empty();
        sockets.push(SocketObservation {
            local_endpoint: endpoint,
            state: match row.state {
                LegacySocketState::Listen => SocketState::Listen,
                LegacySocketState::Bound => SocketState::Bound,
            },
            timer: None,
            owner_completeness: if owners.is_empty() {
                OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                    .expect("one reason fits")
            } else {
                OwnerCompleteness::Complete
            },
            owners,
            socket_token: None,
        });
    }
    NetworkSnapshot {
        capture_started_at: SystemTime::UNIX_EPOCH,
        capture_completed_at: SystemTime::UNIX_EPOCH,
        scope: ObservationScope::new(scope_kind, Some("test"), []).expect("test scope is valid"),
        completeness: if ownership_partial {
            SnapshotCompleteness::Partial
        } else {
            SnapshotCompleteness::Complete
        },
        owner_completeness: if ownership_partial {
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                .expect("one reason fits")
        } else {
            OwnerCompleteness::Complete
        },
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
        sockets,
        processes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PortEntryDescriptor {
    socket_index: u32,
    owner_index: u32,
    protected: bool,
}

impl NetworkSnapshot {
    pub(crate) fn socket_set_diff_safe(&self) -> bool {
        self.completeness != SnapshotCompleteness::Raced
            && self.omitted_evidence_gap_count == 0
            && !self
                .evidence_gaps
                .iter()
                .any(|gap| gap.impact == EvidenceImpact::SocketSet)
    }

    pub(crate) fn platform(&self) -> Platform {
        snapshot_platform(self)
    }

    pub(crate) fn port_entry_descriptors(
        &self,
        protected_names: &[String],
    ) -> Result<Vec<PortEntryDescriptor>, ObservationError> {
        self.port_entry_descriptors_matching(None, None, protected_names)
    }

    pub(crate) fn port_entry_descriptors_matching(
        &self,
        target_pid: Option<u32>,
        target_port: Option<u16>,
        protected_names: &[String],
    ) -> Result<Vec<PortEntryDescriptor>, ObservationError> {
        self.port_entry_descriptors_matching_with_limit(
            target_pid,
            target_port,
            protected_names,
            DERIVED_PORT_ENTRIES_MAX,
        )
    }

    fn port_entry_descriptors_matching_with_limit(
        &self,
        target_pid: Option<u32>,
        target_port: Option<u16>,
        protected_names: &[String],
        max_entries: usize,
    ) -> Result<Vec<PortEntryDescriptor>, ObservationError> {
        let platform = snapshot_platform(self);
        let mut protection_by_identity = HashMap::new();
        let mut descriptors = Vec::new();
        for (socket_index, socket) in self.sockets.iter().enumerate() {
            if target_port.is_some_and(|port| socket.local_endpoint.port.get() != port) {
                continue;
            }
            if !matches!(socket.state, SocketState::Listen | SocketState::Bound) {
                continue;
            }
            let emitted = if let Some(pid) = target_pid {
                socket
                    .owners
                    .iter()
                    .filter(|owner| owner_pid(owner) == pid)
                    .count()
            } else {
                socket.owners.len().max(1)
            };
            if emitted == 0 {
                continue;
            }
            if descriptors
                .len()
                .checked_add(emitted)
                .is_none_or(|count| count > max_entries)
            {
                return Err(ObservationError::LegacyProjectionLimitExceeded);
            }
            let socket_index = u32::try_from(socket_index)
                .map_err(|_| ObservationError::LegacyProjectionLimitExceeded)?;
            if socket.owners.is_empty() {
                descriptors.push(PortEntryDescriptor {
                    socket_index,
                    owner_index: u32::MAX,
                    protected: false,
                });
                continue;
            }
            for (owner_index, owner) in socket.owners.iter().enumerate() {
                if target_pid.is_some_and(|pid| owner_pid(owner) != pid) {
                    continue;
                }
                let protected = match owner {
                    OwnerObservation::Verified(identity) => {
                        *protection_by_identity.entry(*identity).or_insert_with(|| {
                            self.processes.get(identity).is_some_and(|process| {
                                crate::protection::is_protected_process(
                                    platform,
                                    process.name.as_deref(),
                                    process.executable_path.as_deref(),
                                    protected_names,
                                )
                            })
                        })
                    }
                    OwnerObservation::UnverifiedPid { .. } => false,
                };
                descriptors.push(PortEntryDescriptor {
                    socket_index,
                    owner_index: u32::try_from(owner_index)
                        .map_err(|_| ObservationError::LegacyProjectionLimitExceeded)?,
                    protected,
                });
            }
        }
        Ok(descriptors)
    }

    pub(crate) fn port_entry_view(&self, descriptor: &PortEntryDescriptor) -> PortEntryView<'_> {
        let socket = &self.sockets[descriptor.socket_index as usize];
        let owner = (descriptor.owner_index != u32::MAX)
            .then(|| &socket.owners[descriptor.owner_index as usize]);
        let (pid, process_identity, process) = match owner {
            Some(OwnerObservation::Verified(identity)) => (
                Some(identity.pid),
                Some(*identity),
                self.processes.get(identity),
            ),
            Some(OwnerObservation::UnverifiedPid { pid, .. }) => (Some(*pid), None, None),
            None => (None, None, None),
        };
        let state = match socket.state {
            SocketState::Listen => LegacySocketState::Listen,
            SocketState::Bound => LegacySocketState::Bound,
            _ => unreachable!("descriptors contain only open socket states"),
        };
        PortEntryView {
            protocol: socket.local_endpoint.protocol,
            local_addr: socket.local_endpoint.address,
            local_port: socket.local_endpoint.port.get(),
            state,
            pid,
            process_name: process.and_then(|process| process.name.as_deref()),
            executable_path: process.and_then(|process| process.executable_path.as_deref()),
            command_line: process.and_then(|process| process.command_line.as_deref()),
            parent_pid: process.and_then(|process| process.parent_pid),
            parent_process_name: process.and_then(|process| process.parent_process_name.as_deref()),
            protected: descriptor.protected,
            platform: snapshot_platform(self),
            permission: if process.is_some_and(|process| {
                process.metadata_completeness == MetadataCompleteness::Complete
            }) && socket.owner_completeness.is_complete()
            {
                PermissionStatus::Full
            } else {
                PermissionStatus::Partial
            },
            process_identity,
            ipv6_scope: socket.local_endpoint.ipv6_scope,
            label: None,
        }
    }
}

fn snapshot_platform(snapshot: &NetworkSnapshot) -> Platform {
    match snapshot.scope.kind {
        ObservationScopeKind::CurrentNetworkNamespace => Platform::Linux,
        ObservationScopeKind::CurrentHostProcessVisibleSockets => Platform::Macos,
        ObservationScopeKind::CurrentHostNetworkStack => Platform::Windows,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[allow(
    dead_code,
    reason = "some operational variants are native-source specific"
)]
pub(crate) enum ObservationError {
    #[error("socket table is unavailable")]
    SocketTableUnavailable,
    #[error("permission was denied while reading the socket table")]
    SocketTablePermissionDenied,
    #[error("native observation data is malformed")]
    NativeDataMalformed,
    #[error("native observation data exceeds its byte limit")]
    NativeDataOversized,
    #[error("socket observation limit exceeded")]
    SocketObservationLimitExceeded,
    #[error("process identity limit exceeded")]
    ProcessIdentityLimitExceeded,
    #[error("owner attribution limit exceeded")]
    OwnerAttributionLimitExceeded,
    #[error("legacy projection limit exceeded")]
    LegacyProjectionLimitExceeded,
    #[error("platform API failed: {0}")]
    PlatformApiFailed(String),
    #[error("wall clock is unavailable")]
    ClockUnavailable,
    #[error("capture completion precedes capture start")]
    InvalidWallClockInterval,
    #[error("socket set is partial")]
    PartialSocketSet,
    #[error("observation raced")]
    ObservationRaced,
    #[error("owner completeness reason limit exceeded")]
    OwnerReasonLimitExceeded,
    #[error("scope identifier exceeds its byte limit")]
    ScopeIdentifierOversized,
    #[error("scope limitation limit exceeded")]
    ScopeLimitationLimitExceeded,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeSocketObservation {
    pub(crate) endpoint: EndpointIdentity,
    pub(crate) state: SocketState,
    pub(crate) timer: Option<TcpTimerObservation>,
    pub(crate) token: Option<PlatformSocketToken>,
}

impl PartialEq for NativeSocketObservation {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint && self.state == other.state && self.token == other.token
    }
}

impl Eq for NativeSocketObservation {}

impl Ord for NativeSocketObservation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.endpoint
            .cmp(&other.endpoint)
            .then_with(|| self.state.cmp(&other.state))
            .then_with(|| self.token.cmp(&other.token))
    }
}

impl PartialOrd for NativeSocketObservation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeSocketRow {
    pub(crate) socket: NativeSocketObservation,
    pub(crate) owner_pids: Vec<u32>,
    pub(crate) owner_completeness: OwnerCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeObservationPass {
    pub(crate) rows: Vec<NativeSocketRow>,
    pub(crate) global_owner_completeness: OwnerCompleteness,
    pub(crate) evidence_gaps: Vec<EvidenceGap>,
    pub(crate) omitted_evidence_gap_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessRead {
    Verified {
        marker: ProcessStartMarker,
        observation: ProcessObservation,
    },
    Unverified(UnverifiedOwnerReason),
}

pub(crate) type ProcessReadBatch = Vec<(u32, ProcessRead)>;

/// Validated process reads in the same sorted, unique PID order requested from
/// the native adapter. The invariant makes binary search and deterministic
/// metadata materialization possible without a second index.
#[derive(Debug, Default)]
struct ProcessReadTable {
    entries: ProcessReadBatch,
}

impl ProcessReadTable {
    fn from_expected(
        expected_pids: &[u32],
        entries: ProcessReadBatch,
    ) -> Result<Self, ObservationError> {
        debug_assert!(
            expected_pids.windows(2).all(|pair| pair[0] < pair[1]),
            "candidate PIDs are canonicalized before native process reads"
        );
        if entries.len() != expected_pids.len()
            || !expected_pids
                .iter()
                .zip(&entries)
                .all(|(expected_pid, (actual_pid, _))| expected_pid == actual_pid)
        {
            return Err(ObservationError::NativeDataMalformed);
        }
        Ok(Self { entries })
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, pid: u32) -> Option<&ProcessRead> {
        self.entries
            .binary_search_by_key(&pid, |(entry_pid, _)| *entry_pid)
            .ok()
            .map(|index| &self.entries[index].1)
    }

    fn iter(&self) -> impl Iterator<Item = &(u32, ProcessRead)> {
        self.entries.iter()
    }

    fn values(&self) -> impl Iterator<Item = &ProcessRead> {
        self.entries.iter().map(|(_, read)| read)
    }

    fn into_entries(self) -> ProcessReadBatch {
        self.entries
    }
}

/// The internal seam implemented by native adapters.
pub(crate) trait ObservationSource {
    fn wall_clock(&mut self) -> Result<SystemTime, ObservationError>;
    fn collect_native_pass(
        &mut self,
        profile: MetadataProfile,
    ) -> Result<NativeObservationPass, ObservationError>;
    fn read_processes(
        &mut self,
        sorted_pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessReadBatch, ObservationError>;
}

// The sequential metadata-budget reader is the Linux/macOS collection path;
// Windows accounts for its budget inside its own snapshot reader. Tests on
// every platform drive the fake source through this accounting.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn process_read_metadata_bytes(read: &ProcessRead) -> usize {
    let ProcessRead::Verified { observation, .. } = read else {
        return 0;
    };
    [
        observation.name.as_ref().map_or(0, |value| value.len()),
        observation
            .executable_path
            .as_ref()
            .map_or(0, |value| value.as_os_str().as_encoded_bytes().len()),
        observation
            .parent_process_name
            .as_ref()
            .map_or(0, |value| value.len()),
        observation
            .command_line
            .as_ref()
            .map_or(0, |value| value.len()),
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add)
}

#[derive(Debug)]
struct CollectedPass {
    rows: Vec<NativeSocketRow>,
    global_owner_completeness: OwnerCompleteness,
    evidence_gaps: Vec<EvidenceGap>,
    processes_by_pid: ProcessReadTable,
    omitted_evidence_gap_count: u64,
}

#[derive(Debug, Default)]
struct Instability {
    socket_set: bool,
    ownership: bool,
    affected_sockets: BTreeSet<NativeSocketObservation>,
}

impl Instability {
    fn is_stable(&self) -> bool {
        !self.socket_set && !self.ownership
    }
}

pub(crate) fn collect_consistent<S: ObservationSource>(
    source: &mut S,
    scope: ObservationScope,
    profile: MetadataProfile,
) -> Result<NetworkSnapshot, ObservationError> {
    collect_consistent_with_limits(source, scope, profile, ObservationLimits::PRODUCTION)
}

fn collect_consistent_with_limits<S: ObservationSource>(
    source: &mut S,
    scope: ObservationScope,
    profile: MetadataProfile,
    limits: ObservationLimits,
) -> Result<NetworkSnapshot, ObservationError> {
    let mut identity_reads_total = 0usize;
    for attempt_index in 0..CONSISTENCY_ATTEMPTS_MAX {
        let mut identity_reads_attempt = 0usize;
        let started_at = source.wall_clock()?;
        let mut pass_a = collect_pass(
            source,
            MetadataProfile::IdentityOnly,
            limits,
            &mut identity_reads_attempt,
            &mut identity_reads_total,
        )?;
        let mut pass_b = collect_pass(
            source,
            profile,
            limits,
            &mut identity_reads_attempt,
            &mut identity_reads_total,
        )?;
        let completed_at = source.wall_clock()?;
        validate_wall_clock_interval(started_at, completed_at)?;
        let instability = compare_passes(&pass_a, &pass_b);
        merge_attempt_uncertainty(&mut pass_a, &mut pass_b)?;
        drop(pass_a);
        if instability.is_stable() {
            return build_snapshot(started_at, completed_at, scope, pass_b, None, limits);
        }
        if attempt_index + 1 == CONSISTENCY_ATTEMPTS_MAX {
            return build_snapshot(
                started_at,
                completed_at,
                scope,
                pass_b,
                Some(&instability),
                limits,
            );
        }
    }
    unreachable!("the positive consistency-attempt constant exhausts by return")
}

fn collect_pass<S: ObservationSource>(
    source: &mut S,
    profile: MetadataProfile,
    limits: ObservationLimits,
    identity_reads_attempt: &mut usize,
    identity_reads_total: &mut usize,
) -> Result<CollectedPass, ObservationError> {
    let NativeObservationPass {
        mut rows,
        global_owner_completeness,
        evidence_gaps,
        omitted_evidence_gap_count,
    } = source.collect_native_pass(profile)?;
    if rows.len() > limits.sockets {
        return Err(ObservationError::SocketObservationLimitExceeded);
    }
    validate_owner_completeness(&global_owner_completeness)?;
    for row in &rows {
        validate_owner_completeness(&row.owner_completeness)?;
    }
    if evidence_gaps.len() > EVIDENCE_GAPS_MAX {
        return Err(ObservationError::NativeDataMalformed);
    }
    for row in &mut rows {
        row.owner_pids.sort_unstable();
    }
    rows.sort_unstable_by(|left, right| {
        left.socket
            .cmp(&right.socket)
            .then_with(|| left.owner_pids.cmp(&right.owner_pids))
            .then_with(|| {
                compare_owner_completeness(&left.owner_completeness, &right.owner_completeness)
            })
            .then_with(|| left.socket.timer.cmp(&right.socket.timer))
    });
    let owner_edges = rows
        .iter()
        .try_fold(0usize, |count, row| count.checked_add(row.owner_pids.len()))
        .ok_or(ObservationError::OwnerAttributionLimitExceeded)?;
    if owner_edges > limits.owner_edges {
        return Err(ObservationError::OwnerAttributionLimitExceeded);
    }

    let pids: Vec<u32> = rows
        .iter()
        .flat_map(|row| row.owner_pids.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if pids.len() > limits.candidate_pids {
        return Err(ObservationError::ProcessIdentityLimitExceeded);
    }
    let next_attempt = identity_reads_attempt
        .checked_add(pids.len())
        .ok_or(ObservationError::ProcessIdentityLimitExceeded)?;
    if next_attempt > limits.identity_reads_per_attempt {
        return Err(ObservationError::ProcessIdentityLimitExceeded);
    }
    let next_total = identity_reads_total
        .checked_add(pids.len())
        .ok_or(ObservationError::ProcessIdentityLimitExceeded)?;
    if next_total > limits.identity_reads_total {
        return Err(ObservationError::ProcessIdentityLimitExceeded);
    }
    *identity_reads_attempt = next_attempt;
    *identity_reads_total = next_total;

    let process_reads = source.read_processes(&pids, profile, limits.optional_metadata_bytes)?;
    let processes_by_pid = ProcessReadTable::from_expected(&pids, process_reads)?;
    Ok(CollectedPass {
        rows,
        global_owner_completeness,
        evidence_gaps,
        processes_by_pid,
        omitted_evidence_gap_count,
    })
}

pub(crate) fn compare_owner_completeness(
    left: &OwnerCompleteness,
    right: &OwnerCompleteness,
) -> Ordering {
    owner_completeness_rank(left)
        .cmp(&owner_completeness_rank(right))
        .then_with(|| match (left, right) {
            (
                OwnerCompleteness::Partial { reasons: left },
                OwnerCompleteness::Partial { reasons: right },
            ) => owner_reason_names(left).cmp(owner_reason_names(right)),
            _ => Ordering::Equal,
        })
}

/// Snapshot and watch outputs share one owner-completeness ordering:
/// complete before partial before raced.
pub(crate) const fn owner_completeness_rank(completeness: &OwnerCompleteness) -> u8 {
    match completeness {
        OwnerCompleteness::Complete => 0,
        OwnerCompleteness::Partial { .. } => 1,
        OwnerCompleteness::Raced => 2,
    }
}

fn compare_passes(a: &CollectedPass, b: &CollectedPass) -> Instability {
    let mut affected_sockets = BTreeSet::new();
    let mut socket_set = false;
    let mut owner_edges_changed = false;
    let mut index_a = 0;
    let mut index_b = 0;
    while index_a < a.rows.len() || index_b < b.rows.len() {
        match (a.rows.get(index_a), b.rows.get(index_b)) {
            (Some(row_a), Some(row_b)) => match row_a.socket.cmp(&row_b.socket) {
                Ordering::Less => {
                    let end_a = socket_group_end(&a.rows, index_a);
                    socket_set = true;
                    owner_edges_changed |= group_has_owners(a, index_a, end_a);
                    affected_sockets.insert(row_a.socket.clone());
                    index_a = end_a;
                }
                Ordering::Greater => {
                    let end_b = socket_group_end(&b.rows, index_b);
                    socket_set = true;
                    owner_edges_changed |= group_has_owners(b, index_b, end_b);
                    affected_sockets.insert(row_b.socket.clone());
                    index_b = end_b;
                }
                Ordering::Equal => {
                    let end_a = socket_group_end(&a.rows, index_a);
                    let end_b = socket_group_end(&b.rows, index_b);
                    let counts_changed = end_a - index_a != end_b - index_b;
                    socket_set |= counts_changed;
                    let edges_changed =
                        group_owner_pids(a, index_a, end_a) != group_owner_pids(b, index_b, end_b);
                    owner_edges_changed |= edges_changed;
                    if counts_changed || edges_changed {
                        affected_sockets.insert(row_a.socket.clone());
                    }
                    index_a = end_a;
                    index_b = end_b;
                }
            },
            (Some(row), None) => {
                let end = socket_group_end(&a.rows, index_a);
                socket_set = true;
                owner_edges_changed |= group_has_owners(a, index_a, end);
                affected_sockets.insert(row.socket.clone());
                index_a = end;
            }
            (None, Some(row)) => {
                let end = socket_group_end(&b.rows, index_b);
                socket_set = true;
                owner_edges_changed |= group_has_owners(b, index_b, end);
                affected_sockets.insert(row.socket.clone());
                index_b = end;
            }
            (None, None) => break,
        }
    }
    let identity_changed = !identities_equal(a, b);
    if identity_changed {
        for row in &b.rows {
            if row
                .owner_pids
                .iter()
                .any(|pid| process_marker(a, *pid) != process_marker(b, *pid))
            {
                affected_sockets.insert(row.socket.clone());
            }
        }
    }
    Instability {
        socket_set,
        ownership: owner_edges_changed || identity_changed,
        affected_sockets,
    }
}

fn group_owner_pids(pass: &CollectedPass, start: usize, end: usize) -> Vec<u32> {
    let mut pids = pass.rows[start..end]
        .iter()
        .flat_map(|row| row.owner_pids.iter().copied())
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

fn group_has_owners(pass: &CollectedPass, start: usize, end: usize) -> bool {
    pass.rows[start..end]
        .iter()
        .any(|row| !row.owner_pids.is_empty())
}

fn identities_equal(a: &CollectedPass, b: &CollectedPass) -> bool {
    a.processes_by_pid.len() == b.processes_by_pid.len()
        && a.processes_by_pid
            .iter()
            .zip(b.processes_by_pid.iter())
            .all(|((pid_a, _), (pid_b, _))| {
                pid_a == pid_b && process_marker(a, *pid_a) == process_marker(b, *pid_b)
            })
}

fn process_marker(pass: &CollectedPass, pid: u32) -> Option<ProcessStartMarker> {
    match pass.processes_by_pid.get(pid) {
        Some(ProcessRead::Verified { marker, .. }) => Some(*marker),
        Some(ProcessRead::Unverified(_)) | None => None,
    }
}

fn validate_owner_completeness(completeness: &OwnerCompleteness) -> Result<(), ObservationError> {
    if let OwnerCompleteness::Partial { reasons } = completeness
        && reasons.len() > OWNER_COMPLETENESS_REASONS_MAX
    {
        return Err(ObservationError::OwnerReasonLimitExceeded);
    }
    Ok(())
}

fn merge_attempt_uncertainty(
    pass_a: &mut CollectedPass,
    pass_b: &mut CollectedPass,
) -> Result<(), ObservationError> {
    pass_b.global_owner_completeness = merge_owner_completeness(
        &pass_a.global_owner_completeness,
        &pass_b.global_owner_completeness,
    )?;
    let mut index_a = 0usize;
    let mut index_b = 0usize;
    while index_a < pass_a.rows.len() && index_b < pass_b.rows.len() {
        match pass_a.rows[index_a]
            .socket
            .cmp(&pass_b.rows[index_b].socket)
        {
            Ordering::Less => index_a = socket_group_end(&pass_a.rows, index_a),
            Ordering::Greater => index_b = socket_group_end(&pass_b.rows, index_b),
            Ordering::Equal => {
                let end_a = socket_group_end(&pass_a.rows, index_a);
                let end_b = socket_group_end(&pass_b.rows, index_b);
                let mut pass_a_completeness = OwnerCompleteness::Complete;
                for row in &pass_a.rows[index_a..end_a] {
                    pass_a_completeness =
                        merge_owner_completeness(&pass_a_completeness, &row.owner_completeness)?;
                }
                for row in &mut pass_b.rows[index_b..end_b] {
                    row.owner_completeness =
                        merge_owner_completeness(&pass_a_completeness, &row.owner_completeness)?;
                }
                index_a = end_a;
                index_b = end_b;
            }
        }
    }
    pass_b.omitted_evidence_gap_count = pass_b
        .omitted_evidence_gap_count
        .saturating_add(pass_a.omitted_evidence_gap_count);
    // Both passes observe the same host, so a gap that is identical in every
    // field normally shows up in both. Aggregate counts are observations, not
    // disjoint sets: retain the maximum as "at least this many observed"
    // rather than summing and inventing a union. Exact gaps still deduplicate
    // by their complete tuple. Do this before enforcing the merged budget so
    // only distinct evidence consumes retention slots.
    let mut merged: BTreeSet<EvidenceGap> = std::mem::take(&mut pass_a.evidence_gaps)
        .into_iter()
        .collect();
    for gap in pass_b.evidence_gaps.drain(..) {
        if gap.affected_pid_count.is_some()
            && let Some(existing) = merged
                .iter()
                .find(|existing| existing.same_aggregate_observation(&gap))
                .cloned()
        {
            if gap.affected_pid_count > existing.affected_pid_count {
                let removed = merged.remove(&existing);
                debug_assert!(removed, "the aggregate gap was found immediately above");
                merged.insert(gap);
            }
            continue;
        }
        if merged.contains(&gap) {
            continue;
        }
        if merged.len() >= EVIDENCE_GAPS_MAX {
            pass_b.omitted_evidence_gap_count = pass_b.omitted_evidence_gap_count.saturating_add(1);
            continue;
        }
        merged.insert(gap);
    }
    pass_b.evidence_gaps = merged.into_iter().collect();
    Ok(())
}

fn socket_group_end(rows: &[NativeSocketRow], start: usize) -> usize {
    let mut end = start + 1;
    while end < rows.len() && rows[end].socket == rows[start].socket {
        end += 1;
    }
    end
}

fn merge_owner_completeness(
    left: &OwnerCompleteness,
    right: &OwnerCompleteness,
) -> Result<OwnerCompleteness, ObservationError> {
    if matches!(left, OwnerCompleteness::Raced) || matches!(right, OwnerCompleteness::Raced) {
        return Ok(OwnerCompleteness::Raced);
    }
    let reasons = [left, right]
        .into_iter()
        .flat_map(|completeness| match completeness {
            OwnerCompleteness::Partial { reasons } => reasons.as_slice(),
            OwnerCompleteness::Complete | OwnerCompleteness::Raced => &[],
        });
    let reasons: BTreeSet<_> = reasons.copied().collect();
    if reasons.is_empty() {
        Ok(OwnerCompleteness::Complete)
    } else {
        OwnerCompleteness::partial(reasons)
    }
}

fn build_snapshot(
    started_at: SystemTime,
    completed_at: SystemTime,
    scope: ObservationScope,
    mut pass: CollectedPass,
    instability: Option<&Instability>,
    limits: ObservationLimits,
) -> Result<NetworkSnapshot, ObservationError> {
    let raced = instability.is_some();
    let mut evidence_gaps = Vec::new();
    let mut omitted_evidence_gap_count = pass.omitted_evidence_gap_count;
    for gap in pass.evidence_gaps.drain(..) {
        push_gap(
            &mut evidence_gaps,
            &mut omitted_evidence_gap_count,
            gap,
            limits.evidence_gaps,
        );
    }
    if let Some(instability) = instability {
        if instability.socket_set {
            push_gap(
                &mut evidence_gaps,
                &mut omitted_evidence_gap_count,
                EvidenceGap::new(
                    EvidenceImpact::SocketSet,
                    EvidenceGapCode::ObservationRaced,
                    None,
                    None,
                    "native socket multiplicity changed between consistency passes",
                ),
                limits.evidence_gaps,
            );
        }
        if instability.ownership {
            push_gap(
                &mut evidence_gaps,
                &mut omitted_evidence_gap_count,
                EvidenceGap::new(
                    EvidenceImpact::Ownership,
                    EvidenceGapCode::ObservationRaced,
                    None,
                    None,
                    "owner edges or process identities changed between consistency passes",
                ),
                limits.evidence_gaps,
            );
        }
    }

    for read in pass.processes_by_pid.values() {
        let ProcessRead::Unverified(reason) = read else {
            continue;
        };
        let completeness = if *reason == UnverifiedOwnerReason::Raced {
            OwnerCompleteness::Raced
        } else {
            OwnerCompleteness::partial([unverified_gap_code(*reason)])?
        };
        pass.global_owner_completeness =
            merge_owner_completeness(&pass.global_owner_completeness, &completeness)?;
    }

    let sockets = materialize_sockets(
        &pass,
        instability,
        &mut evidence_gaps,
        &mut omitted_evidence_gap_count,
        limits,
    )?;

    let processes = materialize_processes(
        &mut pass,
        &mut evidence_gaps,
        &mut omitted_evidence_gap_count,
        limits,
    );

    let owner_completeness = if instability.is_some_and(|change| change.ownership) {
        OwnerCompleteness::Raced
    } else {
        pass.global_owner_completeness.clone()
    };
    evidence_gaps.sort();
    // The merge above removes the cross-pass copies. This second pass covers
    // the remaining in-pass source: one process that exceeds the retention
    // budget on several optional fields raises the same PID-scoped gap once
    // per field. A repeated gap is not repeated evidence, and the public
    // ordering contract treats a gap as the tuple of all its fields, so the
    // serialized list must not contain the same tuple twice.
    evidence_gaps.dedup();
    let completeness = derive_snapshot_completeness(
        raced,
        &owner_completeness,
        &sockets,
        &evidence_gaps,
        omitted_evidence_gap_count,
    );
    Ok(NetworkSnapshot {
        capture_started_at: started_at,
        capture_completed_at: completed_at,
        scope,
        completeness,
        owner_completeness,
        evidence_gaps,
        omitted_evidence_gap_count,
        sockets,
        processes,
    })
}

fn materialize_processes(
    pass: &mut CollectedPass,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) -> HashMap<ProcessIdentity, ProcessObservation> {
    let mut processes = HashMap::new();
    let mut retained_bytes = 0usize;
    for (pid, read) in std::mem::take(&mut pass.processes_by_pid).into_entries() {
        if let ProcessRead::Verified {
            marker,
            mut observation,
        } = read
        {
            let identity = ProcessIdentity {
                pid,
                start_marker: marker,
            };
            if observation.metadata_omission == Some(MetadataOmission::BudgetExceeded) {
                push_gap(
                    evidence_gaps,
                    omitted_evidence_gap_count,
                    EvidenceGap::new(
                        EvidenceImpact::Metadata,
                        EvidenceGapCode::NoncriticalEvidenceTruncated,
                        None,
                        Some(pid),
                        "optional process metadata exceeded its native allocation budget",
                    ),
                    limits.evidence_gaps,
                );
            }
            apply_process_metadata_budget(
                identity,
                &mut observation,
                &mut retained_bytes,
                evidence_gaps,
                omitted_evidence_gap_count,
                limits,
            );
            if observation.metadata_completeness == MetadataCompleteness::Partial
                && observation.metadata_omission != Some(MetadataOmission::BudgetExceeded)
            {
                push_gap(
                    evidence_gaps,
                    omitted_evidence_gap_count,
                    EvidenceGap::new(
                        EvidenceImpact::Metadata,
                        EvidenceGapCode::ProcessMetadataUnavailable,
                        None,
                        Some(pid),
                        "optional process metadata was incomplete",
                    ),
                    limits.evidence_gaps,
                );
            }
            processes.insert(identity, observation);
        }
    }
    processes
}

mod legacy;

use legacy::owner_pid;
#[cfg(test)]
pub(crate) use legacy::project_legacy_pids;
#[cfg(test)]
use legacy::project_legacy_with_limit;
pub(crate) use legacy::{project_legacy, project_legacy_identities, project_legacy_target};

fn materialize_sockets(
    pass: &CollectedPass,
    instability: Option<&Instability>,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) -> Result<Vec<SocketObservation>, ObservationError> {
    let mut sockets = Vec::with_capacity(pass.rows.len());
    for row in &pass.rows {
        let native = &row.socket;
        let mut owners = Vec::with_capacity(row.owner_pids.len());
        let mut unverified_local = OwnerCompleteness::Complete;
        for pid in &row.owner_pids {
            let owner = match pass.processes_by_pid.get(*pid) {
                Some(ProcessRead::Verified { marker, .. }) => {
                    OwnerObservation::Verified(ProcessIdentity {
                        pid: *pid,
                        start_marker: *marker,
                    })
                }
                Some(ProcessRead::Unverified(reason)) => {
                    let gap_code = unverified_gap_code(*reason);
                    let completeness = if *reason == UnverifiedOwnerReason::Raced {
                        OwnerCompleteness::Raced
                    } else {
                        OwnerCompleteness::partial([gap_code])?
                    };
                    unverified_local = merge_owner_completeness(&unverified_local, &completeness)?;
                    push_gap(
                        evidence_gaps,
                        omitted_evidence_gap_count,
                        EvidenceGap::new(
                            EvidenceImpact::Ownership,
                            gap_code,
                            Some(native.endpoint.clone()),
                            Some(*pid),
                            "native owner PID could not be verified to a process start identity",
                        ),
                        limits.evidence_gaps,
                    );
                    OwnerObservation::UnverifiedPid {
                        pid: *pid,
                        reason: *reason,
                    }
                }
                None => return Err(ObservationError::NativeDataMalformed),
            };
            owners.push(owner);
        }
        owners.sort();
        let local_raced =
            instability.is_some_and(|change| change.affected_sockets.contains(native));
        sockets.push(SocketObservation {
            local_endpoint: native.endpoint.clone(),
            state: native.state,
            timer: native.timer,
            owners,
            owner_completeness: if local_raced {
                OwnerCompleteness::Raced
            } else {
                merge_owner_completeness(&row.owner_completeness, &unverified_local)?
            },
            socket_token: native.token,
        });
    }

    Ok(sockets)
}

const fn unverified_gap_code(reason: UnverifiedOwnerReason) -> EvidenceGapCode {
    match reason {
        UnverifiedOwnerReason::PermissionDenied => EvidenceGapCode::OwnerPermissionDenied,
        UnverifiedOwnerReason::Disappeared => EvidenceGapCode::OwnerDisappeared,
        UnverifiedOwnerReason::IdentityUnavailable => EvidenceGapCode::ProcessIdentityUnavailable,
        UnverifiedOwnerReason::Raced => EvidenceGapCode::ObservationRaced,
    }
}

#[cfg(test)]
fn apply_metadata_budget(
    processes: &mut HashMap<ProcessIdentity, ProcessObservation>,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) {
    let mut identities: Vec<_> = processes.keys().copied().collect();
    identities.sort();
    let mut retained_bytes = 0usize;
    for identity in identities {
        let process = processes
            .get_mut(&identity)
            .expect("identity came from the same process map");
        apply_process_metadata_budget(
            identity,
            process,
            &mut retained_bytes,
            evidence_gaps,
            omitted_evidence_gap_count,
            limits,
        );
    }
}

fn apply_process_metadata_budget(
    identity: ProcessIdentity,
    process: &mut ProcessObservation,
    retained_bytes: &mut usize,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) {
    macro_rules! retain_field {
        ($field:expr, $length:expr, $value_limit:expr) => {
            if let Some(value) = $field.as_ref() {
                let value_length = $length(value);
                let next_total = retained_bytes.checked_add(value_length);
                if value_length <= $value_limit
                    && next_total.is_some_and(|total| total <= limits.optional_metadata_bytes)
                {
                    *retained_bytes = next_total.expect("checked as present");
                } else {
                    *$field = None;
                    process.metadata_omission = Some(MetadataOmission::BudgetExceeded);
                    process.metadata_completeness = MetadataCompleteness::Partial;
                    push_gap(
                        evidence_gaps,
                        omitted_evidence_gap_count,
                        EvidenceGap::new(
                            EvidenceImpact::Metadata,
                            EvidenceGapCode::NoncriticalEvidenceTruncated,
                            None,
                            Some(identity.pid),
                            "optional process metadata exceeded its retention budget",
                        ),
                        limits.evidence_gaps,
                    );
                }
            }
        };
    }
    retain_field!(
        &mut process.name,
        |value: &Arc<str>| value.len(),
        PROCESS_NAME_MAX_BYTES
    );
    retain_field!(
        &mut process.executable_path,
        |value: &Arc<Path>| value.as_os_str().as_encoded_bytes().len(),
        EXECUTABLE_PATH_MAX_BYTES
    );
    retain_field!(
        &mut process.parent_process_name,
        |value: &Arc<str>| value.len(),
        PROCESS_NAME_MAX_BYTES
    );
    retain_field!(
        &mut process.command_line,
        |value: &Arc<str>| value.len(),
        PROCESS_COMMAND_LINE_MAX_BYTES
    );
}

fn push_gap(gaps: &mut Vec<EvidenceGap>, omitted: &mut u64, gap: EvidenceGap, limit: usize) {
    if gaps.len() < limit {
        gaps.push(gap);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn derive_snapshot_completeness(
    raced: bool,
    owner_completeness: &OwnerCompleteness,
    sockets: &[SocketObservation],
    gaps: &[EvidenceGap],
    omitted_gap_count: u64,
) -> SnapshotCompleteness {
    if raced {
        return SnapshotCompleteness::Raced;
    }
    if !gaps.is_empty()
        || omitted_gap_count > 0
        || !owner_completeness.is_complete()
        || sockets
            .iter()
            .any(|socket| !socket.owner_completeness.is_complete())
    {
        return SnapshotCompleteness::Partial;
    }
    SnapshotCompleteness::Complete
}

fn validate_wall_clock_interval(
    started_at: SystemTime,
    completed_at: SystemTime,
) -> Result<(), ObservationError> {
    completed_at
        .duration_since(started_at)
        .map(|_| ())
        .map_err(|_| ObservationError::InvalidWallClockInterval)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn lossy_utf8_len(bytes: &[u8]) -> Option<usize> {
    let mut len = 0usize;
    for chunk in bytes.utf8_chunks() {
        len = len.checked_add(chunk.valid().len())?;
        if !chunk.invalid().is_empty() {
            len = len.checked_add('�'.len_utf8())?;
        }
    }
    Some(len)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn push_utf8_lossy(output: &mut String, bytes: &[u8]) {
    for chunk in bytes.utf8_chunks() {
        output.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            output.push('�');
        }
    }
}

#[cfg(test)]
mod tests;
