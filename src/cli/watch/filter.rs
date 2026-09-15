//! Pure filtering for watch events.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::Config;
use crate::display::human_endpoint_text;
use crate::labels::normalize_ip_address;
use crate::model::BindScope;
use crate::observation::{
    EndpointIdentity, Ipv6Scope, MetadataCompleteness, NetworkSnapshot, OwnerCompleteness,
    OwnerObservation, ProcessIdentity, ProcessObservation, SocketObservation, SocketState,
};
use crate::protection::is_protected_process;
use crate::public_output::socket_state_name;
use crate::query::{AddressFamily, FilterTerm, StateFilter};
use crate::watch::{EventKind, WatchEvent};

use super::{WatchOptions, owner_pid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilterResult {
    NotApplied,
    Matched,
    Indeterminate,
}

impl FilterResult {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::Matched => "matched",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Truth {
    False,
    Unknown,
    True,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnerPidConstraint {
    Any,
    Exact(u32),
    Impossible,
}

#[derive(Debug, Default)]
pub(super) struct FilterCache {
    processes: HashMap<ProcessIdentity, NormalizedProcessMetadata>,
}

#[derive(Debug)]
struct NormalizedProcessMetadata {
    name: Option<String>,
    executable_path: Option<String>,
    parent_process_name: Option<String>,
}

impl FilterCache {
    fn metadata<'a>(
        &'a mut self,
        snapshot: &'a NetworkSnapshot,
        identity: ProcessIdentity,
    ) -> Option<(&'a NormalizedProcessMetadata, &'a ProcessObservation)> {
        let raw = snapshot.processes.get(&identity)?;
        let normalized =
            self.processes
                .entry(identity)
                .or_insert_with(|| NormalizedProcessMetadata {
                    name: raw.name.as_deref().map(str::to_lowercase),
                    executable_path: raw
                        .executable_path
                        .as_ref()
                        .and_then(|path| path.to_str())
                        .map(str::to_lowercase),
                    parent_process_name: raw.parent_process_name.as_deref().map(str::to_lowercase),
                });
        Some((normalized, raw))
    }
}

pub(super) fn evaluate_event(
    event: WatchEvent<'_>,
    options: &WatchOptions,
    config: &Config,
    previous_cache: Option<&mut FilterCache>,
    current_cache: Option<&mut FilterCache>,
) -> Option<FilterResult> {
    if !selectors_match(event.endpoint(), options) {
        return None;
    }
    if !options.filter_active {
        return Some(FilterResult::NotApplied);
    }
    let result = match event.kind {
        EventKind::Baseline | EventKind::Bind => evaluate_side(
            event
                .current_snapshot
                .expect("current event side has a snapshot"),
            event
                .current_socket
                .expect("current event side has a socket"),
            options,
            config,
            current_cache.expect("current event side has a filter cache"),
        ),
        EventKind::Release => evaluate_side(
            event
                .previous_snapshot
                .expect("release has a previous snapshot"),
            event
                .previous_socket
                .expect("release has a previous socket"),
            options,
            config,
            previous_cache.expect("previous event side has a filter cache"),
        ),
        EventKind::Replacement => {
            let previous = evaluate_side(
                event
                    .previous_snapshot
                    .expect("replacement has previous snapshot"),
                event
                    .previous_socket
                    .expect("replacement has previous socket"),
                options,
                config,
                previous_cache.expect("replacement previous side has a filter cache"),
            );
            let current = evaluate_side(
                event
                    .current_snapshot
                    .expect("replacement has current snapshot"),
                event
                    .current_socket
                    .expect("replacement has current socket"),
                options,
                config,
                current_cache.expect("replacement current side has a filter cache"),
            );
            match (previous, current) {
                (Truth::True, _) | (_, Truth::True) => Truth::True,
                (Truth::False, Truth::False) => Truth::False,
                _ => Truth::Unknown,
            }
        }
    };
    match result {
        Truth::False => None,
        Truth::True => Some(FilterResult::Matched),
        Truth::Unknown => Some(FilterResult::Indeterminate),
    }
}

fn selectors_match(endpoint: &EndpointIdentity, options: &WatchOptions) -> bool {
    options.protocols.includes(endpoint.protocol)
        && options
            .address
            .is_none_or(|address| normalize_ip_address(endpoint.address) == address)
        && options.port.is_none_or(|port| endpoint.port.get() == port)
        && options
            .scope_id
            .is_none_or(|scope_id| endpoint.ipv6_scope == Some(Ipv6Scope::InterfaceIndex(scope_id)))
}

pub(super) fn evaluate_side(
    snapshot: &NetworkSnapshot,
    socket: &SocketObservation,
    options: &WatchOptions,
    config: &Config,
    cache: &mut FilterCache,
) -> Truth {
    if options.terms.is_empty() {
        return Truth::True;
    }
    let label = config.labels.resolve(&socket.local_endpoint);
    if options.terms.iter().any(|term| {
        owner_independent(term)
            && evaluate_term(snapshot, socket, None, label, term, false, config, cache)
                == Truth::False
    }) {
        return Truth::False;
    }
    let common_plain_matches = options
        .terms
        .iter()
        .map(|term| match term {
            FilterTerm::Plain(needle) => common_plain_match(socket, label, needle),
            _ => false,
        })
        .collect::<Vec<_>>();
    let owner_terms_present = options.terms.iter().any(|term| !owner_independent(term));
    let owner_pid_constraint = owner_pid_constraint(&options.terms);
    let endpointless_ownership_unknown = owner_terms_present
        && (snapshot.evidence_gaps.iter().any(|gap| {
            gap.impact == crate::observation::EvidenceImpact::Ownership
                && gap.endpoint.is_none()
                && endpointless_ownership_gap_is_relevant(gap.pid, owner_pid_constraint)
        }) || (snapshot.omitted_evidence_gap_count != 0
            && !snapshot.owner_completeness.is_complete()
            && endpointless_ownership_gap_is_relevant(None, owner_pid_constraint)));
    if socket.owners.is_empty() {
        let result = evaluate_terms_for_owner(
            snapshot,
            socket,
            None,
            label,
            &options.terms,
            &common_plain_matches,
            config,
            cache,
        );
        return if result == Truth::False && endpointless_ownership_unknown {
            Truth::Unknown
        } else {
            result
        };
    }
    let mut unknown = false;
    for owner in &socket.owners {
        match evaluate_terms_for_owner(
            snapshot,
            socket,
            Some(owner),
            label,
            &options.terms,
            &common_plain_matches,
            config,
            cache,
        ) {
            Truth::True => return Truth::True,
            Truth::Unknown => unknown = true,
            Truth::False => {}
        }
    }
    if unknown || !socket.owner_completeness.is_complete() || endpointless_ownership_unknown {
        Truth::Unknown
    } else {
        Truth::False
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "event-side filtering keeps snapshot, socket, owner, parsed terms, policy, and cache explicit"
)]
fn evaluate_terms_for_owner(
    snapshot: &NetworkSnapshot,
    socket: &SocketObservation,
    owner: Option<&OwnerObservation>,
    label: Option<&str>,
    terms: &[FilterTerm],
    common_plain_matches: &[bool],
    config: &Config,
    cache: &mut FilterCache,
) -> Truth {
    let mut unknown = false;
    for (index, term) in terms.iter().enumerate() {
        if owner_independent(term) {
            continue;
        }
        match evaluate_term(
            snapshot,
            socket,
            owner,
            label,
            term,
            common_plain_matches[index],
            config,
            cache,
        ) {
            Truth::False => return Truth::False,
            Truth::Unknown => unknown = true,
            Truth::True => {}
        }
    }
    if unknown { Truth::Unknown } else { Truth::True }
}

#[expect(
    clippy::too_many_arguments,
    reason = "term evaluation keeps endpoint facts and one conceptual owner row explicit"
)]
fn evaluate_term(
    snapshot: &NetworkSnapshot,
    socket: &SocketObservation,
    owner: Option<&OwnerObservation>,
    label: Option<&str>,
    term: &FilterTerm,
    common_plain_match: bool,
    config: &Config,
    cache: &mut FilterCache,
) -> Truth {
    let endpoint = &socket.local_endpoint;
    match term {
        FilterTerm::Port(port) => truth(endpoint.port.get() == *port),
        FilterTerm::Protocol(protocol) => truth(endpoint.protocol == *protocol),
        FilterTerm::Scope(scope) => truth(bind_scope(endpoint.address) == *scope),
        FilterTerm::Label(needle) => {
            truth(label.is_some_and(|label| lowered_contains(label, needle)))
        }
        FilterTerm::Address(address) => truth(normalize_ip_address(endpoint.address) == *address),
        FilterTerm::ScopeId(scope_id) => {
            truth(endpoint.ipv6_scope == Some(Ipv6Scope::InterfaceIndex(*scope_id)))
        }
        FilterTerm::Family(AddressFamily::Ipv4) => {
            truth(normalize_ip_address(endpoint.address).is_ipv4())
        }
        FilterTerm::Family(AddressFamily::Ipv6) => {
            truth(normalize_ip_address(endpoint.address).is_ipv6())
        }
        FilterTerm::State(state) => truth(state_matches(socket.state, *state)),
        FilterTerm::Pid(pid) => owner_pid_truth(owner, *pid, &socket.owner_completeness),
        FilterTerm::Parent(needle) => metadata_truth(
            snapshot,
            owner,
            cache,
            |metadata, normalized| {
                metadata
                    .parent_pid
                    .is_some_and(|pid| pid.to_string().contains(needle))
                    || normalized
                        .parent_process_name
                        .as_deref()
                        .is_some_and(|name| name.contains(needle))
            },
            &socket.owner_completeness,
        ),
        FilterTerm::Protected(expected) => protection_truth(
            snapshot,
            owner,
            *expected,
            config,
            &socket.owner_completeness,
        ),
        FilterTerm::Plain(needle) => {
            if common_plain_match
                || owner.is_some_and(|owner| owner_pid(owner).to_string().contains(needle))
            {
                Truth::True
            } else {
                let metadata = metadata_truth(
                    snapshot,
                    owner,
                    cache,
                    |metadata, normalized| process_plain_match(owner, metadata, normalized, needle),
                    &socket.owner_completeness,
                );
                match protection_plain_truth(snapshot, owner, needle, config) {
                    Truth::True => Truth::True,
                    Truth::Unknown if metadata == Truth::False => Truth::Unknown,
                    Truth::False | Truth::Unknown => metadata,
                }
            }
        }
    }
}

fn protection_truth(
    snapshot: &NetworkSnapshot,
    owner: Option<&OwnerObservation>,
    expected: bool,
    config: &Config,
    owner_completeness: &OwnerCompleteness,
) -> Truth {
    let Some(owner) = owner else {
        return if owner_completeness.is_complete() {
            truth(!expected)
        } else {
            Truth::Unknown
        };
    };
    owner_protection(snapshot, owner, config)
        .map_or(Truth::Unknown, |protected| truth(protected == expected))
}

fn protection_plain_truth(
    snapshot: &NetworkSnapshot,
    owner: Option<&OwnerObservation>,
    needle: &str,
    config: &Config,
) -> Truth {
    let Some(protected) = owner.and_then(|owner| owner_protection(snapshot, owner, config)) else {
        return Truth::Unknown;
    };
    let classification = if protected {
        "protected"
    } else {
        "unprotected"
    };
    match needle {
        "protected" => truth(protected),
        "unprotected" => truth(!protected),
        _ => truth(classification.contains(needle)),
    }
}

fn owner_protection(
    snapshot: &NetworkSnapshot,
    owner: &OwnerObservation,
    config: &Config,
) -> Option<bool> {
    let OwnerObservation::Verified(identity) = owner else {
        return None;
    };
    let process = snapshot.processes.get(identity)?;
    let protected = is_protected_process(
        snapshot.platform(),
        process.name.as_deref(),
        process.executable_path.as_deref(),
        &config.protected_processes,
    );
    // An executable match proves protection even when the name is unreadable.
    // Without a match, a missing name still leaves the classification unknown.
    (protected || process.name.is_some()).then_some(protected)
}

fn metadata_truth(
    snapshot: &NetworkSnapshot,
    owner: Option<&OwnerObservation>,
    cache: &mut FilterCache,
    predicate: impl FnOnce(&ProcessObservation, &NormalizedProcessMetadata) -> bool,
    owner_completeness: &OwnerCompleteness,
) -> Truth {
    let Some(owner) = owner else {
        return if owner_completeness.is_complete() {
            Truth::False
        } else {
            Truth::Unknown
        };
    };
    let OwnerObservation::Verified(identity) = owner else {
        return Truth::Unknown;
    };
    let Some((normalized, metadata)) = cache.metadata(snapshot, *identity) else {
        return Truth::Unknown;
    };
    if predicate(metadata, normalized) {
        Truth::True
    } else if metadata.metadata_completeness == MetadataCompleteness::Partial {
        Truth::Unknown
    } else {
        Truth::False
    }
}

fn owner_pid_truth(
    owner: Option<&OwnerObservation>,
    pid: u32,
    completeness: &OwnerCompleteness,
) -> Truth {
    match owner {
        Some(OwnerObservation::Verified(identity)) => truth(identity.pid == pid),
        Some(OwnerObservation::UnverifiedPid { pid: owner_pid, .. }) => truth(*owner_pid == pid),
        None if completeness.is_complete() => Truth::False,
        None => Truth::Unknown,
    }
}

fn common_plain_match(socket: &SocketObservation, label: Option<&str>, needle: &str) -> bool {
    let endpoint = &socket.local_endpoint;
    endpoint.port.get().to_string().contains(needle)
        || endpoint.address.to_string().to_lowercase().contains(needle)
        || format!("{}:{}", endpoint.address, endpoint.port)
            .to_lowercase()
            .contains(needle)
        || format!("[{}]:{}", endpoint.address, endpoint.port)
            .to_lowercase()
            .contains(needle)
        || human_endpoint_text(endpoint.address, endpoint.port.get(), endpoint.ipv6_scope)
            .to_lowercase()
            .contains(needle)
        || endpoint
            .protocol
            .label()
            .to_ascii_lowercase()
            .contains(needle)
        || socket_state_name(socket.state).contains(needle)
        || bind_scope(endpoint.address).label().contains(needle)
        || label.is_some_and(|label| lowered_contains(label, needle))
}

fn process_plain_match(
    owner: Option<&OwnerObservation>,
    metadata: &ProcessObservation,
    normalized: &NormalizedProcessMetadata,
    needle: &str,
) -> bool {
    owner.is_some_and(|owner| owner_pid(owner).to_string().contains(needle))
        || normalized
            .name
            .as_deref()
            .is_some_and(|name| name.contains(needle))
        || normalized
            .executable_path
            .as_deref()
            .is_some_and(|path| path.contains(needle))
        || metadata
            .parent_pid
            .is_some_and(|pid| pid.to_string().contains(needle))
        || normalized
            .parent_process_name
            .as_deref()
            .is_some_and(|name| name.contains(needle))
}

const fn owner_independent(term: &FilterTerm) -> bool {
    matches!(
        term,
        FilterTerm::Port(_)
            | FilterTerm::Protocol(_)
            | FilterTerm::Scope(_)
            | FilterTerm::Label(_)
            | FilterTerm::Address(_)
            | FilterTerm::ScopeId(_)
            | FilterTerm::Family(_)
            | FilterTerm::State(_)
    )
}

pub(super) fn owner_pid_constraint(terms: &[FilterTerm]) -> OwnerPidConstraint {
    let mut required = None;
    for term in terms {
        let FilterTerm::Pid(pid) = term else {
            continue;
        };
        if required.is_some_and(|required| required != *pid) {
            return OwnerPidConstraint::Impossible;
        }
        required = Some(*pid);
    }
    required.map_or(OwnerPidConstraint::Any, OwnerPidConstraint::Exact)
}

const fn endpointless_ownership_gap_is_relevant(
    gap_pid: Option<u32>,
    constraint: OwnerPidConstraint,
) -> bool {
    match (gap_pid, constraint) {
        (_, OwnerPidConstraint::Impossible) => false,
        (None, _) | (Some(_), OwnerPidConstraint::Any) => true,
        (Some(gap_pid), OwnerPidConstraint::Exact(required)) => gap_pid == required,
    }
}

fn lowered_contains(value: &str, lowered_needle: &str) -> bool {
    value.to_lowercase().contains(lowered_needle)
}

const fn truth(value: bool) -> Truth {
    if value { Truth::True } else { Truth::False }
}

fn bind_scope(address: IpAddr) -> BindScope {
    if address.is_unspecified() {
        BindScope::Public
    } else if address.is_loopback() {
        BindScope::Loopback
    } else {
        BindScope::Local
    }
}

fn state_matches(state: SocketState, filter: StateFilter) -> bool {
    matches!(
        (state, filter),
        (SocketState::Listen, StateFilter::Listen)
            | (SocketState::Bound, StateFilter::Bound)
            | (SocketState::Closed, StateFilter::Closed)
            | (SocketState::SynSent, StateFilter::SynSent)
            | (SocketState::SynReceived, StateFilter::SynReceived)
            | (SocketState::Established, StateFilter::Established)
            | (SocketState::FinWait1, StateFilter::FinWait1)
            | (SocketState::FinWait2, StateFilter::FinWait2)
            | (SocketState::CloseWait, StateFilter::CloseWait)
            | (SocketState::Closing, StateFilter::Closing)
            | (SocketState::LastAck, StateFilter::LastAck)
            | (SocketState::TimeWait, StateFilter::TimeWait)
            | (SocketState::DeleteTcb, StateFilter::DeleteTcb)
            | (SocketState::NewSynReceived, StateFilter::NewSynReceived)
            | (SocketState::Unknown(_), StateFilter::Unknown)
    )
}
