//! The shared filter-and-sort engine behind both the CLI and TUI views.
//!
//! The collector decides which rows exist; this module only picks which of those
//! confirmed rows are visible for a given query and in what order.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};

use thiserror::Error;

use crate::labels::{SELECTOR_ADDRESS_MAX_BYTES, normalize_ip_address};
use crate::model::{BindScope, PortEntryView, Protocol, SortMode};
use crate::observation::Ipv6Scope;

/// Longest search text we'll take from the TUI or CLI.
///
/// Filtering runs on every TUI keypress, so this cap bounds per-key work.
pub(crate) const FILTER_TEXT_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) struct QueryOptions<'a> {
    pub(crate) port: Option<u16>,
    pub(crate) process: Option<&'a str>,
    pub(crate) filter_text: &'a str,
    pub(crate) sort_mode: SortMode,
    pub(crate) hide_system_processes: bool,
    pub(crate) capabilities: QueryCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryCapabilities {
    state: bool,
}

impl QueryCapabilities {
    pub(crate) const LIST: Self = Self { state: false };
    pub(crate) const WATCH: Self = Self { state: true };
}

#[derive(Debug)]
pub(crate) struct QueryIndexResult {
    pub(crate) indices: Vec<usize>,
    pub(crate) explicit_filter_active: bool,
    pub(crate) hidden_system_process_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum QueryError {
    #[error("filter text is {actual} bytes, maximum is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("invalid {field} filter value {value:?}: expected {expected}")]
    InvalidValue {
        field: &'static str,
        value: String,
        expected: &'static str,
    },
    #[error("filter field {field:?} is not supported by this command")]
    UnsupportedField { field: &'static str },
    #[error("unknown filter field {field:?}; did you mean {suggestion:?}?")]
    MisspelledField {
        field: String,
        suggestion: &'static str,
    },
    #[error("scope_id filter cannot be combined with an IPv4 address or family")]
    ScopeRequiresIpv6,
    #[error("these filter capabilities require full socket-state entries")]
    FullStateEntriesRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilterTerm {
    Plain(String),
    Pid(u32),
    Port(u16),
    Protocol(Protocol),
    Scope(BindScope),
    Protected(bool),
    Parent(String),
    Label(String),
    Address(IpAddr),
    ScopeId(NonZeroU32),
    Family(AddressFamily),
    State(StateFilter),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateFilter {
    Listen,
    Bound,
    Closed,
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
    Unknown,
}

/// Query a bounded row source without first materializing every borrowed view.
///
/// The callback is evaluated exactly once per source row. Matching facts are
/// reduced immediately to a compact sort candidate, so callers backed by a
/// structured snapshot do not need a second table-shaped allocation.
pub(crate) fn query_view_indices_by<'a>(
    entry_count: usize,
    mut view_at: impl FnMut(usize) -> PortEntryView<'a>,
    options: QueryOptions<'_>,
) -> Result<QueryIndexResult, QueryError> {
    let prepared = prepare_query(options)?;
    let filter_plan = QueryFilterPlan::new(&options, &prepared);
    let (indices, hidden_system_process_count) = match options.sort_mode {
        SortMode::Port => collect_sorted_indices(
            entry_count,
            &mut view_at,
            filter_plan,
            |_, _| (),
            |(), (), _| Ordering::Equal,
        ),
        SortMode::Pid => collect_sorted_indices(
            entry_count,
            &mut view_at,
            filter_plan,
            |entry, _| entry.pid,
            |left, right, _| (left.is_none(), left).cmp(&(right.is_none(), right)),
        ),
        SortMode::Protocol => collect_sorted_indices(
            entry_count,
            &mut view_at,
            filter_plan,
            |entry, _| entry.protocol,
            |left, right, _| left.cmp(right),
        ),
        SortMode::Process => collect_sorted_indices(
            entry_count,
            &mut view_at,
            filter_plan,
            |entry, normalization| entry.process_name.map(|name| normalization.key(name)),
            |left, right, normalization| compare_normalized_keys(*left, *right, normalization),
        ),
        SortMode::Parent => collect_sorted_indices(
            entry_count,
            &mut view_at,
            filter_plan,
            |entry, normalization| ParentSortKey {
                normalized_name: entry
                    .parent_process_name
                    .map(|name| normalization.key(name)),
                pid: entry.parent_pid,
            },
            |left, right, normalization| {
                compare_normalized_keys(left.normalized_name, right.normalized_name, normalization)
                    .then_with(|| {
                        (left.pid.is_none(), left.pid).cmp(&(right.pid.is_none(), right.pid))
                    })
            },
        ),
        SortMode::Scope => collect_sorted_indices(
            entry_count,
            &mut view_at,
            filter_plan,
            |entry, _| entry.scope(),
            |left, right, _| left.cmp(right),
        ),
    };

    Ok(QueryIndexResult {
        indices,
        explicit_filter_active: prepared.explicit_filter_active,
        hidden_system_process_count,
    })
}

/// Filter source indices that are already in the requested display order.
///
/// Removing rows from a total ordering preserves that ordering, so TUI search
/// edits can reuse a snapshot-scoped permutation instead of sorting again.
pub(crate) fn filter_preordered_view_indices_by<'a>(
    preordered_indices: &[usize],
    mut view_at: impl FnMut(usize) -> PortEntryView<'a>,
    options: QueryOptions<'_>,
) -> Result<QueryIndexResult, QueryError> {
    let prepared = prepare_query(options)?;
    let filter_plan = QueryFilterPlan::new(&options, &prepared);
    let mut indices = if filter_plan.all_rows_match_without_metadata() {
        Vec::with_capacity(preordered_indices.len())
    } else {
        Vec::new()
    };
    let mut hidden_system_process_count = 0;
    let mut metadata =
        MetadataMatchCache::new(metadata_match_cache_limit(preordered_indices.len()));
    for &source_index in preordered_indices {
        let entry = view_at(source_index);
        if filter_plan.hide_system_processes && entry.is_system_process() {
            hidden_system_process_count += 1;
            continue;
        }
        if entry_matches(entry, filter_plan, &mut metadata) {
            indices.push(source_index);
        }
    }

    Ok(QueryIndexResult {
        indices,
        explicit_filter_active: prepared.explicit_filter_active,
        hidden_system_process_count,
    })
}

struct PreparedQuery {
    terms: Vec<PreparedFilterTerm>,
    cheap_term_count: usize,
    process_needle: Option<String>,
    explicit_filter_active: bool,
}

#[derive(Clone, Copy)]
struct PlainNeedleShape {
    decimal: bool,
    address: bool,
    endpoint: bool,
}

impl PlainNeedleShape {
    fn new(needle: &str) -> Self {
        Self {
            decimal: needle.bytes().all(|byte| byte.is_ascii_digit()),
            address: needle
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'.' | b':')),
            endpoint: needle.contains(':'),
        }
    }
}

struct PreparedFilterTerm {
    term: FilterTerm,
    plain_shape: Option<PlainNeedleShape>,
}

impl PreparedFilterTerm {
    fn new(term: FilterTerm) -> Self {
        let plain_shape = match &term {
            FilterTerm::Plain(needle) => Some(PlainNeedleShape::new(needle)),
            _ => None,
        };
        Self { term, plain_shape }
    }

    const fn cost(&self) -> u8 {
        match self.term {
            FilterTerm::Pid(_)
            | FilterTerm::Port(_)
            | FilterTerm::Address(_)
            | FilterTerm::ScopeId(_) => 0,
            FilterTerm::Protocol(_)
            | FilterTerm::Scope(_)
            | FilterTerm::Protected(_)
            | FilterTerm::Family(_)
            | FilterTerm::State(_) => 1,
            FilterTerm::Label(_) | FilterTerm::Parent(_) => 2,
            FilterTerm::Plain(_) => 3,
        }
    }

    const fn is_cheap(&self) -> bool {
        self.cost() <= 1
    }
}

fn prepare_query(options: QueryOptions<'_>) -> Result<PreparedQuery, QueryError> {
    if options.capabilities != QueryCapabilities::LIST {
        return Err(QueryError::FullStateEntriesRequired);
    }
    if options.port == Some(0) {
        return Err(invalid_value("port", "0", "a TCP/UDP port from 1 to 65535"));
    }
    if options.process == Some("") {
        return Err(invalid_value(
            "process",
            "",
            "a nonempty process name substring",
        ));
    }
    let mut terms = parse_filter_text(options.filter_text, options.capabilities)?
        .into_iter()
        .map(PreparedFilterTerm::new)
        .collect::<Vec<_>>();
    terms.sort_unstable_by_key(PreparedFilterTerm::cost);
    let cheap_term_count = terms.partition_point(PreparedFilterTerm::is_cheap);
    let process_needle = options.process.map(normalized);
    let explicit_filter_active =
        options.port.is_some() || options.process.is_some() || !terms.is_empty();
    Ok(PreparedQuery {
        terms,
        cheap_term_count,
        process_needle,
        explicit_filter_active,
    })
}

#[derive(Clone, Copy)]
struct SortCandidate<K> {
    source_index: usize,
    // The generic keeps non-name sort candidates from carrying unused name or
    // parent fields across the full row bound.
    primary: K,
    tie_break: SortTieBreak,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SortTieBreak {
    local_port: u16,
    protocol: Protocol,
    local_addr: IpAddr,
    pid: Option<u32>,
}

impl From<PortEntryView<'_>> for SortTieBreak {
    fn from(entry: PortEntryView<'_>) -> Self {
        Self {
            local_port: entry.local_port,
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            pid: entry.pid,
        }
    }
}

#[derive(Clone, Copy)]
struct ParentSortKey {
    normalized_name: Option<usize>,
    pid: Option<u32>,
}

#[derive(Clone, Copy)]
struct QueryFilterPlan<'a> {
    port: Option<u16>,
    process_needle: Option<&'a str>,
    cheap_terms: &'a [PreparedFilterTerm],
    metadata_terms: &'a [PreparedFilterTerm],
    hide_system_processes: bool,
}

impl<'a> QueryFilterPlan<'a> {
    fn new(options: &QueryOptions<'_>, prepared: &'a PreparedQuery) -> Self {
        let (cheap_terms, metadata_terms) = prepared.terms.split_at(prepared.cheap_term_count);
        Self {
            port: options.port,
            process_needle: prepared.process_needle.as_deref(),
            cheap_terms,
            metadata_terms,
            hide_system_processes: options.hide_system_processes,
        }
    }

    fn all_rows_match_without_metadata(self) -> bool {
        !self.hide_system_processes
            && self.port.is_none()
            && self.process_needle.is_none()
            && self.cheap_terms.is_empty()
            && self.metadata_terms.is_empty()
    }
}

fn entry_matches<'value, 'needle>(
    entry: PortEntryView<'value>,
    filter_plan: QueryFilterPlan<'needle>,
    metadata: &mut MetadataMatchCache<'value, 'needle>,
) -> bool {
    if filter_plan
        .port
        .is_some_and(|port| entry.local_port != port)
    {
        return false;
    }
    if !filter_plan
        .cheap_terms
        .iter()
        .all(|term| term_matches(entry, term, metadata))
    {
        return false;
    }
    if filter_plan.process_needle.is_some_and(|needle| {
        entry
            .process_name
            .is_none_or(|name| !metadata.contains(name, needle))
    }) {
        return false;
    }
    filter_plan
        .metadata_terms
        .iter()
        .all(|term| term_matches(entry, term, metadata))
}

fn collect_sorted_indices<'value, 'needle, K>(
    entry_count: usize,
    view_at: &mut impl FnMut(usize) -> PortEntryView<'value>,
    filter_plan: QueryFilterPlan<'needle>,
    mut primary_key: impl FnMut(PortEntryView<'value>, &mut NormalizationCache<'value>) -> K,
    compare_primary: impl Fn(&K, &K, &NormalizationCache<'value>) -> Ordering,
) -> (Vec<usize>, usize) {
    let mut candidates = if filter_plan.all_rows_match_without_metadata() {
        Vec::with_capacity(entry_count)
    } else {
        Vec::new()
    };
    let mut hidden_system_process_count = 0;
    let mut metadata = MetadataMatchCache::new(metadata_match_cache_limit(entry_count));
    for index in 0..entry_count {
        let entry = view_at(index);
        if filter_plan.hide_system_processes && entry.is_system_process() {
            hidden_system_process_count += 1;
            continue;
        }
        if !entry_matches(entry, filter_plan, &mut metadata) {
            continue;
        }
        candidates.push(SortCandidate {
            source_index: index,
            primary: primary_key(entry, &mut metadata.normalization),
            tie_break: SortTieBreak::from(entry),
        });
    }

    candidates.sort_unstable_by(|left, right| {
        compare_primary(&left.primary, &right.primary, &metadata.normalization)
            .then_with(|| left.tie_break.cmp(&right.tie_break))
            // This is the stable source-order tie-break made explicit, allowing
            // the hot sort to avoid an auxiliary stable-sort allocation.
            .then_with(|| left.source_index.cmp(&right.source_index))
    });
    let indices = candidates
        .into_iter()
        .map(|candidate| candidate.source_index)
        .collect();
    (indices, hidden_system_process_count)
}

fn compare_normalized_keys(
    left: Option<usize>,
    right: Option<usize>,
    normalization: &NormalizationCache<'_>,
) -> Ordering {
    let left = left.map(|key| normalization.value(key));
    let right = right.map(|key| normalization.value(key));
    (left.is_none(), left).cmp(&(right.is_none(), right))
}

pub(crate) fn validate_filter_text(
    text: &str,
    capabilities: QueryCapabilities,
) -> Result<(), QueryError> {
    parse_filter_text(text, capabilities).map(|_| ())
}

pub(crate) fn parse_filter_text(
    text: &str,
    capabilities: QueryCapabilities,
) -> Result<Vec<FilterTerm>, QueryError> {
    if text.len() > FILTER_TEXT_MAX_BYTES {
        return Err(QueryError::TooLong {
            actual: text.len(),
            max: FILTER_TEXT_MAX_BYTES,
        });
    }

    let terms = text
        .split_whitespace()
        .map(|token| parse_token(token, capabilities))
        .collect::<Result<Vec<_>, _>>()?;
    validate_term_combinations(&terms)?;
    Ok(terms)
}

fn parse_token(token: &str, capabilities: QueryCapabilities) -> Result<FilterTerm, QueryError> {
    let Some((field, value)) = token.split_once(':') else {
        return Ok(FilterTerm::Plain(normalized(token)));
    };

    match field {
        "pid" => parse_pid(value),
        "port" => parse_port(value),
        "proto" => parse_protocol(value),
        "scope" => parse_scope(value),
        "protected" => parse_protected(value),
        "parent" => parse_parent(value),
        "label" => parse_nonempty_text("label", value).map(FilterTerm::Label),
        "address" => parse_address(value),
        "scope_id" => parse_scope_id(value),
        "family" => parse_family(value),
        "state" if capabilities.state => parse_state(value),
        "state" => Err(QueryError::UnsupportedField { field: "state" }),
        _ => match misspelled_field(field, capabilities) {
            Some(suggestion) => Err(QueryError::MisspelledField {
                field: field.to_owned(),
                suggestion,
            }),
            None => Ok(FilterTerm::Plain(normalized(token))),
        },
    }
}

/// The structured field an unknown `field:` prefix most likely meant.
///
/// Text with a colon is a plain search unless it looks like a field name a
/// couple of keystrokes away from a real one, so `localhost:3000`, `::1`, and
/// `node:18` still search, while `prot:tcp` reports the typo.
fn misspelled_field(field: &str, capabilities: QueryCapabilities) -> Option<&'static str> {
    const FIELDS: [&str; 11] = [
        "pid",
        "port",
        "proto",
        "scope",
        "protected",
        "parent",
        "label",
        "address",
        "scope_id",
        "family",
        "state",
    ];
    if field.len() < 3
        || !field
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return None;
    }
    FIELDS
        .into_iter()
        .filter(|candidate| capabilities.state || *candidate != "state")
        .map(|candidate| (edit_distance(field, candidate), candidate))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

/// Levenshtein distance between two short ASCII strings.
fn edit_distance(left: &str, right: &str) -> usize {
    let right = right.as_bytes();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    for (row, left_byte) in left.bytes().enumerate() {
        let mut current = vec![row + 1; right.len() + 1];
        for (column, right_byte) in right.iter().enumerate() {
            let substitution = previous[column] + usize::from(left_byte != *right_byte);
            current[column + 1] = substitution
                .min(previous[column + 1] + 1)
                .min(current[column] + 1);
        }
        previous = current;
    }
    previous[right.len()]
}

fn parse_pid(value: &str) -> Result<FilterTerm, QueryError> {
    value
        .parse::<u32>()
        .map(FilterTerm::Pid)
        .map_err(|_| invalid_value("pid", value, "a non-negative integer PID"))
}

fn parse_port(value: &str) -> Result<FilterTerm, QueryError> {
    value
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .map(|port| FilterTerm::Port(port.get()))
        .ok_or_else(|| invalid_value("port", value, "a TCP/UDP port from 1 to 65535"))
}

fn parse_protocol(value: &str) -> Result<FilterTerm, QueryError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "tcp" => Ok(FilterTerm::Protocol(Protocol::Tcp)),
        "udp" => Ok(FilterTerm::Protocol(Protocol::Udp)),
        _ => Err(invalid_value("proto", value, "tcp or udp")),
    }
}

fn parse_scope(value: &str) -> Result<FilterTerm, QueryError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "public" => Ok(FilterTerm::Scope(BindScope::Public)),
        "local" => Ok(FilterTerm::Scope(BindScope::Local)),
        "loopback" => Ok(FilterTerm::Scope(BindScope::Loopback)),
        _ => Err(invalid_value("scope", value, "public, local, or loopback")),
    }
}

fn parse_protected(value: &str) -> Result<FilterTerm, QueryError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "true" => Ok(FilterTerm::Protected(true)),
        "false" => Ok(FilterTerm::Protected(false)),
        _ => Err(invalid_value("protected", value, "true or false")),
    }
}

fn parse_parent(value: &str) -> Result<FilterTerm, QueryError> {
    if value.is_empty() {
        return Err(invalid_value(
            "parent",
            value,
            "a parent process name or PID",
        ));
    }
    Ok(FilterTerm::Parent(normalized(value)))
}

fn parse_nonempty_text(field: &'static str, value: &str) -> Result<String, QueryError> {
    if value.is_empty() {
        return Err(invalid_value(field, value, "a nonempty value"));
    }
    Ok(normalized(value))
}

fn parse_address(value: &str) -> Result<FilterTerm, QueryError> {
    if value.is_empty() || value.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err(invalid_value(
            "address",
            value,
            "a literal IP address of at most 64 bytes",
        ));
    }
    value
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map(FilterTerm::Address)
        .map_err(|_| invalid_value("address", value, "a literal IPv4 or IPv6 address"))
}

fn parse_scope_id(value: &str) -> Result<FilterTerm, QueryError> {
    value
        .parse::<u32>()
        .ok()
        .and_then(NonZeroU32::new)
        .map(FilterTerm::ScopeId)
        .ok_or_else(|| invalid_value("scope_id", value, "an integer from 1 to 4294967295"))
}

fn parse_family(value: &str) -> Result<FilterTerm, QueryError> {
    match value.to_ascii_lowercase().as_str() {
        "ipv4" => Ok(FilterTerm::Family(AddressFamily::Ipv4)),
        "ipv6" => Ok(FilterTerm::Family(AddressFamily::Ipv6)),
        _ => Err(invalid_value("family", value, "ipv4 or ipv6")),
    }
}

fn parse_state(value: &str) -> Result<FilterTerm, QueryError> {
    let state = match value {
        "listen" => StateFilter::Listen,
        "bound" => StateFilter::Bound,
        "closed" => StateFilter::Closed,
        "syn_sent" => StateFilter::SynSent,
        "syn_received" => StateFilter::SynReceived,
        "established" => StateFilter::Established,
        "fin_wait1" => StateFilter::FinWait1,
        "fin_wait2" => StateFilter::FinWait2,
        "close_wait" => StateFilter::CloseWait,
        "closing" => StateFilter::Closing,
        "last_ack" => StateFilter::LastAck,
        "time_wait" => StateFilter::TimeWait,
        "delete_tcb" => StateFilter::DeleteTcb,
        "new_syn_received" => StateFilter::NewSynReceived,
        "unknown" => StateFilter::Unknown,
        _ => {
            return Err(invalid_value(
                "state",
                value,
                "a lowercase socket state name",
            ));
        }
    };
    Ok(FilterTerm::State(state))
}

fn validate_term_combinations(terms: &[FilterTerm]) -> Result<(), QueryError> {
    let has_scope = terms
        .iter()
        .any(|term| matches!(term, FilterTerm::ScopeId(_)));
    if !has_scope {
        return Ok(());
    }
    if terms.iter().any(|term| {
        matches!(
            term,
            FilterTerm::Family(AddressFamily::Ipv4) | FilterTerm::Address(IpAddr::V4(_))
        )
    }) {
        return Err(QueryError::ScopeRequiresIpv6);
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value.to_lowercase()
}

fn invalid_value(field: &'static str, value: &str, expected: &'static str) -> QueryError {
    QueryError::InvalidValue {
        field,
        value: value.to_owned(),
        expected,
    }
}

fn term_matches<'value, 'needle>(
    entry: PortEntryView<'value>,
    term: &'needle PreparedFilterTerm,
    metadata: &mut MetadataMatchCache<'value, 'needle>,
) -> bool {
    match &term.term {
        FilterTerm::Plain(needle) => plain_matches(
            entry,
            needle,
            term.plain_shape
                .expect("plain terms carry their precomputed needle shape"),
            metadata,
        ),
        FilterTerm::Pid(pid) => entry.pid == Some(*pid),
        FilterTerm::Port(port) => entry.local_port == *port,
        FilterTerm::Protocol(protocol) => entry.protocol == *protocol,
        FilterTerm::Scope(scope) => entry.scope() == *scope,
        FilterTerm::Protected(protected) => entry.protected == *protected,
        FilterTerm::Parent(needle) => parent_matches(entry, needle, metadata),
        FilterTerm::Label(needle) => entry
            .label
            .is_some_and(|label| metadata.contains(label, needle)),
        FilterTerm::Address(address) => normalize_ip_address(entry.local_addr) == *address,
        FilterTerm::ScopeId(scope_id) => {
            entry.ipv6_scope == Some(Ipv6Scope::InterfaceIndex(*scope_id))
        }
        FilterTerm::Family(AddressFamily::Ipv4) => normalize_ip_address(entry.local_addr).is_ipv4(),
        FilterTerm::Family(AddressFamily::Ipv6) => normalize_ip_address(entry.local_addr).is_ipv6(),
        FilterTerm::State(_) => {
            unreachable!("full-state filters cannot be evaluated against legacy list rows")
        }
    }
}

fn plain_matches<'value, 'needle>(
    entry: PortEntryView<'value>,
    needle_lower: &'needle str,
    shape: PlainNeedleShape,
    metadata: &mut MetadataMatchCache<'value, 'needle>,
) -> bool {
    contains_ascii(entry.protocol.label(), needle_lower)
        || contains_ascii(entry.state.label(), needle_lower)
        || contains_ascii(entry.scope_label(), needle_lower)
        || (shape.decimal && display_matches(entry.local_port, needle_lower))
        || (shape.decimal
            && entry
                .pid
                .is_some_and(|pid| display_matches(pid, needle_lower)))
        || (shape.address && display_matches(entry.local_addr, needle_lower))
        || (shape.endpoint && socket_text_matches(&entry, needle_lower))
        || entry
            .label
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || entry
            .process_name
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || entry
            .executable_path
            .as_ref()
            .and_then(|path| path.to_str())
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || entry
            .command_line
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || parent_matches(entry, needle_lower, metadata)
}

fn socket_text_matches(entry: &PortEntryView<'_>, needle_lower: &str) -> bool {
    debug_assert!(needle_lower.contains(':'));

    let plain = format!("{}:{}", entry.local_addr, entry.local_port);
    if contains_ascii(&plain, needle_lower) {
        return true;
    }
    if contains_ascii(
        &format!("[{}]:{}", entry.local_addr, entry.local_port),
        needle_lower,
    ) {
        return true;
    }

    let (IpAddr::V6(address), Some(Ipv6Scope::InterfaceIndex(index))) =
        (entry.local_addr, entry.ipv6_scope)
    else {
        return false;
    };
    contains_ascii(
        &format!("[{address}%{index}]:{}", entry.local_port),
        needle_lower,
    )
}

fn parent_matches<'value, 'needle>(
    entry: PortEntryView<'value>,
    needle_lower: &'needle str,
    metadata: &mut MetadataMatchCache<'value, 'needle>,
) -> bool {
    entry
        .parent_pid
        .is_some_and(|pid| display_matches(pid, needle_lower))
        || entry
            .parent_process_name
            .is_some_and(|value| metadata.contains(value, needle_lower))
}

fn display_matches(value: impl fmt::Display, needle: &str) -> bool {
    contains_ascii(&value.to_string(), needle)
}

fn contains_ascii(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[derive(Default)]
struct NormalizationCache<'a> {
    // Snapshot metadata and endpoint labels already have aggregate source
    // bounds. This cache retains at most one lowercase copy per distinct
    // borrowed value and is shared by filtering and name sorting.
    by_pointer: HashMap<(usize, usize), usize>,
    by_value: HashMap<&'a str, usize>,
    values: Vec<String>,
}

// A plain term can inspect at most these borrowed metadata fields on one row:
// label, process name, executable path, command line, and parent process name.
// The relative cap matches the old single-predicate entry count. The absolute
// cap prevents a maximum-size snapshot and many needles from retaining tens of
// megabytes of match keys; misses beyond it remain correct but are recomputed.
const METADATA_MATCHES_PER_ROW_MAX: usize = 5;
const METADATA_MATCH_CACHE_MAX_ENTRIES: usize = 65_536;

fn metadata_match_cache_limit(entry_count: usize) -> usize {
    entry_count
        .saturating_mul(METADATA_MATCHES_PER_ROW_MAX)
        .min(METADATA_MATCH_CACHE_MAX_ENTRIES)
}

/// Substring results per (lowercased value, needle).
///
/// A process's command line can be a megabyte and shared by hundreds of
/// socket rows, so each pair is scanned once. Needles are keyed by address:
/// they stay borrowed for `'needle`, so no other needle can reuse an address
/// while the cache exists.
struct MetadataMatchCache<'value, 'needle> {
    normalization: NormalizationCache<'value>,
    matches: HashMap<(usize, usize, usize), bool>,
    matches_max: usize,
    needles: PhantomData<&'needle str>,
    #[cfg(test)]
    scan_count: usize,
}

impl<'value, 'needle> MetadataMatchCache<'value, 'needle> {
    fn new(matches_max: usize) -> Self {
        Self {
            normalization: NormalizationCache::default(),
            matches: HashMap::new(),
            matches_max,
            needles: PhantomData,
            #[cfg(test)]
            scan_count: 0,
        }
    }

    fn contains(&mut self, value: &'value str, needle: &'needle str) -> bool {
        let value_key = self.normalization.key(value);
        let key = (value_key, needle.as_ptr() as usize, needle.len());
        if let Some(result) = self.matches.get(&key) {
            return *result;
        }
        #[cfg(test)]
        {
            self.scan_count += 1;
        }
        let result = self.normalization.values[value_key].contains(needle);
        if self.matches.len() < self.matches_max {
            self.matches.insert(key, result);
        }
        result
    }
}

impl<'a> NormalizationCache<'a> {
    fn key(&mut self, value: &'a str) -> usize {
        let pointer = (value.as_ptr() as usize, value.len());
        if let Some(&key) = self.by_pointer.get(&pointer) {
            key
        } else if let Some(&key) = self.by_value.get(value) {
            self.by_pointer.insert(pointer, key);
            key
        } else {
            let key = self.values.len();
            self.values.push(value.to_lowercase());
            self.by_pointer.insert(pointer, key);
            self.by_value.insert(value, key);
            key
        }
    }

    fn value(&self, key: usize) -> &str {
        &self.values[key]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    use super::{
        FILTER_TEXT_MAX_BYTES, QueryCapabilities, QueryError, QueryOptions,
        filter_preordered_view_indices_by, query_view_indices_by,
    };
    use crate::labels::SELECTOR_ADDRESS_MAX_BYTES;
    use crate::model::{
        PermissionStatus, Platform, PortEntry, PortEntryView, Protocol, SocketState, SortMode,
    };
    use crate::observation::Ipv6Scope;

    fn query_view_indices(
        entries: &[PortEntryView<'_>],
        options: QueryOptions<'_>,
    ) -> Result<super::QueryIndexResult, QueryError> {
        query_view_indices_by(entries.len(), |index| entries[index], options)
    }

    fn entry(port: u16, name: &str) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(u32::from(port)),
            process_name: Some(name.into()),
            executable_path: Some(PathBuf::from(format!("/usr/bin/{name}")).into()),
            command_line: Some(format!("{name} --port {port}").into()),
            parent_pid: Some(10),
            parent_process_name: Some("agent".into()),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    fn query(filter_text: &str) -> QueryOptions<'_> {
        QueryOptions {
            port: None,
            process: None,
            filter_text,
            sort_mode: SortMode::Port,
            hide_system_processes: false,
            capabilities: QueryCapabilities::LIST,
        }
    }

    fn matching_ports(rows: &[PortEntry], filter_text: &str) -> Vec<u16> {
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        query_view_indices(&views, query(filter_text))
            .expect("query is valid")
            .indices
            .into_iter()
            .map(|index| rows[index].local_port)
            .collect()
    }

    #[test]
    fn plain_search_matches_user_visible_fields() {
        let mut node = entry(3000, "node");
        node.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        node.parent_process_name = Some("cursor-agent".into());
        let mut vite = entry(5173, "vite");
        vite.local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let rows = vec![node, vite];

        assert_eq!(matching_ports(&rows, "3000"), vec![3000]);
        assert_eq!(matching_ports(&rows, "127.0.0.1"), vec![3000]);
        assert_eq!(matching_ports(&rows, "127.0.0.1:3000"), vec![3000]);
        assert_eq!(matching_ports(&rows, "NODE"), vec![3000]);
        assert_eq!(matching_ports(&rows, "/usr/bin/vite"), vec![5173]);
        assert_eq!(matching_ports(&rows, "--port 3000"), vec![3000]);
        assert_eq!(matching_ports(&rows, "cursor"), vec![3000]);
        assert_eq!(matching_ports(&rows, "tcp"), vec![3000, 5173]);
    }

    #[test]
    fn process_filter_option_matches_case_insensitive_substring() {
        let mut hidden = entry(8080, "hidden");
        hidden.process_name = None;
        let rows = [entry(3000, "Node"), entry(5173, "vite"), hidden];
        let options = QueryOptions {
            process: Some("OD"),
            ..query("")
        };

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let result = query_view_indices(&views, options).expect("query is valid");
        let ports: Vec<u16> = result
            .indices
            .iter()
            .map(|&index| rows[index].local_port)
            .collect();

        assert_eq!(ports, vec![3000]);
        assert!(result.explicit_filter_active);
    }

    /// The CLI parser rejects an empty `--process` before this seam is reached,
    /// so this guards the other construction site: a programmatic caller must
    /// not be able to turn an empty needle into "every row with a readable
    /// name", which is what an unguarded substring match would produce.
    #[test]
    fn empty_process_option_is_refused_instead_of_matching_every_named_row() {
        let mut hidden = entry(8080, "hidden");
        hidden.process_name = None;
        let rows = [entry(3000, "node"), hidden];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();

        let refused = query_view_indices(
            &views,
            QueryOptions {
                process: Some(""),
                ..query("")
            },
        )
        .expect_err("an empty process selector must be refused");

        assert_eq!(
            refused,
            QueryError::InvalidValue {
                field: "process",
                value: String::new(),
                expected: "a nonempty process name substring",
            }
        );
    }

    #[test]
    fn structured_filters_match_exact_fields() {
        let mut protected = entry(5432, "postgres");
        protected.protected = true;
        protected.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

        let mut udp = entry(5353, "avahi-daemon");
        udp.protocol = Protocol::Udp;
        udp.state = SocketState::Bound;
        udp.pid = Some(902);
        udp.parent_pid = Some(1);
        udp.parent_process_name = Some("systemd".into());

        let rows = vec![entry(3000, "node"), protected, udp];

        assert_eq!(matching_ports(&rows, "pid:902"), vec![5353]);
        assert_eq!(matching_ports(&rows, "port:5432"), vec![5432]);
        assert_eq!(matching_ports(&rows, "proto:udp"), vec![5353]);
        assert_eq!(matching_ports(&rows, "scope:public"), vec![5432]);
        assert_eq!(matching_ports(&rows, "protected:true"), vec![5432]);
        assert_eq!(matching_ports(&rows, "parent:systemd"), vec![5353]);
    }

    #[test]
    fn endpoint_and_label_filters_match_normalized_fields() {
        let mut ipv4 = entry(3000, "node");
        ipv4.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut ipv6 = entry(5353, "mdns");
        ipv6.protocol = Protocol::Udp;
        ipv6.state = SocketState::Bound;
        ipv6.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        ipv6.ipv6_scope = Some(crate::observation::Ipv6Scope::interface_index(7).unwrap());
        let rows = [ipv4, ipv6];
        let mut views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        views[0].label = Some("Web Development");
        views[1].label = Some("mDNS");

        let matching = |filter| {
            query_view_indices(&views, query(filter))
                .unwrap()
                .indices
                .iter()
                .map(|&index| rows[index].local_port)
                .collect::<Vec<_>>()
        };
        assert_eq!(matching("label:development"), [3000]);
        assert_eq!(matching("web"), [3000]);
        assert_eq!(matching("address:::1"), [5353]);
        assert_eq!(matching("family:ipv4"), [3000]);
        assert_eq!(matching("family:ipv6 scope_id:7"), [5353]);
        assert_eq!(matching("[::1%7]:5353"), [5353]);
        assert_eq!(matching("[::1%8]:5353"), [] as [u16; 0]);
        assert_eq!(matching("scope_id:8"), [] as [u16; 0]);
    }

    #[test]
    fn alphabetic_ipv6_and_unicode_metadata_searches_remain_supported() {
        let mut ipv6 = entry(5353, "mdns");
        ipv6.local_addr = "dead::beef".parse().expect("test address is valid");
        let unicode = entry(3000, "Äther");
        let rows = [ipv6, unicode];

        assert_eq!(matching_ports(&rows, "dead"), [5353]);
        assert_eq!(matching_ports(&rows, "äth"), [3000]);
    }

    #[test]
    fn misspelled_fields_are_reported_but_colon_text_still_searches() {
        let error = super::parse_filter_text("prot:tcp", QueryCapabilities::LIST)
            .expect_err("a near-miss field name is a typo");
        assert_eq!(
            error,
            QueryError::MisspelledField {
                field: "prot".to_owned(),
                suggestion: "proto",
            }
        );
        assert!(matches!(
            super::parse_filter_text("lable:web", QueryCapabilities::LIST),
            Err(QueryError::MisspelledField {
                suggestion: "label",
                ..
            })
        ));
        // `state` is only suggested where it is supported.
        assert!(super::parse_filter_text("stat:listen", QueryCapabilities::LIST).is_ok());
        assert!(super::parse_filter_text("stat:listen", QueryCapabilities::WATCH).is_err());
        for plain in [
            "localhost:3000",
            "::1",
            "node:18",
            "127.0.0.1:5432",
            "http://x",
        ] {
            assert!(
                super::parse_filter_text(plain, QueryCapabilities::LIST).is_ok(),
                "{plain} must remain a plain search"
            );
        }
    }

    #[test]
    fn endpoint_search_preserves_every_ipv6_scope_rendering() {
        let mut unavailable = entry(5353, "unavailable");
        unavailable.local_addr = "fe80::1".parse().expect("test address is valid");
        unavailable.ipv6_scope = Some(Ipv6Scope::Unavailable);
        let mut missing = entry(5354, "missing");
        missing.local_addr = "fe80::2".parse().expect("test address is valid");
        let mut unscoped = entry(5355, "unscoped");
        unscoped.local_addr = "fe80::3".parse().expect("test address is valid");
        unscoped.ipv6_scope = Some(Ipv6Scope::Unscoped);
        let rows = [unavailable, missing, unscoped];

        assert_eq!(matching_ports(&rows, "[fe80::1]:5353"), [5353]);
        assert_eq!(matching_ports(&rows, "[fe80::2]:5354"), [5354]);
        assert_eq!(matching_ports(&rows, "[fe80::3]:5355"), [5355]);
        assert_eq!(matching_ports(&rows, "%unavailable"), [] as [u16; 0]);
    }

    #[test]
    fn family_filters_ignore_transport_protocol() {
        let mut tcp_v4 = entry(3000, "tcp-v4");
        tcp_v4.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut udp_v4 = entry(3001, "udp-v4");
        udp_v4.protocol = Protocol::Udp;
        udp_v4.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut tcp_v6 = entry(3002, "tcp-v6");
        tcp_v6.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut udp_v6 = entry(3003, "udp-v6");
        udp_v6.protocol = Protocol::Udp;
        udp_v6.local_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let rows = [tcp_v4, udp_v4, tcp_v6, udp_v6];

        assert_eq!(matching_ports(&rows, "family:ipv4"), [3000, 3001]);
        assert_eq!(matching_ports(&rows, "family:ipv6"), [3002, 3003]);
    }

    #[test]
    fn mapped_address_filters_normalize_and_scope_conflicts_fail() {
        let row = entry(3000, "node");
        assert_eq!(matching_ports(&[row], "address:::ffff:127.0.0.1"), [3000]);

        let mut mapped = entry(3000, "node");
        mapped.local_addr = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        mapped.ipv6_scope = Some(Ipv6Scope::Unavailable);
        assert_eq!(
            matching_ports(&[mapped.clone()], "address:127.0.0.1"),
            [3000]
        );
        assert_eq!(matching_ports(&[mapped.clone()], "family:ipv4"), [3000]);
        assert_eq!(matching_ports(&[mapped], "family:ipv6"), [] as [u16; 0]);

        let rows = [entry(3000, "node")];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        for filter in ["family:ipv4 scope_id:1", "address:127.0.0.1 scope_id:1"] {
            assert!(matches!(
                query_view_indices(&views, query(filter)),
                Err(QueryError::ScopeRequiresIpv6)
            ));
        }
    }

    #[test]
    fn watch_only_state_filter_is_reserved_from_list_queries() {
        assert_eq!(
            super::validate_filter_text("state:listen", QueryCapabilities::LIST),
            Err(QueryError::UnsupportedField { field: "state" })
        );
        assert!(super::validate_filter_text("state:listen", QueryCapabilities::WATCH).is_ok());
        assert!(super::validate_filter_text("state:established", QueryCapabilities::WATCH).is_ok());
        assert!(matches!(
            super::validate_filter_text("state:not-a-state", QueryCapabilities::WATCH),
            Err(QueryError::InvalidValue { field: "state", .. })
        ));
        assert!(super::validate_filter_text("future:value", QueryCapabilities::LIST).is_ok());

        let rows = [entry(3000, "node")];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let options = QueryOptions {
            capabilities: QueryCapabilities::WATCH,
            ..query("state:listen")
        };
        assert!(matches!(
            query_view_indices(&views, options),
            Err(QueryError::FullStateEntriesRequired)
        ));
    }

    #[test]
    fn structured_filters_reject_bad_values() {
        let rows = [entry(3000, "node")];

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let error = query_view_indices(&views, query("port:not-a-port")).expect_err("invalid port");
        assert!(matches!(
            error,
            QueryError::InvalidValue { field: "port", .. }
        ));

        assert!(matches!(
            query_view_indices(&views, query("port:0")),
            Err(QueryError::InvalidValue { field: "port", .. })
        ));

        let mut direct = query("");
        direct.port = Some(0);
        assert!(matches!(
            query_view_indices(&views, direct),
            Err(QueryError::InvalidValue { field: "port", .. })
        ));

        let error = query_view_indices(&views, query("protected:maybe")).expect_err("invalid bool");
        assert!(matches!(
            error,
            QueryError::InvalidValue {
                field: "protected",
                ..
            }
        ));
    }

    #[test]
    fn family_scope_and_address_filters_reject_malformed_values() {
        let cases = [
            ("family:ip", "family"),
            ("family:", "family"),
            ("scope:wan", "scope"),
            ("scope:", "scope"),
            ("scope_id:0", "scope_id"),
            ("scope_id:4294967296", "scope_id"),
            ("scope_id:not-a-number", "scope_id"),
            ("address:", "address"),
            ("address:localhost", "address"),
            ("address:127.0.0.999", "address"),
            ("address:gggg::1", "address"),
        ];

        for (filter, expected_field) in cases {
            assert!(matches!(
                super::validate_filter_text(filter, QueryCapabilities::LIST),
                Err(QueryError::InvalidValue { field, .. }) if field == expected_field
            ));
        }
    }

    #[test]
    fn filter_text_over_the_byte_cap_is_rejected() {
        // The TUI already caps input in `append_search_char`, so the only way to
        // hit this bound is via CLI `--filter`. The cap lives here, so
        // the test pins it here too; the CLI turns the error into exit 2.
        let rows = [entry(3000, "node")];
        let maximum = "a".repeat(FILTER_TEXT_MAX_BYTES);
        let too_long = "a".repeat(FILTER_TEXT_MAX_BYTES + 1);

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        assert!(query_view_indices(&views, query(&maximum)).is_ok());
        let error =
            query_view_indices(&views, query(&too_long)).expect_err("over-cap filter is rejected");

        assert_eq!(
            error,
            QueryError::TooLong {
                actual: FILTER_TEXT_MAX_BYTES + 1,
                max: FILTER_TEXT_MAX_BYTES,
            }
        );

        let address_at_cap = format!("address:{}", "1".repeat(SELECTOR_ADDRESS_MAX_BYTES));
        assert!(matches!(
            super::validate_filter_text(&address_at_cap, QueryCapabilities::LIST),
            Err(QueryError::InvalidValue {
                field: "address",
                expected: "a literal IPv4 or IPv6 address",
                ..
            })
        ));
        let address_above_cap = format!("address:{}", "1".repeat(SELECTOR_ADDRESS_MAX_BYTES + 1));
        assert!(matches!(
            super::validate_filter_text(&address_above_cap, QueryCapabilities::LIST),
            Err(QueryError::InvalidValue {
                field: "address",
                expected: "a literal IP address of at most 64 bytes",
                ..
            })
        ));
    }

    #[test]
    fn hide_system_processes_uses_conservative_classification() {
        let mut service = entry(53, "systemd-resolved");
        service.parent_pid = Some(1);
        let rows = [entry(3000, "node"), service];
        let options = QueryOptions {
            hide_system_processes: true,
            ..query("")
        };

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let result = query_view_indices(&views, options).expect("query is valid");

        assert_eq!(result.indices.len(), 1);
        assert_eq!(
            rows[result.indices[0]].process_name.as_deref(),
            Some("node")
        );
        assert!(!result.explicit_filter_active);
        assert_eq!(result.hidden_system_process_count, 1);
    }

    #[test]
    fn query_sort_mode_is_shared_with_model_sorting() {
        let mut public = entry(4000, "public");
        public.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut local = entry(2000, "local");
        local.local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mut loopback = entry(1000, "loopback");
        loopback.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let options = QueryOptions {
            sort_mode: SortMode::Scope,
            ..query("")
        };

        let rows = [loopback, local, public];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let result = query_view_indices(&views, options).expect("valid query");
        let ports: Vec<u16> = result
            .indices
            .iter()
            .map(|&index| rows[index].local_port)
            .collect();

        assert_eq!(ports, vec![4000, 2000, 1000]);
    }

    #[test]
    fn process_and_parent_sort_unicode_names() {
        let process_a: std::sync::Arc<str> = "Zulu".into();
        let process_b: std::sync::Arc<str> = "Äther".into();
        let parent_a: std::sync::Arc<str> = "Zulu Parent".into();
        let parent_b: std::sync::Arc<str> = "Äther Parent".into();
        let mut zulu = entry(3000, "placeholder");
        zulu.process_name = Some(std::sync::Arc::clone(&process_a));
        zulu.parent_process_name = Some(std::sync::Arc::clone(&parent_a));
        let mut aether = entry(4000, "placeholder");
        aether.process_name = Some(std::sync::Arc::clone(&process_b));
        aether.parent_process_name = Some(std::sync::Arc::clone(&parent_b));
        let rows = [zulu, aether];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();

        for sort_mode in [SortMode::Process, SortMode::Parent] {
            let result = query_view_indices(
                &views,
                QueryOptions {
                    sort_mode,
                    ..query("")
                },
            )
            .expect("sort succeeds");
            assert_eq!(result.indices, [0, 1]);
        }
    }

    #[test]
    fn every_sort_mode_preserves_primary_tie_break_and_duplicate_order() {
        let mut zulu = entry(4000, "Zulu");
        zulu.local_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        zulu.pid = Some(20);
        zulu.parent_pid = Some(2);
        zulu.parent_process_name = Some("Same".into());

        let mut missing = entry(3000, "missing");
        missing.protocol = Protocol::Udp;
        missing.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        missing.pid = None;
        missing.process_name = None;
        missing.parent_pid = None;
        missing.parent_process_name = None;

        let mut alpha = entry(3000, "alpha");
        alpha.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        alpha.pid = Some(10);
        alpha.parent_pid = Some(1);
        alpha.parent_process_name = Some("same".into());

        let mut alpha_loopback = entry(3000, "Alpha");
        alpha_loopback.pid = Some(10);
        alpha_loopback.parent_pid = Some(1);
        alpha_loopback.parent_process_name = None;

        let duplicate = alpha.clone();
        let rows = [zulu, missing, alpha, alpha_loopback, duplicate];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let cases = [
            (SortMode::Port, &[2, 4, 3, 1, 0][..]),
            (SortMode::Pid, &[2, 4, 3, 0, 1][..]),
            (SortMode::Protocol, &[2, 4, 3, 0, 1][..]),
            (SortMode::Process, &[2, 4, 3, 0, 1][..]),
            (SortMode::Parent, &[2, 4, 0, 3, 1][..]),
            (SortMode::Scope, &[2, 4, 1, 3, 0][..]),
        ];

        for (sort_mode, expected) in cases {
            let options = QueryOptions {
                sort_mode,
                ..query("")
            };
            let result =
                query_view_indices(&views, options).expect("indexed list sort options are valid");
            assert_eq!(
                result.indices, expected,
                "unexpected indexed {sort_mode:?} order"
            );
        }
    }

    #[test]
    fn multiple_metadata_needles_must_match_the_same_row() {
        let mut alpha = entry(3000, "alpha");
        alpha.parent_process_name = Some("runner".into());
        let mut beta = entry(4000, "beta");
        beta.parent_process_name = Some("runner".into());
        let rows = [alpha, beta];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let options = query("runner alpha");

        let result = query_view_indices(&views, options).expect("filter is valid");

        assert_eq!(result.indices, [0]);
    }

    #[test]
    fn filtering_a_preordered_permutation_preserves_source_indices_and_query_metadata() {
        let mut zulu = entry(4000, "zulu");
        zulu.parent_process_name = Some("runner".into());
        let mut alpha = entry(3000, "alpha");
        alpha.protocol = Protocol::Udp;
        let mut system = entry(5000, "systemd-resolved");
        system.parent_pid = Some(1);
        let mut beta = entry(2000, "beta");
        beta.parent_process_name = Some("runner".into());
        let rows = [zulu, alpha, system, beta];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();

        for sort_mode in [
            SortMode::Port,
            SortMode::Pid,
            SortMode::Protocol,
            SortMode::Process,
            SortMode::Parent,
            SortMode::Scope,
        ] {
            let sorted = query_view_indices(
                &views,
                QueryOptions {
                    sort_mode,
                    ..query("")
                },
            )
            .expect("unfiltered sort is valid");
            let options = QueryOptions {
                sort_mode,
                hide_system_processes: true,
                ..query("parent:runner")
            };
            let expected = query_view_indices(&views, options).expect("ordinary query is valid");
            let mut projections = 0;
            let actual = filter_preordered_view_indices_by(
                &sorted.indices,
                |source_index| {
                    projections += 1;
                    views[source_index]
                },
                options,
            )
            .expect("preordered query is valid");

            assert_eq!(actual.indices, expected.indices);
            let mut source_indices = actual.indices.clone();
            source_indices.sort_unstable();
            assert_eq!(source_indices, [0, 3]);
            assert_eq!(
                actual.explicit_filter_active,
                expected.explicit_filter_active
            );
            assert_eq!(
                actual.hidden_system_process_count,
                expected.hidden_system_process_count
            );
            assert_eq!(projections, rows.len());
        }
    }

    #[test]
    fn cheap_terms_reject_rows_before_metadata_scans() {
        let row = entry(3000, "worker");
        let options = query("worker proto:udp");
        let prepared = super::prepare_query(options).expect("query is valid");
        let plan = super::QueryFilterPlan::new(&options, &prepared);
        let mut metadata = super::MetadataMatchCache::new(super::metadata_match_cache_limit(1));

        assert!(!super::entry_matches(
            PortEntryView::from(&row),
            plan,
            &mut metadata
        ));
        assert_eq!(metadata.scan_count, 0);
    }

    #[test]
    fn metadata_match_cache_isolates_and_reuses_multiple_needles() {
        let mut metadata = super::MetadataMatchCache::new(2);

        for _ in 0..2 {
            assert!(metadata.contains("alpha", "alp"));
            assert!(!metadata.contains("alpha", "beta"));
        }

        assert_eq!(metadata.scan_count, 2);
        assert_eq!(metadata.matches.len(), 2);
    }

    #[test]
    fn metadata_match_cache_stops_growing_at_its_bound() {
        let mut metadata = super::MetadataMatchCache::new(1);

        assert!(metadata.contains("alpha", "alp"));
        assert!(metadata.contains("alpha", "alp"));
        assert!(!metadata.contains("alpha", "beta"));
        assert!(!metadata.contains("alpha", "beta"));

        assert_eq!(metadata.matches.len(), 1);
        assert_eq!(metadata.scan_count, 3);
    }

    #[test]
    fn metadata_match_cache_limit_has_relative_and_absolute_boundaries() {
        assert_eq!(super::metadata_match_cache_limit(0), 0);
        assert_eq!(super::metadata_match_cache_limit(1), 5);
        assert_eq!(
            super::metadata_match_cache_limit(usize::MAX),
            super::METADATA_MATCH_CACHE_MAX_ENTRIES
        );
    }

    #[test]
    fn sparse_name_sorts_keep_source_indices_aligned_with_compact_keys() {
        let mut alpha = entry(4000, "selected-alpha");
        alpha.parent_process_name = Some("alpha-parent".into());
        let mut zulu = entry(6000, "Selected-Zulu");
        zulu.parent_process_name = Some("Zulu Parent".into());
        let rows = [
            entry(3000, "ignored-a"),
            alpha,
            entry(5000, "ignored-b"),
            zulu,
        ];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();

        for mode in [SortMode::Process, SortMode::Parent] {
            let result = query_view_indices(
                &views,
                QueryOptions {
                    sort_mode: mode,
                    process: Some("selected"),
                    ..query("")
                },
            )
            .expect("filtered sort is valid");
            assert_eq!(result.indices, [1, 3]);
        }
    }

    #[test]
    fn indexed_query_projects_each_source_row_once() {
        let rows = [
            entry(3000, "Zulu"),
            entry(4000, "alpha"),
            entry(5000, "beta"),
        ];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let calls = std::array::from_fn::<_, 3, _>(|_| std::cell::Cell::new(0));

        let result = query_view_indices_by(
            views.len(),
            |index| {
                calls[index].set(calls[index].get() + 1);
                views[index]
            },
            QueryOptions {
                sort_mode: SortMode::Process,
                ..query("")
            },
        )
        .expect("list-mode query options are valid");

        assert_eq!(result.indices, [1, 2, 0]);
        assert!(calls.iter().all(|count| count.get() == 1));
    }

    #[test]
    fn separate_metadata_needles_never_share_match_results() {
        let rows = [entry(3000, "alpha")];
        let views = [PortEntryView::from(&rows[0]).with_label(Some("alpha"))];
        let options = query("alpha label:beta");

        let result = query_view_indices(&views, options).expect("metadata filter syntax is valid");

        assert_eq!(result.indices, [] as [usize; 0]);
    }
}
