//! The `watch` command's bounded polling, filtering, diffing, and event output.
//!
//! Monotonic time drives scheduling and cancellation while captured wall-clock
//! values remain output evidence; the two clocks stay separate.

use std::collections::HashMap;
use std::io::{self, ErrorKind, Write};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant, SystemTime};

use clap::Args;
use serde::Serialize;

use crate::collector::{self, CollectorError};
use crate::config::Config;
use crate::display::{human_endpoint_text, sanitize, sanitize_bounded};
use crate::labels::{SELECTOR_ADDRESS_MAX_BYTES, label_display_text, normalize_ip_address};
use crate::model::Protocol;
use crate::observation::{
    EndpointIdentity, EvidenceGap, MetadataProfile, NetworkSnapshot, ObservationError,
    OwnerObservation, SnapshotCompleteness, SocketObservation,
};
use crate::public_output::{
    EndpointDto, EvidenceDto, EvidenceGapDto, OwnerSetDto, PublicOutputError, SocketStateDto,
    SocketTokenDto, socket_state_name, unix_milliseconds,
};
use crate::query::{FilterTerm, QueryCapabilities};
use crate::watch::{
    Certainty, DiffError, EventKind, WATCH_EVENT_BATCH_MAX, WATCH_EVENT_EVIDENCE_MAX,
    WATCH_EVENT_GAPS_MAX, WATCH_FAILURES_MAX, WATCH_RECORD_MAX_BYTES, WatchEvent, baseline_events,
    compare_event_prefix, diff_snapshots,
};

use super::ExitReason;

/// Clap passes this default through the same duration parser as user input.
const WATCH_INTERVAL_DEFAULT_TOKEN: &str = "1s";
const WATCH_INTERVAL_MIN: Duration = Duration::from_millis(100);
const WATCH_INTERVAL_MAX: Duration = Duration::from_mins(1);
const WATCH_DURATION_MIN: Duration = Duration::from_millis(100);
const WATCH_DURATION_MAX: Duration = Duration::from_hours(168);
const CANCELLATION_POLL_MAX: Duration = Duration::from_millis(25);

#[derive(Debug, Args)]
pub(crate) struct WatchArgs {
    /// Include TCP; combine with --udp. Neither flag means both protocols.
    #[arg(long)]
    tcp: bool,
    /// Include UDP; combine with --tcp. Neither flag means both protocols.
    #[arg(long)]
    udp: bool,
    /// Match this literal normalized IP address across IPv6 scopes.
    #[arg(long, value_name = "ADDRESS")]
    address: Option<String>,
    /// Narrow an explicit IPv6 address to this nonzero interface index.
    #[arg(long, value_name = "ID")]
    scope_id: Option<u64>,
    /// Match this exact nonzero port.
    #[arg(long, value_parser = super::parse_port)]
    port: Option<u16>,
    /// Apply plain or structured full-state filters using AND semantics.
    ///
    /// Fields: `pid:`, `port:`, `proto:`, `scope:`, `protected:`, `parent:`,
    /// `label:`, `address:`, `scope_id:`, `family:`, and `state:`. State values:
    /// `listen`, `bound`, `closed`, `syn_sent`, `syn_received`, `established`,
    /// `fin_wait1`, `fin_wait2`, `close_wait`, `closing`, `last_ack`,
    /// `time_wait`, `delete_tcb`, `new_syn_received`, `unknown`.
    #[arg(long, value_name = "TEXT")]
    filter: Option<String>,
    /// Poll every 100ms..=60s (default 1s), for example 500ms or 2s.
    #[arg(long, value_name = "DURATION", default_value = WATCH_INTERVAL_DEFAULT_TOKEN)]
    interval: String,
    /// Stop after 100ms..=7d instead of waiting for Ctrl-C.
    #[arg(long, value_name = "DURATION")]
    duration: Option<String>,
    /// Emit `kickoutchi.watch_event/1` NDJSON to stdout; diagnostics use stderr.
    #[arg(long)]
    json: bool,
}

#[derive(Debug)]
struct WatchOptions {
    protocols: ProtocolSelection,
    address: Option<IpAddr>,
    scope_id: Option<NonZeroU32>,
    port: Option<u16>,
    terms: Vec<FilterTerm>,
    filter_active: bool,
    interval: Duration,
    duration: Option<Duration>,
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolSelection {
    Tcp,
    Udp,
    Both,
}

impl ProtocolSelection {
    const fn includes(self, protocol: Protocol) -> bool {
        matches!(
            (self, protocol),
            (Self::Tcp | Self::Both, Protocol::Tcp) | (Self::Udp | Self::Both, Protocol::Udp)
        )
    }
}

impl WatchOptions {
    fn parse(args: &WatchArgs) -> Result<Self, String> {
        let interval = parse_duration_token(&args.interval, WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX)
            .map_err(|error| format!("invalid --interval: {error}"))?;
        let duration = args
            .duration
            .as_deref()
            .map(|value| parse_duration_token(value, WATCH_DURATION_MIN, WATCH_DURATION_MAX))
            .transpose()
            .map_err(|error| format!("invalid --duration: {error}"))?;
        let address = args.address.as_deref().map(parse_address).transpose()?;
        let scope_id = args
            .scope_id
            .map(|value| {
                u32::try_from(value)
                    .ok()
                    .and_then(NonZeroU32::new)
                    .ok_or_else(|| "--scope-id must be in 1..=4294967295".to_owned())
            })
            .transpose()?;
        if scope_id.is_some() && !matches!(address, Some(IpAddr::V6(_))) {
            return Err("--scope-id requires one explicit IPv6 --address".to_owned());
        }
        let port = args.port;
        let terms = crate::query::parse_filter_text(
            args.filter.as_deref().unwrap_or_default(),
            QueryCapabilities::WATCH,
        )
        .map_err(|error| format!("invalid filter: {error}"))?;
        let protocol_selected = args.tcp || args.udp;
        Ok(Self {
            protocols: match (args.tcp, args.udp) {
                (true, false) => ProtocolSelection::Tcp,
                (false, true) => ProtocolSelection::Udp,
                (false, false) | (true, true) => ProtocolSelection::Both,
            },
            address,
            scope_id,
            port,
            filter_active: protocol_selected
                || args.address.is_some()
                || args.scope_id.is_some()
                || args.port.is_some()
                || !terms.is_empty(),
            terms,
            interval,
            duration,
            json: args.json,
        })
    }
}

pub(super) fn run_watch(
    args: &WatchArgs,
    config: &Config,
    _signal_guard: WatchSignalGuard,
) -> ExitReason {
    let options = match WatchOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {}", sanitize(&error));
            return ExitReason::InvalidArguments;
        }
    };
    let mut runtime = ProductionRuntime::new();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut output = stdout.lock();
    let mut diagnostics = stderr.lock();
    run_watch_loop(
        &options,
        config,
        &mut runtime,
        &mut output,
        &mut diagnostics,
    )
}

trait WatchRuntime {
    fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError>;
    fn monotonic_now(&mut self) -> Duration;
    fn wall_now(&mut self) -> Result<SystemTime, ObservationError>;
    fn sleep(&mut self, duration: Duration);
    fn cancelled(&self) -> bool;
}

struct ProductionRuntime {
    started: Instant,
}

impl ProductionRuntime {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl WatchRuntime for ProductionRuntime {
    fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError> {
        collector::collect_snapshot(MetadataProfile::Display)
    }

    fn monotonic_now(&mut self) -> Duration {
        self.started.elapsed()
    }

    fn wall_now(&mut self) -> Result<SystemTime, ObservationError> {
        Ok(SystemTime::now())
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn cancelled(&self) -> bool {
        WatchSignalGuard::cancelled()
    }
}

#[expect(
    clippy::too_many_lines,
    clippy::single_match_else,
    reason = "the polling state machine keeps each failure and flush transition in execution order"
)]
fn run_watch_loop(
    options: &WatchOptions,
    config: &Config,
    runtime: &mut impl WatchRuntime,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> ExitReason {
    let started = runtime.monotonic_now();
    let deadline = match options.duration {
        Some(duration) => match started.checked_add(duration) {
            Some(deadline) => Some(deadline),
            None => {
                write_diagnostic(diagnostics, "watch duration overflowed the monotonic clock");
                return ExitReason::Failure;
            }
        },
        None => None,
    };
    if runtime.cancelled() {
        return flush_exit(output, diagnostics, ExitReason::Success);
    }

    let mut previous = match collect_initial_snapshot(runtime, diagnostics) {
        Ok(snapshot) => snapshot,
        Err(reason) => return reason,
    };
    if should_stop(
        runtime.cancelled(),
        deadline.map(|end| (runtime.monotonic_now(), end)),
    ) {
        return flush_exit(output, diagnostics, ExitReason::Success);
    }
    let mut writer = EventWriter {
        output,
        diagnostics,
        sequence: 0,
    };
    let mut previous_index = SnapshotIndex::new(&previous);
    let initial_times = match observation_times(
        None,
        previous.capture_started_at,
        previous.capture_completed_at,
    ) {
        Ok(times) => times,
        Err(error) => return output_failure(writer.diagnostics, &error),
    };
    let baseline = match baseline_events(&previous) {
        Ok(events) => events,
        Err(error) => {
            write_diagnostic(writer.diagnostics, &error.to_string());
            return ExitReason::Failure;
        }
    };
    if let Some(reason) = write_ordered_events(
        baseline.map(baseline_event_result),
        options,
        config,
        runtime,
        deadline,
        &mut writer,
        EventBatch {
            previous: None,
            current: &mut previous_index,
            observation: initial_times,
        },
    ) {
        return reason;
    }
    if let Err(error) = writer.output.flush() {
        return io_failure(writer.diagnostics, &error);
    }

    let mut consecutive_failures = 0u8;
    let Some(mut next_poll) = next_poll_after(runtime.monotonic_now(), options.interval) else {
        write_diagnostic(writer.diagnostics, "watch poll deadline overflowed");
        return ExitReason::Failure;
    };
    loop {
        if wait_until(runtime, next_poll, deadline) {
            return flush_exit(writer.output, writer.diagnostics, ExitReason::Success);
        }
        let attempt_monotonic = runtime.monotonic_now();
        let attempt_started = match runtime.wall_now() {
            Ok(value) => value,
            Err(error) => return clock_failure(writer.diagnostics, &error),
        };
        if let Err(error) = validate_wall_interval(previous.capture_completed_at, attempt_started) {
            return clock_failure(writer.diagnostics, &error);
        }
        let collected = runtime.collect();
        let attempt_completed = match runtime.wall_now() {
            Ok(value) => value,
            Err(error) => return clock_failure(writer.diagnostics, &error),
        };
        if let Err(error) = validate_wall_interval(attempt_started, attempt_completed) {
            return clock_failure(writer.diagnostics, &error);
        }
        if let Some(error) = collector_clock_error(&collected) {
            return clock_failure(writer.diagnostics, error);
        }
        let gap_times = match observation_times(
            Some(previous.capture_completed_at),
            attempt_started,
            attempt_completed,
        ) {
            Ok(times) => times,
            Err(error) => return output_failure(writer.diagnostics, &error),
        };

        let current = match collected {
            Ok(snapshot) if snapshot.socket_set_diff_safe() => snapshot,
            result => {
                consecutive_failures = match consecutive_failures.checked_add(1) {
                    Some(value) => value,
                    None => {
                        write_diagnostic(writer.diagnostics, "watch failure count overflowed");
                        return ExitReason::Failure;
                    }
                };
                let gap = gap_from_result(&result, consecutive_failures);
                match write_gap(
                    writer.output,
                    options.json,
                    writer.sequence,
                    gap_times,
                    &gap,
                ) {
                    Ok(()) => {}
                    Err(OutputError::BrokenPipe) => return ExitReason::Success,
                    Err(error) => return output_failure(writer.diagnostics, &error),
                }
                if let Err(error) = writer.output.flush() {
                    return io_failure(writer.diagnostics, &error);
                }
                writer.sequence = match writer.sequence.checked_add(1) {
                    Some(value) => value,
                    None => {
                        write_diagnostic(writer.diagnostics, "watch sequence overflowed");
                        return ExitReason::Failure;
                    }
                };
                if consecutive_failures == WATCH_FAILURES_MAX {
                    return ExitReason::Failure;
                }
                if should_stop(
                    runtime.cancelled(),
                    deadline.map(|end| (runtime.monotonic_now(), end)),
                ) {
                    return flush_exit(writer.output, writer.diagnostics, ExitReason::Success);
                }
                next_poll = match next_poll_after(runtime.monotonic_now(), options.interval) {
                    Some(value) => value,
                    None => {
                        write_diagnostic(writer.diagnostics, "watch poll deadline overflowed");
                        return ExitReason::Failure;
                    }
                };
                continue;
            }
        };
        if let Err(error) =
            validate_wall_interval(previous.capture_completed_at, current.capture_started_at)
        {
            return clock_failure(writer.diagnostics, &error);
        }
        if should_stop(
            runtime.cancelled(),
            deadline.map(|end| (runtime.monotonic_now(), end)),
        ) {
            return flush_exit(writer.output, writer.diagnostics, ExitReason::Success);
        }

        consecutive_failures = 0;
        let mut current_index = SnapshotIndex::new(&current);
        let event_times = match observation_times(
            Some(previous.capture_completed_at),
            current.capture_started_at,
            current.capture_completed_at,
        ) {
            Ok(times) => times,
            Err(error) => return output_failure(writer.diagnostics, &error),
        };
        let diff = match diff_snapshots(&previous, &current) {
            Ok(diff) => diff,
            Err(error) => {
                write_diagnostic(writer.diagnostics, &error.to_string());
                return ExitReason::Failure;
            }
        };
        if let Some(reason) = write_ordered_events(
            diff,
            options,
            config,
            runtime,
            deadline,
            &mut writer,
            EventBatch {
                previous: Some(&mut previous_index),
                current: &mut current_index,
                observation: event_times,
            },
        ) {
            return reason;
        }
        if let Err(error) = writer.output.flush() {
            return io_failure(writer.diagnostics, &error);
        }
        previous = current;
        previous_index = current_index;
        next_poll = match next_poll_after(attempt_monotonic, options.interval) {
            Some(value) => value,
            None => {
                write_diagnostic(writer.diagnostics, "watch poll deadline overflowed");
                return ExitReason::Failure;
            }
        };
    }
}

fn collect_initial_snapshot(
    runtime: &mut impl WatchRuntime,
    diagnostics: &mut impl Write,
) -> Result<NetworkSnapshot, ExitReason> {
    let started = runtime
        .wall_now()
        .map_err(|error| clock_failure(diagnostics, &error))?;
    let collected = runtime.collect();
    let completed = runtime
        .wall_now()
        .map_err(|error| clock_failure(diagnostics, &error))?;
    validate_wall_interval(started, completed)
        .map_err(|error| clock_failure(diagnostics, &error))?;
    if let Some(error) = collector_clock_error(&collected) {
        return Err(clock_failure(diagnostics, error));
    }

    match collected {
        Ok(snapshot) if snapshot.socket_set_diff_safe() => Ok(snapshot),
        Ok(snapshot) => {
            let detail = if snapshot.completeness == SnapshotCompleteness::Raced {
                "initial observation raced"
            } else {
                "initial observation has a partial socket set"
            };
            write_diagnostic(diagnostics, detail);
            Err(ExitReason::Failure)
        }
        Err(error) => {
            write_diagnostic(
                diagnostics,
                &format!(
                    "initial collection failed: {}",
                    sanitize(&error.to_string())
                ),
            );
            Err(ExitReason::Failure)
        }
    }
}

fn observation_times(
    previous_completed_at: Option<SystemTime>,
    attempt_started_at: SystemTime,
    attempt_completed_at: SystemTime,
) -> Result<ObservationTimes, OutputError> {
    Ok(ObservationTimes {
        previous_completed_unix_ms: previous_completed_at.map(unix_milliseconds).transpose()?,
        attempt_started_unix_ms: unix_milliseconds(attempt_started_at)?,
        attempt_completed_unix_ms: unix_milliseconds(attempt_completed_at)?,
    })
}

fn next_poll_after(anchor: Duration, interval: Duration) -> Option<Duration> {
    anchor.checked_add(interval)
}

fn should_stop(cancelled: bool, deadline_check: Option<(Duration, Duration)>) -> bool {
    cancelled || deadline_check.is_some_and(|(now, deadline)| now >= deadline)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "adapts baseline events to the fallible diff-event stream"
)]
const fn baseline_event_result(event: WatchEvent<'_>) -> Result<WatchEvent<'_>, DiffError> {
    Ok(event)
}

struct SnapshotIndex {
    filter: FilterCache,
    gaps: GapIndex,
}

impl SnapshotIndex {
    fn new(snapshot: &NetworkSnapshot) -> Self {
        Self {
            filter: FilterCache::default(),
            gaps: GapIndex::new(snapshot),
        }
    }
}

struct EventBatch<'a> {
    previous: Option<&'a mut SnapshotIndex>,
    current: &'a mut SnapshotIndex,
    observation: ObservationTimes,
}

struct EventWriter<'a, Output, Diagnostics> {
    output: &'a mut Output,
    diagnostics: &'a mut Diagnostics,
    sequence: u64,
}

#[expect(
    clippy::too_many_lines,
    reason = "bounded rescanning and emission share one ordered group cursor"
)]
fn write_ordered_events<'a, I>(
    mut events: I,
    options: &WatchOptions,
    config: &Config,
    runtime: &mut impl WatchRuntime,
    deadline: Option<Duration>,
    writer: &mut EventWriter<'_, impl Write, impl Write>,
    batch: EventBatch<'_>,
) -> Option<ExitReason>
where
    I: Iterator<Item = Result<WatchEvent<'a>, DiffError>> + Clone,
{
    let EventWriter {
        output,
        diagnostics,
        sequence,
    } = writer;
    let (mut previous_cache, previous_gap_index) = match batch.previous {
        Some(index) => (Some(&mut index.filter), Some(&index.gaps)),
        None => (None, None),
    };
    let mut current_cache = Some(&mut batch.current.filter);
    let current_gap_index = Some(&batch.current.gaps);
    let observation = batch.observation;
    let mut batch_count = 0;
    let mut scanned_since_check = 0usize;
    loop {
        let group_start = events.clone();
        let first = match events.next()? {
            Ok(event) => event,
            Err(error) => {
                write_diagnostic(diagnostics, &error.to_string());
                return Some(flush_exit(output, diagnostics, ExitReason::Failure));
            }
        };
        let mut scan = group_start.clone();
        let mut group_end = group_start.clone();
        let mut rank_mask = 0u16;
        while let Some(result) = scan.next() {
            let event = match result {
                Ok(event) => event,
                Err(error) => {
                    write_diagnostic(diagnostics, &error.to_string());
                    return Some(flush_exit(output, diagnostics, ExitReason::Failure));
                }
            };
            if compare_event_prefix(first, event) != std::cmp::Ordering::Equal {
                break;
            }
            group_end = scan.clone();
            if let Some(filter_result) = evaluate_event(
                event,
                options,
                config,
                previous_cache.as_deref_mut(),
                current_cache.as_deref_mut(),
            ) {
                rank_mask |= 1 << event_order_rank(filter_result, event.certainty);
            }
            scanned_since_check += 1;
            if scanned_since_check == WATCH_EVENT_BATCH_MAX {
                if should_stop(
                    runtime.cancelled(),
                    deadline.map(|end| (runtime.monotonic_now(), end)),
                ) {
                    return Some(flush_exit(output, diagnostics, ExitReason::Success));
                }
                scanned_since_check = 0;
            }
        }
        events = group_end;

        // Re-scan once per rank to keep memory independent of group size.
        // There are at most EVENT_ORDER_RANK_COUNT passes; most groups contain
        // one event. Buffering a group could retain an entire poll's events.
        for rank in 0..EVENT_ORDER_RANK_COUNT {
            if rank_mask & (1 << rank) == 0 {
                continue;
            }
            let mut pass = group_start.clone();
            loop {
                if should_stop(
                    runtime.cancelled(),
                    deadline.map(|end| (runtime.monotonic_now(), end)),
                ) {
                    return Some(flush_exit(output, diagnostics, ExitReason::Success));
                }
                let Some(result) = pass.next() else { break };
                let event = match result {
                    Ok(event) => event,
                    Err(error) => {
                        write_diagnostic(diagnostics, &error.to_string());
                        return Some(flush_exit(output, diagnostics, ExitReason::Failure));
                    }
                };
                if compare_event_prefix(first, event) != std::cmp::Ordering::Equal {
                    break;
                }
                let Some(filter_result) = evaluate_event(
                    event,
                    options,
                    config,
                    previous_cache.as_deref_mut(),
                    current_cache.as_deref_mut(),
                ) else {
                    continue;
                };
                if event_order_rank(filter_result, event.certainty) != rank {
                    continue;
                }
                match write_endpoint_event(
                    output,
                    options.json,
                    *sequence,
                    observation,
                    event,
                    filter_result,
                    &options.terms,
                    config,
                    previous_gap_index,
                    current_gap_index,
                ) {
                    Ok(()) => {}
                    Err(OutputError::BrokenPipe) => return Some(ExitReason::Success),
                    Err(error) => return Some(output_failure(diagnostics, &error)),
                }
                let Some(next_sequence) = sequence.checked_add(1) else {
                    write_diagnostic(diagnostics, "watch sequence overflowed");
                    return Some(flush_exit(output, diagnostics, ExitReason::Failure));
                };
                *sequence = next_sequence;
                batch_count += 1;
                if batch_count == WATCH_EVENT_BATCH_MAX {
                    if let Err(error) = output.flush() {
                        return Some(io_failure(diagnostics, &error));
                    }
                    batch_count = 0;
                }
            }
        }
    }
}

/// Distinct values [`event_order_rank`] can return: three filter results times
/// four certainties. The emission loop iterates exactly this many passes, and
/// `rank_mask` must be wide enough to hold one bit per rank.
const EVENT_ORDER_RANK_COUNT: u32 = 12;
const _: () = assert!(EVENT_ORDER_RANK_COUNT <= u16::BITS);

const fn event_order_rank(filter_result: FilterResult, certainty: Certainty) -> u32 {
    let filter_rank = match filter_result {
        FilterResult::NotApplied => 0,
        FilterResult::Matched => 1,
        FilterResult::Indeterminate => 2,
    };
    let certainty_rank = match certainty {
        Certainty::Proven => 0,
        Certainty::Estimated => 1,
        Certainty::Heuristic => 2,
        Certainty::Unknown => 3,
    };
    filter_rank * 4 + certainty_rank
}

fn wait_until(
    runtime: &mut impl WatchRuntime,
    deadline: Duration,
    watch_deadline: Option<Duration>,
) -> bool {
    loop {
        if runtime.cancelled() {
            return true;
        }
        let now = runtime.monotonic_now();
        if watch_deadline.is_some_and(|end| now >= end) {
            return true;
        }
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_sub(now);
        let duration_remaining = watch_deadline.map_or(remaining, |end| end.saturating_sub(now));
        runtime.sleep(remaining.min(duration_remaining).min(CANCELLATION_POLL_MAX));
    }
}

fn parse_duration_token(
    value: &str,
    minimum: Duration,
    maximum: Duration,
) -> Result<Duration, String> {
    let suffix = ["ms", "s", "m", "h", "d"]
        .into_iter()
        .find(|suffix| value.ends_with(suffix))
        .ok_or_else(|| "expected one unsigned integer followed by ms, s, m, h, or d".to_owned())?;
    let number = &value[..value.len() - suffix.len()];
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected one unsigned integer followed by ms, s, m, h, or d".to_owned());
    }
    let magnitude = number
        .parse::<u64>()
        .map_err(|_| "duration value is too large".to_owned())?;
    let multiplier = match suffix {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => unreachable!("suffix is selected from a fixed set"),
    };
    let milliseconds = magnitude
        .checked_mul(multiplier)
        .ok_or_else(|| "duration value is too large".to_owned())?;
    let duration = Duration::from_millis(milliseconds);
    if duration < minimum || duration > maximum {
        return Err(format!(
            "value must be between {}ms and {}ms",
            minimum.as_millis(),
            maximum.as_millis()
        ));
    }
    Ok(duration)
}

fn parse_address(value: &str) -> Result<IpAddr, String> {
    if value.is_empty() || value.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err("--address must be a literal IP address of at most 64 bytes".to_owned());
    }
    value
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map_err(|_| "--address must be a literal IPv4 or IPv6 address without a zone".to_owned())
}

mod filter;

use filter::{FilterCache, FilterResult, OwnerPidConstraint, evaluate_event, owner_pid_constraint};
#[cfg(test)]
use filter::{Truth, evaluate_side};

#[derive(Debug, Clone, Copy, Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "field names are the versioned JSON contract"
)]
struct ObservationTimes {
    previous_completed_unix_ms: Option<u64>,
    attempt_started_unix_ms: u64,
    attempt_completed_unix_ms: u64,
}

#[derive(Serialize)]
struct WatchRecord<T> {
    schema: &'static str,
    version: u32,
    sequence: u64,
    event: &'static str,
    observation: ObservationTimes,
    data: T,
}

#[derive(Serialize)]
struct EndpointEventData<'a> {
    endpoint: EndpointDto<'a>,
    state: SocketStateDto,
    previous_owners: Option<OwnerSetDto<'a>>,
    current_owners: Option<OwnerSetDto<'a>>,
    previous_socket_token: Option<SocketTokenDto>,
    current_socket_token: Option<SocketTokenDto>,
    multiplicity: u32,
    label: Option<&'a str>,
    filter_result: &'static str,
    certainty: &'static str,
    evidence: Vec<EvidenceDto<'static>>,
    omitted_evidence_count: u64,
    evidence_gaps: Vec<EvidenceGapDto<'a>>,
    omitted_evidence_gap_count: u64,
}

#[derive(Serialize)]
struct GapData<'a> {
    error: PublicError,
    certainty: &'static str,
    consecutive_failures: u8,
    completeness: Option<&'static str>,
    evidence_gaps: Vec<EvidenceGapDto<'a>>,
    omitted_evidence_gap_count: u64,
}

#[derive(Serialize)]
struct PublicError {
    code: &'static str,
    message: String,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the streaming boundary keeps event, schema, filter, and bounded gap context explicit"
)]
fn write_endpoint_event(
    writer: &mut impl Write,
    json: bool,
    sequence: u64,
    observation: ObservationTimes,
    event: WatchEvent<'_>,
    filter_result: FilterResult,
    filter_terms: &[FilterTerm],
    config: &Config,
    previous_gap_index: Option<&GapIndex>,
    current_gap_index: Option<&GapIndex>,
) -> Result<(), OutputError> {
    if !json {
        return write_human_event(writer, observation, event, filter_result, config);
    }
    let socket = event.event_socket();
    let (evidence_gaps, omitted_gap_count) = if filter_result == FilterResult::Indeterminate {
        event_gap_dtos(event, filter_terms, previous_gap_index, current_gap_index)
    } else {
        (Vec::new(), 0)
    };
    let evidence = if event.kind == EventKind::Replacement {
        vec![EvidenceDto::literal(
            "process_identity_changed",
            "analysis",
            Certainty::Proven.name(),
            "verified process identity changed between observations",
        )]
    } else {
        Vec::new()
    };
    let (evidence, omitted_evidence_count) = retain_event_evidence(evidence);
    let data = EndpointEventData {
        endpoint: EndpointDto::from(&socket.local_endpoint),
        state: SocketStateDto::from(socket.state),
        previous_owners: event
            .previous_socket
            .map(|socket| OwnerSetDto::new(&socket.owners, &socket.owner_completeness))
            .transpose()?,
        current_owners: event
            .current_socket
            .map(|socket| OwnerSetDto::new(&socket.owners, &socket.owner_completeness))
            .transpose()?,
        previous_socket_token: event
            .previous_socket
            .and_then(|socket| socket.socket_token.map(SocketTokenDto::from)),
        current_socket_token: event
            .current_socket
            .and_then(|socket| socket.socket_token.map(SocketTokenDto::from)),
        multiplicity: event.multiplicity,
        label: config.labels.resolve(&socket.local_endpoint),
        filter_result: filter_result.name(),
        certainty: event.certainty.name(),
        evidence,
        omitted_evidence_count,
        evidence_gaps,
        omitted_evidence_gap_count: omitted_gap_count,
    };
    write_json_record(
        writer,
        &WatchRecord {
            schema: "kickoutchi.watch_event",
            version: 1,
            sequence,
            event: event.kind.name(),
            observation,
            data,
        },
    )
}

/// Enforce the bounded evidence contract on a watch event. Today
/// [`write_endpoint_event`] emits at most one evidence item, so the truncation
/// path is unreachable. The helper enforces the NDJSON contract that
/// `evidence` never exceeds `WATCH_EVENT_EVIDENCE_MAX` and `omitted_evidence_count`
/// accounts for the rest.
fn retain_event_evidence(evidence: Vec<EvidenceDto<'static>>) -> (Vec<EvidenceDto<'static>>, u64) {
    let omitted = evidence.len().saturating_sub(WATCH_EVENT_EVIDENCE_MAX);
    (
        evidence
            .into_iter()
            .take(WATCH_EVENT_EVIDENCE_MAX)
            .collect(),
        u64::try_from(omitted).unwrap_or(u64::MAX),
    )
}

#[derive(Debug, Default)]
struct GapBucket {
    indices: Vec<usize>,
    total: u64,
}

impl GapBucket {
    fn add(&mut self, index: usize) {
        self.total = self.total.saturating_add(1);
        if self.indices.len() < WATCH_EVENT_GAPS_MAX {
            self.indices.push(index);
        }
    }
}

#[derive(Debug, Default)]
struct GapIndex {
    global: GapBucket,
    endpointless_ownership: GapBucket,
    ownership_by_pid: HashMap<u32, GapBucket>,
    by_endpoint: HashMap<EndpointIdentity, GapBucket>,
    by_pid: HashMap<u32, GapBucket>,
    omitted_endpointless_ownership: u64,
}

impl GapIndex {
    fn new(snapshot: &NetworkSnapshot) -> Self {
        let mut index = Self {
            omitted_endpointless_ownership: if snapshot.owner_completeness.is_complete() {
                0
            } else {
                snapshot.omitted_evidence_gap_count
            },
            ..Self::default()
        };
        for (gap_index, gap) in snapshot.evidence_gaps.iter().enumerate() {
            match (&gap.endpoint, gap.pid) {
                (Some(endpoint), _) => index
                    .by_endpoint
                    .entry(endpoint.clone())
                    .or_default()
                    .add(gap_index),
                (None, Some(pid))
                    if gap.impact == crate::observation::EvidenceImpact::Ownership =>
                {
                    index.endpointless_ownership.add(gap_index);
                    index
                        .ownership_by_pid
                        .entry(pid)
                        .or_default()
                        .add(gap_index);
                }
                (None, Some(pid)) => index.by_pid.entry(pid).or_default().add(gap_index),
                (None, None) => index.global.add(gap_index),
            }
        }
        index
    }

    fn append<'a>(
        &self,
        snapshot: &'a NetworkSnapshot,
        socket: &SocketObservation,
        owner_pid_constraint: OwnerPidConstraint,
        gaps: &mut Vec<&'a EvidenceGap>,
        total: &mut u64,
    ) {
        append_gap_bucket(&self.global, snapshot, gaps, total);
        match owner_pid_constraint {
            OwnerPidConstraint::Any => {
                append_gap_bucket(&self.endpointless_ownership, snapshot, gaps, total);
            }
            OwnerPidConstraint::Exact(pid) => {
                if let Some(bucket) = self.ownership_by_pid.get(&pid) {
                    append_gap_bucket(bucket, snapshot, gaps, total);
                }
            }
            OwnerPidConstraint::Impossible => {}
        }
        if owner_pid_constraint != OwnerPidConstraint::Impossible {
            *total = total.saturating_add(self.omitted_endpointless_ownership);
        }
        if let Some(bucket) = self.by_endpoint.get(&socket.local_endpoint) {
            append_gap_bucket(bucket, snapshot, gaps, total);
        }
        for owner in &socket.owners {
            if let Some(bucket) = self.by_pid.get(&owner_pid(owner)) {
                append_gap_bucket(bucket, snapshot, gaps, total);
            }
        }
    }
}

fn append_gap_bucket<'a>(
    bucket: &GapBucket,
    snapshot: &'a NetworkSnapshot,
    gaps: &mut Vec<&'a EvidenceGap>,
    total: &mut u64,
) {
    *total = total.saturating_add(bucket.total);
    for index in &bucket.indices {
        retain_bounded_gap(gaps, &snapshot.evidence_gaps[*index]);
    }
}

fn retain_bounded_gap<'a>(gaps: &mut Vec<&'a EvidenceGap>, gap: &'a EvidenceGap) {
    let position = gaps.partition_point(|retained| *retained <= gap);
    if gaps.len() < WATCH_EVENT_GAPS_MAX {
        gaps.insert(position, gap);
    } else if position < WATCH_EVENT_GAPS_MAX {
        gaps.copy_within(position..WATCH_EVENT_GAPS_MAX - 1, position + 1);
        gaps[position] = gap;
    }
}

fn event_gap_dtos<'a>(
    event: WatchEvent<'a>,
    filter_terms: &[FilterTerm],
    previous_index: Option<&GapIndex>,
    current_index: Option<&GapIndex>,
) -> (Vec<EvidenceGapDto<'a>>, u64) {
    let mut gaps = Vec::with_capacity(WATCH_EVENT_GAPS_MAX);
    let mut total = 0u64;
    let owner_pid_constraint = owner_pid_constraint(filter_terms);
    if let (Some(snapshot), Some(socket), Some(index)) = (
        event.previous_snapshot,
        event.previous_socket,
        previous_index,
    ) {
        index.append(
            snapshot,
            socket,
            owner_pid_constraint,
            &mut gaps,
            &mut total,
        );
    }
    if let (Some(snapshot), Some(socket), Some(index)) =
        (event.current_snapshot, event.current_socket, current_index)
    {
        index.append(
            snapshot,
            socket,
            owner_pid_constraint,
            &mut gaps,
            &mut total,
        );
    }
    // `retain_bounded_gap` already caps `gaps` at WATCH_EVENT_GAPS_MAX.
    let retained = gaps.len();
    let omitted = total.saturating_sub(u64::try_from(retained).unwrap_or(u64::MAX));
    (
        gaps.into_iter().map(EvidenceGapDto::from).collect(),
        omitted,
    )
}

fn write_human_event(
    writer: &mut impl Write,
    observation: ObservationTimes,
    event: WatchEvent<'_>,
    filter_result: FilterResult,
    config: &Config,
) -> Result<(), OutputError> {
    let socket = event.event_socket();
    let endpoint = &socket.local_endpoint;
    let mut owners = socket
        .owners
        .iter()
        .take(crate::observation::SERIALIZED_OWNERS_MAX)
        .map(owner_pid)
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let omitted_owners = socket
        .owners
        .len()
        .saturating_sub(crate::observation::SERIALIZED_OWNERS_MAX);
    if omitted_owners != 0 {
        let _ = std::fmt::Write::write_fmt(&mut owners, format_args!(",+{omitted_owners}"));
    }
    let label = config.labels.resolve(endpoint).map(label_display_text);
    let endpoint_text =
        human_endpoint_text(endpoint.address, endpoint.port.get(), endpoint.ipv6_scope);
    writeln!(
        writer,
        "{} {} {} {} owners={}{} filter={} certainty={} observed={}..{} previous_completed={}",
        event.kind.name().to_ascii_uppercase(),
        endpoint.protocol.label(),
        endpoint_text,
        socket_state_name(socket.state),
        if owners.is_empty() { "-" } else { &owners },
        label
            .as_deref()
            .map_or(String::new(), |label| format!(" label={label}")),
        filter_result.name(),
        event.certainty.name(),
        observation.attempt_started_unix_ms,
        observation.attempt_completed_unix_ms,
        observation
            .previous_completed_unix_ms
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
    )
    .map_err(OutputError::from)
}

fn write_gap(
    writer: &mut impl Write,
    json: bool,
    sequence: u64,
    observation: ObservationTimes,
    gap: &GapData<'_>,
) -> Result<(), OutputError> {
    if !json {
        return writeln!(
            writer,
            "COLLECTION_GAP {} failures={} certainty=unknown observed={}..{} previous_completed={}",
            sanitize(&gap.error.message),
            gap.consecutive_failures,
            observation.attempt_started_unix_ms,
            observation.attempt_completed_unix_ms,
            observation
                .previous_completed_unix_ms
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        )
        .map_err(OutputError::from);
    }
    write_json_record(
        writer,
        &WatchRecord {
            schema: "kickoutchi.watch_event",
            version: 1,
            sequence,
            event: "collection_gap",
            observation,
            data: gap,
        },
    )
}

fn gap_from_result(
    result: &Result<NetworkSnapshot, CollectorError>,
    consecutive_failures: u8,
) -> GapData<'_> {
    match result {
        Err(error) => GapData {
            error: PublicError {
                code: collector_error_code(error),
                message: sanitize_bounded(&error.to_string(), 512),
            },
            certainty: "unknown",
            consecutive_failures,
            completeness: None,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
        },
        Ok(snapshot) => {
            let code = if snapshot.completeness == SnapshotCompleteness::Raced {
                "observation_raced"
            } else {
                "partial_socket_set"
            };
            let completeness = Some(if snapshot.completeness == SnapshotCompleteness::Raced {
                "raced"
            } else {
                "partial"
            });
            let omitted = snapshot.omitted_evidence_gap_count.saturating_add(
                u64::try_from(
                    snapshot
                        .evidence_gaps
                        .len()
                        .saturating_sub(WATCH_EVENT_GAPS_MAX),
                )
                .unwrap_or(u64::MAX),
            );
            GapData {
                error: PublicError {
                    code,
                    message: if code == "observation_raced" {
                        "observation raced during collection".to_owned()
                    } else {
                        "socket set was partial during collection".to_owned()
                    },
                },
                certainty: "unknown",
                consecutive_failures,
                completeness,
                evidence_gaps: snapshot
                    .evidence_gaps
                    .iter()
                    .take(WATCH_EVENT_GAPS_MAX)
                    .map(EvidenceGapDto::from)
                    .collect(),
                omitted_evidence_gap_count: omitted,
            }
        }
    }
}

fn write_json_record(writer: &mut impl Write, value: &impl Serialize) -> Result<(), OutputError> {
    let mut record = BoundedRecord::new();
    serde_json::to_writer(&mut record, value).map_err(|error| {
        if record.limit_exceeded {
            OutputError::EventLimit
        } else {
            OutputError::from(PublicOutputError::from(error))
        }
    })?;
    record
        .write_all(b"\n")
        .map_err(|_| OutputError::EventLimit)?;
    writer.write_all(&record.bytes).map_err(OutputError::from)
}

struct BoundedRecord {
    bytes: Vec<u8>,
    limit_exceeded: bool,
}

impl BoundedRecord {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4_096),
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > WATCH_RECORD_MAX_BYTES)
        {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "watch record exceeds 64 KiB",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum OutputError {
    BrokenPipe,
    Io(io::Error),
    Public(PublicOutputError),
    EventLimit,
}

impl From<io::Error> for OutputError {
    fn from(error: io::Error) -> Self {
        if error.kind() == ErrorKind::BrokenPipe {
            Self::BrokenPipe
        } else {
            Self::Io(error)
        }
    }
}

impl From<PublicOutputError> for OutputError {
    fn from(error: PublicOutputError) -> Self {
        if error.io_error_kind() == Some(ErrorKind::BrokenPipe) {
            Self::BrokenPipe
        } else {
            Self::Public(error)
        }
    }
}

fn output_failure(diagnostics: &mut impl Write, error: &OutputError) -> ExitReason {
    let message = match error {
        OutputError::BrokenPipe => return ExitReason::Success,
        OutputError::Io(error) => format!("writing watch output failed: {error}"),
        OutputError::Public(PublicOutputError::Io(error)) => {
            format!("writing watch output failed: {error}")
        }
        OutputError::Public(error @ PublicOutputError::Serialization(_)) => {
            format!("serializing watch event failed: {error}")
        }
        OutputError::Public(error) => format!("preparing watch event failed: {error}"),
        OutputError::EventLimit => "watch event exceeded its 64 KiB record limit".to_owned(),
    };
    write_diagnostic(diagnostics, &message);
    ExitReason::Failure
}

fn io_failure(diagnostics: &mut impl Write, error: &io::Error) -> ExitReason {
    if error.kind() == ErrorKind::BrokenPipe {
        ExitReason::Success
    } else {
        write_diagnostic(
            diagnostics,
            &format!("writing watch output failed: {error}"),
        );
        ExitReason::Failure
    }
}

fn flush_exit(
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    reason: ExitReason,
) -> ExitReason {
    match output.flush() {
        Ok(()) => reason,
        Err(error) => io_failure(diagnostics, &error),
    }
}

fn clock_failure(diagnostics: &mut impl Write, error: &ObservationError) -> ExitReason {
    write_diagnostic(diagnostics, &format!("wall clock failed: {error}"));
    ExitReason::Failure
}

fn write_diagnostic(writer: &mut impl Write, message: &str) {
    let _ = writeln!(writer, "error: {}", sanitize(message));
    let _ = writer.flush();
}

fn validate_wall_interval(
    started: SystemTime,
    completed: SystemTime,
) -> Result<(), ObservationError> {
    completed
        .duration_since(started)
        .map(|_| ())
        .map_err(|_| ObservationError::InvalidWallClockInterval)
}

const fn owner_pid(owner: &OwnerObservation) -> u32 {
    match owner {
        OwnerObservation::Verified(identity) => identity.pid,
        OwnerObservation::UnverifiedPid { pid, .. } => *pid,
    }
}

fn collector_error_code(error: &CollectorError) -> &'static str {
    match error {
        #[cfg(target_os = "linux")]
        CollectorError::Read { source, .. } if source.kind() == ErrorKind::PermissionDenied => {
            "socket_table_permission_denied"
        }
        #[cfg(target_os = "linux")]
        CollectorError::Read { .. } => "socket_table_unavailable",
        #[cfg(any(target_os = "macos", windows))]
        CollectorError::Platform { .. } => "platform_api_failed",
        CollectorError::WorkerExited => "platform_api_failed",
        CollectorError::OwnershipPermissionDenied => "socket_table_permission_denied",
        CollectorError::Observation(error) => observation_error_code(error),
    }
}

fn collector_clock_error(
    result: &Result<NetworkSnapshot, CollectorError>,
) -> Option<&ObservationError> {
    match result {
        Err(CollectorError::Observation(
            error @ (ObservationError::ClockUnavailable
            | ObservationError::InvalidWallClockInterval),
        )) => Some(error),
        _ => None,
    }
}

const fn observation_error_code(error: &ObservationError) -> &'static str {
    match error {
        ObservationError::SocketTableUnavailable => "socket_table_unavailable",
        ObservationError::SocketTablePermissionDenied => "socket_table_permission_denied",
        ObservationError::NativeDataMalformed => "native_data_malformed",
        ObservationError::NativeDataOversized
        | ObservationError::ScopeIdentifierOversized
        | ObservationError::ScopeLimitationLimitExceeded => "native_data_oversized",
        ObservationError::SocketObservationLimitExceeded => "socket_observation_limit_exceeded",
        ObservationError::ProcessIdentityLimitExceeded => "process_identity_limit_exceeded",
        ObservationError::OwnerAttributionLimitExceeded => "owner_attribution_limit_exceeded",
        ObservationError::LegacyProjectionLimitExceeded => "legacy_projection_limit_exceeded",
        ObservationError::PlatformApiFailed(_) => "platform_api_failed",
        ObservationError::ClockUnavailable | ObservationError::InvalidWallClockInterval => {
            "clock_unavailable"
        }
        ObservationError::PartialSocketSet => "partial_socket_set",
        ObservationError::ObservationRaced => "observation_raced",
        ObservationError::OwnerReasonLimitExceeded => "owner_reason_limit_exceeded",
    }
}

mod signal;

pub(crate) use signal::WatchSignalGuard;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use signal::handle_sigint;
#[cfg(test)]
use signal::{WATCH_CANCELLED, WatchSignalReservation};

#[cfg(test)]
mod tests;
