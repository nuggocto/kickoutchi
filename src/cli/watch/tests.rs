use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use super::{
    BoundedRecord, EVENT_ORDER_RANK_COUNT, FilterCache, FilterResult, GapIndex, ObservationTimes,
    OwnerPidConstraint, ProtocolSelection, Truth, WATCH_DURATION_MAX, WATCH_DURATION_MIN,
    WATCH_INTERVAL_DEFAULT_TOKEN, WATCH_INTERVAL_MAX, WATCH_INTERVAL_MIN, WatchArgs, WatchOptions,
    WatchRuntime, evaluate_event, evaluate_side, event_order_rank, next_poll_after,
    observation_times, parse_duration_token, run_watch_loop, should_stop, write_human_event,
    write_ordered_events,
};
use crate::cli::ExitReason;
use crate::collector::{Collector, CollectorError, FakeCollector};
use crate::config::Config;
use crate::model::Protocol;

#[test]
fn watch_signal_reservation_rejects_overlap_and_fails_closed() {
    let slot = std::sync::atomic::AtomicBool::new(false);
    let first = super::WatchSignalReservation::acquire(&slot).unwrap();
    let overlap = super::WatchSignalReservation::acquire(&slot)
        .err()
        .expect("overlapping reservation must be refused");
    assert_eq!(overlap.kind(), io::ErrorKind::WouldBlock);
    drop(first);

    let mut stranded = super::WatchSignalReservation::acquire(&slot).unwrap();
    stranded.keep_reserved();
    drop(stranded);
    assert!(slot.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(
        super::WatchSignalReservation::acquire(&slot)
            .err()
            .expect("a failed restoration must retain ownership")
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn watch_signal_guard_rejects_overlap_without_mutating_the_owner() {
    use std::process::Command;
    use std::sync::atomic::Ordering;

    const CHILD_ENV: &str = "KICKOUTCHI_TEST_WATCH_SIGNAL_OWNERSHIP";
    if std::env::var_os(CHILD_ENV).is_some() {
        #[cfg(unix)]
        unsafe {
            // SAFETY: this isolated child owns its SIGINT disposition.
            let mut ignored: libc::sigaction = std::mem::zeroed();
            ignored.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&raw mut ignored.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGINT, &raw const ignored, std::ptr::null_mut()),
                0,
            );
        }

        let first = super::WatchSignalGuard::install().unwrap();
        super::WATCH_CANCELLED.store(true, Ordering::Relaxed);
        let overlap = super::WatchSignalGuard::install()
            .err()
            .expect("overlapping watch guard must be refused");
        assert_eq!(overlap.kind(), io::ErrorKind::WouldBlock);
        assert!(super::WATCH_CANCELLED.load(Ordering::Relaxed));

        #[cfg(unix)]
        unsafe {
            // SAFETY: a null action queries this isolated child's disposition.
            let mut current: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGINT, std::ptr::null(), &raw mut current),
                0,
            );
            assert_eq!(
                current.sa_sigaction,
                super::handle_sigint as *const () as usize
            );
        }

        drop(first);

        #[cfg(unix)]
        unsafe {
            // SAFETY: a null action queries this isolated child's disposition.
            let mut restored: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGINT, std::ptr::null(), &raw mut restored),
                0,
            );
            assert_eq!(restored.sa_sigaction, libc::SIG_IGN);
        }

        let final_guard = super::WatchSignalGuard::install().unwrap();
        assert!(
            super::WatchSignalGuard::cancelled(),
            "process-wide cancellation must not reset for a later owner"
        );
        drop(final_guard);
        return;
    }

    let status = Command::new(std::env::current_exe().expect("test executable must exist"))
        .args([
            "--exact",
            "cli::watch::tests::watch_signal_guard_rejects_overlap_without_mutating_the_owner",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .expect("watch ownership child must start");
    assert!(
        status.success(),
        "watch ownership child exited with {status}"
    );
}
use crate::labels::{LabelInput, LabelRegistry};
use crate::observation::{
    EvidenceGap, EvidenceGapCode, EvidenceImpact, MetadataCompleteness, MetadataProfile,
    NetworkSnapshot, ObservationError, OwnerCompleteness, OwnerObservation, ProcessIdentity,
    ProcessObservation, ProcessStartMarker, SnapshotCompleteness, UnverifiedOwnerReason,
};
use crate::query::QueryCapabilities;
use crate::watch::{Certainty, EventKind, WatchEvent, baseline_events, diff_snapshots};

#[test]
fn duration_parser_accepts_boundaries_and_rejects_noncanonical_tokens() {
    assert_eq!(
        parse_duration_token("100ms", WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX).unwrap(),
        WATCH_INTERVAL_MIN
    );
    assert_eq!(
        parse_duration_token("60s", WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX).unwrap(),
        WATCH_INTERVAL_MAX
    );
    assert_eq!(
        parse_duration_token("7d", WATCH_DURATION_MIN, WATCH_DURATION_MAX).unwrap(),
        WATCH_DURATION_MAX
    );
    assert!(parse_duration_token("99ms", WATCH_DURATION_MIN, WATCH_DURATION_MAX).is_err());
    assert!(parse_duration_token("604800001ms", WATCH_DURATION_MIN, WATCH_DURATION_MAX,).is_err());
    for invalid in [
        "0ms", "99ms", "60001ms", "-1s", "+1s", "1.5s", "1M", "1m30s", "1 s",
    ] {
        assert!(
            parse_duration_token(invalid, WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn observation_times_preserve_optional_previous_and_reject_pre_epoch_values() {
    let epoch = SystemTime::UNIX_EPOCH;
    let times = observation_times(
        Some(epoch + Duration::from_millis(1)),
        epoch + Duration::from_millis(2),
        epoch + Duration::from_millis(3),
    )
    .unwrap();

    assert_eq!(times.previous_completed_unix_ms, Some(1));
    assert_eq!(times.attempt_started_unix_ms, 2);
    assert_eq!(times.attempt_completed_unix_ms, 3);
    assert_eq!(
        observation_times(
            None,
            epoch + Duration::from_millis(4),
            epoch + Duration::from_millis(5),
        )
        .unwrap()
        .previous_completed_unix_ms,
        None,
    );

    let pre_epoch = epoch
        .checked_sub(Duration::from_millis(1))
        .expect("one millisecond is representable before the Unix epoch");
    assert!(matches!(
        observation_times(None, pre_epoch, epoch),
        Err(super::OutputError::Public(
            crate::public_output::PublicOutputError::ClockUnavailable
        ))
    ));
}

#[test]
fn monotonic_deadlines_accept_exact_boundaries_and_reject_overflow() {
    let one_nanosecond = Duration::from_nanos(1);
    let last_before_max = Duration::MAX
        .checked_sub(one_nanosecond)
        .expect("one nanosecond is below the maximum duration");
    assert_eq!(
        next_poll_after(last_before_max, one_nanosecond),
        Some(Duration::MAX),
    );
    assert_eq!(next_poll_after(Duration::MAX, one_nanosecond), None);

    let deadline = Duration::from_secs(1);
    let just_before_deadline = deadline
        .checked_sub(one_nanosecond)
        .expect("one nanosecond is below the test deadline");
    assert!(!should_stop(false, Some((just_before_deadline, deadline))));
    assert!(should_stop(false, Some((deadline, deadline))));
    assert!(should_stop(true, None));
    assert!(!should_stop(false, None));
}

/// The emission loop runs exactly `EVENT_ORDER_RANK_COUNT` passes, so a
/// rank outside that range would silently drop every event carrying it.
/// Enumerating the full product keeps the constant tied to the function
/// rather than to a remembered arithmetic.
#[test]
fn event_order_ranks_are_distinct_and_fit_the_emission_passes() {
    let mut seen = Vec::new();
    for filter_result in [
        FilterResult::NotApplied,
        FilterResult::Matched,
        FilterResult::Indeterminate,
    ] {
        for certainty in [
            Certainty::Proven,
            Certainty::Estimated,
            Certainty::Heuristic,
            Certainty::Unknown,
        ] {
            let rank = event_order_rank(filter_result, certainty);
            assert!(
                rank < EVENT_ORDER_RANK_COUNT,
                "rank {rank} for {filter_result:?}/{certainty:?} is outside the emission passes",
            );
            seen.push(rank);
        }
    }
    seen.sort_unstable();
    let distinct = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), distinct, "ordering ranks must not collide");
    assert_eq!(
        distinct, EVENT_ORDER_RANK_COUNT as usize,
        "EVENT_ORDER_RANK_COUNT must match the rank domain exactly",
    );
}

#[test]
fn default_interval_is_one_second_and_scope_requires_ipv6_address() {
    let args = WatchArgs {
        tcp: false,
        udp: false,
        address: None,
        scope_id: None,
        port: None,
        filter: None,
        interval: WATCH_INTERVAL_DEFAULT_TOKEN.to_owned(),
        duration: Some("100ms".to_owned()),
        json: true,
    };
    // The declared default reaches the parser as a plain token, so resolve
    // it through a real clap parse rather than trusting a hand-written
    // string to still match the attribute.
    let parsed = <crate::cli::Cli as clap::Parser>::try_parse_from(["kickoutchi", "watch"])
        .expect("bare watch invocation parses");
    let Some(crate::cli::Command::Watch(declared)) = parsed.command else {
        panic!("expected a watch command");
    };
    assert_eq!(declared.interval, WATCH_INTERVAL_DEFAULT_TOKEN);
    assert_eq!(
        WatchOptions::parse(&declared).unwrap().interval,
        Duration::from_secs(1),
        "the documented one-second default must survive token parsing",
    );
    assert_eq!(
        WatchOptions::parse(&args).unwrap().interval,
        Duration::from_secs(1)
    );

    let invalid = WatchArgs {
        scope_id: Some(1),
        ..args
    };
    assert!(WatchOptions::parse(&invalid).is_err());
}

#[test]
fn protocol_flags_normalize_to_exact_internal_selection() {
    for (tcp, udp, expected, includes_tcp, includes_udp, filter_active) in [
        (false, false, ProtocolSelection::Both, true, true, false),
        (true, false, ProtocolSelection::Tcp, true, false, true),
        (false, true, ProtocolSelection::Udp, false, true, true),
        (true, true, ProtocolSelection::Both, true, true, true),
    ] {
        let args = WatchArgs {
            tcp,
            udp,
            address: None,
            scope_id: None,
            port: None,
            filter: None,
            interval: WATCH_INTERVAL_DEFAULT_TOKEN.to_owned(),
            duration: None,
            json: false,
        };

        let options = WatchOptions::parse(&args).expect("protocol flags are valid");
        assert_eq!(options.protocols, expected);
        assert_eq!(options.protocols.includes(Protocol::Tcp), includes_tcp);
        assert_eq!(options.protocols.includes(Protocol::Udp), includes_udp);
        assert_eq!(options.filter_active, filter_active);
    }
}

struct FakeRuntime {
    snapshots: VecDeque<Result<NetworkSnapshot, CollectorError>>,
    monotonic: Duration,
    wall: SystemTime,
    cancelled: bool,
    cancel_at: Option<Duration>,
    collection_durations: VecDeque<Duration>,
    monotonic_step: Duration,
    collect_count: usize,
    wall_count: usize,
    wall_fail_on: Option<usize>,
    wall_values: VecDeque<Result<SystemTime, ObservationError>>,
}

impl FakeRuntime {
    fn new(snapshots: Vec<Result<NetworkSnapshot, CollectorError>>) -> Self {
        Self {
            snapshots: snapshots.into(),
            monotonic: Duration::ZERO,
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            cancelled: false,
            cancel_at: None,
            collection_durations: VecDeque::new(),
            monotonic_step: Duration::ZERO,
            collect_count: 0,
            wall_count: 0,
            wall_fail_on: None,
            wall_values: VecDeque::new(),
        }
    }
}

impl WatchRuntime for FakeRuntime {
    fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError> {
        self.collect_count += 1;
        self.monotonic += self.collection_durations.pop_front().unwrap_or_default();
        if self
            .cancel_at
            .is_some_and(|deadline| self.monotonic >= deadline)
        {
            self.cancelled = true;
        }
        self.snapshots
            .pop_front()
            .unwrap_or_else(|| Err(ObservationError::SocketTableUnavailable.into()))
    }

    fn monotonic_now(&mut self) -> Duration {
        let now = self.monotonic;
        self.monotonic += self.monotonic_step;
        now
    }

    fn wall_now(&mut self) -> Result<SystemTime, ObservationError> {
        self.wall_count += 1;
        if let Some(value) = self.wall_values.pop_front() {
            return value;
        }
        if self.wall_fail_on == Some(self.wall_count) {
            return Err(ObservationError::ClockUnavailable);
        }
        self.wall += Duration::from_millis(1);
        Ok(self.wall)
    }

    fn sleep(&mut self, duration: Duration) {
        self.monotonic += duration;
        if self
            .cancel_at
            .is_some_and(|deadline| self.monotonic >= deadline)
        {
            self.cancelled = true;
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled
    }
}

fn snapshot() -> NetworkSnapshot {
    FakeCollector
        .collect(MetadataProfile::Display)
        .expect("fake snapshot is valid")
}

fn options(duration: Duration) -> WatchOptions {
    WatchOptions {
        protocols: ProtocolSelection::Both,
        address: None,
        scope_id: None,
        port: Some(65_535),
        terms: Vec::new(),
        filter_active: true,
        interval: WATCH_INTERVAL_MIN,
        duration: Some(duration),
        json: true,
    }
}

fn filtered_options(text: &str) -> WatchOptions {
    let mut filter = options(Duration::from_millis(100));
    filter.port = None;
    filter.terms = crate::query::parse_filter_text(text, QueryCapabilities::WATCH).unwrap();
    filter
}

fn owned_snapshot(pid: u32, name: Option<&str>, metadata: MetadataCompleteness) -> NetworkSnapshot {
    let mut observed = snapshot();
    observed.sockets.truncate(1);
    observed.processes.clear();
    let identity = ProcessIdentity {
        pid,
        start_marker: ProcessStartMarker::linux(u64::from(pid) + 1).unwrap(),
    };
    observed.sockets[0].owners = vec![OwnerObservation::Verified(identity)];
    observed.processes.insert(
        identity,
        ProcessObservation {
            name: name.map(Into::into),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            metadata_omission: None,
            metadata_completeness: metadata,
        },
    );
    observed
}

#[test]
fn event_filter_uses_the_documented_side_and_three_valued_matrix() {
    let previous = owned_snapshot(10, Some("alpha"), MetadataCompleteness::Complete);
    let current = owned_snapshot(20, Some("beta"), MetadataCompleteness::Complete);
    let config = Config::default();
    let event = |kind| WatchEvent {
        kind,
        previous_snapshot: (kind != EventKind::Baseline).then_some(&previous),
        current_snapshot: (kind != EventKind::Release).then_some(&current),
        previous_socket: matches!(kind, EventKind::Release | EventKind::Replacement)
            .then_some(&previous.sockets[0]),
        current_socket: matches!(
            kind,
            EventKind::Baseline | EventKind::Bind | EventKind::Replacement
        )
        .then_some(&current.sockets[0]),
        multiplicity: 1,
        certainty: Certainty::Proven,
    };

    for kind in [EventKind::Baseline, EventKind::Bind] {
        assert_eq!(
            evaluate_event(
                event(kind),
                &filtered_options("pid:20 beta"),
                &config,
                None,
                Some(&mut FilterCache::default()),
            ),
            Some(FilterResult::Matched),
            "{kind:?} must use current facts"
        );
    }
    assert_eq!(
        evaluate_event(
            event(EventKind::Release),
            &filtered_options("pid:10 alpha"),
            &config,
            Some(&mut FilterCache::default()),
            None,
        ),
        Some(FilterResult::Matched)
    );
    for text in ["pid:10 alpha", "pid:20 beta"] {
        assert_eq!(
            evaluate_event(
                event(EventKind::Replacement),
                &filtered_options(text),
                &config,
                Some(&mut FilterCache::default()),
                Some(&mut FilterCache::default()),
            ),
            Some(FilterResult::Matched),
            "replacement must match either complete side"
        );
    }

    let unknown = owned_snapshot(20, None, MetadataCompleteness::Partial);
    let unknown_event = WatchEvent {
        current_snapshot: Some(&unknown),
        current_socket: Some(&unknown.sockets[0]),
        ..event(EventKind::Bind)
    };
    assert_eq!(
        evaluate_event(
            unknown_event,
            &filtered_options("missing"),
            &config,
            None,
            Some(&mut FilterCache::default()),
        ),
        Some(FilterResult::Indeterminate)
    );
    assert_eq!(
        evaluate_event(
            unknown_event,
            &filtered_options("port:1 missing"),
            &config,
            None,
            Some(&mut FilterCache::default()),
        ),
        None,
        "a definite false term suppresses an otherwise unknown event"
    );
}

#[test]
fn owner_terms_must_be_satisfied_by_the_same_owner() {
    let mut observed = owned_snapshot(10, Some("alpha"), MetadataCompleteness::Complete);
    let second = ProcessIdentity {
        pid: 20,
        start_marker: ProcessStartMarker::linux(21).unwrap(),
    };
    observed.sockets[0]
        .owners
        .push(OwnerObservation::Verified(second));
    observed.processes.insert(
        second,
        ProcessObservation {
            name: Some("beta".into()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            metadata_omission: None,
            metadata_completeness: MetadataCompleteness::Complete,
        },
    );

    assert_eq!(
        evaluate_side(
            &observed,
            &observed.sockets[0],
            &filtered_options("pid:10 beta"),
            &Config::default(),
            &mut FilterCache::default(),
        ),
        Truth::False
    );
    assert_eq!(
        evaluate_side(
            &observed,
            &observed.sockets[0],
            &filtered_options("pid:10 alpha"),
            &Config::default(),
            &mut FilterCache::default(),
        ),
        Truth::True
    );
}

#[test]
fn third_consecutive_failure_flushes_three_gaps_and_stops_collection() {
    let snapshots = vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Ok(snapshot()),
    ];
    let mut runtime = FakeRuntime::new(snapshots);
    let mut stdout = BufferedTrackingWriter::default();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_secs(1)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert_eq!(runtime.collect_count, 4);
    assert_eq!(stdout.flush_count, 4);
    assert!(stdout.pending.is_empty());
    let records = String::from_utf8(stdout.committed).unwrap();
    let values = records
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    assert!(
        values
            .iter()
            .all(|value| value["event"] == "collection_gap")
    );
    assert_eq!(values[0]["schema"], "kickoutchi.watch_event");
    assert_eq!(values[0]["version"], 1);
    assert_eq!(values[0]["sequence"], 0);
    assert!(values[0]["observation"]["previous_completed_unix_ms"].is_number());
    assert!(values[0]["observation"]["attempt_started_unix_ms"].is_number());
    assert!(values[0]["observation"]["attempt_completed_unix_ms"].is_number());
    assert_eq!(values[0]["data"]["certainty"], "unknown");
    assert!(values[0]["data"]["completeness"].is_null());
    assert_eq!(values[0]["data"]["evidence_gaps"], serde_json::json!([]));
    assert_eq!(values[0]["data"]["omitted_evidence_gap_count"], 0);
    assert_eq!(values[2]["data"]["consecutive_failures"], 3);
    assert!(stderr.is_empty());
}

#[test]
fn failed_collection_waits_a_full_interval_after_slow_completion() {
    let snapshots = vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ];
    let mut runtime = FakeRuntime::new(snapshots);
    runtime.collection_durations = [
        Duration::ZERO,
        Duration::from_millis(200),
        Duration::ZERO,
        Duration::ZERO,
    ]
    .into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_secs(2)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert_eq!(runtime.monotonic, Duration::from_millis(500));
    assert!(stderr.is_empty());
}

#[test]
fn recovery_uses_the_last_valid_snapshot_without_fabricated_releases() {
    let baseline = snapshot();
    let snapshots = vec![
        Ok(baseline.clone()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Ok(baseline),
    ];
    let mut runtime = FakeRuntime::new(snapshots);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(250)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Success);
    assert_eq!(runtime.collect_count, 3);
    let records = String::from_utf8(stdout).unwrap();
    let events = records
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
        .collect::<Vec<_>>();
    assert_eq!(events, ["collection_gap"]);
    assert!(stderr.is_empty());
}

#[test]
fn ownership_and_metadata_partial_snapshot_advances_the_comparison_baseline() {
    let mut first = snapshot();
    first.sockets.truncate(1);
    first.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(10);
    first.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(11);
    let mut partial = snapshot();
    partial.sockets = vec![partial.sockets[1].clone()];
    partial.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(20);
    partial.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(21);
    partial.completeness = SnapshotCompleteness::Partial;
    partial.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
    partial.processes.values_mut().for_each(|process| {
        process.metadata_completeness = MetadataCompleteness::Partial;
    });
    let mut final_snapshot = first.clone();
    final_snapshot.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(30);
    final_snapshot.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(31);
    let mut runtime = FakeRuntime::new(vec![Ok(first), Ok(partial), Ok(final_snapshot)]);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut watch_options = options(Duration::from_millis(250));
    watch_options.port = None;
    watch_options.filter_active = false;

    let reason = run_watch_loop(
        &watch_options,
        &Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(reason, ExitReason::Success);
    let events = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
        .collect::<Vec<_>>();
    assert_eq!(events, ["baseline", "release", "bind", "bind", "release"]);
    assert!(diagnostics.is_empty());
}

#[test]
fn unsafe_snapshot_does_not_advance_the_comparison_baseline() {
    let mut first = snapshot();
    first.sockets.truncate(1);
    first.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(10);
    first.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(11);
    let mut changed = snapshot();
    changed.sockets = vec![changed.sockets[1].clone()];
    changed.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(20);
    changed.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(21);
    let mut unsafe_snapshot = changed.clone();
    unsafe_snapshot.completeness = SnapshotCompleteness::Partial;
    unsafe_snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        None,
        None,
        "socket set incomplete",
    ));
    changed.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(30);
    changed.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(31);
    let mut runtime = FakeRuntime::new(vec![Ok(first), Ok(unsafe_snapshot), Ok(changed)]);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut watch_options = options(Duration::from_millis(250));
    watch_options.port = None;
    watch_options.filter_active = false;

    let reason = run_watch_loop(
        &watch_options,
        &Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(reason, ExitReason::Success);
    let events = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
        .collect::<Vec<_>>();
    assert_eq!(events, ["baseline", "collection_gap", "release", "bind"]);
    assert!(diagnostics.is_empty());
}

#[test]
fn successful_poll_resets_the_failure_budget() {
    let observed = snapshot();
    let mut runtime = FakeRuntime::new(vec![
        Ok(observed.clone()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Ok(observed),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ]);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let reason = run_watch_loop(
        &options(Duration::from_millis(450)),
        &Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(runtime.collect_count, 5);
    let failures = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["data"]["consecutive_failures"]
                .as_u64()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(failures, [1, 1, 2]);
    assert!(diagnostics.is_empty());
}

struct FailingWriter {
    kind: io::ErrorKind,
}

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(self.kind, "injected writer failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FlushFailWriter {
    kind: io::ErrorKind,
}

#[derive(Default)]
struct BufferedTrackingWriter {
    pending: Vec<u8>,
    committed: Vec<u8>,
    flush_count: usize,
}

impl Write for BufferedTrackingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_count += 1;
        self.committed.append(&mut self.pending);
        Ok(())
    }
}

impl Write for FlushFailWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(self.kind, "injected flush failure"))
    }
}

#[test]
fn broken_pipe_is_success_and_other_writer_failures_are_operational() {
    let mut broken_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    let mut broken = FailingWriter {
        kind: io::ErrorKind::BrokenPipe,
    };
    let mut diagnostics = Vec::new();
    let mut unfiltered = options(Duration::from_millis(100));
    unfiltered.port = None;
    unfiltered.filter_active = false;
    assert_eq!(
        run_watch_loop(
            &unfiltered,
            &Config::default(),
            &mut broken_runtime,
            &mut broken,
            &mut diagnostics,
        ),
        ExitReason::Success
    );
    assert!(diagnostics.is_empty());

    let mut failed_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    let mut failed = FailingWriter {
        kind: io::ErrorKind::Other,
    };
    assert_eq!(
        run_watch_loop(
            &unfiltered,
            &Config::default(),
            &mut failed_runtime,
            &mut failed,
            &mut diagnostics,
        ),
        ExitReason::Failure
    );
    assert!(
        String::from_utf8(diagnostics)
            .unwrap()
            .contains("writing watch output failed")
    );

    let mut flush_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    let mut flush_broken = FlushFailWriter {
        kind: io::ErrorKind::BrokenPipe,
    };
    let mut flush_diagnostics = Vec::new();
    let filtered = options(Duration::from_millis(100));
    assert_eq!(
        run_watch_loop(
            &filtered,
            &Config::default(),
            &mut flush_runtime,
            &mut flush_broken,
            &mut flush_diagnostics,
        ),
        ExitReason::Success
    );
    assert!(flush_diagnostics.is_empty());

    let mut flush_failed_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    let mut flush_failed = FlushFailWriter {
        kind: io::ErrorKind::Other,
    };
    let mut flush_failed_diagnostics = Vec::new();
    assert_eq!(
        run_watch_loop(
            &filtered,
            &Config::default(),
            &mut flush_failed_runtime,
            &mut flush_failed,
            &mut flush_failed_diagnostics,
        ),
        ExitReason::Failure
    );
    assert!(
        String::from_utf8(flush_failed_diagnostics)
            .unwrap()
            .contains("injected flush failure")
    );
}

#[test]
fn no_duration_watch_stops_on_injected_cancellation_without_an_extra_collection() {
    let mut runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    runtime.cancel_at = Some(Duration::from_millis(25));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut watch_options = options(Duration::from_millis(100));
    watch_options.duration = None;

    let result = run_watch_loop(
        &watch_options,
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Success);
    assert_eq!(runtime.collect_count, 1);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn initial_collection_failure_emits_no_record_and_one_diagnostic() {
    let mut runtime = FakeRuntime::new(vec![Err(ObservationError::SocketTableUnavailable.into())]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(100)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    let diagnostic = String::from_utf8(stderr).unwrap();
    assert_eq!(diagnostic.lines().count(), 1);
    assert!(diagnostic.contains("initial collection failed"));
}

#[test]
fn initial_partial_socket_set_fails_without_emitting_a_baseline() {
    let mut partial = snapshot();
    partial.completeness = SnapshotCompleteness::Partial;
    partial.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        None,
        None,
        "injected partial socket set",
    ));
    let mut runtime = FakeRuntime::new(vec![Ok(partial)]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(100)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "error: initial observation has a partial socket set\n"
    );
}

#[test]
fn slow_initial_collection_failure_is_not_masked_by_duration_expiry() {
    let mut runtime = FakeRuntime::new(vec![Err(ObservationError::SocketTableUnavailable.into())]);
    runtime.collection_durations = [Duration::from_millis(200)].into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(100)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("initial collection failed")
    );
}

#[test]
fn cancellation_during_initial_failure_does_not_mask_the_error() {
    let mut runtime = FakeRuntime::new(vec![Err(ObservationError::SocketTableUnavailable.into())]);
    runtime.collection_durations = [Duration::from_millis(200)].into();
    runtime.cancel_at = Some(Duration::from_millis(100));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_secs(1)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("initial collection failed")
    );
}

#[test]
fn failed_poll_crossing_duration_emits_and_flushes_its_gap() {
    let mut runtime = FakeRuntime::new(vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ]);
    runtime.collection_durations = [Duration::ZERO, Duration::from_millis(200)].into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(250)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Success);
    assert_eq!(runtime.collect_count, 2);
    let records = String::from_utf8(stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(value["event"], "collection_gap");
    assert_eq!(value["data"]["error"]["code"], "socket_table_unavailable");
    assert!(stderr.is_empty());
}

#[test]
fn unsafe_poll_crossing_duration_emits_and_flushes_its_gap() {
    let mut raced = snapshot();
    raced.completeness = SnapshotCompleteness::Raced;
    let mut partial = snapshot();
    partial.completeness = SnapshotCompleteness::Partial;
    partial.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        None,
        None,
        "injected partial socket set",
    ));

    for (unsafe_snapshot, expected_code) in [
        (raced, "observation_raced"),
        (partial, "partial_socket_set"),
    ] {
        let mut runtime = FakeRuntime::new(vec![Ok(snapshot()), Ok(unsafe_snapshot)]);
        runtime.collection_durations = [Duration::ZERO, Duration::from_millis(200)].into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(250)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Success);
        assert_eq!(runtime.collect_count, 2);
        let records = String::from_utf8(stdout).unwrap();
        let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
        assert_eq!(value["event"], "collection_gap");
        assert_eq!(value["data"]["error"]["code"], expected_code);
        assert!(stderr.is_empty());
    }
}

#[test]
fn third_failed_poll_crossing_duration_exhausts_the_failure_budget() {
    let mut runtime = FakeRuntime::new(vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ]);
    runtime.collection_durations = [
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::from_millis(200),
    ]
    .into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(450)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert_eq!(runtime.collect_count, 4);
    assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 3);
    assert!(stderr.is_empty());
}

#[test]
fn cancellation_during_third_failed_poll_does_not_mask_budget_exhaustion() {
    let mut runtime = FakeRuntime::new(vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ]);
    runtime.collection_durations = [
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO,
        Duration::from_millis(200),
    ]
    .into();
    runtime.cancel_at = Some(Duration::from_millis(350));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_secs(1)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert_eq!(runtime.collect_count, 4);
    assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 3);
    assert!(stderr.is_empty());
}

#[test]
fn cancellation_during_failed_poll_exits_cleanly_after_its_gap() {
    let mut runtime = FakeRuntime::new(vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ]);
    runtime.collection_durations = [Duration::ZERO, Duration::from_millis(200)].into();
    runtime.cancel_at = Some(Duration::from_millis(150));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_secs(1)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Success);
    assert_eq!(runtime.collect_count, 2);
    let records = String::from_utf8(stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
    assert_eq!(value["event"], "collection_gap");
    assert!(stderr.is_empty());
}

#[test]
fn wall_clock_failure_after_baseline_emits_no_gap() {
    let mut runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    runtime.wall_fail_on = Some(3);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(200)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("wall clock failed")
    );
}

#[test]
fn reversed_failed_poll_interval_is_an_immediate_clock_failure() {
    let mut runtime = FakeRuntime::new(vec![
        Ok(snapshot()),
        Err(ObservationError::SocketTableUnavailable.into()),
    ]);
    runtime.wall_values = [
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(2)),
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(4)),
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(3)),
    ]
    .into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(200)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("wall clock failed")
    );
}

#[test]
fn reversed_interval_between_successful_snapshots_is_a_clock_failure() {
    let mut previous = snapshot();
    previous.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
    previous.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut current = snapshot();
    current.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(5);
    current.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(6);
    let mut runtime = FakeRuntime::new(vec![Ok(previous), Ok(current)]);
    runtime.wall_values = [
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(2)),
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(11)),
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(12)),
    ]
    .into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(200)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("wall clock failed")
    );
}

#[test]
fn collector_clock_failure_is_immediate_and_never_becomes_a_gap() {
    let mut runtime = FakeRuntime::new(vec![Err(ObservationError::ClockUnavailable.into())]);
    runtime.collection_durations = [Duration::from_millis(200)].into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_watch_loop(
        &options(Duration::from_millis(200)),
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Failure);
    assert!(stdout.is_empty());
    assert_eq!(runtime.collect_count, 1);
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("wall clock failed")
    );
}

#[test]
fn duration_is_checked_between_baseline_events() {
    let mut runtime = FakeRuntime::new(vec![Ok(snapshot())]);
    runtime.monotonic_step = Duration::from_millis(10);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut unfiltered = options(Duration::from_millis(25));
    unfiltered.port = None;
    unfiltered.filter_active = false;

    let result = run_watch_loop(
        &unfiltered,
        &Config::default(),
        &mut runtime,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(result, ExitReason::Success);
    assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 1);
    assert!(stderr.is_empty());
}

#[test]
fn unverified_owner_pid_plain_search_matches_without_metadata() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.sockets[0].owners = vec![OwnerObservation::UnverifiedPid {
        pid: 4_242,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    }];
    snapshot.sockets[0].owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::ProcessIdentityUnavailable]).unwrap();
    snapshot.owner_completeness = snapshot.sockets[0].owner_completeness.clone();
    snapshot.completeness = SnapshotCompleteness::Partial;
    let terms = crate::query::parse_filter_text("4242", QueryCapabilities::WATCH).unwrap();
    let mut filter = options(Duration::from_millis(100));
    filter.port = None;
    filter.terms = terms;

    assert_eq!(
        evaluate_side(
            &snapshot,
            &snapshot.sockets[0],
            &filter,
            &Config::default(),
            &mut super::FilterCache::default(),
        ),
        Truth::True
    );
}

#[test]
fn partial_ownership_cannot_override_a_false_endpoint_term() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.sockets[0].owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
    snapshot.owner_completeness = snapshot.sockets[0].owner_completeness.clone();
    snapshot.completeness = SnapshotCompleteness::Partial;
    let impossible_port = if snapshot.sockets[0].local_endpoint.port.get() == 1 {
        2
    } else {
        1
    };
    let terms = crate::query::parse_filter_text(
        &format!("port:{impossible_port}"),
        QueryCapabilities::WATCH,
    )
    .unwrap();
    let mut filter = options(Duration::from_millis(100));
    filter.port = None;
    filter.terms = terms;

    assert_eq!(
        evaluate_side(
            &snapshot,
            &snapshot.sockets[0],
            &filter,
            &Config::default(),
            &mut super::FilterCache::default(),
        ),
        Truth::False
    );
}

#[test]
fn global_ownership_gap_makes_owner_dependent_miss_indeterminate() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
    snapshot.completeness = SnapshotCompleteness::Partial;
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerAttributionIncomplete,
        None,
        None,
        "an owner could not be attributed to an endpoint",
    ));
    let mut filter = options(Duration::from_millis(100));
    filter.port = None;
    filter.terms =
        crate::query::parse_filter_text("pid:4294967295", QueryCapabilities::WATCH).unwrap();

    assert_eq!(
        evaluate_side(
            &snapshot,
            &snapshot.sockets[0],
            &filter,
            &Config::default(),
            &mut FilterCache::default(),
        ),
        Truth::Unknown
    );

    filter.terms = crate::query::parse_filter_text(
        &format!("port:{}", snapshot.sockets[0].local_endpoint.port),
        QueryCapabilities::WATCH,
    )
    .unwrap();
    assert_eq!(
        evaluate_side(
            &snapshot,
            &snapshot.sockets[0],
            &filter,
            &Config::default(),
            &mut FilterCache::default(),
        ),
        Truth::True,
        "global owner uncertainty must not weaken endpoint-only filters"
    );
}

#[test]
fn pid_scoped_ownership_gap_is_indeterminate_and_emitted_for_hidden_owner() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
    snapshot.completeness = SnapshotCompleteness::Partial;
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        Some(4_242),
        "permission denied before the PID's socket ownership could be attributed",
    ));
    let filter = filtered_options("pid:4242");
    let event = WatchEvent {
        kind: EventKind::Baseline,
        previous_snapshot: None,
        current_snapshot: Some(&snapshot),
        previous_socket: None,
        current_socket: Some(&snapshot.sockets[0]),
        multiplicity: 1,
        certainty: Certainty::Proven,
    };

    assert_eq!(
        evaluate_event(
            event,
            &filter,
            &Config::default(),
            None,
            Some(&mut FilterCache::default()),
        ),
        Some(FilterResult::Indeterminate)
    );
    assert_eq!(
        evaluate_event(
            event,
            &filtered_options("pid:9999"),
            &Config::default(),
            None,
            Some(&mut FilterCache::default()),
        ),
        None,
        "a PID-scoped gap must not weaken a filter for a different PID"
    );

    let gap_index = GapIndex::new(&snapshot);
    let mut output = Vec::new();
    super::write_endpoint_event(
        &mut output,
        true,
        0,
        ObservationTimes {
            previous_completed_unix_ms: None,
            attempt_started_unix_ms: 1,
            attempt_completed_unix_ms: 2,
        },
        event,
        FilterResult::Indeterminate,
        &filter.terms,
        &Config::default(),
        None,
        Some(&gap_index),
    )
    .unwrap();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["filter_result"], "indeterminate");
    assert_eq!(value["data"]["evidence_gaps"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["evidence_gaps"][0]["impact"], "ownership");
    assert_eq!(
        value["data"]["evidence_gaps"][0]["code"],
        "owner_permission_denied"
    );
    assert_eq!(value["data"]["evidence_gaps"][0]["pid"], 4_242);
}

#[test]
fn omitted_ownership_gap_keeps_pid_filter_indeterminate_and_counts_the_gap() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
    snapshot.completeness = SnapshotCompleteness::Partial;
    snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Ownership,
        EvidenceGapCode::OwnerPermissionDenied,
        None,
        Some(9_999),
        "an unrelated retained PID could not be scanned",
    ));
    snapshot.omitted_evidence_gap_count = 1;
    let filter = filtered_options("pid:4242");
    let event = WatchEvent {
        kind: EventKind::Baseline,
        previous_snapshot: None,
        current_snapshot: Some(&snapshot),
        previous_socket: None,
        current_socket: Some(&snapshot.sockets[0]),
        multiplicity: 1,
        certainty: Certainty::Proven,
    };

    assert_eq!(
        evaluate_event(
            event,
            &filter,
            &Config::default(),
            None,
            Some(&mut FilterCache::default()),
        ),
        Some(FilterResult::Indeterminate)
    );

    let gap_index = GapIndex::new(&snapshot);
    let mut output = Vec::new();
    super::write_endpoint_event(
        &mut output,
        true,
        0,
        ObservationTimes {
            previous_completed_unix_ms: None,
            attempt_started_unix_ms: 1,
            attempt_completed_unix_ms: 2,
        },
        event,
        FilterResult::Indeterminate,
        &filter.terms,
        &Config::default(),
        None,
        Some(&gap_index),
    )
    .unwrap();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["filter_result"], "indeterminate");
    assert_eq!(value["data"]["evidence_gaps"], serde_json::json!([]));
    assert_eq!(value["data"]["omitted_evidence_gap_count"], 1);
}

#[test]
fn complete_ownerless_socket_matches_protected_false() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.sockets[0].owners.clear();
    snapshot.sockets[0].owner_completeness = OwnerCompleteness::Complete;
    snapshot.owner_completeness = OwnerCompleteness::Complete;
    snapshot.completeness = SnapshotCompleteness::Complete;
    let mut filter = options(Duration::from_millis(100));
    filter.port = None;
    filter.terms =
        crate::query::parse_filter_text("protected:false", QueryCapabilities::WATCH).unwrap();

    assert_eq!(
        evaluate_side(
            &snapshot,
            &snapshot.sockets[0],
            &filter,
            &Config::default(),
            &mut FilterCache::default(),
        ),
        Truth::True
    );
    filter.terms =
        crate::query::parse_filter_text("protected:true", QueryCapabilities::WATCH).unwrap();
    assert_eq!(
        evaluate_side(
            &snapshot,
            &snapshot.sockets[0],
            &filter,
            &Config::default(),
            &mut FilterCache::default(),
        ),
        Truth::False
    );
}

#[test]
fn protection_filters_use_an_available_name_despite_unrelated_metadata_gaps() {
    let mut snapshot = snapshot();
    let protected_index = snapshot
        .sockets
        .iter()
        .position(|socket| socket.local_endpoint.port.get() == 5_432)
        .expect("fixture has the partial-metadata postgres socket");
    let unprotected_index = snapshot
        .sockets
        .iter()
        .position(|socket| socket.local_endpoint.port.get() == 3_000)
        .expect("fixture has the node socket");
    let unprotected_identity = match snapshot.sockets[unprotected_index].owners.as_slice() {
        [OwnerObservation::Verified(identity)] => *identity,
        _ => panic!("fixture node socket has one verified owner"),
    };
    snapshot
        .processes
        .get_mut(&unprotected_identity)
        .expect("fixture node metadata exists")
        .metadata_completeness = MetadataCompleteness::Partial;
    let config = Config::default();

    let evaluate = |socket_index: usize, text: &str| {
        let mut filter = options(Duration::from_millis(100));
        filter.port = None;
        filter.terms = crate::query::parse_filter_text(text, QueryCapabilities::WATCH)
            .expect("protection filter is valid");
        evaluate_side(
            &snapshot,
            &snapshot.sockets[socket_index],
            &filter,
            &config,
            &mut FilterCache::default(),
        )
    };

    assert_eq!(evaluate(protected_index, "protected:true"), Truth::True);
    assert_eq!(evaluate(protected_index, "protected:false"), Truth::False);
    assert_eq!(evaluate(unprotected_index, "protected:true"), Truth::False);
    assert_eq!(evaluate(unprotected_index, "protected:false"), Truth::True);
    assert_eq!(evaluate(protected_index, "protected"), Truth::True);
    assert_eq!(evaluate(protected_index, "unprotected"), Truth::Unknown);
    assert_eq!(evaluate(unprotected_index, "protected"), Truth::Unknown);
    assert_eq!(evaluate(unprotected_index, "unprotected"), Truth::True);
}

#[test]
fn macos_protection_filters_recognize_the_executable_with_or_without_a_name() {
    for name in [Some("worker"), None] {
        let mut snapshot = snapshot();
        snapshot.scope.kind =
            crate::observation::ObservationScopeKind::CurrentHostProcessVisibleSockets;
        let OwnerObservation::Verified(identity) = snapshot.sockets[0].owners[0] else {
            panic!("fixture has a verified owner");
        };
        let process = snapshot.processes.get_mut(&identity).unwrap();
        process.name = name.map(std::sync::Arc::from);
        process.executable_path = Some(std::sync::Arc::from(std::path::Path::new("/opt/postgres")));
        let config = Config::default();
        for (text, expected) in [
            ("protected:true", Truth::True),
            ("protected:false", Truth::False),
            ("protected", Truth::True),
        ] {
            let mut filter = options(Duration::from_millis(100));
            filter.port = None;
            filter.terms = crate::query::parse_filter_text(text, QueryCapabilities::WATCH).unwrap();
            assert_eq!(
                evaluate_side(
                    &snapshot,
                    &snapshot.sockets[0],
                    &filter,
                    &config,
                    &mut FilterCache::default()
                ),
                expected,
                "{text}, name={name:?}",
            );
        }
    }
}

#[test]
fn filter_result_order_crosses_batch_boundaries_without_retaining_the_group() {
    let mut snapshot = snapshot();
    let mut common_owners = (1..=64)
        .map(|pid| OwnerObservation::UnverifiedPid {
            pid,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        })
        .collect::<Vec<_>>();
    let mut indeterminate = snapshot.sockets[0].clone();
    common_owners.push(OwnerObservation::UnverifiedPid {
        pid: 101,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    });
    indeterminate.owners = common_owners.clone();
    indeterminate.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
    let mut matched = indeterminate.clone();
    *matched.owners.last_mut().unwrap() = OwnerObservation::UnverifiedPid {
        pid: 100,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    };
    snapshot.sockets = vec![indeterminate; crate::watch::WATCH_EVENT_BATCH_MAX];
    snapshot.sockets.push(matched);
    snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
    snapshot.completeness = SnapshotCompleteness::Partial;

    let mut filter = options(Duration::from_secs(1));
    filter.json = false;
    filter.port = None;
    filter.terms = crate::query::parse_filter_text("pid:100", QueryCapabilities::WATCH).unwrap();
    let events = baseline_events(&snapshot)
        .unwrap()
        .map(super::baseline_event_result);
    let mut runtime = FakeRuntime::new(Vec::new());
    let mut output = BufferedTrackingWriter::default();
    let mut diagnostics = Vec::new();
    let mut writer = super::EventWriter {
        output: &mut output,
        diagnostics: &mut diagnostics,
        sequence: 0,
    };
    let mut current_index = super::SnapshotIndex::new(&snapshot);

    let reason = write_ordered_events(
        events,
        &filter,
        &Config::default(),
        &mut runtime,
        None,
        &mut writer,
        super::EventBatch {
            previous: None,
            current: &mut current_index,
            observation: ObservationTimes {
                previous_completed_unix_ms: None,
                attempt_started_unix_ms: 1,
                attempt_completed_unix_ms: 2,
            },
        },
    );
    let sequence = writer.sequence;
    output.flush().unwrap();

    assert_eq!(reason, None);
    assert!(diagnostics.is_empty());
    let rendered = String::from_utf8(output.committed).unwrap();
    let mut lines = rendered.lines();
    assert!(lines.next().unwrap().contains("filter=matched"));
    assert_eq!(
        lines
            .filter(|line| line.contains("filter=indeterminate"))
            .count(),
        crate::watch::WATCH_EVENT_BATCH_MAX
    );
    assert_eq!(
        usize::try_from(sequence).unwrap(),
        crate::watch::WATCH_EVENT_BATCH_MAX + 1
    );
}

#[test]
fn filtering_uses_the_uncancelled_owner_beyond_the_public_owner_limit() {
    let mut previous = snapshot();
    previous.sockets.truncate(1);
    let common = (1..=crate::observation::SERIALIZED_OWNERS_MAX)
        .map(|pid| OwnerObservation::UnverifiedPid {
            pid: u32::try_from(pid).unwrap(),
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        })
        .collect::<Vec<_>>();
    let mut hidden_100 = previous.sockets[0].clone();
    hidden_100.owners = common.clone();
    hidden_100.owners.push(OwnerObservation::UnverifiedPid {
        pid: 100,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    });
    let mut hidden_101 = previous.sockets[0].clone();
    hidden_101.owners = common;
    hidden_101.owners.push(OwnerObservation::UnverifiedPid {
        pid: 101,
        reason: UnverifiedOwnerReason::IdentityUnavailable,
    });
    previous.sockets = vec![hidden_101, hidden_100.clone()];
    let mut current = previous.clone();
    current.sockets = vec![hidden_100];
    let mut filter = options(Duration::from_secs(1));
    filter.json = false;
    filter.port = None;
    filter.terms = crate::query::parse_filter_text("pid:101", QueryCapabilities::WATCH).unwrap();
    let mut runtime = FakeRuntime::new(Vec::new());
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut writer = super::EventWriter {
        output: &mut output,
        diagnostics: &mut diagnostics,
        sequence: 0,
    };
    let mut previous_index = super::SnapshotIndex::new(&previous);
    let mut current_index = super::SnapshotIndex::new(&current);

    let reason = write_ordered_events(
        diff_snapshots(&previous, &current).unwrap(),
        &filter,
        &Config::default(),
        &mut runtime,
        None,
        &mut writer,
        super::EventBatch {
            previous: Some(&mut previous_index),
            current: &mut current_index,
            observation: ObservationTimes {
                previous_completed_unix_ms: Some(1),
                attempt_started_unix_ms: 2,
                attempt_completed_unix_ms: 3,
            },
        },
    );

    assert_eq!(reason, None);
    assert!(diagnostics.is_empty());
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains("RELEASE"));
    assert!(output.contains("filter=matched"));
}

#[test]
fn human_output_bounds_owner_and_label_display() {
    let mut snapshot = snapshot();
    snapshot.sockets.truncate(1);
    snapshot.sockets[0].owners = (1..=65)
        .map(|pid| OwnerObservation::UnverifiedPid {
            pid,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        })
        .collect();
    let endpoint = snapshot.sockets[0].local_endpoint.clone();
    let config = Config {
        labels: LabelRegistry::from_inputs(vec![LabelInput {
            protocol: endpoint.protocol.label().to_ascii_lowercase(),
            address: endpoint.address.to_string(),
            port: u64::from(endpoint.port.get()),
            scope_id: None,
            label: "x".repeat(33),
        }])
        .unwrap(),
        ..Config::default()
    };
    let event = WatchEvent {
        kind: EventKind::Baseline,
        previous_snapshot: None,
        current_snapshot: Some(&snapshot),
        previous_socket: None,
        current_socket: Some(&snapshot.sockets[0]),
        multiplicity: 1,
        certainty: Certainty::Proven,
    };
    let mut output = Vec::new();

    write_human_event(
        &mut output,
        ObservationTimes {
            previous_completed_unix_ms: None,
            attempt_started_unix_ms: 1,
            attempt_completed_unix_ms: 2,
        },
        event,
        FilterResult::NotApplied,
        &config,
    )
    .unwrap();

    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("owners=1,2,3"));
    assert!(output.contains("64,+1"));
    assert!(!output.contains(",65"));
    assert!(output.contains(&format!("label={}…", "x".repeat(31))));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the complete schema contract keeps every field and event-side rule explicit"
)]
fn endpoint_event_shapes_pin_previous_and_current_sides() {
    let mut previous = snapshot();
    let mut current = snapshot();
    previous.sockets[0].socket_token =
        Some(crate::observation::PlatformSocketToken::linux_inode(11).unwrap());
    current.sockets[0].socket_token =
        Some(crate::observation::PlatformSocketToken::macos_socket_id(12).unwrap());
    let current_identity = crate::observation::ProcessIdentity {
        pid: 20_000,
        start_marker: crate::observation::ProcessStartMarker::linux(20_001).unwrap(),
    };
    current.sockets[0].owners = vec![OwnerObservation::Verified(current_identity)];
    previous
        .processes
        .values_mut()
        .for_each(|process| process.command_line = Some("private previous command".into()));
    current
        .processes
        .values_mut()
        .for_each(|process| process.command_line = Some("private current command".into()));
    let previous_owner = serde_json::json!({
        "owners": [{
            "kind": "verified",
            "identity": {
                "pid": 18_422,
                "start_marker": {"kind": "linux_start_ticks", "ticks": 18_423}
            }
        }],
        "omitted_owner_count": 0,
        "completeness": "complete",
        "reasons": []
    });
    let current_owner = serde_json::json!({
        "owners": [{
            "kind": "verified",
            "identity": {
                "pid": 20_000,
                "start_marker": {"kind": "linux_start_ticks", "ticks": 20_001}
            }
        }],
        "omitted_owner_count": 0,
        "completeness": "complete",
        "reasons": []
    });
    let cases = [
        (
            EventKind::Baseline,
            None,
            Some(&current.sockets[0]),
            serde_json::Value::Null,
            current_owner.clone(),
            serde_json::Value::Null,
            serde_json::json!({"kind": "macos_socket_id", "value": 12}),
        ),
        (
            EventKind::Bind,
            None,
            Some(&current.sockets[0]),
            serde_json::Value::Null,
            current_owner.clone(),
            serde_json::Value::Null,
            serde_json::json!({"kind": "macos_socket_id", "value": 12}),
        ),
        (
            EventKind::Release,
            Some(&previous.sockets[0]),
            None,
            previous_owner.clone(),
            serde_json::Value::Null,
            serde_json::json!({"kind": "linux_inode", "value": 11}),
            serde_json::Value::Null,
        ),
        (
            EventKind::Replacement,
            Some(&previous.sockets[0]),
            Some(&current.sockets[0]),
            previous_owner.clone(),
            current_owner.clone(),
            serde_json::json!({"kind": "linux_inode", "value": 11}),
            serde_json::json!({"kind": "macos_socket_id", "value": 12}),
        ),
    ];

    for (
        kind,
        previous_socket,
        current_socket,
        expected_previous_owners,
        expected_current_owners,
        expected_previous_token,
        expected_current_token,
    ) in cases
    {
        let observation = ObservationTimes {
            previous_completed_unix_ms: (kind != EventKind::Baseline).then_some(1),
            attempt_started_unix_ms: 2,
            attempt_completed_unix_ms: 3,
        };
        let event = WatchEvent {
            kind,
            previous_snapshot: (kind != EventKind::Baseline).then_some(&previous),
            current_snapshot: Some(&current),
            previous_socket,
            current_socket,
            multiplicity: 1,
            certainty: if kind == EventKind::Replacement {
                Certainty::Heuristic
            } else {
                Certainty::Proven
            },
        };
        let mut output = Vec::new();
        super::write_endpoint_event(
            &mut output,
            true,
            7,
            observation,
            event,
            FilterResult::Matched,
            &[],
            &Config::default(),
            Some(&GapIndex::new(&previous)),
            Some(&GapIndex::new(&current)),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let certainty = if kind == EventKind::Replacement {
            "heuristic"
        } else {
            "proven"
        };
        let evidence = if kind == EventKind::Replacement {
            serde_json::json!([{
                "code": "process_identity_changed",
                "source": "analysis",
                "certainty": "proven",
                "message": "verified process identity changed between observations"
            }])
        } else {
            serde_json::json!([])
        };
        assert_eq!(
            value,
            serde_json::json!({
                "schema": "kickoutchi.watch_event",
                "version": 1,
                "sequence": 7,
                "event": kind.name(),
                "observation": {
                    "previous_completed_unix_ms": observation.previous_completed_unix_ms,
                    "attempt_started_unix_ms": 2,
                    "attempt_completed_unix_ms": 3
                },
                "data": {
                    "endpoint": {
                        "protocol": "tcp",
                        "address": "127.0.0.1",
                        "port": 3000,
                        "ipv6_scope": null
                    },
                    "state": {"kind": "listen", "native_code": null},
                    "previous_owners": expected_previous_owners,
                    "current_owners": expected_current_owners,
                    "previous_socket_token": expected_previous_token,
                    "current_socket_token": expected_current_token,
                    "multiplicity": 1,
                    "label": null,
                    "filter_result": "matched",
                    "certainty": certainty,
                    "evidence": evidence,
                    "omitted_evidence_count": 0,
                    "evidence_gaps": [],
                    "omitted_evidence_gap_count": 0
                }
            })
        );
        let rendered = String::from_utf8(output).unwrap();
        assert!(!rendered.contains("command_line"));
        assert!(!rendered.contains("private previous command"));
        assert!(!rendered.contains("private current command"));
    }
}

#[test]
fn collection_gap_shape_is_fully_pinned() {
    let result = Err(ObservationError::SocketTableUnavailable.into());
    let gap = super::gap_from_result(&result, 2);
    let observation = ObservationTimes {
        previous_completed_unix_ms: Some(10),
        attempt_started_unix_ms: 11,
        attempt_completed_unix_ms: 12,
    };
    let mut output = Vec::new();

    super::write_gap(&mut output, true, 9, observation, &gap).unwrap();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "schema": "kickoutchi.watch_event",
            "version": 1,
            "sequence": 9,
            "event": "collection_gap",
            "observation": {
                "previous_completed_unix_ms": 10,
                "attempt_started_unix_ms": 11,
                "attempt_completed_unix_ms": 12
            },
            "data": {
                "error": {
                    "code": "socket_table_unavailable",
                    "message": "socket table is unavailable"
                },
                "certainty": "unknown",
                "consecutive_failures": 2,
                "completeness": null,
                "evidence_gaps": [],
                "omitted_evidence_gap_count": 0
            }
        })
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the maximum schema fixture keeps every bounded field visible"
)]
fn fully_populated_replacement_record_stays_within_its_calculated_bound() {
    let snapshot = snapshot();
    let endpoint = &snapshot.sockets[0].local_endpoint;
    let owners = (0..crate::observation::SERIALIZED_OWNERS_MAX)
        .map(|offset| {
            OwnerObservation::Verified(crate::observation::ProcessIdentity {
                pid: u32::MAX - u32::try_from(offset).unwrap(),
                start_marker: crate::observation::ProcessStartMarker::windows(
                    u64::MAX - u64::try_from(offset).unwrap(),
                )
                .unwrap(),
            })
        })
        .collect::<Vec<_>>();
    let owner_completeness = OwnerCompleteness::partial([
        EvidenceGapCode::NativeFieldUnavailable,
        EvidenceGapCode::NoncriticalEvidenceTruncated,
        EvidenceGapCode::ObservationRaced,
        EvidenceGapCode::OwnerAttributionIncomplete,
        EvidenceGapCode::OwnerDisappeared,
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::ProcessIdentityUnavailable,
        EvidenceGapCode::ProcessMetadataUnavailable,
    ])
    .unwrap();
    let owner_set = || super::OwnerSetDto::new(&owners, &owner_completeness).unwrap();
    let escaped_message = "\\".repeat(512);
    let evidence = (0..crate::watch::WATCH_EVENT_EVIDENCE_MAX)
        .map(|_| {
            super::EvidenceDto::literal(
                "process_identity_changed",
                "analysis",
                "heuristic",
                &escaped_message,
            )
        })
        .collect();
    let gaps = (0..crate::watch::WATCH_EVENT_GAPS_MAX)
        .map(|offset| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                Some(endpoint.clone()),
                Some(u32::MAX - u32::try_from(offset).unwrap()),
                &escaped_message,
            )
        })
        .collect::<Vec<_>>();
    let evidence_gaps = gaps.iter().map(super::EvidenceGapDto::from).collect();
    let label = "x".repeat(128);
    let data = super::EndpointEventData {
        endpoint: super::EndpointDto::from(endpoint),
        state: super::SocketStateDto::from(snapshot.sockets[0].state),
        previous_owners: Some(owner_set()),
        current_owners: Some(owner_set()),
        previous_socket_token: Some(super::SocketTokenDto::from(
            crate::observation::PlatformSocketToken::macos_socket_id(u64::MAX).unwrap(),
        )),
        current_socket_token: Some(super::SocketTokenDto::from(
            crate::observation::PlatformSocketToken::macos_socket_id(u64::MAX).unwrap(),
        )),
        multiplicity: u32::MAX,
        label: Some(&label),
        filter_result: "indeterminate",
        certainty: "heuristic",
        evidence,
        omitted_evidence_count: u64::MAX,
        evidence_gaps,
        omitted_evidence_gap_count: u64::MAX,
    };
    let record = super::WatchRecord {
        schema: "kickoutchi.watch_event",
        version: 1,
        sequence: u64::MAX,
        event: "replacement",
        observation: ObservationTimes {
            previous_completed_unix_ms: Some(u64::MAX),
            attempt_started_unix_ms: u64::MAX,
            attempt_completed_unix_ms: u64::MAX,
        },
        data,
    };
    let mut output = Vec::new();

    super::write_json_record(&mut output, &record).unwrap();

    assert!(output.len() <= 52_224, "record was {} bytes", output.len());
    assert!(output.len() <= crate::watch::WATCH_RECORD_MAX_BYTES);
    assert_eq!(output.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["event"], "replacement");
    assert_eq!(
        value["data"]["previous_owners"]["owners"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        value["data"]["current_owners"]["owners"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(value["data"]["evidence"].as_array().unwrap().len(), 8);
    assert_eq!(value["data"]["evidence_gaps"].as_array().unwrap().len(), 8);
}

#[test]
fn gap_index_and_record_writer_enforce_exact_bounds() {
    let mut snapshot = snapshot();
    snapshot.evidence_gaps = (0..9)
        .map(|_| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                None,
                "metadata unavailable",
            )
        })
        .collect();
    let index = GapIndex::new(&snapshot);
    assert_eq!(index.global.indices.len(), 8);
    assert_eq!(index.global.total, 9);

    snapshot.evidence_gaps = (42..=51)
        .map(|pid| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                Some(pid),
                "metadata unavailable",
            )
        })
        .collect();
    snapshot.sockets[0].owners = (42..=50)
        .map(|pid| OwnerObservation::UnverifiedPid {
            pid,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        })
        .collect();
    let index = GapIndex::new(&snapshot);
    assert_eq!(index.global.total, 0);
    assert_eq!(index.by_pid[&42].total, 1);
    let mut applicable = Vec::new();
    let mut applicable_total = 0;
    index.append(
        &snapshot,
        &snapshot.sockets[0],
        OwnerPidConstraint::Any,
        &mut applicable,
        &mut applicable_total,
    );
    assert_eq!(applicable_total, 9);
    assert_eq!(applicable.len(), 8);
    assert_eq!(applicable[0].pid, Some(42));
    assert_eq!(applicable[7].pid, Some(49));

    let descending = (42..=50)
        .rev()
        .map(|pid| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                Some(pid),
                "metadata unavailable",
            )
        })
        .collect::<Vec<_>>();
    let mut retained = Vec::with_capacity(8);
    for gap in &descending {
        super::retain_bounded_gap(&mut retained, gap);
    }
    assert_eq!(retained.len(), 8);
    assert_eq!(retained[0].pid, Some(42));
    assert_eq!(retained[7].pid, Some(49));

    snapshot.sockets[0].owner_completeness = OwnerCompleteness::partial([
        EvidenceGapCode::OwnerPermissionDenied,
        EvidenceGapCode::OwnerAttributionIncomplete,
    ])
    .unwrap();
    let owner_set = super::OwnerSetDto::new(
        &snapshot.sockets[0].owners,
        &snapshot.sockets[0].owner_completeness,
    )
    .unwrap();
    let owner_set = serde_json::to_value(owner_set).unwrap();
    assert_eq!(
        owner_set["reasons"],
        serde_json::json!(["owner_attribution_incomplete", "owner_permission_denied"])
    );

    let mut record = BoundedRecord::new();
    assert_eq!(record.write(&vec![0; 65_536]).unwrap(), 65_536);
    assert!(record.write(&[0]).is_err());
    assert_eq!(record.bytes.len(), 65_536);
}

#[test]
fn event_evidence_retains_zero_maximum_and_counts_the_first_omission() {
    for (count, retained, omitted) in [
        (0, 0, 0),
        (
            crate::watch::WATCH_EVENT_EVIDENCE_MAX,
            crate::watch::WATCH_EVENT_EVIDENCE_MAX,
            0,
        ),
        (
            crate::watch::WATCH_EVENT_EVIDENCE_MAX + 1,
            crate::watch::WATCH_EVENT_EVIDENCE_MAX,
            1,
        ),
    ] {
        let evidence = (0..count)
            .map(|_| {
                super::EvidenceDto::literal("fixture", "analysis", "proven", "fixture evidence")
            })
            .collect();
        let (evidence, actual_omitted) = super::retain_event_evidence(evidence);
        assert_eq!(evidence.len(), retained, "count={count}");
        assert_eq!(actual_omitted, omitted, "count={count}");
    }
}
