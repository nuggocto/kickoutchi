use std::collections::HashMap;
use std::io;
use std::num::NonZeroU64;
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::diagnostic::verdict::Evidence;
use crate::labels::{LabelInput, LabelRegistry};
use crate::observation::{
    EvidenceGap, EvidenceGapCode, EvidenceImpact, ObservationScope, ObservationScopeKind,
    OwnerCompleteness, ScopeLimitation, SnapshotCompleteness, SocketObservation, SocketState,
};
use crate::probe::ProbeOutcome;

fn args() -> WhyArgs {
    WhyArgs {
        port: 3000,
        tcp: false,
        udp: false,
        all_protocols: false,
        address: None,
        all_addresses: false,
        scope_id: None,
        ipv6_only: false,
        dual_stack: false,
        reuse_address: false,
        json: false,
    }
}

fn snapshot() -> NetworkSnapshot {
    let captured = UNIX_EPOCH + Duration::from_secs(10);
    NetworkSnapshot {
        capture_started_at: captured,
        capture_completed_at: captured,
        scope: ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
            Some("net:[1]"),
            [],
        )
        .expect("test scope is valid"),
        completeness: SnapshotCompleteness::Complete,
        owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
        sockets: Vec::new(),
        processes: HashMap::new(),
    }
}

struct FakeRuntime {
    snapshot: NetworkSnapshot,
    collect_error: bool,
    outcomes: Vec<ProbeOutcome>,
    collect_profiles: Vec<MetadataProfile>,
    probes: usize,
    clock_calls: u64,
    raw_os_error: Option<i32>,
    os_error_message: Option<Box<str>>,
}

impl FakeRuntime {
    fn new(outcomes: Vec<ProbeOutcome>) -> Self {
        Self {
            snapshot: snapshot(),
            collect_error: false,
            outcomes,
            collect_profiles: Vec::new(),
            probes: 0,
            clock_calls: 0,
            raw_os_error: None,
            os_error_message: None,
        }
    }
}

impl WhyRuntime for FakeRuntime {
    fn collect(&mut self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        self.collect_profiles.push(profile);
        if self.collect_error {
            Err(crate::observation::ObservationError::SocketTableUnavailable.into())
        } else {
            Ok(self.snapshot.clone())
        }
    }

    fn now(&mut self) -> SystemTime {
        self.clock_calls += 1;
        UNIX_EPOCH + Duration::from_millis(20_000 + self.clock_calls)
    }

    fn probe(&mut self, _request: ProbeRequest) -> ProbeResult {
        let outcome = self.outcomes[self.probes];
        self.probes += 1;
        ProbeResult {
            outcome,
            raw_os_error: self.raw_os_error,
            os_error_message: self.os_error_message.clone(),
        }
    }
}

struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FlushWriter {
    kind: ErrorKind,
}

impl Write for FlushWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(self.kind))
    }
}

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    flushes: usize,
}

impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

struct MidstreamErrorWriter {
    successful_writes: usize,
    attempts: usize,
    kind: ErrorKind,
}

impl Write for MidstreamErrorWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.attempts += 1;
        if self.attempts > self.successful_writes {
            Err(io::Error::new(self.kind, "injected midstream failure"))
        } else {
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn bare_query_is_the_two_tcp_loopback_endpoints() {
    let options = WhyOptions::parse(&args()).expect("default query is valid");

    assert_eq!(options.protocols, vec![Protocol::Tcp]);
    assert_eq!(
        options.addresses,
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        ]
    );
    assert_eq!(options.endpoints.len(), 2);
}

/// `--tcp` names the same protocol the bare query defaults to, so a version
/// that ignored the flag would still pass the test above. Asserting each
/// selector on its own is what catches a `--tcp` that stopped being read.
#[test]
fn every_protocol_selector_is_read_independently_of_the_default() {
    for (input, expected) in [
        (
            WhyArgs {
                tcp: true,
                ..args()
            },
            vec![Protocol::Tcp],
        ),
        (
            WhyArgs {
                udp: true,
                ..args()
            },
            vec![Protocol::Udp],
        ),
        (
            WhyArgs {
                all_protocols: true,
                ..args()
            },
            vec![Protocol::Tcp, Protocol::Udp],
        ),
        (args(), vec![Protocol::Tcp]),
    ] {
        let options = WhyOptions::parse(&input).expect("protocol selector is valid");
        assert_eq!(options.protocols, expected);
    }
}

#[test]
fn expanded_query_is_the_canonical_eight_endpoint_matrix() {
    let mut input = args();
    input.all_protocols = true;
    input.all_addresses = true;

    let options = WhyOptions::parse(&input).expect("maximum matrix is valid");

    assert_eq!(options.protocols, vec![Protocol::Tcp, Protocol::Udp]);
    assert_eq!(
        options.addresses,
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ]
    );
    assert_eq!(options.endpoints.len(), WHY_ENDPOINTS_MAX);
}

#[test]
fn endpoint_count_accepts_only_the_contract_range() {
    assert!(endpoint_count(0, 1).is_err());
    assert_eq!(
        endpoint_count(2, WHY_ENDPOINTS_MAX / 2).unwrap(),
        WHY_ENDPOINTS_MAX
    );
    assert!(endpoint_count(1, WHY_ENDPOINTS_MAX + 1).is_err());
    assert!(endpoint_count(usize::MAX, 2).is_err());
}

#[test]
fn port_scope_and_address_boundaries_are_validated_exactly() {
    assert!(WhyOptions::parse(&WhyArgs { port: 1, ..args() }).is_ok());
    assert!(
        WhyOptions::parse(&WhyArgs {
            port: 65_535,
            ..args()
        })
        .is_ok()
    );
    assert!(WhyOptions::parse(&WhyArgs { port: 0, ..args() }).is_err());
    let scoped = WhyArgs {
        address: Some("fe80::1".to_owned()),
        scope_id: Some(u32::MAX),
        ..args()
    };
    assert!(WhyOptions::parse(&scoped).is_ok());
    assert!(
        WhyOptions::parse(&WhyArgs {
            scope_id: Some(0),
            ..scoped
        })
        .is_err()
    );

    let oversized = WhyArgs {
        address: Some("1".repeat(SELECTOR_ADDRESS_MAX_BYTES + 1)),
        ..args()
    };
    assert_eq!(
        WhyOptions::parse(&oversized).expect_err("oversized address must fail"),
        "address exceeds the 64-byte limit"
    );
}

#[test]
fn invalid_queries_are_rejected_before_collection_or_probing() {
    let invalid = [
        WhyArgs { port: 0, ..args() },
        WhyArgs {
            address: Some("127.0.0.1".to_owned()),
            scope_id: Some(3),
            ..args()
        },
        WhyArgs {
            address: Some("fe80::1%3".to_owned()),
            ..args()
        },
        WhyArgs {
            all_addresses: true,
            ipv6_only: true,
            ..args()
        },
    ];

    for input in invalid {
        let mut runtime = FakeRuntime::new(Vec::new());
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::InvalidArguments);
        assert!(output.is_empty());
        assert!(!diagnostics.is_empty());
        assert!(runtime.collect_profiles.is_empty());
        assert_eq!(runtime.probes, 0);
    }
}

#[test]
fn collection_failure_happens_before_probes_or_output() {
    let mut runtime = FakeRuntime::new(Vec::new());
    runtime.collect_error = true;
    let mut output = RecordingWriter::default();
    let mut diagnostics = Vec::new();

    let reason = run_why_with(
        &args(),
        &Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(reason, ExitReason::Failure);
    assert_eq!(runtime.collect_profiles, [MetadataProfile::Display]);
    assert_eq!(runtime.probes, 0);
    assert_eq!(runtime.clock_calls, 0);
    assert!(output.bytes.is_empty());
    assert!(
        String::from_utf8(diagnostics)
            .unwrap()
            .contains("collecting endpoint evidence failed")
    );
}

#[test]
fn orchestration_collects_display_once_and_probes_each_endpoint_sequentially() {
    let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow, ProbeOutcome::BindableNow]);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let reason = run_why_with(
        &args(),
        &Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );

    assert_eq!(reason, ExitReason::Success);
    assert_eq!(runtime.collect_profiles, vec![MetadataProfile::Display]);
    assert_eq!(runtime.probes, 2);
    assert_eq!(runtime.clock_calls, 4);
    assert!(diagnostics.is_empty());
    assert!(
        String::from_utf8(output)
            .expect("human output is UTF-8")
            .contains("bindable_now")
    );
}

#[test]
fn aggregate_precedence_is_failure_then_permission_then_unavailable_then_success() {
    assert_eq!(
        aggregate_exit([Verdict::BindableNow, Verdict::Owned]),
        ExitReason::NoMatch
    );
    assert_eq!(
        aggregate_exit([Verdict::Owned, Verdict::PermissionDenied]),
        ExitReason::PermissionDenied
    );
    assert_eq!(
        aggregate_exit([Verdict::PermissionDenied, Verdict::Indeterminate]),
        ExitReason::Failure
    );
    assert_eq!(
        aggregate_exit([Verdict::BindableNow, Verdict::BindableNow]),
        ExitReason::Success
    );

    for (verdict, expected) in [
        (Verdict::BindableNow, ExitReason::Success),
        (Verdict::Owned, ExitReason::NoMatch),
        (Verdict::OwnerHidden, ExitReason::NoMatch),
        (Verdict::KernelStateObserved, ExitReason::NoMatch),
        (Verdict::PermissionDenied, ExitReason::PermissionDenied),
        (Verdict::AddressUnavailable, ExitReason::NoMatch),
        (Verdict::ReservationOrPolicyUnknown, ExitReason::NoMatch),
        (Verdict::ObservationRaced, ExitReason::Failure),
        (Verdict::Unsupported, ExitReason::NoMatch),
        (Verdict::Indeterminate, ExitReason::Failure),
    ] {
        assert_eq!(aggregate_exit([verdict]), expected, "verdict {verdict:?}");
    }
}

#[test]
fn broken_stdout_preserves_each_computed_aggregate_exit() {
    for (outcome, expected) in [
        (ProbeOutcome::BindableNow, ExitReason::Success),
        (ProbeOutcome::Other, ExitReason::Failure),
        (ProbeOutcome::Unsupported, ExitReason::NoMatch),
        (ProbeOutcome::PermissionDenied, ExitReason::PermissionDenied),
    ] {
        let mut input = args();
        input.address = Some("127.0.0.1".to_owned());
        let mut runtime = FakeRuntime::new(vec![outcome]);
        let mut diagnostics = Vec::new();

        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut BrokenWriter,
            &mut diagnostics,
        );

        assert_eq!(reason, expected, "outcome {outcome:?}");
        assert!(diagnostics.is_empty());
        assert_eq!(runtime.probes, 1);
    }
}

#[test]
fn every_endpoint_is_evaluated_before_broken_output_is_observed() {
    let mut input = args();
    input.all_protocols = true;
    input.all_addresses = true;
    let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported; WHY_ENDPOINTS_MAX]);
    let mut diagnostics = Vec::new();

    let reason = run_why_with(
        &input,
        &Config::default(),
        &mut runtime,
        &mut BrokenWriter,
        &mut diagnostics,
    );

    assert_eq!(reason, ExitReason::NoMatch);
    assert_eq!(runtime.probes, WHY_ENDPOINTS_MAX);
    assert_eq!(
        runtime.clock_calls,
        u64::try_from(WHY_ENDPOINTS_MAX * 2).unwrap()
    );
    assert!(diagnostics.is_empty());
}

#[test]
fn broken_flush_preserves_the_aggregate_but_other_writer_failures_do_not() {
    let mut input = args();
    input.address = Some("127.0.0.1".to_owned());
    let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
    let mut diagnostics = Vec::new();
    let reason = run_why_with(
        &input,
        &Config::default(),
        &mut runtime,
        &mut FlushWriter {
            kind: ErrorKind::BrokenPipe,
        },
        &mut diagnostics,
    );
    assert_eq!(reason, ExitReason::NoMatch);
    assert!(diagnostics.is_empty());

    let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow]);
    let mut diagnostics = Vec::new();
    let reason = run_why_with(
        &input,
        &Config::default(),
        &mut runtime,
        &mut FlushWriter {
            kind: ErrorKind::Other,
        },
        &mut diagnostics,
    );
    assert_eq!(reason, ExitReason::Failure);
    assert!(
        String::from_utf8(diagnostics)
            .expect("diagnostic is UTF-8")
            .contains("writing why output failed")
    );
}

#[test]
fn human_and_pretty_json_are_written_and_flushed() {
    for json in [false, true] {
        let mut input = args();
        input.address = Some("127.0.0.1".to_owned());
        input.json = json;
        let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow]);
        let mut output = RecordingWriter::default();
        let mut diagnostics = Vec::new();

        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::Success, "json={json}");
        assert_eq!(output.flushes, 1, "json={json}");
        assert!(!output.bytes.is_empty());
        assert!(diagnostics.is_empty());
    }
}

#[test]
fn midstream_writer_errors_preserve_only_broken_pipe_aggregate() {
    for json in [false, true] {
        for (kind, expected) in [
            (ErrorKind::BrokenPipe, ExitReason::NoMatch),
            (ErrorKind::Other, ExitReason::Failure),
        ] {
            let mut input = args();
            input.address = Some("127.0.0.1".to_owned());
            input.json = json;
            let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
            let mut output = MidstreamErrorWriter {
                successful_writes: 3,
                attempts: 0,
                kind,
            };
            let mut diagnostics = Vec::new();

            let reason = run_why_with(
                &input,
                &Config::default(),
                &mut runtime,
                &mut output,
                &mut diagnostics,
            );

            assert_eq!(reason, expected, "json={json}, kind={kind:?}");
            if kind == ErrorKind::BrokenPipe {
                assert!(diagnostics.is_empty());
            } else {
                assert!(
                    String::from_utf8(diagnostics)
                        .expect("diagnostic is UTF-8")
                        .contains("writing why output failed")
                );
            }
        }
    }
}

#[test]
fn maximum_quote_heavy_json_shape_can_exceed_the_old_document_cap() {
    let mut input = args();
    input.all_protocols = true;
    input.all_addresses = true;
    input.json = true;
    let options = WhyOptions::parse(&input).expect("maximum query is valid");
    let quote_heavy = "\"".repeat(PUBLIC_MESSAGE_MAX_BYTES);
    let completed = options
        .endpoints
        .iter()
        .map(|requested| CompletedResult {
            verdict: VerdictResult {
                endpoint: requested.identity.clone(),
                label: Some(quote_heavy.clone()),
                verdict: Verdict::Indeterminate,
                certainty: crate::watch::Certainty::Unknown,
                evidence: (0..crate::diagnostic::verdict::WHY_EVIDENCE_MAX)
                    .map(|_| Evidence {
                        code: crate::diagnostic::verdict::EvidenceCode::ExactBindOtherError,
                        source: crate::diagnostic::verdict::EvidenceSource::Analysis,
                        certainty: crate::watch::Certainty::Unknown,
                        message: quote_heavy.clone(),
                    })
                    .collect(),
                omitted_evidence_count: 0,
                evidence_gaps: (0..crate::diagnostic::verdict::WHY_EVIDENCE_GAPS_MAX)
                    .map(|_| {
                        EvidenceGap::new(
                            EvidenceImpact::Metadata,
                            EvidenceGapCode::ProcessMetadataUnavailable,
                            Some(requested.identity.clone()),
                            None,
                            &quote_heavy,
                        )
                    })
                    .collect(),
                omitted_evidence_gap_count: 0,
            },
            probe: TimedProbe {
                result: ProbeResult {
                    outcome: ProbeOutcome::Other,
                    raw_os_error: None,
                    os_error_message: Some(quote_heavy.clone().into_boxed_str()),
                },
                capture: CaptureDto::new(
                    UNIX_EPOCH + Duration::from_millis(20_001),
                    UNIX_EPOCH + Duration::from_millis(20_002),
                )
                .expect("test probe interval is valid"),
            },
        })
        .collect::<Vec<_>>();
    let mut output = RecordingWriter::default();

    let aggregate = aggregate_exit(completed.iter().map(|result| result.verdict.verdict));
    render_document(&mut output, &options, &snapshot(), &completed, aggregate)
        .expect("maximum legal JSON shape renders");

    assert_eq!(completed.len(), WHY_ENDPOINTS_MAX);
    assert!(
        output.bytes.len() > 256 * 1024,
        "bytes={}",
        output.bytes.len()
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.bytes).expect("output is valid JSON");
    assert_eq!(
        value["results"].as_array().map(Vec::len),
        Some(WHY_ENDPOINTS_MAX)
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the schema contract asserts every envelope and nested result field"
)]
fn json_contract_has_exact_envelope_and_omits_command_lines() {
    let mut input = args();
    input.address = Some("fe80::1".to_owned());
    input.scope_id = Some(3);
    input.json = true;
    let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow]);
    let endpoint = EndpointIdentity::new(
        Protocol::Tcp,
        "fe80::1".parse().expect("literal is valid"),
        3000,
        Some(Ipv6Scope::InterfaceIndex(
            NonZeroU32::new(3).expect("scope is nonzero"),
        )),
    )
    .expect("endpoint is valid");
    runtime.snapshot.completeness = SnapshotCompleteness::Partial;
    runtime.snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Scope,
        EvidenceGapCode::NativeFieldUnavailable,
        Some(endpoint),
        None,
        "scope detail is unavailable",
    ));
    runtime.snapshot.omitted_evidence_gap_count = 2;
    let config = Config {
        labels: LabelRegistry::from_inputs(vec![LabelInput {
            protocol: "tcp".to_owned(),
            address: "fe80::1".to_owned(),
            port: 3000,
            scope_id: Some(3),
            label: "scoped fixture".to_owned(),
        }])
        .expect("label config is valid"),
        ..Config::default()
    };
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let reason = run_why_with(&input, &config, &mut runtime, &mut output, &mut diagnostics);

    assert_eq!(reason, ExitReason::Success);
    assert!(diagnostics.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&output).expect("why output is valid JSON");
    let mut keys = value
        .as_object()
        .expect("why envelope is an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "aggregate_exit_code",
            "capture",
            "completeness",
            "owner_completeness",
            "query",
            "results",
            "schema",
            "scope",
            "version",
        ]
    );
    assert_eq!(value["schema"], "kickoutchi.why");
    assert_eq!(value["version"], 1);
    assert_eq!(value["aggregate_exit_code"], 0);
    assert_eq!(value["results"][0]["verdict"], "bindable_now");
    assert_eq!(value["completeness"], "partial");
    assert_eq!(value["results"][0]["label"], "scoped fixture");
    assert_object_keys(
        &value["query"],
        &[
            "port",
            "protocols",
            "addresses",
            "scope_id",
            "ipv6_mode",
            "reuse_address",
        ],
    );
    assert_object_keys(&value["capture"], &["started_unix_ms", "completed_unix_ms"]);
    assert_object_keys(&value["scope"], &["kind", "identifier", "limitations"]);
    assert_object_keys(
        &value["results"][0],
        &[
            "endpoint",
            "label",
            "verdict",
            "certainty",
            "probe",
            "evidence",
            "omitted_evidence_count",
            "evidence_gaps",
            "omitted_evidence_gap_count",
        ],
    );
    assert_object_keys(
        &value["results"][0]["endpoint"],
        &["protocol", "address", "port", "ipv6_scope"],
    );
    assert_object_keys(
        &value["results"][0]["endpoint"]["ipv6_scope"],
        &["kind", "interface_index"],
    );
    assert_eq!(
        value["results"][0]["endpoint"]["ipv6_scope"]["kind"],
        "interface_index"
    );
    assert_eq!(
        value["results"][0]["endpoint"]["ipv6_scope"]["interface_index"],
        3
    );
    assert_object_keys(
        &value["results"][0]["probe"],
        &[
            "outcome",
            "started_unix_ms",
            "completed_unix_ms",
            "raw_os_error",
            "message",
        ],
    );
    assert_object_keys(
        &value["results"][0]["evidence"][0],
        &["code", "source", "certainty", "message"],
    );
    assert_object_keys(
        &value["results"][0]["evidence_gaps"][0],
        &[
            "code",
            "impact",
            "endpoint",
            "pid",
            "affected_pid_count",
            "message",
        ],
    );
    assert!(value["results"][0]["evidence_gaps"][0]["affected_pid_count"].is_null());
    assert_eq!(value["results"][0]["omitted_evidence_gap_count"], 2);
    assert!(
        !String::from_utf8(output)
            .expect("JSON is UTF-8")
            .contains("command_line")
    );
}

#[test]
fn privileged_ownerless_ipv4_result_reports_one_aggregate_gap_without_omission() {
    let mut input = args();
    input.address = Some("127.0.0.1".to_owned());
    input.json = true;
    let mut runtime = FakeRuntime::new(vec![ProbeOutcome::AddressInUse]);
    let endpoint =
        EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 3000, None)
            .expect("fixture endpoint is valid");
    runtime.snapshot.sockets.push(SocketObservation {
        local_endpoint: endpoint,
        state: SocketState::Listen,
        timer: None,
        owners: Vec::new(),
        owner_completeness: OwnerCompleteness::Complete,
        socket_token: None,
        local_uid: None,
    });
    runtime.snapshot.completeness = SnapshotCompleteness::Partial;
    runtime.snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
            .expect("one reason fits");
    runtime
        .snapshot
        .evidence_gaps
        .push(EvidenceGap::aggregate_for_pids(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            NonZeroU64::new(4_097).expect("fixture count is nonzero"),
            "permission denied for at least the reported number of PIDs",
        ));
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();

    let reason = run_why_with(
        &input,
        &Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output).expect("why output is valid JSON");
    let gaps = value["results"][0]["evidence_gaps"]
        .as_array()
        .expect("gap array");

    assert_eq!(reason, ExitReason::NoMatch);
    // Unreadable processes could hold the socket, so its owner is hidden.
    assert_eq!(value["results"][0]["verdict"], "owner_hidden");
    assert_eq!(value["results"][0]["certainty"], "unknown");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["code"], "owner_permission_denied");
    assert!(gaps[0]["pid"].is_null());
    assert_eq!(gaps[0]["affected_pid_count"], 4_097);
    assert_eq!(value["results"][0]["omitted_evidence_gap_count"], 0);
    assert!(diagnostics.is_empty());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "human and JSON output are compared across every result fact"
)]
fn human_and_json_renderers_carry_the_same_result_facts() {
    let mut json_input = args();
    json_input.address = Some("fe80::1".to_owned());
    json_input.scope_id = Some(3);
    json_input.json = true;
    let mut json_runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
    json_runtime.raw_os_error = Some(99);
    json_runtime.os_error_message = Some("unsupported fixture".into());
    json_runtime.snapshot.completeness = SnapshotCompleteness::Partial;
    json_runtime.snapshot.owner_completeness =
        OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
            .expect("one reason fits");
    json_runtime
        .snapshot
        .scope
        .limitations
        .push(ScopeLimitation::NativeFieldUnavailable);
    let endpoint = EndpointIdentity::new(
        Protocol::Tcp,
        "fe80::1".parse().expect("literal is valid"),
        3000,
        Some(Ipv6Scope::InterfaceIndex(
            NonZeroU32::new(3).expect("scope is nonzero"),
        )),
    )
    .expect("endpoint is valid");
    json_runtime.snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::Metadata,
        EvidenceGapCode::ProcessMetadataUnavailable,
        Some(endpoint.clone()),
        None,
        "fixture metadata gap",
    ));
    json_runtime.snapshot.evidence_gaps.push(EvidenceGap::new(
        EvidenceImpact::SocketSet,
        EvidenceGapCode::NativeFieldUnavailable,
        None,
        Some(77),
        "fixture socket gap",
    ));
    json_runtime.snapshot.omitted_evidence_gap_count = 2;
    let config = Config {
        labels: LabelRegistry::from_inputs(vec![LabelInput {
            protocol: "tcp".to_owned(),
            address: "fe80::1".to_owned(),
            port: 3000,
            scope_id: Some(3),
            label: "parity fixture".to_owned(),
        }])
        .expect("label config is valid"),
        ..Config::default()
    };
    let mut json_output = Vec::new();
    let mut diagnostics = Vec::new();
    let json_reason = run_why_with(
        &json_input,
        &config,
        &mut json_runtime,
        &mut json_output,
        &mut diagnostics,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json_output).expect("why output is valid JSON");

    let mut human_input = args();
    human_input.address = Some("fe80::1".to_owned());
    human_input.scope_id = Some(3);
    let mut human_runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
    human_runtime.raw_os_error = Some(99);
    human_runtime.os_error_message = Some("unsupported fixture".into());
    human_runtime.snapshot = json_runtime.snapshot.clone();
    let mut human_output = Vec::new();
    let human_reason = run_why_with(
        &human_input,
        &config,
        &mut human_runtime,
        &mut human_output,
        &mut diagnostics,
    );
    let human = String::from_utf8(human_output).expect("human output is UTF-8");

    assert_eq!(json_reason, human_reason);
    assert!(human.contains("tcp://[fe80::1%3]:3000"));
    assert!(human.contains("addresses=fe80::1 scope_id=3"));
    assert!(human.contains("ipv6_mode=system_default"));
    assert!(human.contains("snapshot=partial"));
    assert!(human.contains("ownership=partial"));
    assert!(human.contains("capture_started_unix_ms=10000"));
    assert!(human.contains("capture_completed_unix_ms=10000"));
    assert!(human.contains("scope kind=current_network_namespace"));
    assert!(human.contains("identifier=net:[1]"));
    assert!(human.contains("limitations=native_field_unavailable"));
    assert!(human.contains("label=parity fixture"));
    assert!(human.contains(&format!(
        "verdict={}",
        value["results"][0]["verdict"].as_str().unwrap()
    )));
    assert!(human.contains(&format!(
        "certainty={}",
        value["results"][0]["certainty"].as_str().unwrap()
    )));
    assert!(human.contains(&format!(
        "probe={}",
        value["results"][0]["probe"]["outcome"].as_str().unwrap()
    )));
    assert!(human.contains("raw_os_error=99"));
    assert!(human.contains("message=unsupported fixture"));
    assert!(human.contains("started_unix_ms=20001 completed_unix_ms=20002"));
    assert!(human.contains("evidence code=exact_bind_unsupported"));
    assert!(human.contains("source=bind_probe certainty=proven"));
    assert!(human.contains("gap code=process_metadata_unavailable impact=metadata"));
    assert!(human.contains("endpoint=tcp://[fe80::1%3]:3000 pid=-"));
    assert!(human.contains("message=fixture metadata gap"));
    assert!(human.contains("gap code=native_field_unavailable impact=socket_set"));
    assert!(human.contains("endpoint=- pid=77"));
    assert!(human.contains("omitted_evidence_count=0"));
    assert!(human.contains("omitted_evidence_gap_count=2"));
    assert!(human.contains(&format!(
        "aggregate_exit_code={}",
        value["aggregate_exit_code"]
    )));
}

#[test]
fn public_probe_messages_are_sanitized_and_clipped_on_utf8_boundaries() {
    for (message, expected) in [
        ("a".repeat(512), "a".repeat(512)),
        ("é".repeat(257), "é".repeat(256)),
        (
            format!("safe\x1b[2J{}", "b".repeat(513)),
            format!("safe{}", "b".repeat(508)),
        ),
    ] {
        let mut input = args();
        input.address = Some("127.0.0.1".to_owned());
        input.json = true;
        let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Other]);
        runtime.os_error_message = Some(message.into_boxed_str());
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("why output is valid JSON");
        let rendered = value["results"][0]["probe"]["message"]
            .as_str()
            .expect("probe message is present");

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(rendered, expected);
        assert_eq!(rendered.len(), PUBLIC_MESSAGE_MAX_BYTES);
        assert!(!rendered.contains('\x1b'));
        assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
        assert!(diagnostics.is_empty());
    }
}

#[test]
fn evidence_and_gap_messages_share_the_public_utf8_bound_in_both_formats() {
    let mut input = args();
    input.address = Some("127.0.0.1".to_owned());
    let mut options = WhyOptions::parse(&input).expect("query is valid");
    let endpoint = options.endpoints[0].identity.clone();
    let completed = vec![CompletedResult {
        verdict: VerdictResult {
            endpoint: endpoint.clone(),
            label: None,
            verdict: Verdict::Indeterminate,
            certainty: crate::watch::Certainty::Unknown,
            evidence: vec![Evidence {
                code: crate::diagnostic::verdict::EvidenceCode::ExactBindOtherError,
                source: crate::diagnostic::verdict::EvidenceSource::Analysis,
                certainty: crate::watch::Certainty::Unknown,
                message: "é".repeat(257),
            }],
            omitted_evidence_count: 0,
            evidence_gaps: vec![EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                Some(endpoint),
                None,
                &"\x01".repeat(171),
            )],
            omitted_evidence_gap_count: 0,
        },
        probe: TimedProbe {
            result: ProbeResult {
                outcome: ProbeOutcome::Other,
                raw_os_error: None,
                os_error_message: Some("a".repeat(513).into_boxed_str()),
            },
            capture: CaptureDto::new(
                UNIX_EPOCH + Duration::from_millis(20_001),
                UNIX_EPOCH + Duration::from_millis(20_002),
            )
            .expect("test probe interval is valid"),
        },
    }];
    options.json = true;
    let mut json = Vec::new();
    let aggregate = aggregate_exit(completed.iter().map(|result| result.verdict.verdict));
    render_document(&mut json, &options, &snapshot(), &completed, aggregate).expect("JSON renders");
    let value: serde_json::Value = serde_json::from_slice(&json).expect("why output is valid JSON");
    let evidence = value["results"][0]["evidence"][0]["message"]
        .as_str()
        .expect("evidence message is present");
    let gap = value["results"][0]["evidence_gaps"][0]["message"]
        .as_str()
        .expect("gap message is present");
    let probe = value["results"][0]["probe"]["message"]
        .as_str()
        .expect("probe message is present");

    assert_eq!(evidence, "é".repeat(256));
    assert_eq!(gap, crate::display::REPLACEMENT.to_string().repeat(170));
    assert_eq!(probe, "a".repeat(512));
    assert_eq!(evidence.len(), PUBLIC_MESSAGE_MAX_BYTES);
    assert_eq!(gap.len(), 510);
    assert_eq!(probe.len(), PUBLIC_MESSAGE_MAX_BYTES);

    options.json = false;
    let mut human = Vec::new();
    render_document(&mut human, &options, &snapshot(), &completed, aggregate)
        .expect("human output renders");
    let human = String::from_utf8(human).expect("human output is UTF-8");
    assert!(human.contains(evidence));
    assert!(human.contains(gap));
    assert!(human.contains(probe));
}

fn assert_object_keys(value: &serde_json::Value, expected: &[&str]) {
    let actual = value
        .as_object()
        .expect("contract value must be an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected.iter().copied().collect();
    assert_eq!(actual, expected);
}
