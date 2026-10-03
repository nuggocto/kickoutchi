use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::labels::{LabelInput, LabelRegistry};
use crate::observation::{MetadataOmission, ObservationScope};

fn identity(pid: u32, marker: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        start_marker: ProcessStartMarker::linux(marker).expect("nonzero fixture marker"),
    }
}

fn endpoint(port: u32) -> EndpointIdentity {
    EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
        .expect("valid fixture endpoint")
}

fn socket(port: u32, owners: Vec<OwnerObservation>) -> SocketObservation {
    SocketObservation {
        local_endpoint: endpoint(port),
        state: SocketState::Listen,
        timer: None,
        owners,
        owner_completeness: OwnerCompleteness::Complete,
        socket_token: None,
        local_uid: None,
    }
}

fn process(name: &str) -> ProcessObservation {
    ProcessObservation {
        name: Some(Arc::from(name)),
        executable_path: Some(std::path::PathBuf::from("/bin/worker").into()),
        command_line: Some(Arc::from("COMMAND_LINE_SENTINEL_7f2a")),
        parent_pid: Some(1),
        parent_process_name: Some(Arc::from("PARENT_NAME_SENTINEL_7f2a")),
        metadata_omission: Some(MetadataOmission::BudgetExceeded),
        metadata_completeness: MetadataCompleteness::Partial,
    }
}

fn snapshot(sockets: Vec<SocketObservation>) -> NetworkSnapshot {
    let mut processes = HashMap::new();
    for socket in &sockets {
        for owner in &socket.owners {
            if let OwnerObservation::Verified(identity) = owner {
                processes.insert(*identity, process(&format!("worker-{}", identity.pid)));
            }
        }
    }
    NetworkSnapshot {
        capture_started_at: UNIX_EPOCH + Duration::from_secs(10),
        capture_completed_at: UNIX_EPOCH + Duration::from_secs(11),
        scope: ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
            Some("net:[42]"),
            [],
        )
        .expect("valid fixture scope"),
        completeness: SnapshotCompleteness::Complete,
        owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
        sockets,
        processes,
    }
}

fn render(snapshot: &NetworkSnapshot, labels: &LabelRegistry) -> serde_json::Value {
    let mut output = Vec::new();
    write_snapshot_json(&mut output, snapshot, labels).expect("snapshot serializes");
    assert_eq!(output.last(), Some(&b'\n'));
    assert_ne!(output.get(output.len().saturating_sub(2)), Some(&b'\n'));
    serde_json::from_slice(&output).expect("valid JSON")
}

#[test]
fn snapshot_schema_omits_private_process_fields() {
    let identity = identity(7, 70);
    let value = render(
        &snapshot(vec![socket(
            3000,
            vec![OwnerObservation::Verified(identity)],
        )]),
        &LabelRegistry::default(),
    );
    assert_eq!(value["schema"], "kickoutchi.snapshot");
    assert_eq!(value["version"], 1);
    let process = &value["processes"][0];
    assert!(process.get("command_line").is_none());
    assert!(process.get("parent_process_name").is_none());
    assert!(process.get("metadata_omission").is_none());
    assert_eq!(process["metadata_completeness"], "partial");
    let rendered = serde_json::to_string(&value).expect("parsed value serializes");
    assert!(!rendered.contains("COMMAND_LINE_SENTINEL_7f2a"));
    assert!(!rendered.contains("PARENT_NAME_SENTINEL_7f2a"));
    assert!(!rendered.contains("budget_exceeded"));
}

#[test]
fn canonical_sorting_ignores_input_and_hash_map_order_and_puts_null_tokens_last() {
    let first = identity(2, 20);
    let second = identity(9, 90);
    let mut high = socket(
        9000,
        vec![
            OwnerObservation::UnverifiedPid {
                pid: 1,
                reason: UnverifiedOwnerReason::PermissionDenied,
            },
            OwnerObservation::Verified(second),
            OwnerObservation::Verified(first),
        ],
    );
    high.socket_token = None;
    let mut token_high = socket(3000, Vec::new());
    token_high.socket_token = Some(PlatformSocketToken::MacOsSocketId(
        NonZeroU64::new(1).expect("nonzero token"),
    ));
    let mut token_low = socket(3000, Vec::new());
    token_low.socket_token = Some(PlatformSocketToken::LinuxInode(
        NonZeroU64::new(9).expect("nonzero token"),
    ));
    let null = socket(3000, Vec::new());
    let value = render(
        &snapshot(vec![high, null, token_high, token_low]),
        &LabelRegistry::default(),
    );

    assert_eq!(value["sockets"][0]["socket_token"]["kind"], "linux_inode");
    assert_eq!(value["sockets"][0]["socket_token"]["value"], 9);
    assert_eq!(
        value["sockets"][1]["socket_token"]["kind"],
        "macos_socket_id"
    );
    assert!(value["sockets"][2]["socket_token"].is_null());
    assert_eq!(value["sockets"][3]["endpoint"]["port"], 9000);
    assert_eq!(
        value["sockets"][3]["owners"]["owners"][0]["identity"]["pid"],
        2
    );
    assert_eq!(
        value["sockets"][3]["owners"]["owners"][0]["kind"],
        "verified"
    );
    assert_eq!(value["processes"][0]["identity"]["pid"], 2);
    assert_eq!(value["processes"][1]["identity"]["pid"], 9);
}

#[test]
fn gaps_sort_by_public_key_after_sanitization() {
    let mut snapshot = snapshot(Vec::new());
    snapshot.evidence_gaps = vec![
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ScopeExcluded,
            None,
            Some(9),
            "z",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ScopeExcluded,
            Some(endpoint(9)),
            None,
            "specific",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ScopeExcluded,
            None,
            None,
            "global\nmessage",
        ),
    ];
    let value = render(&snapshot, &LabelRegistry::default());
    assert_eq!(
        value["evidence_gaps"][0]["endpoint"],
        serde_json::Value::Null
    );
    assert_eq!(value["evidence_gaps"][0]["message"], "global message");
    assert!(value["evidence_gaps"][0]["affected_pid_count"].is_null());
    assert_eq!(value["evidence_gaps"][1]["endpoint"]["port"], 9);
    assert_eq!(value["evidence_gaps"][2]["impact"], "metadata");
}

#[test]
fn aggregate_gap_count_is_public_and_part_of_canonical_order() {
    let aggregate = |count| {
        EvidenceGap::aggregate_for_pids(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            NonZeroU64::new(count).expect("fixture count is nonzero"),
            "at least the reported number of PIDs were denied",
        )
    };
    let mut snapshot = snapshot(Vec::new());
    snapshot.evidence_gaps = vec![aggregate(9), aggregate(2)];

    let value = render(&snapshot, &LabelRegistry::default());
    let gaps = value["evidence_gaps"].as_array().expect("gap array");

    assert_eq!(gaps[0]["pid"], serde_json::Value::Null);
    assert_eq!(gaps[0]["affected_pid_count"], 2);
    assert_eq!(gaps[1]["affected_pid_count"], 9);
}

#[test]
fn gap_order_uses_code_endpoint_pid_and_sanitized_message_ties() {
    let endpoint = endpoint(3000);
    let mut snapshot = snapshot(Vec::new());
    snapshot.evidence_gaps = vec![
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ScopeExcluded,
            Some(endpoint.clone()),
            Some(2),
            "\tZ",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            None,
            "first code",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ScopeExcluded,
            Some(endpoint.clone()),
            Some(2),
            "\nA",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ScopeExcluded,
            Some(endpoint),
            Some(1),
            "lower pid",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::ScopeExcluded,
            None,
            None,
            "global",
        ),
    ];

    let value = render(&snapshot, &LabelRegistry::default());
    let gaps = value["evidence_gaps"].as_array().expect("gap array");
    assert_eq!(gaps[0]["code"], "native_field_unavailable");
    assert!(gaps[1]["endpoint"].is_null());
    assert_eq!(gaps[2]["pid"], 1);
    assert_eq!(gaps[3]["message"], " A");
    assert_eq!(gaps[4]["message"], " Z");
}

#[test]
fn validated_labels_are_attached_without_filtering() {
    let labels = LabelRegistry::from_inputs(vec![LabelInput {
        protocol: "tcp".to_owned(),
        address: "127.0.0.1".to_owned(),
        port: 3000,
        scope_id: None,
        label: "web dev".to_owned(),
    }])
    .expect("valid label");
    let value = render(
        &snapshot(vec![socket(4000, Vec::new()), socket(3000, Vec::new())]),
        &labels,
    );
    assert_eq!(value["sockets"].as_array().map(Vec::len), Some(2));
    assert_eq!(value["sockets"][0]["label"], "web dev");
    assert!(value["sockets"][1]["label"].is_null());
}

#[test]
fn owner_output_is_capped_truthfully_and_race_reason_is_explicit() {
    let owners = (1..=SERIALIZED_OWNERS_MAX + 3)
        .rev()
        .map(|pid| {
            OwnerObservation::Verified(identity(
                u32::try_from(pid).expect("fixture PID"),
                u64::try_from(pid + 100).expect("fixture marker"),
            ))
        })
        .collect::<Vec<_>>();
    let mut socket = socket(3000, owners);
    socket.owner_completeness = OwnerCompleteness::Raced;
    let value = render(&snapshot(vec![socket]), &LabelRegistry::default());
    let owners = &value["sockets"][0]["owners"];
    assert_eq!(owners["owners"].as_array().map(Vec::len), Some(64));
    assert_eq!(owners["omitted_owner_count"], 3);
    assert_eq!(owners["completeness"], "raced");
    assert_eq!(owners["reasons"], serde_json::json!(["observation_raced"]));
}

#[test]
fn owner_count_boundaries_are_exact() {
    for (count, retained, omitted) in [(0, 0, 0), (1, 1, 0), (64, 64, 0), (65, 64, 1)] {
        let owners = (1..=count)
            .map(|pid| {
                OwnerObservation::Verified(identity(
                    u32::try_from(pid).expect("fixture PID"),
                    u64::try_from(pid + 100).expect("fixture marker"),
                ))
            })
            .collect::<Vec<_>>();
        let value = render(
            &snapshot(vec![socket(3000, owners)]),
            &LabelRegistry::default(),
        );
        let owner_set = &value["sockets"][0]["owners"];
        assert_eq!(owner_set["owners"].as_array().map(Vec::len), Some(retained));
        assert_eq!(owner_set["omitted_owner_count"], omitted);
    }
}

#[test]
fn reversed_snapshot_inputs_produce_identical_canonical_documents() {
    let owner = identity(42, 420);
    let mut first = socket(4000, vec![OwnerObservation::Verified(owner)]);
    first.state = SocketState::Established;
    first.socket_token = Some(PlatformSocketToken::LinuxInode(
        NonZeroU64::new(8).expect("nonzero token"),
    ));
    let mut second = socket(3000, Vec::new());
    second.owner_completeness = OwnerCompleteness::Partial {
        reasons: vec![
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerDisappeared,
        ],
    };

    let mut left = snapshot(vec![first.clone(), second.clone()]);
    left.evidence_gaps = vec![
        EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            None,
            Some(42),
            "z",
        ),
        EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            None,
            "a",
        ),
    ];
    let mut right = snapshot(vec![second, first]);
    right.evidence_gaps = left.evidence_gaps.iter().rev().cloned().collect();

    let mut left_output = Vec::new();
    let mut right_output = Vec::new();
    write_snapshot_json(&mut left_output, &left, &LabelRegistry::default())
        .expect("left snapshot serializes");
    write_snapshot_json(&mut right_output, &right, &LabelRegistry::default())
        .expect("right snapshot serializes");
    assert_eq!(left_output, right_output);
}

#[test]
fn socket_order_uses_state_token_owner_and_timer_tie_breakers() {
    let mut established = socket(3000, Vec::new());
    established.state = SocketState::Established;
    let listen = socket(3000, Vec::new());
    let value = render(
        &snapshot(vec![established, listen]),
        &LabelRegistry::default(),
    );
    assert_eq!(value["sockets"][0]["state"]["kind"], "listen");
    assert_eq!(value["sockets"][1]["state"]["kind"], "established");

    let mut no_token = socket(3000, Vec::new());
    no_token.socket_token = None;
    let mut macos_token = socket(3000, Vec::new());
    macos_token.socket_token = PlatformSocketToken::macos_socket_id(1);
    let mut linux_token = socket(3000, Vec::new());
    linux_token.socket_token = PlatformSocketToken::linux_inode(1);
    let value = render(
        &snapshot(vec![no_token, macos_token, linux_token]),
        &LabelRegistry::default(),
    );
    assert_eq!(value["sockets"][0]["socket_token"]["kind"], "linux_inode");
    assert_eq!(
        value["sockets"][1]["socket_token"]["kind"],
        "macos_socket_id"
    );
    assert!(value["sockets"][2]["socket_token"].is_null());

    let complete = socket(3000, Vec::new());
    let mut partial = socket(3000, Vec::new());
    partial.owner_completeness = OwnerCompleteness::Partial {
        reasons: vec![EvidenceGapCode::OwnerPermissionDenied],
    };
    let mut raced = socket(3000, Vec::new());
    raced.owner_completeness = OwnerCompleteness::Raced;
    let value = render(
        &snapshot(vec![raced, partial, complete]),
        &LabelRegistry::default(),
    );
    assert_eq!(value["sockets"][0]["owners"]["completeness"], "complete");
    assert_eq!(value["sockets"][1]["owners"]["completeness"], "partial");
    assert_eq!(value["sockets"][2]["owners"]["completeness"], "raced");

    let no_timer = socket(3000, Vec::new());
    let mut idle_timer = socket(3000, Vec::new());
    idle_timer.timer = Some(TcpTimerObservation::from_linux_native(0, 2, Some(100)));
    let mut retransmit_high = socket(3000, Vec::new());
    retransmit_high.timer = Some(TcpTimerObservation::from_linux_native(1, 2, Some(100)));
    let mut retransmit_low = socket(3000, Vec::new());
    retransmit_low.timer = Some(TcpTimerObservation::from_linux_native(1, 1, Some(100)));
    let value = render(
        &snapshot(vec![retransmit_high, retransmit_low, idle_timer, no_timer]),
        &LabelRegistry::default(),
    );
    assert!(value["sockets"][0]["timer"].is_null());
    assert_eq!(value["sockets"][1]["timer"]["kind"], "none");
    assert_eq!(value["sockets"][2]["timer"]["kind"], "retransmit");
    assert_eq!(value["sockets"][2]["timer"]["raw_ticks"], 1);
    assert_eq!(value["sockets"][3]["timer"]["raw_ticks"], 2);
}

#[test]
fn invalid_timer_fails_before_writing() {
    let mut socket = socket(3000, Vec::new());
    socket.timer = Some(TcpTimerObservation {
        kind: TcpTimerKind::Retransmit,
        native_code: Some(1),
        raw_ticks: 1,
        estimated_remaining_milliseconds: Some(10),
    });
    let snapshot = snapshot(vec![socket]);
    let mut output = Vec::new();
    assert!(matches!(
        write_snapshot_json(&mut output, &snapshot, &LabelRegistry::default()),
        Err(PublicOutputError::InvalidTimer),
    ));
    assert!(output.is_empty());
}

#[test]
fn owner_reason_limit_fails_before_writing() {
    let mut socket = socket(3000, Vec::new());
    socket.owner_completeness = OwnerCompleteness::Partial {
        reasons: vec![
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerDisappeared,
            EvidenceGapCode::ProcessIdentityUnavailable,
            EvidenceGapCode::ProcessMetadataUnavailable,
            EvidenceGapCode::NativeFieldUnavailable,
            EvidenceGapCode::ScopeExcluded,
            EvidenceGapCode::NoncriticalEvidenceTruncated,
            EvidenceGapCode::ObservationRaced,
        ],
    };
    let snapshot = snapshot(vec![socket]);
    let mut output = Vec::new();
    assert!(matches!(
        write_snapshot_json(&mut output, &snapshot, &LabelRegistry::default()),
        Err(PublicOutputError::OwnerReasonLimitExceeded),
    ));
    assert!(output.is_empty());
}

#[test]
fn timestamps_reject_pre_epoch_and_reversed_intervals() {
    assert!(matches!(
        CaptureDto::new(UNIX_EPOCH - Duration::from_millis(1), UNIX_EPOCH),
        Err(PublicOutputError::ClockUnavailable)
    ));
    assert!(matches!(
        CaptureDto::new(
            UNIX_EPOCH + Duration::from_secs(2),
            UNIX_EPOCH + Duration::from_secs(1)
        ),
        Err(PublicOutputError::InvalidWallClockInterval)
    ));
}

#[test]
fn invalid_capture_fails_before_writing() {
    let mut reversed = snapshot(Vec::new());
    reversed.capture_started_at = UNIX_EPOCH + Duration::from_secs(2);
    reversed.capture_completed_at = UNIX_EPOCH + Duration::from_secs(1);
    let mut output = Vec::new();
    assert!(matches!(
        write_snapshot_json(&mut output, &reversed, &LabelRegistry::default()),
        Err(PublicOutputError::InvalidWallClockInterval),
    ));
    assert!(output.is_empty());

    let mut pre_epoch = snapshot(Vec::new());
    pre_epoch.capture_started_at = UNIX_EPOCH - Duration::from_millis(1);
    pre_epoch.capture_completed_at = UNIX_EPOCH;
    assert!(matches!(
        write_snapshot_json(&mut output, &pre_epoch, &LabelRegistry::default()),
        Err(PublicOutputError::ClockUnavailable),
    ));
    assert!(output.is_empty());
}

#[cfg(unix)]
#[test]
fn non_utf8_process_path_fails_before_writing() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let identity = identity(7, 70);
    let mut process = process("worker");
    process.executable_path = Some(std::path::PathBuf::from(OsString::from_vec(vec![0xff])).into());
    let mut snapshot = snapshot(Vec::new());
    snapshot.processes.insert(identity, process);
    let mut output = Vec::new();
    assert!(matches!(
        write_snapshot_json(&mut output, &snapshot, &LabelRegistry::default()),
        Err(PublicOutputError::Serialization(_)),
    ));
    assert!(output.is_empty());
}

#[test]
fn timer_shape_has_fixed_certainty_and_native_unknown_code() {
    let mut socket = socket(3000, Vec::new());
    socket.timer = Some(TcpTimerObservation::from_linux_native(99, 17, Some(100)));
    let value = render(&snapshot(vec![socket]), &LabelRegistry::default());
    let timer = &value["sockets"][0]["timer"];
    assert_eq!(timer["kind"], "unknown");
    assert_eq!(timer["native_code"], 99);
    assert_eq!(timer["raw_ticks"], 17);
    assert_eq!(timer["estimated_remaining_milliseconds"], 170);
    assert_eq!(timer["certainty"], "estimated");
}

fn tagged_variant_snapshot() -> NetworkSnapshot {
    let linux = identity(7, 70);
    let macos = ProcessIdentity {
        pid: 7,
        start_marker: ProcessStartMarker::macos(8, 9).expect("valid macOS marker"),
    };
    let windows = ProcessIdentity {
        pid: 7,
        start_marker: ProcessStartMarker::windows(10).expect("valid Windows marker"),
    };
    let mut snapshot = snapshot(Vec::new());
    snapshot.processes.insert(windows, process("windows"));
    snapshot.processes.insert(macos, process("macos"));
    snapshot.processes.insert(linux, process("linux"));

    let scoped_endpoint = |scope| {
        EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            3000,
            Some(scope),
        )
        .expect("valid IPv6 fixture")
    };
    snapshot.sockets = vec![
        SocketObservation {
            local_endpoint: endpoint(3000),
            state: SocketState::Unknown(77),
            timer: None,
            owners: vec![OwnerObservation::UnverifiedPid {
                pid: 99,
                reason: UnverifiedOwnerReason::PermissionDenied,
            }],
            owner_completeness: OwnerCompleteness::Partial {
                reasons: vec![EvidenceGapCode::OwnerPermissionDenied],
            },
            socket_token: Some(PlatformSocketToken::MacOsSocketId(
                NonZeroU64::new(11).expect("nonzero token"),
            )),
            local_uid: None,
        },
        SocketObservation {
            local_endpoint: scoped_endpoint(Ipv6Scope::Unavailable),
            state: SocketState::Listen,
            timer: None,
            owners: Vec::new(),
            owner_completeness: OwnerCompleteness::Complete,
            socket_token: None,
            local_uid: None,
        },
        SocketObservation {
            local_endpoint: scoped_endpoint(Ipv6Scope::InterfaceIndex(
                NonZeroU32::new(3).expect("nonzero scope"),
            )),
            state: SocketState::Listen,
            timer: None,
            owners: Vec::new(),
            owner_completeness: OwnerCompleteness::Complete,
            socket_token: None,
            local_uid: None,
        },
        SocketObservation {
            local_endpoint: scoped_endpoint(Ipv6Scope::Unscoped),
            state: SocketState::Listen,
            timer: None,
            owners: Vec::new(),
            owner_completeness: OwnerCompleteness::Complete,
            socket_token: None,
            local_uid: None,
        },
    ];
    snapshot
}

#[test]
fn tagged_platform_and_scope_variants_have_exact_shapes() {
    let value = render(&tagged_variant_snapshot(), &LabelRegistry::default());
    assert_eq!(
        value["processes"][0]["identity"]["start_marker"],
        serde_json::json!({"kind": "linux_start_ticks", "ticks": 70}),
    );
    assert_eq!(
        value["processes"][1]["identity"]["start_marker"],
        serde_json::json!({"kind": "macos_start_time", "seconds": 8, "microseconds": 9}),
    );
    assert_eq!(
        value["processes"][2]["identity"]["start_marker"],
        serde_json::json!({"kind": "windows_creation_time", "filetime_ticks": 10}),
    );
    let sockets = value["sockets"].as_array().expect("socket array");
    assert!(sockets[0]["endpoint"]["ipv6_scope"].is_null());
    assert_eq!(
        sockets[0]["state"],
        serde_json::json!({"kind": "unknown", "native_code": 77})
    );
    assert_eq!(
        sockets[0]["owners"]["owners"][0],
        serde_json::json!({
            "kind": "unverified_pid",
            "pid": 99,
            "reason": "owner_permission_denied"
        }),
    );
    assert_eq!(
        sockets[0]["socket_token"],
        serde_json::json!({"kind": "macos_socket_id", "value": 11}),
    );
    assert_eq!(
        sockets[1]["endpoint"]["ipv6_scope"],
        serde_json::json!({"kind": "unscoped", "interface_index": null}),
    );
    assert_eq!(
        sockets[1]["state"],
        serde_json::json!({"kind": "listen", "native_code": null}),
    );
    assert_eq!(
        sockets[2]["endpoint"]["ipv6_scope"],
        serde_json::json!({"kind": "interface_index", "interface_index": 3}),
    );
    assert_eq!(
        sockets[3]["endpoint"]["ipv6_scope"],
        serde_json::json!({"kind": "unavailable", "interface_index": null}),
    );
}

#[test]
fn serde_writer_failure_preserves_io_kind() {
    struct FailedWriter;
    impl Write for FailedWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error = write_snapshot_json(
        &mut FailedWriter,
        &snapshot(Vec::new()),
        &LabelRegistry::default(),
    )
    .expect_err("writer fails");
    assert_eq!(error.io_error_kind(), Some(io::ErrorKind::BrokenPipe));
}
