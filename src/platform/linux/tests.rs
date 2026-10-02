use crate::model::PortEntryView;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use super::{
    AddressFamily, CollectionLimits, LinuxCollector, MAX_CHILD_PROCESSES, MAX_STATUS_BYTES,
    OwnerScanLoss, OwnerScanResult, SocketParseError, SocketRecord,
    ancestor_pid_visibility_not_proven, bounded_scope_identifier, collect_child_processes_from,
    collect_pid_socket_owners, collect_process_context_from, collect_related_process_hints_from,
    collect_related_process_hints_from_with_limit, collect_socket_owners,
    collect_socket_owners_detailed, collect_socket_records, collect_tree_process_infos,
    decode_cmdline, native_pass_from_records, parse_process_group_id,
    parse_process_start_time_ticks, parse_process_status, parse_socket_inode, parse_socket_line,
    parse_socket_table, proc_visibility_restricted, read_bounded_text, read_cmdline,
    read_cmdline_bounded, read_fresh_process_evidence, read_link_bounded,
    read_process_metadata_bounded, read_process_status, read_socket_table_bounded,
};
use crate::model::{PermissionStatus, Platform, Protocol};
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, EvidenceGapCode, EvidenceImpact, FILE_DESCRIPTOR_ENTRIES_MAX,
    ObservationError, OwnerCompleteness, PROCESS_NAME_MAX_BYTES, PlatformSocketToken,
    SCOPE_IDENTIFIER_MAX_BYTES, SnapshotCompleteness, SocketState, TcpTimerKind,
    UnverifiedOwnerReason,
};

#[test]
fn scope_identifier_exact_max_is_retained_and_max_plus_one_is_omitted() {
    let exact = PathBuf::from("x".repeat(SCOPE_IDENTIFIER_MAX_BYTES));
    let over = PathBuf::from("x".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1));

    assert_eq!(bounded_scope_identifier(&exact), exact.to_str());
    assert_eq!(bounded_scope_identifier(&over), None);
}

#[test]
fn collector_reports_one_scope_gap_for_oversized_namespace_identifier() {
    let proc_root = temp_proc_root("oversized-scope-identifier");
    write_socket_table(&proc_root, "net/tcp", &[]);
    write_socket_table(&proc_root, "net/udp", &[]);
    fs::create_dir_all(proc_root.join("self/ns")).expect("test namespace directory");
    let namespace = proc_root.join("self/ns/net");
    let exact = "x".repeat(SCOPE_IDENTIFIER_MAX_BYTES);
    std::os::unix::fs::symlink(&exact, &namespace).expect("exact namespace identifier");
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    let exact_snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect("exact scope identifier collects");
    assert_eq!(
        exact_snapshot.scope.identifier.as_deref(),
        Some(exact.as_str())
    );

    fs::remove_file(&namespace).expect("replace namespace identifier");
    std::os::unix::fs::symlink("x".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1), &namespace)
        .expect("oversized namespace identifier");
    let oversized_snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect("oversized scope identifier remains a partial snapshot");

    assert_eq!(oversized_snapshot.scope.identifier, None);
    assert_eq!(
        oversized_snapshot.completeness,
        SnapshotCompleteness::Partial
    );
    assert_eq!(oversized_snapshot.omitted_evidence_gap_count, 0);
    assert_eq!(oversized_snapshot.evidence_gaps.len(), 1);
    let gap = &oversized_snapshot.evidence_gaps[0];
    assert_eq!(gap.impact, EvidenceImpact::Scope);
    assert_eq!(gap.code, EvidenceGapCode::NativeFieldUnavailable);
    assert_eq!(gap.endpoint, None);
    assert_eq!(gap.pid, None);

    fs::remove_dir_all(proc_root).expect("test proc root cleanup");
}

const HEADER: &str =
    "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode";
const HEADER6: &str =
    "sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode";

fn row(local: &str, state: &str, inode: u64) -> String {
    row_with_timer(local, state, "00:00000000", inode)
}

fn row_with_timer(local: &str, state: &str, timer: &str, inode: u64) -> String {
    format!(
        "   0: {local} 00000000:0000 {state} 00000000:00000000 {timer} 00000000 1000 0 {inode} 1 0000000000000000 100 0 0 10 0"
    )
}

fn temp_proc_root(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock is after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "kickoutchi-linux-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(path.join("net")).expect("test proc net directory must be created");
    fs::create_dir_all(path.join("self")).expect("test proc self directory must be created");
    fs::write(path.join("self/status"), "Name:\tkickoutchi\nNSpid:\t1\n")
        .expect("process status fixture must be written");
    fs::create_dir_all(path.join("self/ns")).expect("namespace fixture directory");
    std::os::unix::fs::symlink("pid:[4026531836]", path.join("self/ns/pid"))
        .expect("initial PID namespace fixture");
    fs::write(
        path.join("mounts"),
        format!("proc {} proc rw,nosuid,nodev 0 0\n", path.display()),
    )
    .expect("unrestricted proc mount evidence must be written");
    path
}

fn write_socket_table(proc_root: &Path, relative_path: &str, rows: &[String]) {
    let header = if relative_path.ends_with('6') {
        HEADER6
    } else {
        HEADER
    };
    let text = format!("{header}\n{}\n", rows.join("\n"));
    fs::write(proc_root.join(relative_path), text).expect("test socket table must be written");
}

fn write_process(proc_root: &Path, pid: u32, name: &str, parent_pid: u32) {
    let process_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(process_dir.join("fd")).expect("test process directory must be created");
    fs::write(process_dir.join("comm"), format!("{name}\n"))
        .expect("test process name must be written");
    fs::write(
        process_dir.join("cmdline"),
        format!("{name}\0--test\0").as_bytes(),
    )
    .expect("test cmdline must be written");
    fs::write(
        process_dir.join("status"),
        format!("Name:\t{name}\nPPid:\t{parent_pid}\nUid:\t1000\t1000\t1000\t1000\n"),
    )
    .expect("test status must be written");
    fs::write(
        process_dir.join("stat"),
        stat_text(pid, name, parent_pid, u64::from(pid) * 10),
    )
    .expect("test stat must be written");
    std::os::unix::fs::symlink(format!("/usr/bin/{name}"), process_dir.join("exe"))
        .expect("test exe symlink must be created");
}

#[test]
fn fresh_name_reader_accepts_exact_4k_and_refuses_empty_and_max_plus_one() {
    let proc_root = temp_proc_root("fresh-name-boundaries");
    let pid = 42;
    write_process(&proc_root, pid, "worker", 1);
    let comm = proc_root.join(pid.to_string()).join("comm");

    fs::write(
        &comm,
        "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES),
    )
    .expect("exact-max name");
    let exact = read_fresh_process_evidence(&proc_root, pid).expect("exact 4 KiB name");
    assert_eq!(
        exact.name.len(),
        crate::observation::PROTECTION_NAME_MAX_BYTES
    );

    fs::write(&comm, "").expect("empty name");
    assert_eq!(
        read_fresh_process_evidence(&proc_root, pid),
        Err(crate::process_evidence::ProcessEvidenceError::NameMissing { pid })
    );

    fs::write(
        &comm,
        "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES + 1),
    )
    .expect("oversized name");
    assert_eq!(
        read_fresh_process_evidence(&proc_root, pid),
        Err(
            crate::process_evidence::ProcessEvidenceError::NameOversized {
                pid,
                bytes: crate::observation::PROTECTION_NAME_MAX_BYTES + 1
            }
        )
    );
    fs::remove_dir_all(proc_root).expect("test proc root cleanup");
}

#[test]
fn fresh_name_lossy_decoding_preserves_identity_and_bounds_decoded_bytes() {
    let proc_root = temp_proc_root("fresh-name-lossy");
    let pid = 42;
    write_process(&proc_root, pid, "worker", 1);
    let comm = proc_root.join("42/comm");
    fs::write(&comm, b"aaaaaaaaaaaaaa\xc3\n").expect("kernel-truncated UTF-8 name");
    let evidence = read_fresh_process_evidence(&proc_root, pid).expect("bounded lossy name");
    assert_eq!(evidence.name, "aaaaaaaaaaaaaa�");
    assert_eq!(evidence.pid, pid);
    assert_eq!(
        evidence.start_marker,
        crate::observation::ProcessStartMarker::linux(420).unwrap()
    );

    // Raw bytes fit, but replacement characters expand beyond the name budget.
    fs::write(
        &comm,
        vec![0xff; crate::observation::PROTECTION_NAME_MAX_BYTES / 3 + 1],
    )
    .expect("name exceeding the decoded budget");
    assert!(matches!(
        read_fresh_process_evidence(&proc_root, pid),
        Err(crate::process_evidence::ProcessEvidenceError::NameOversized { pid: 42, .. })
    ));
    fs::remove_dir_all(proc_root).expect("test proc root cleanup");
}

fn stat_text(pid: u32, name: &str, parent_pid: u32, start_time_ticks: u64) -> String {
    let mut fields = vec!["S".to_owned(), parent_pid.to_string()];
    for _ in 0..17 {
        fields.push("0".to_owned());
    }
    fields.push(start_time_ticks.to_string());
    format!("{pid} ({name}) {}\n", fields.join(" "))
}

#[test]
fn parses_ipv4_tcp_listen_rows() {
    let record = parse_socket_line(
        &row("0100007F:0BB8", "0A", 12_345),
        Protocol::Tcp,
        AddressFamily::Ipv4,
        Some(100),
    )
    .expect("valid row")
    .expect("listen row is kept");

    assert_eq!(record.protocol, Protocol::Tcp);
    assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(record.local_port, 3000);
    assert_eq!(record.state, SocketState::Listen);
    assert_eq!(record.inode, 12_345);
}

#[test]
fn retains_and_maps_every_linux_tcp_state_and_unknown_codes() {
    let cases = [
        ("01", SocketState::Established),
        ("02", SocketState::SynSent),
        ("03", SocketState::SynReceived),
        ("04", SocketState::FinWait1),
        ("05", SocketState::FinWait2),
        ("06", SocketState::TimeWait),
        ("07", SocketState::Closed),
        ("08", SocketState::CloseWait),
        ("09", SocketState::LastAck),
        ("0A", SocketState::Listen),
        ("0B", SocketState::Closing),
        ("0C", SocketState::NewSynReceived),
        ("00", SocketState::Unknown(0)),
        ("FFFFFFFF", SocketState::Unknown(u32::MAX)),
    ];

    for (native, expected) in cases {
        let record = parse_socket_line(
            &row("0100007F:0BB8", native, 12_345),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            Some(100),
        )
        .expect("numeric TCP state is valid")
        .expect("every TCP state is retained");
        assert_eq!(record.state, expected, "native state {native}");
    }
}

#[test]
fn parses_udp_rows_as_bound_sockets() {
    let record = parse_socket_line(
        &row("00000000:14E9", "07", 902),
        Protocol::Udp,
        AddressFamily::Ipv4,
        Some(100),
    )
    .expect("valid row")
    .expect("udp row is kept");

    assert_eq!(record.protocol, Protocol::Udp);
    assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(record.local_port, 5353);
    assert_eq!(record.state, SocketState::Bound);
    assert_eq!(record.timer, None);
}

#[test]
fn rejects_malformed_or_out_of_range_udp_state() {
    for state in ["not-hex", "100000000"] {
        let error = parse_socket_line(
            &row("00000000:14E9", state, 902),
            Protocol::Udp,
            AddressFamily::Ipv4,
            Some(100),
        )
        .expect_err("UDP st must be bounded hexadecimal");
        assert_eq!(
            error,
            SocketParseError::InvalidState {
                value: state.to_owned()
            }
        );
    }
}

#[test]
fn parses_known_and_unknown_tcp_timers_with_checked_estimates() {
    let known = [
        ("00", TcpTimerKind::None),
        ("01", TcpTimerKind::Retransmit),
        ("02", TcpTimerKind::Other),
        ("03", TcpTimerKind::TimeWait),
        ("04", TcpTimerKind::ZeroWindowProbe),
    ];
    for (native, expected_kind) in known {
        let record = parse_socket_line(
            &row_with_timer("0100007F:0BB8", "01", &format!("{native}:00000001"), 7),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            Some(3),
        )
        .expect("known timer parses")
        .expect("TCP row is retained");
        let timer = record.timer.expect("TCP rows carry timer evidence");
        assert_eq!(timer.kind, expected_kind);
        assert_eq!(timer.native_code, None);
        assert_eq!(timer.raw_ticks, 1);
        assert_eq!(timer.estimated_remaining_milliseconds, Some(334));
    }

    let unknown = parse_socket_line(
        &row_with_timer("0100007F:0BB8", "01", "FFFFFFFF:0000000A", 7),
        Protocol::Tcp,
        AddressFamily::Ipv4,
        None,
    )
    .expect("bounded unknown timer parses")
    .expect("TCP row is retained")
    .timer
    .expect("TCP rows carry timer evidence");
    assert_eq!(unknown.kind, TcpTimerKind::Unknown(u32::MAX));
    assert_eq!(unknown.native_code, Some(u32::MAX));
    assert_eq!(unknown.raw_ticks, 10);
    assert_eq!(unknown.estimated_remaining_milliseconds, None);
}

#[test]
fn rejects_malformed_or_out_of_range_tcp_timer_fields() {
    for timer in [
        "00",
        "x:00000001",
        "100000000:00000001",
        "00:x",
        "00:10000000000000000",
    ] {
        let error = parse_socket_line(
            &row_with_timer("0100007F:0BB8", "01", timer, 7),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            Some(100),
        )
        .expect_err("malformed timer text must fail the table");
        assert_eq!(
            error,
            SocketParseError::InvalidTcpTimer {
                value: timer.to_owned()
            }
        );
    }
}

#[test]
fn decodes_ipv6_loopback_rows() {
    let record = parse_socket_line(
        &row("00000000000000000000000001000000:1F90", "0A", 55),
        Protocol::Tcp,
        AddressFamily::Ipv6,
        Some(100),
    )
    .expect("valid row")
    .expect("listen row is kept");

    assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(record.local_port, 8080);
}

#[test]
fn normalizes_ipv4_mapped_ipv6_rows() {
    let record = parse_socket_line(
        &row("0000000000000000FFFF00000100007F:0BB8", "0A", 55),
        Protocol::Tcp,
        AddressFamily::Ipv6,
        Some(100),
    )
    .expect("valid row")
    .expect("listen row is kept");

    assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(record.local_port, 3000);
}

#[test]
fn missing_ipv6_socket_tables_do_not_block_ipv4_collection() {
    let proc_root = temp_proc_root("missing-ipv6");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 1)]);
    write_socket_table(&proc_root, "net/udp", &[row("00000000:14E9", "07", 2)]);

    let records = collect_socket_records(&proc_root).expect("missing tcp6/udp6 is allowed");

    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record.local_port == 3000));
    assert!(records.iter().any(|record| record.local_port == 5353));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn missing_ipv4_socket_tables_still_fail_collection() {
    let proc_root = temp_proc_root("missing-ipv4");

    let error = collect_socket_records(&proc_root).expect_err("missing tcp table must fail");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(ObservationError::SocketTableUnavailable)
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn rejects_malformed_rows_with_specific_errors() {
    let missing = parse_socket_line("0:", Protocol::Tcp, AddressFamily::Ipv4, Some(100))
        .expect_err("missing fields must be rejected");
    assert_eq!(
        missing,
        SocketParseError::MissingField {
            field: "local_address"
        }
    );

    let malformed = parse_socket_line(
        &row("not-an-address", "0A", 1),
        Protocol::Tcp,
        AddressFamily::Ipv4,
        Some(100),
    )
    .expect_err("missing address separator must be rejected");
    assert_eq!(
        malformed,
        SocketParseError::MalformedLocalAddress {
            value: "not-an-address".to_owned(),
        }
    );

    let bad_port = parse_socket_line(
        &row("0100007F:ZZZZ", "0A", 1),
        Protocol::Tcp,
        AddressFamily::Ipv4,
        Some(100),
    )
    .expect_err("bad port must be rejected");
    assert_eq!(
        bad_port,
        SocketParseError::InvalidPort {
            value: "ZZZZ".to_owned(),
        }
    );
}

#[test]
fn table_parser_rejects_a_pass_containing_a_malformed_row() {
    let text = format!(
        "{HEADER}\n{}\nnot enough fields\n{}\n",
        row("0100007F:0BB8", "0A", 1),
        row("0100007F:1770", "01", 2),
    );
    let error = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8)
        .expect_err("an authoritative table with a malformed row must fail");

    assert!(matches!(error, SocketParseError::MissingField { .. }));
}

#[test]
fn table_parser_rejects_empty_garbage_and_headerless_inputs() {
    let first = row("0100007F:0BB8", "0A", 1);
    let second = row("0100007F:1770", "01", 2);
    for text in [
        String::new(),
        "not a proc socket table\n".to_owned(),
        format!("{first}\n"),
        format!("{first}\n{second}\n"),
    ] {
        assert_eq!(
            parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8,),
            Err(SocketParseError::InvalidHeader),
            "input must not be accepted without the procfs header: {text:?}",
        );
    }
}

#[test]
fn table_parser_accepts_header_only_and_normal_proc_tables() {
    assert_eq!(
        parse_socket_table(HEADER, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8,),
        Ok(Vec::new()),
    );
    assert_eq!(
        parse_socket_table(HEADER6, Protocol::Tcp, AddressFamily::Ipv6, Some(100), 8,),
        Ok(Vec::new()),
    );

    let text = format!("  {HEADER}  \n{}\n", row("0100007F:0BB8", "0A", 7));
    let records = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8)
        .expect("normal proc socket table parses");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].inode, 7);
    assert_eq!(records[0].local_port, 3000);
}

#[test]
fn table_parser_refuses_the_first_row_past_its_retention_limit() {
    let text = format!(
        "{HEADER}\n{}\n{}\n",
        row("0100007F:0BB8", "0A", 1),
        row("0100007F:1770", "01", 2),
    );
    let exact = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 2)
        .expect("exact socket retention limit is accepted");
    assert_eq!(exact.len(), 2);

    assert_eq!(
        parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 1,),
        Err(SocketParseError::SocketObservationLimitExceeded)
    );
}

#[test]
fn collector_fails_a_pass_with_a_malformed_authoritative_socket_row() {
    let proc_root = temp_proc_root("malformed-authoritative-row");
    let text = format!(
        "{HEADER}\n{}\nnot enough fields\n",
        row("0100007F:0BB8", "0A", 1),
    );
    fs::write(proc_root.join("net/tcp"), text).expect("test TCP table must be written");
    write_socket_table(&proc_root, "net/udp", &[]);

    let collector = LinuxCollector::with_proc_root(proc_root.clone());
    let error = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::LegacyList,
    )
    .expect_err("malformed authoritative rows must fail the pass");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(ObservationError::NativeDataMalformed)
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn socket_table_reader_preserves_malformed_and_oversized_categories() {
    let proc_root = temp_proc_root("socket-table-errors");
    let path = proc_root.join("net/tcp");
    fs::write(&path, [0xff]).expect("invalid UTF-8 fixture");
    assert!(matches!(
        read_socket_table_bounded(&path, false, 1),
        Err(crate::collector::CollectorError::Observation(
            ObservationError::NativeDataMalformed
        ))
    ));

    fs::write(&path, b"abcd").expect("oversized fixture");
    assert!(matches!(
        read_socket_table_bounded(&path, false, 3),
        Err(crate::collector::CollectorError::Observation(
            ObservationError::NativeDataOversized
        ))
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn bounded_text_reader_rejects_oversized_proc_files() {
    let proc_root = temp_proc_root("bounded-text");
    let path = proc_root.join("net").join("huge");
    fs::write(&path, "abcd").expect("test file must be written");

    let text = read_bounded_text(&path, 4).expect("file at the cap is accepted");
    assert_eq!(text, "abcd");

    let error = read_bounded_text(&path, 3).expect_err("over-cap file must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn executable_symlink_reader_enforces_budget_before_read_allocation() {
    let root = temp_proc_root("bounded-readlink");
    fs::create_dir_all(&root).expect("fixture root");
    let link = root.join("exe");
    std::os::unix::fs::symlink("12345678", &link).expect("fixture symlink");

    assert_eq!(
        read_link_bounded(&link, 8).expect("exact byte maximum is accepted"),
        PathBuf::from("12345678"),
    );
    assert_eq!(
        read_link_bounded(&link, 7)
            .expect_err("maximum plus one is rejected")
            .kind(),
        ErrorKind::InvalidData,
    );
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn executable_symlink_reader_accepts_exact_proc_magic_symlink_target() {
    let link = Path::new("/proc/self/exe");
    let target = fs::read_link(link).expect("current executable proc symlink is readable");
    let target_len = target.as_os_str().as_encoded_bytes().len();
    assert!(target_len > 0);

    assert_eq!(
        read_link_bounded(link, target_len).expect("exact proc magic symlink target fits"),
        target,
    );
    assert_eq!(
        read_link_bounded(link, target_len - 1)
            .expect_err("proc magic symlink maximum plus one is rejected")
            .kind(),
        ErrorKind::InvalidData,
    );
}

#[test]
fn socket_inode_is_extracted_from_fd_symlink_targets() {
    assert_eq!(
        parse_socket_inode(Path::new("socket:[12345]")),
        Some(12_345)
    );
    assert_eq!(parse_socket_inode(Path::new("/tmp/file")), None);
    assert_eq!(parse_socket_inode(Path::new("socket:[]")), None);
}

#[test]
fn command_line_decoding_accepts_exact_output_max_and_counts_separators() {
    assert_eq!(
        decode_cmdline(b"python3\0-m\0http.server\x003000\0", 27),
        (Some("python3 -m http.server 3000".to_owned()), false)
    );
    assert_eq!(
        decode_cmdline(b"ab\0cd\0", 5),
        (Some("ab cd".to_owned()), false)
    );
    assert_eq!(decode_cmdline(b"ab\0cd\0", 4), (None, true));
}

#[test]
fn command_line_decoding_handles_empty_arguments_without_extra_spaces() {
    assert_eq!(decode_cmdline(b"", 0), (None, false));
    assert_eq!(decode_cmdline(b"\0\0", 0), (None, false));
    assert_eq!(
        decode_cmdline(b"\0alpha\0\0beta\0", 10),
        (Some("alpha beta".to_owned()), false)
    );
}

#[test]
fn command_line_decoding_bounds_lossy_utf8_expansion() {
    assert_eq!(
        decode_cmdline(b"a\xff\0b", 6),
        (Some("a� b".to_owned()), false)
    );
    assert_eq!(decode_cmdline(b"a\xff\0b", 5), (None, true));
    assert_eq!(decode_cmdline(b"\xff", 2), (None, true));
}

#[test]
fn command_line_reader_rejects_lossy_output_over_max_when_raw_bytes_fit() {
    let proc_root = temp_proc_root("lossy-command-line-boundary");
    let path = proc_root.join("cmdline");
    fs::write(&path, [0xff]).expect("invalid UTF-8 command fixture");

    assert_eq!(
        read_cmdline_bounded(&path, 3).expect("exact decoded maximum reads"),
        (Some("�".to_owned()), false)
    );
    assert_eq!(
        read_cmdline_bounded(&path, 2).expect("decoded overage is typed"),
        (None, true)
    );

    fs::remove_dir_all(proc_root).expect("test proc root cleanup");
}

#[test]
fn legacy_command_line_retains_exact_one_mib_and_rejects_max_plus_one() {
    let proc_root = temp_proc_root("legacy-command-line-boundary");
    let pid = 42;
    write_process(&proc_root, pid, "worker", 0);
    let path = proc_root.join(pid.to_string()).join("cmdline");
    let limit = crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
    assert_eq!(limit, 1024 * 1024);

    fs::write(&path, vec![b'x'; limit]).expect("exact-limit command fixture");
    let (command, partial) = read_cmdline(&path).expect("authoritative exact limit reads");
    assert_eq!(command.as_deref().map(str::len), Some(limit));
    assert!(!partial);

    fs::write(&path, vec![b'x'; limit + 1]).expect("oversized command fixture");
    let (command, partial) = read_cmdline(&path).expect("authoritative over limit is typed");
    assert_eq!(command, None);
    assert!(partial);

    let legacy = read_process_metadata_bounded(
        &proc_root,
        pid,
        crate::observation::MetadataProfile::LegacyList,
        usize::MAX,
    );
    assert!(legacy.command_line.is_none());
    assert!(legacy.partial);
    assert!(
        legacy.budget_omitted,
        "oversize must produce an evidence gap"
    );

    let display = read_process_metadata_bounded(
        &proc_root,
        pid,
        crate::observation::MetadataProfile::Display,
        usize::MAX,
    );
    assert!(
        display.command_line.is_none(),
        "Display skips command lines"
    );
    fs::remove_dir_all(proc_root).expect("test proc root cleanup");
}

#[test]
fn parent_pid_is_read_from_status_text() {
    assert_eq!(
        parse_process_status("Name:\tnode\nPPid:\t42\n")
            .expect("valid status text must parse")
            .parent_pid,
        Some(42),
    );
    assert_eq!(
        parse_process_status("Name:\tnode\n")
            .expect("missing PPid is not malformed")
            .parent_pid,
        None,
    );
    assert!(parse_process_status("PPid:\tnot-a-pid\n").is_err());
}

#[test]
fn saved_proc_parser_corpus_remains_bounded_and_panic_free() {
    for input in [
        include_bytes!("../../../fuzz/corpus/linux_proc/stat").as_slice(),
        include_bytes!("../../../fuzz/corpus/linux_proc/status").as_slice(),
        include_bytes!("../../../fuzz/corpus/linux_proc/socket-table").as_slice(),
    ] {
        super::exercise_proc_parser(input);
    }
}

#[test]
fn process_status_reads_parent_and_owner_uid() {
    let status = parse_process_status("Name:\tnode\nPPid:\t42\nUid:\t1000\t1001\t1002\t1003\n")
        .expect("valid status text must parse");

    assert_eq!(status.parent_pid, Some(42));
    assert_eq!(status.owner_uid, Some(1000));
}

#[test]
fn process_group_id_is_read_from_stat_field_5_and_fails_closed() {
    // Field 5 (pgrp) is the third token after the comm terminator; the
    // right-split keeps a paren-laden comm from shifting it.
    let text = "1234 (node worker) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 0 0 987654\n";
    assert_eq!(parse_process_group_id(text.as_bytes()), Some(4242));
    assert_eq!(parse_process_group_id(b"garbage with no comm"), None);

    // Group kill derives membership from the group ID, so the snapshot
    // read fails closed: a stat whose group token is unreadable while the
    // start marker still parses must error the scan, and the kernel's
    // group 0 must map to "no targetable group", never to a member edge.
    let dir = std::env::temp_dir().join(format!(
        "kickoutchi-tree-stat-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos(),
    ));
    fs::create_dir_all(&dir).expect("temp stat dir must be created");
    // Derive both cases from the canonical `stat_text` shape (start marker
    // parseable at field 22) so only the pgrp token differs per case:
    // `stat_text` emits `... S <ppid> <pgrp=0> ...`, so its own output is
    // the kernel case, and one targeted replace corrupts the pgrp token.
    let corrupt = dir.join("stat-corrupt");
    let corrupt_text = stat_text(1234, "node", 1, 987_654).replacen("S 1 0", "S 1 x", 1);
    assert!(corrupt_text.contains("S 1 x"), "{corrupt_text}");
    fs::write(&corrupt, corrupt_text).expect("corrupt stat must be written");
    assert!(super::read_tree_stat(&corrupt).is_err());

    let kernel = dir.join("stat-kernel");
    fs::write(&kernel, stat_text(2, "kthreadd", 0, 987_654)).expect("kernel stat must be written");
    let stat = super::read_tree_stat(&kernel)
        .expect("kernel stat must read")
        .expect("kernel stat must exist");
    assert_eq!(stat.process_group, None);
    fs::remove_dir_all(dir).expect("temp stat dir must clean up");
}

#[test]
fn process_start_time_is_read_from_stat_field_22() {
    let text = stat_text(1234, "node worker", 1, 987_654);

    let start_time = parse_process_start_time_ticks(text.as_bytes())
        .expect("valid stat text must expose process start time");

    assert_eq!(start_time, 987_654);
}

#[test]
fn process_start_time_survives_parens_in_comm() {
    // comm is an unescaped task name that can contain `) `; the right-split in
    // parse_process_start_time_ticks must still land on the real terminator
    // rather than a paren inside the name. A first/left split would read the
    // paren in `ev) il` as the terminator and parse the wrong field.
    let text = stat_text(1234, "ev) il", 1, 987_654);

    let start_time =
        parse_process_start_time_ticks(text.as_bytes()).expect("paren-laden comm must still parse");

    assert_eq!(start_time, 987_654);
}

#[test]
fn process_identity_parsing_ignores_non_utf8_comm_bytes() {
    let text = stat_text(1234, "node", 1, 987_654);
    let mut bytes = text.into_bytes();
    let name = bytes
        .windows(4)
        .position(|window| window == b"node")
        .expect("fixture contains comm");
    bytes[name] = 0xff;

    assert_eq!(
        parse_process_start_time_ticks(&bytes).expect("numeric tail remains authoritative"),
        987_654
    );
    assert_eq!(parse_process_group_id(&bytes), Some(0));

    let proc_root = temp_proc_root("non-utf8-stat");
    let stat = proc_root.join("stat");
    fs::write(&stat, &bytes).expect("non-UTF-8 stat fixture");
    assert!(super::read_native_process_marker(&stat).is_ok());
    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn restricted_proc_visibility_makes_global_ownership_partial() {
    let proc_root = temp_proc_root("hidepid-owner-scan");
    fs::write(
        proc_root.join("mounts"),
        format!(
            "proc {} proc rw,nosuid,nodev,hidepid=2 0 0\n",
            proc_root.display()
        ),
    )
    .expect("mount fixture");
    assert!(proc_visibility_restricted(&proc_root));

    let scan = collect_socket_owners_detailed(&proc_root, &HashSet::from([7]), 4, 4)
        .expect("restricted empty scan remains evidence");
    assert!(scan.losses.contains(&OwnerScanLoss::EnumerationIncomplete));
    let pass = native_pass_from_records(&[], &scan).expect("loss is representable");
    assert!(matches!(
        pass.global_owner_completeness,
        OwnerCompleteness::Partial { .. }
    ));
    assert_eq!(pass.evidence_gaps[0].pid, None);

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn unrestricted_proc_mount_modes_prove_complete_visibility() {
    let proc_root = temp_proc_root("unrestricted-proc-owner-scan");
    for options in ["rw,nosuid,nodev", "rw,hidepid=0", "rw,hidepid=off"] {
        fs::write(
            proc_root.join("mounts"),
            format!("proc {} proc {options} 0 0\n", proc_root.display()),
        )
        .expect("mount fixture");
        assert!(!proc_visibility_restricted(&proc_root), "{options}");

        let scan = collect_socket_owners_detailed(&proc_root, &HashSet::from([7]), 4, 4)
            .expect("unrestricted empty scan succeeds");
        assert!(!scan.losses.contains(&OwnerScanLoss::EnumerationIncomplete));
    }

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn unproven_proc_mount_visibility_fails_closed() {
    let proc_root = temp_proc_root("unproven-proc-owner-scan");
    let mounts = proc_root.join("mounts");

    fs::remove_file(&mounts).expect("remove default mount fixture");
    assert!(proc_visibility_restricted(&proc_root), "missing mounts");

    fs::create_dir(&mounts).expect("unreadable mount fixture");
    assert!(proc_visibility_restricted(&proc_root), "unreadable mounts");
    fs::remove_dir(&mounts).expect("remove unreadable mount fixture");

    for (name, evidence) in [
        ("malformed", b"proc /proc proc rw 0\n".as_slice()),
        ("invalid UTF-8", b"proc /proc proc rw 0 \xff\n".as_slice()),
        ("no matching mount", b"proc /other proc rw 0 0\n".as_slice()),
    ] {
        fs::write(&mounts, evidence).expect("mount evidence fixture");
        assert!(proc_visibility_restricted(&proc_root), "{name}");
    }

    let matching = format!("proc {} proc rw 0 0\n", proc_root.display());
    fs::write(&mounts, format!("{matching}{matching}")).expect("ambiguous mount evidence fixture");
    assert!(proc_visibility_restricted(&proc_root), "ambiguous mounts");

    fs::write(&mounts, vec![b'x'; MAX_STATUS_BYTES + 1]).expect("oversized mount fixture");
    assert!(proc_visibility_restricted(&proc_root), "oversized mounts");

    let scan = collect_socket_owners_detailed(&proc_root, &HashSet::from([7]), 4, 4)
        .expect("unproven empty scan remains evidence");
    assert!(scan.losses.contains(&OwnerScanLoss::EnumerationIncomplete));

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn restricted_proc_visibility_is_global_loss_without_target_inodes() {
    let proc_root = temp_proc_root("restricted-empty-inodes");
    write_process(&proc_root, 42, "worker", 1);
    fs::write(
        proc_root.join("mounts"),
        format!("proc {} proc rw,hidepid=2 0 0\n", proc_root.display()),
    )
    .expect("restricted mount fixture");

    let scan = collect_socket_owners_detailed(&proc_root, &HashSet::new(), 0, 0)
        .expect("empty inode scan skips PID enumeration");
    assert_eq!(scan.losses.len(), 1);
    assert!(scan.losses.contains(&OwnerScanLoss::EnumerationIncomplete));
    let pass = native_pass_from_records(&[], &scan).expect("global loss is representable");
    assert!(matches!(
        pass.global_owner_completeness,
        OwnerCompleteness::Partial { .. }
    ));
    assert_eq!(pass.evidence_gaps.len(), 1);

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn unproven_mount_and_ancestor_visibility_are_losses_without_target_inodes() {
    let proc_root = temp_proc_root("unproven-empty-inodes");
    write_process(&proc_root, 42, "worker", 1);
    fs::remove_file(proc_root.join("mounts")).expect("remove mount evidence");
    fs::remove_file(proc_root.join("self/ns/pid")).expect("remove namespace evidence");

    let scan = collect_socket_owners_detailed(&proc_root, &HashSet::new(), 0, 0)
        .expect("empty inode scan skips PID enumeration");
    assert_eq!(scan.losses.len(), 2);
    assert!(scan.losses.contains(&OwnerScanLoss::EnumerationIncomplete));
    assert!(
        scan.losses
            .contains(&OwnerScanLoss::AncestorPidOwnersInvisible)
    );
    let pass = native_pass_from_records(&[], &scan).expect("global losses are representable");
    assert!(matches!(
        pass.global_owner_completeness,
        OwnerCompleteness::Partial { .. }
    ));
    assert_eq!(pass.evidence_gaps.len(), 2);

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn unrestricted_visibility_remains_complete_without_target_inodes() {
    let proc_root = temp_proc_root("unrestricted-empty-inodes");
    write_process(&proc_root, 42, "worker", 1);

    let scan = collect_socket_owners_detailed(&proc_root, &HashSet::new(), 0, 0)
        .expect("empty inode scan skips PID enumeration");
    assert!(scan.losses.is_empty());
    let pass = native_pass_from_records(&[], &scan).expect("complete scan is representable");
    assert_eq!(pass.global_owner_completeness, OwnerCompleteness::Complete);
    assert!(pass.evidence_gaps.is_empty());

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn initial_pid_namespace_keeps_visible_socket_ownership_complete() {
    let proc_root = temp_proc_root("initial-pid-namespace");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 1234, "worker", 1);
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234/fd/0"))
        .expect("visible socket owner fixture");
    fs::create_dir_all(proc_root.join("self")).expect("self proc fixture");
    fs::write(
        proc_root.join("self/status"),
        "Name:\tkickoutchi\nUmask:\t0022\nState:\tR (running)\nTgid:\t4321\nNgid:\t0\nPid:\t4321\nPPid:\t4000\nTracerPid:\t0\nNSpid:\t4321\nUid:\t1000\t1000\t1000\t1000\n",
    )
    .expect("production-shaped initial namespace status");

    assert!(!ancestor_pid_visibility_not_proven(&proc_root));
    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::Display,
    )
    .expect("initial PID namespace collection succeeds");
    assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::Complete
    );

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn nested_pid_namespace_marks_visible_owner_and_hidden_co_owner_incomplete() {
    let proc_root = temp_proc_root("nested-pid-namespace");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 12, "visible-worker", 1);
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("12/fd/0"))
        .expect("visible socket owner fixture");
    fs::create_dir_all(proc_root.join("self")).expect("self proc fixture");
    fs::write(
        proc_root.join("self/status"),
        "Name:\tkickoutchi\nUmask:\t0022\nState:\tR (running)\nTgid:\t12\nNgid:\t0\nPid:\t12\nPPid:\t1\nTracerPid:\t0\nNSpid:\t12\nUid:\t1000\t1000\t1000\t1000\n",
    )
    .expect("nested namespace status after remounting procfs");
    fs::remove_file(proc_root.join("self/ns/pid")).expect("replace namespace fixture");
    std::os::unix::fs::symlink("pid:[4026533000]", proc_root.join("self/ns/pid"))
        .expect("nested PID namespace fixture");

    assert!(ancestor_pid_visibility_not_proven(&proc_root));
    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::Display,
    )
    .expect("nested PID namespace collection remains usable");
    let visible_owner_pids = snapshot.sockets[0]
        .owners
        .iter()
        .map(|owner| match owner {
            crate::observation::OwnerObservation::Verified(identity) => identity.pid,
            crate::observation::OwnerObservation::UnverifiedPid { pid, .. } => *pid,
        })
        .collect::<Vec<_>>();
    assert_eq!(visible_owner_pids, [12]);
    assert!(!snapshot.owner_completeness.is_complete());
    assert!(!snapshot.sockets[0].owner_completeness.is_complete());
    assert!(snapshot.evidence_gaps.iter().any(|gap| {
        gap.code == EvidenceGapCode::OwnerAttributionIncomplete && gap.pid.is_none()
    }));

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn missing_or_unrecognized_namespace_identity_cannot_prove_complete_pid_visibility() {
    let proc_root = temp_proc_root("unknown-pid-namespace");
    let namespace = proc_root.join("self/ns/pid");
    fs::remove_file(&namespace).expect("remove default namespace fixture");
    assert!(ancestor_pid_visibility_not_proven(&proc_root));

    for identity in [
        "pid:[4026533000]".to_owned(),
        "net:[4026531836]".to_owned(),
        "pid:[0]".to_owned(),
        "pid:[4026531836]extra".to_owned(),
        "x".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1),
    ] {
        std::os::unix::fs::symlink(&identity, &namespace).expect("namespace identity fixture");
        assert!(
            ancestor_pid_visibility_not_proven(&proc_root),
            "namespace: {identity:?}"
        );
        fs::remove_file(&namespace).expect("remove namespace fixture");
    }

    fs::write(&namespace, "pid:[4026531836]").expect("regular file is not namespace evidence");
    assert!(ancestor_pid_visibility_not_proven(&proc_root));

    fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
}

#[test]
fn status_read_parses_inside_the_cap_and_fails_closed_past_it() {
    // The cap is sized so every legitimate `status` file fits (even a
    // pathological `Groups:` line stays under it), and past the cap the
    // read must fail closed rather than hand the parser a silently
    // truncated view: a partial file that still "parses" is exactly the
    // wrong-but-valid answer the bounded-read convention exists to stop.
    let proc_root = temp_proc_root("status-cap");
    let process_dir = proc_root.join("99");
    fs::create_dir_all(&process_dir).expect("test process directory must exist");
    let status_path = process_dir.join("status");

    let groups = (0..60_000u32).fold(String::from("Groups:"), |mut line, gid| {
        line.push(' ');
        line.push_str(&gid.to_string());
        line
    });
    let status = format!("Name:\tnode\nPPid:\t42\n{groups}\n");
    assert!(status.len() < MAX_STATUS_BYTES, "fixture must fit the cap");
    fs::write(&status_path, status).expect("test status must be written");
    let parent = read_process_status(&status_path)
        .expect("in-cap status read must succeed")
        .parent_pid;
    assert_eq!(parent, Some(42));

    let oversized = format!(
        "Name:\tnode\nPPid:\t42\n{}",
        "Filler:\t0\n".repeat(MAX_STATUS_BYTES / 8),
    );
    assert!(
        oversized.len() > MAX_STATUS_BYTES,
        "fixture must exceed cap"
    );
    fs::write(&status_path, oversized).expect("test status must be written");
    let error =
        read_process_status(&status_path).expect_err("over-cap status read must fail closed");
    assert_eq!(error.kind(), ErrorKind::InvalidData);

    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn linux_collection_enriches_rows_with_parent_metadata() {
    let proc_root = temp_proc_root("parent-metadata");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 1234, "node", 1);
    write_process(&proc_root, 1, "systemd", 0);
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234").join("fd").join("0"))
        .expect("test socket symlink must be created");

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::LegacyList,
    )
    .expect("test proc root must collect");
    let entries = crate::observation::project_legacy(&snapshot).expect("legacy projection");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].pid, Some(1234));
    assert_eq!(entries[0].process_name.as_deref(), Some("node"));
    assert_eq!(entries[0].parent_pid, Some(1));
    assert_eq!(entries[0].parent_process_name.as_deref(), Some("systemd"));
    assert_eq!(entries[0].permission, PermissionStatus::Full);
    assert!(PortEntryView::from(&entries[0]).is_system_process());
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn retried_enrichment_does_not_reuse_parent_names_from_discarded_attempts() {
    let proc_root = temp_proc_root("parent-metadata-retry");
    write_process(&proc_root, 1234, "child", 1);
    write_process(&proc_root, 1, "parent-old", 0);
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    let discarded = collector
        .read_native_processes(
            &[1234],
            crate::observation::MetadataProfile::Display,
            crate::observation::OPTIONAL_METADATA_MAX_BYTES,
        )
        .expect("discarded enrichment pass reads");
    fs::write(proc_root.join("1/comm"), "parent-new\n")
        .expect("parent name changes without changing its start marker");
    let accepted = collector
        .read_native_processes(
            &[1234],
            crate::observation::MetadataProfile::Display,
            crate::observation::OPTIONAL_METADATA_MAX_BYTES,
        )
        .expect("accepted retry reads");

    let discarded_read = discarded
        .iter()
        .find(|(pid, _)| *pid == 1234)
        .map(|(_, read)| read)
        .expect("requested PID has one read");
    let discarded_parent_name = match discarded_read {
        crate::observation::ProcessRead::Verified { observation, .. } => {
            observation.parent_process_name.clone()
        }
        crate::observation::ProcessRead::Unverified(_) => None,
    };
    let accepted_read = accepted
        .iter()
        .find(|(pid, _)| *pid == 1234)
        .map(|(_, read)| read)
        .expect("requested PID has one read");
    let accepted_parent_name = match accepted_read {
        crate::observation::ProcessRead::Verified { observation, .. } => {
            observation.parent_process_name.clone()
        }
        crate::observation::ProcessRead::Unverified(_) => None,
    };
    assert_eq!(discarded_parent_name.as_deref(), Some("parent-old"));
    assert_eq!(accepted_parent_name.as_deref(), Some("parent-new"));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn linux_collection_emits_one_row_per_shared_socket_owner() {
    let proc_root = temp_proc_root("shared-socket-rows");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 1234, "parent", 1);
    write_process(&proc_root, 1235, "child", 1234);
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234").join("fd").join("0"))
        .expect("parent socket symlink must be created");
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("1235").join("fd").join("0"))
        .expect("child socket symlink must be created");

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::LegacyList,
    )
    .expect("test proc root must collect");
    let entries = crate::observation::project_legacy(&snapshot).expect("legacy projection");
    let pids = entries.iter().map(|entry| entry.pid).collect::<Vec<_>>();

    assert_eq!(pids, vec![Some(1234), Some(1235)]);
    assert!(entries.iter().all(|entry| entry.local_port == 3000));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn native_snapshot_retains_inode_and_complete_empty_owner_set() {
    let proc_root = temp_proc_root("native-inode-ownerless");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect("native ownerless collection succeeds");

    assert_eq!(snapshot.sockets.len(), 1);
    assert_eq!(
        snapshot.sockets[0].socket_token,
        PlatformSocketToken::linux_inode(77)
    );
    assert_eq!(
        snapshot.sockets[0]
            .timer
            .expect("TCP timer is retained")
            .kind,
        TcpTimerKind::None
    );
    assert!(snapshot.sockets[0].owners.is_empty());
    assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(
        snapshot.sockets[0].owner_completeness,
        OwnerCompleteness::Complete
    );
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn native_snapshot_retains_full_tcp_state_and_timer_before_legacy_projection() {
    let proc_root = temp_proc_root("native-full-state");
    write_socket_table(
        &proc_root,
        "net/tcp",
        &[
            row_with_timer("0100007F:0BB8", "01", "01:0000000A", 77),
            row_with_timer("0100007F:0BB9", "02", "FF:0000000A", 78),
            row("0100007F:0BBA", "03", 79),
            row("0100007F:0BBB", "04", 80),
            row("0100007F:0BBC", "05", 81),
            row("0100007F:0BBD", "06", 82),
            row("0100007F:0BBE", "07", 83),
            row("0100007F:0BBF", "08", 84),
            row("0100007F:0BC0", "09", 85),
            row("0100007F:0BC1", "0A", 86),
            row("0100007F:0BC2", "0B", 87),
            row("0100007F:0BC3", "0C", 88),
            row("0100007F:0BC4", "FF", 89),
        ],
    );
    write_socket_table(&proc_root, "net/udp", &[]);

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::Display,
    )
    .expect("full-state native snapshot collects");

    let established = snapshot
        .sockets
        .iter()
        .find(|socket| socket.state == crate::observation::SocketState::Established)
        .expect("established row survives the platform bridge");
    assert_eq!(established.local_endpoint.port.get(), 3000);
    assert_eq!(
        established.timer.expect("nonzero timer survives").kind,
        TcpTimerKind::Retransmit
    );
    let timer = established.timer.expect("nonzero timer survives");
    assert_eq!(timer.native_code, None);
    assert_eq!(timer.raw_ticks, 10);
    assert!(timer.estimated_remaining_milliseconds.is_some());

    let syn_sent = snapshot
        .sockets
        .iter()
        .find(|socket| socket.state == crate::observation::SocketState::SynSent)
        .expect("SYN-SENT row survives the platform bridge");
    let unknown_timer = syn_sent.timer.expect("unknown timer survives");
    assert_eq!(unknown_timer.kind, TcpTimerKind::Unknown(255));
    assert_eq!(unknown_timer.native_code, Some(255));
    assert_eq!(unknown_timer.raw_ticks, 10);
    assert!(unknown_timer.estimated_remaining_milliseconds.is_some());

    let retained_states = snapshot
        .sockets
        .iter()
        .map(|socket| socket.state)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        retained_states,
        [
            crate::observation::SocketState::Closed,
            crate::observation::SocketState::Listen,
            crate::observation::SocketState::SynSent,
            crate::observation::SocketState::SynReceived,
            crate::observation::SocketState::Established,
            crate::observation::SocketState::FinWait1,
            crate::observation::SocketState::FinWait2,
            crate::observation::SocketState::CloseWait,
            crate::observation::SocketState::Closing,
            crate::observation::SocketState::LastAck,
            crate::observation::SocketState::TimeWait,
            crate::observation::SocketState::NewSynReceived,
            crate::observation::SocketState::Unknown(255),
        ]
        .into_iter()
        .collect()
    );
    let legacy = crate::observation::project_legacy(&snapshot).expect("legacy projection fits");
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].local_port, 3009);
    assert_eq!(legacy[0].state, crate::model::SocketState::Listen);

    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn unavailable_ipv6_scope_adds_exactly_one_scope_gap() {
    let proc_root = temp_proc_root("ipv6-scope-gap");
    write_socket_table(&proc_root, "net/tcp", &[]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_socket_table(
        &proc_root,
        "net/tcp6",
        &[
            row("00000000000000000000000001000000:0BB8", "01", 11),
            row("00000000000000000000000001000000:0BB9", "02", 12),
        ],
    );
    write_socket_table(&proc_root, "net/udp6", &[]);
    fs::create_dir_all(proc_root.join("self/ns")).expect("test namespace directory");
    std::os::unix::fs::symlink("net:[42]", proc_root.join("self/ns/net"))
        .expect("test namespace identifier");
    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::Display,
    )
    .expect("IPv6 scope loss remains a partial snapshot");

    assert_eq!(
        snapshot
            .evidence_gaps
            .iter()
            .filter(|gap| {
                gap.code == EvidenceGapCode::NativeFieldUnavailable
                    && gap.impact == EvidenceImpact::Scope
                    && gap.endpoint.is_none()
            })
            .count(),
        1
    );
    assert_eq!(snapshot.sockets.len(), 2);
    assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
    assert!(snapshot.evidence_gaps.iter().all(|gap| {
        gap.code != EvidenceGapCode::NativeFieldUnavailable || gap.impact == EvidenceImpact::Scope
    }));
    fs::remove_dir_all(proc_root).expect("test proc root cleanup");
}

#[test]
fn native_snapshot_retains_shared_socket_owners() {
    let proc_root = temp_proc_root("native-shared-socket");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    for pid in [1234, 1235] {
        write_process(&proc_root, pid, "worker", 1);
        std::os::unix::fs::symlink("socket:[77]", proc_root.join(pid.to_string()).join("fd/0"))
            .expect("shared socket symlink must be created");
    }
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect("native shared ownership collection succeeds");
    let owner_pids = snapshot.sockets[0]
        .owners
        .iter()
        .map(|owner| match owner {
            crate::observation::OwnerObservation::Verified(identity) => identity.pid,
            crate::observation::OwnerObservation::UnverifiedPid { pid, .. } => *pid,
        })
        .collect::<Vec<_>>();

    assert_eq!(owner_pids, vec![1234, 1235]);
    assert_eq!(snapshot.processes.len(), 2);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn edge_free_owner_scan_denial_is_aggregated_not_socket_local() {
    let record = SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        timer: None,
        inode: 77,
    };
    let mut scan = OwnerScanResult::default();
    scan.record_pid_losses(
        [OwnerScanLoss::PermissionDenied(42)].into_iter().collect(),
        false,
    );
    let pass = native_pass_from_records(&[record], &scan)
        .expect("denied scan is retained as partial evidence");

    assert_eq!(
        pass.global_owner_completeness,
        OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap()
    );
    assert_eq!(pass.evidence_gaps[0].endpoint, None);
    assert_eq!(pass.evidence_gaps[0].pid, None);
    assert_eq!(pass.evidence_gaps[0].affected_pid_count(), Some(1));
    assert_eq!(pass.omitted_evidence_gap_count, 0);
    assert_eq!(
        pass.rows
            .iter()
            .map(|row| row.owner_completeness.clone())
            .collect::<Vec<_>>(),
        [OwnerCompleteness::Complete]
    );
}

#[test]
fn global_scan_denial_does_not_reduce_verified_endpoint_completeness() {
    let record = SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        timer: None,
        inode: 77,
    };
    let mut scan = OwnerScanResult {
        owners: HashMap::from([(77, vec![1234])]),
        owner_edges: 1,
        ..OwnerScanResult::default()
    };
    scan.record_pid_losses(
        [OwnerScanLoss::PermissionDenied(42)].into_iter().collect(),
        false,
    );
    let pass = native_pass_from_records(&[record], &scan).expect("proven ownership remains usable");

    assert!(!pass.global_owner_completeness.is_complete());
    assert_eq!(
        pass.rows
            .iter()
            .map(|row| row.owner_completeness.clone())
            .collect::<Vec<_>>(),
        [OwnerCompleteness::Complete]
    );
}

#[test]
fn restricted_proc_visibility_refuses_port_kill_with_a_visible_owner() {
    let proc_root = temp_proc_root("restricted-proc-port-kill");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 1234, "worker", 1);
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234/fd/0"))
        .expect("visible socket owner fixture must be linked");
    fs::write(
        proc_root.join("mounts"),
        format!(
            "proc {} proc rw,nosuid,nodev,hidepid=1 0 0\n",
            proc_root.display()
        ),
    )
    .expect("restricted proc mount evidence must be written");

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &LinuxCollector::with_proc_root(proc_root.clone()),
        crate::observation::MetadataProfile::Display,
    )
    .expect("restricted proc ownership remains observable as partial");
    let socket = snapshot
        .sockets
        .iter()
        .find(|socket| socket.local_endpoint.port.get() == 3000)
        .expect("visible target socket must be retained");
    assert_eq!(socket.owner_completeness, OwnerCompleteness::Complete);
    assert!(socket.owners.iter().any(|owner| {
        matches!(
            owner,
            crate::observation::OwnerObservation::Verified(identity)
                if identity.pid == 1234
        )
    }));
    assert!(snapshot.evidence_gaps.iter().any(|gap| {
        gap.impact == EvidenceImpact::Ownership
            && gap.code == EvidenceGapCode::OwnerAttributionIncomplete
            && gap.endpoint.is_none()
    }));
    assert!(matches!(
        crate::collector::kill_ports_from_snapshot(&snapshot, None, Some(3000)),
        Err(crate::collector::CollectorError::Observation(
            ObservationError::PartialSocketSet
        ))
    ));

    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn edge_free_owner_scan_losses_aggregate_across_gap_limit_boundaries() {
    for count in [
        0,
        1,
        crate::observation::EVIDENCE_GAPS_MAX,
        crate::observation::EVIDENCE_GAPS_MAX + 1,
    ] {
        let proc_root = temp_proc_root("aggregate-owner-loss-boundary");
        for pid in 1..=count {
            fs::create_dir(proc_root.join(pid.to_string()))
                .expect("fixture PID directory must be created");
        }

        let scan = collect_socket_owners_detailed(&proc_root, &HashSet::from([77]), count, 0)
            .expect("production owner scan remains bounded");
        let pass = native_pass_from_records(&[], &scan)
            .expect("aggregate owner losses remain representable");
        assert_eq!(pass.evidence_gaps.len(), usize::from(count != 0));
        assert_eq!(
            pass.evidence_gaps
                .first()
                .and_then(crate::observation::EvidenceGap::affected_pid_count),
            (count != 0).then(|| u64::try_from(count).expect("fixture count fits")),
        );
        assert_eq!(pass.omitted_evidence_gap_count, 0);
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }
}

#[test]
fn owner_scan_loss_stays_pid_specific_after_a_target_edge_is_discovered() {
    let proc_root = temp_proc_root("exact-owner-loss-with-edge");
    write_process(&proc_root, 42, "worker", 1);
    fs::write(proc_root.join("42/fd/0"), b"not a symlink")
        .expect("unattributable fd fixture must be written");
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("42/fd/1"))
        .expect("target socket fixture must be linked");
    let record = SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        timer: None,
        inode: 77,
    };
    let scan = collect_socket_owners_detailed(&proc_root, &HashSet::from([77]), 1, 2)
        .expect("production owner scan remains representable");

    let pass = native_pass_from_records(&[record], &scan)
        .expect("target-relevant loss remains representable");
    assert_eq!(pass.evidence_gaps.len(), 1);
    assert_eq!(pass.evidence_gaps[0].pid, Some(42));
    assert_eq!(pass.evidence_gaps[0].affected_pid_count(), None);
    assert_eq!(pass.omitted_evidence_gap_count, 0);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn vanished_pid_identity_is_reported_after_an_owner_edge_is_known() {
    let proc_root = temp_proc_root("vanished-native-identity");
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    assert_eq!(
        collector
            .read_native_process(
                42,
                crate::observation::MetadataProfile::Display,
                crate::observation::OPTIONAL_METADATA_MAX_BYTES,
            )
            .expect("a vanished stat is ordinary unavailable identity"),
        crate::observation::ProcessRead::Unverified(UnverifiedOwnerReason::Disappeared)
    );
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn malformed_identity_stat_has_the_stable_native_data_code() {
    let proc_root = temp_proc_root("malformed-native-identity");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 42, "worker", 1);
    std::os::unix::fs::symlink("socket:[44]", proc_root.join("42/fd/0"))
        .expect("test socket symlink must be created");
    fs::write(proc_root.join("42/stat"), "malformed stat\n")
        .expect("malformed stat fixture must be written");
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    let error = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect_err("malformed identity-critical stat must fail");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(ObservationError::NativeDataMalformed)
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn oversized_identity_stat_has_the_stable_native_data_code() {
    let proc_root = temp_proc_root("oversized-native-identity");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 42, "worker", 1);
    std::os::unix::fs::symlink("socket:[44]", proc_root.join("42/fd/0"))
        .expect("test socket symlink must be created");
    fs::write(
        proc_root.join("42/stat"),
        vec![b'x'; super::MAX_STAT_BYTES + 1],
    )
    .expect("oversized stat fixture must be written");
    let collector = LinuxCollector::with_proc_root(proc_root.clone());

    let error = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect_err("oversized identity-critical stat must fail");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(ObservationError::NativeDataOversized)
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn selected_process_context_collects_owner_uid_and_direct_children() {
    let proc_root = temp_proc_root("selected-context");
    write_process(&proc_root, 100, "parent", 1);
    write_process(&proc_root, 101, "worker-a", 100);
    write_process(&proc_root, 102, "worker-b", 100);
    write_process(&proc_root, 200, "unrelated", 1);

    let context = collect_process_context_from(&proc_root, 100);

    assert_eq!(context.owner_uid, Some(1000));
    assert_eq!(
        context.process_start_time_marker,
        crate::observation::ProcessStartMarker::linux(1000).ok()
    );
    let children: Vec<(u32, Option<&str>)> = context
        .children
        .children
        .iter()
        .map(|child| (child.pid, child.process_name.as_deref()))
        .collect();
    assert_eq!(
        children,
        vec![(101, Some("worker-a")), (102, Some("worker-b"))]
    );
    assert!(!context.children.truncated);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn process_context_and_child_collection_bound_optional_process_names() {
    let proc_root = temp_proc_root("context-child-name-boundary");
    write_process(&proc_root, 100, "parent", 1);
    write_process(&proc_root, 101, "worker", 100);
    let comm = proc_root.join("101/comm");

    fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES]).expect("exact-max child name");
    let exact = collect_process_context_from(&proc_root, 100);
    assert_eq!(exact.children.children.len(), 1);
    assert_eq!(
        exact.children.children[0]
            .process_name
            .as_deref()
            .map(str::len),
        Some(PROCESS_NAME_MAX_BYTES)
    );
    let exact_children = collect_child_processes_from(&proc_root, 100);
    assert_eq!(
        exact_children.children[0]
            .process_name
            .as_deref()
            .map(str::len),
        Some(PROCESS_NAME_MAX_BYTES)
    );

    fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES + 1]).expect("oversized child name");
    let oversized = collect_process_context_from(&proc_root, 100);
    assert_eq!(oversized.children.children.len(), 1);
    assert_eq!(oversized.children.children[0].pid, 101);
    assert_eq!(oversized.children.children[0].process_name, None);
    let oversized_children = collect_child_processes_from(&proc_root, 100);
    assert_eq!(oversized_children.children.len(), 1);
    assert_eq!(oversized_children.children[0].pid, 101);
    assert_eq!(oversized_children.children[0].process_name, None);

    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn tree_process_snapshot_reads_parent_name_and_start_marker() {
    let proc_root = temp_proc_root("tree-snapshot");
    write_process(&proc_root, 100, "root", 1);
    write_process(&proc_root, 101, "child", 100);
    write_process(&proc_root, 102, "grandchild", 101);

    let infos = collect_tree_process_infos(&proc_root).expect("tree snapshot must collect");
    let tree = crate::tree::plan_process_tree(100, &infos, &[], Platform::Linux, 256)
        .expect("root must be present");
    let tuples = infos
        .iter()
        .filter(|info| matches!(info.pid, 100..=102))
        .map(|info| {
            (
                info.pid,
                info.parent_pid,
                info.process_name.as_deref(),
                info.start_time_marker,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(tree.len(), 3);
    assert!(tuples.contains(&(
        100,
        Some(1),
        Some("root"),
        crate::observation::ProcessStartMarker::linux(1000).ok()
    )));
    assert!(tuples.contains(&(
        101,
        Some(100),
        Some("child"),
        crate::observation::ProcessStartMarker::linux(1010).ok()
    )));
    assert!(tuples.contains(&(
        102,
        Some(101),
        Some("grandchild"),
        crate::observation::ProcessStartMarker::linux(1020).ok()
    )));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn tree_snapshot_accepts_exact_max_name_and_rejects_max_plus_one() {
    let proc_root = temp_proc_root("tree-name-boundary");
    write_process(&proc_root, 100, "worker", 1);
    let comm = proc_root.join("100/comm");

    fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES]).expect("exact-max tree name");
    let exact = collect_tree_process_infos(&proc_root).expect("exact-max tree name must collect");
    assert_eq!(exact.len(), 1);
    assert_eq!(
        exact[0].process_name.as_deref().map(str::len),
        Some(PROCESS_NAME_MAX_BYTES)
    );

    fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES + 1]).expect("oversized tree name");
    let error = collect_tree_process_infos(&proc_root)
        .expect_err("oversized live tree name must fail closed");
    assert!(error.to_string().contains("100/comm"), "{error}");
    assert!(
        error
            .to_string()
            .contains(&format!("exceeds {PROCESS_NAME_MAX_BYTES} byte read limit")),
        "{error}"
    );

    fs::remove_file(&comm).expect("vanished tree name");
    assert!(
        collect_tree_process_infos(&proc_root)
            .expect("a process vanishing during its name read must still be skipped")
            .is_empty()
    );

    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn child_process_collection_is_bounded() {
    let proc_root = temp_proc_root("bounded-children");
    write_process(&proc_root, 100, "parent", 1);
    let max_children =
        u32::try_from(MAX_CHILD_PROCESSES).expect("child-process cap must fit in u32 test PIDs");
    for offset in 0..=max_children {
        write_process(&proc_root, 1_000 + offset, "worker", 100);
    }

    let children = collect_child_processes_from(&proc_root, 100);

    assert_eq!(children.children.len(), MAX_CHILD_PROCESSES);
    assert!(children.truncated);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn related_process_hints_use_strict_command_line_evidence() {
    let proc_root = temp_proc_root("related-hints");
    write_process(&proc_root, 100, "candidate", 1);
    fs::write(
        proc_root.join("100").join("cmdline"),
        b"python3\0-m\0http.server\0--port\x003000\0",
    )
    .expect("candidate cmdline must be written");
    write_process(&proc_root, 101, "weak", 1);
    fs::write(
        proc_root.join("101").join("cmdline"),
        b"worker\0--timeout\x003000\0",
    )
    .expect("weak cmdline must be written");
    write_process(&proc_root, std::process::id(), "kickoutchi", 1);
    fs::write(
        proc_root
            .join(std::process::id().to_string())
            .join("cmdline"),
        b"kickoutchi\0list\0--port\x003000\0",
    )
    .expect("self cmdline must be written");
    write_process(&proc_root, 1, "cargo", 0);
    fs::write(
        proc_root.join("1").join("cmdline"),
        b"cargo\0run\0--\0list\0--port\x003000\0",
    )
    .expect("ancestor cmdline must be written");

    let hints = collect_related_process_hints_from(&proc_root, 3000);

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].pid, 100);
    assert_eq!(hints[0].process_name.as_deref(), Some("candidate"));
    assert!(hints[0].command_line.contains("--port 3000"));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn related_hint_retains_exact_max_name_and_omits_max_plus_one() {
    let proc_root = temp_proc_root("hint-name-boundary");
    write_process(&proc_root, 100, "candidate", 1);
    fs::write(
        proc_root.join("100/cmdline"),
        b"python3\0-m\0http.server\0--port\x003000\0",
    )
    .expect("candidate cmdline must be written");
    let comm = proc_root.join("100/comm");

    fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES]).expect("exact-max hint name");
    let exact = collect_related_process_hints_from(&proc_root, 3000);
    assert_eq!(exact.len(), 1);
    assert_eq!(
        exact[0].process_name.as_deref().map(str::len),
        Some(PROCESS_NAME_MAX_BYTES)
    );

    fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES + 1]).expect("oversized hint name");
    let oversized = collect_related_process_hints_from(&proc_root, 3000);
    assert_eq!(oversized.len(), 1);
    assert_eq!(oversized[0].pid, 100);
    assert_eq!(oversized[0].process_name, None);

    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn related_process_hints_refuse_the_first_command_past_the_read_budget() {
    let proc_root = temp_proc_root("hint-read-budget");
    for pid in [100, 101, 102] {
        write_process(&proc_root, pid, "candidate", 1);
    }
    fs::write(
        proc_root.join("100/cmdline"),
        b"python3\0-m\0http.server\x003000\0",
    )
    .expect("over-budget matching command line");
    fs::write(
        proc_root.join("101/cmdline"),
        b"python3\0-m\0http.server\x003000\0",
    )
    .expect("second matching command line");
    fs::write(
        proc_root.join("102/cmdline"),
        b"worker\0--timeout\x003000\0",
    )
    .expect("first nonmatch command line");

    let exact = collect_related_process_hints_from_with_limit(&proc_root, 3000, 2);
    let plus_one = collect_related_process_hints_from_with_limit(&proc_root, 3000, 3);

    assert_eq!(exact.iter().map(|hint| hint.pid).collect::<Vec<_>>(), [101]);
    assert_eq!(
        plus_one.iter().map(|hint| hint.pid).collect::<Vec<_>>(),
        [101, 100]
    );
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn missing_proc_root_is_a_collection_error() {
    let collector = LinuxCollector::with_proc_root(PathBuf::from(
        "/definitely-not-a-real-kickoutchi-proc-root",
    ));

    let error = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::LegacyList,
    )
    .expect_err("missing proc root must fail");
    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(ObservationError::SocketTableUnavailable)
    ));
}

#[test]
fn socket_owner_collection_requires_a_readable_proc_root() {
    let target_inodes = HashSet::from([1]);
    let error = collect_socket_owners(
        Path::new("/definitely-not-a-real-kickoutchi-proc-root"),
        &target_inodes,
        CANDIDATE_PROCESS_IDS_MAX,
        FILE_DESCRIPTOR_ENTRIES_MAX,
    )
    .expect_err("missing proc root must fail");

    assert!(error.to_string().contains("cannot read"), "{error}");
}

#[test]
fn socket_owner_collection_ignores_non_target_inodes() {
    let proc_root = temp_proc_root("target-inodes");
    let fd_dir = proc_root.join("1234").join("fd");
    fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
    std::os::unix::fs::symlink("socket:[11]", fd_dir.join("0"))
        .expect("test socket symlink must be created");
    std::os::unix::fs::symlink("socket:[22]", fd_dir.join("1"))
        .expect("test socket symlink must be created");

    let owners = collect_socket_owners(
        &proc_root,
        &HashSet::from([22]),
        CANDIDATE_PROCESS_IDS_MAX,
        FILE_DESCRIPTOR_ENTRIES_MAX,
    )
    .expect("targeted owner collection must succeed");

    assert_eq!(owners.get(&22).map(Vec::as_slice), Some(&[1234][..]));
    assert!(!owners.contains_key(&11));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn socket_owner_collection_retains_multiple_pids_for_shared_inodes() {
    let proc_root = temp_proc_root("shared-inode-owners");
    for pid in [100, 101] {
        let fd_dir = proc_root.join(pid.to_string()).join("fd");
        fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
        std::os::unix::fs::symlink("socket:[44]", fd_dir.join("0"))
            .expect("test socket symlink must be created");
    }

    let owners = collect_socket_owners(
        &proc_root,
        &HashSet::from([44]),
        CANDIDATE_PROCESS_IDS_MAX,
        FILE_DESCRIPTOR_ENTRIES_MAX,
    )
    .expect("targeted owner collection must succeed");

    assert_eq!(owners.get(&44).map(Vec::as_slice), Some(&[100, 101][..]));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn pid_socket_owner_collection_records_matching_inode_once_per_pid() {
    let proc_root = temp_proc_root("target-owner-once");
    let fd_dir = proc_root.join("1234").join("fd");
    fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
    std::os::unix::fs::symlink("socket:[44]", fd_dir.join("0"))
        .expect("test socket symlink must be created");
    std::os::unix::fs::symlink("socket:[44]", fd_dir.join("1"))
        .expect("duplicate socket symlink must be created");

    let target_inodes = HashSet::from([44]);
    let mut owners = HashMap::new();
    let mut visited = 0;
    collect_pid_socket_owners(
        &proc_root,
        1234,
        &target_inodes,
        &mut owners,
        &mut visited,
        2,
    )
    .expect("fd traversal at the cap must succeed");

    assert_eq!(owners.get(&44).map(Vec::as_slice), Some(&[1234][..]));
    assert_eq!(visited, 2);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn pid_socket_owner_collection_fails_closed_past_fd_budget() {
    let proc_root = temp_proc_root("fd-budget");
    let fd_dir = proc_root.join("1234").join("fd");
    fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
    for fd in 0..3 {
        std::os::unix::fs::symlink("socket:[44]", fd_dir.join(fd.to_string()))
            .expect("test socket symlink must be created");
    }
    let mut owners = HashMap::new();
    let mut visited = 0;

    let error = collect_pid_socket_owners(
        &proc_root,
        1234,
        &HashSet::from([44]),
        &mut owners,
        &mut visited,
        2,
    )
    .expect_err("fd traversal past the cap must fail closed");

    assert_eq!(visited, 2);
    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(
            ObservationError::OwnerAttributionLimitExceeded
        )
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn collector_enforces_fd_budget_through_production_orchestration() {
    let proc_root = temp_proc_root("collector-fd-budget");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 100, "worker", 1);
    for fd in 0..3 {
        std::os::unix::fs::symlink("socket:[44]", proc_root.join("100/fd").join(fd.to_string()))
            .expect("test socket symlink must be created");
    }
    let collector = LinuxCollector::with_proc_root_and_limits(
        proc_root.clone(),
        CollectionLimits {
            fd_entries: 2,
            ..CollectionLimits::PRODUCTION
        },
    );

    let error = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::LegacyList,
    )
    .expect_err("collector must enforce fd cap");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(
            ObservationError::OwnerAttributionLimitExceeded
        )
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn display_collection_does_not_apply_the_legacy_projection_limit() {
    let proc_root = temp_proc_root("collector-independent-projection-budget");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    for pid in [100, 101, 102] {
        write_process(&proc_root, pid, "worker", 1);
        std::os::unix::fs::symlink("socket:[44]", proc_root.join(pid.to_string()).join("fd/0"))
            .expect("test socket symlink must be created");
    }
    let collector = LinuxCollector::with_proc_root_and_limits(
        proc_root.clone(),
        CollectionLimits {
            socket_observations: 2,
            ..CollectionLimits::PRODUCTION
        },
    );

    let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::Display,
    )
    .expect("full-state collection must not enforce a legacy projection limit");

    assert_eq!(snapshot.sockets.len(), 1);
    assert_eq!(snapshot.sockets[0].owners.len(), 3);
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn collector_enforces_pid_budget_through_production_orchestration() {
    let proc_root = temp_proc_root("collector-pid-budget");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    for pid in [100, 101, 102] {
        write_process(&proc_root, pid, "worker", 1);
    }
    let collector = LinuxCollector::with_proc_root_and_limits(
        proc_root.clone(),
        CollectionLimits {
            process_ids: 2,
            ..CollectionLimits::PRODUCTION
        },
    );

    let error = <LinuxCollector as crate::collector::Collector>::collect(
        &collector,
        crate::observation::MetadataProfile::LegacyList,
    )
    .expect_err("collector must enforce PID cap");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(
            ObservationError::ProcessIdentityLimitExceeded
        )
    ));
    fs::remove_dir_all(proc_root).expect("test proc root must clean up");
}

#[test]
fn native_metadata_profiles_preserve_socket_owners_and_limit_enrichment() {
    use crate::collector::Collector;
    use crate::observation::MetadataProfile;
    let proc_root = temp_proc_root("metadata-profiles");
    write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
    write_socket_table(&proc_root, "net/udp", &[]);
    write_process(&proc_root, 1234, "worker", 1);
    write_process(&proc_root, 1, "parent", 0);
    std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234/fd/3"))
        .expect("socket owner fixture");
    let collector = LinuxCollector::with_proc_root(proc_root.clone());
    let identity = collector
        .collect(MetadataProfile::IdentityOnly)
        .expect("identity collection");
    let display = collector
        .collect(MetadataProfile::Display)
        .expect("display collection");
    let legacy = collector
        .collect(MetadataProfile::LegacyList)
        .expect("legacy collection");
    fs::remove_dir_all(proc_root).expect("fixture cleanup");

    assert_eq!(identity.sockets.len(), 1);
    assert_eq!(identity.sockets, display.sockets);
    assert_eq!(display.sockets, legacy.sockets);
    let owner = crate::observation::ProcessIdentity {
        pid: 1234,
        start_marker: crate::observation::ProcessStartMarker::linux(12340).expect("fixture marker"),
    };
    assert_eq!(
        identity.sockets[0].owners,
        [crate::observation::OwnerObservation::Verified(owner)]
    );
    assert_eq!(identity.processes.len(), 1);
    assert_eq!(
        identity.processes[&owner],
        crate::observation::ProcessObservation::identity_only()
    );
    assert_eq!(display.processes[&owner].name.as_deref(), Some("worker"));
    assert_eq!(
        display.processes[&owner].parent_process_name.as_deref(),
        Some("parent")
    );
    assert_eq!(display.processes[&owner].command_line, None);
    assert_eq!(
        legacy.processes[&owner].command_line.as_deref(),
        Some("worker --test")
    );
}
