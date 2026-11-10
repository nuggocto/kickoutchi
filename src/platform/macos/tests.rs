use std::collections::BTreeSet;
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use super::{
    In4In6Addr, InSocketAddress, InSockinfo, InSockinfoV4, InSockinfoV6, ProcessMetadata,
    SocketFdinfo, SocketProtocolInfo, SocketScanLoss, TSI_S_LISTEN, TcpSockinfo,
    checked_returned_buffer_len, collect_pid_socket_records_from_fds, decode_port,
    decode_procargs2, decode_procargs2_bounded, fd_list_is_complete, fd_record_count,
    fresh_process_evidence_from_reads, list_process_fds_with_reader, native_pass_from_records,
    process_ids_with_reader, process_observation_from_metadata, read_changing_native_buffer,
    retain_parent_process_name, retain_socket_record, socket_record_from_info,
};
use crate::model::Protocol;
use crate::observation::{
    EvidenceImpact, Ipv6Scope, MetadataCompleteness, OwnerCompleteness, PlatformSocketToken,
    SocketState,
};
use crate::process_evidence::ProcessEvidenceError;
use crate::tree::TreeProcessOps;

fn zeroed_socket_fdinfo() -> SocketFdinfo {
    unsafe {
        // SAFETY: these C layout structs are plain data buffers in production;
        // tests zero them before filling the fields relevant to record parsing.
        MaybeUninit::<SocketFdinfo>::zeroed().assume_init()
    }
}

fn grouped_record(socket: super::SocketRecord, owner_pids: &[u32]) -> super::GroupedSocketRecord {
    super::GroupedSocketRecord {
        socket,
        owner_pids: owner_pids.to_vec(),
    }
}

#[test]
fn prepare_thaw_records_the_identity_used_by_production_continuation() {
    let marker = crate::observation::ProcessStartMarker::macos(1, 0).expect("test marker is valid");
    let mut ops = super::MacosTreeOps::new();

    ops.prepare_thaw(42, Some(marker));

    assert_eq!(ops.verified_markers.get(&42), Some(&marker));
}

#[test]
fn rollback_identity_after_stop_uses_the_immediate_marker() {
    let stopped =
        crate::observation::ProcessStartMarker::macos(2, 0).expect("test marker is valid");

    assert_eq!(
        super::MacosTreeOps::rollback_identity_after_stop_with(42, |_| Ok(Some(stopped))),
        Some(stopped)
    );
}

#[test]
fn unreadable_post_stop_identity_does_not_fall_back_to_prior_identity() {
    assert_eq!(
        super::MacosTreeOps::rollback_identity_after_stop_with(42, |_| {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        }),
        None
    );
}

#[test]
fn continuation_guard_refuses_a_pid_without_a_verified_marker() {
    let ops = super::MacosTreeOps::new();

    assert_eq!(
        ops.recheck_marker(42),
        Err(crate::tree::TreeSignalResult::Denied)
    );
}

#[test]
fn rollback_without_observed_marker_clears_prior_authorization() {
    let marker = crate::observation::ProcessStartMarker::macos(1, 0).expect("test marker is valid");
    let mut ops = super::MacosTreeOps::new();
    ops.prepare_thaw(42, Some(marker));

    ops.prepare_thaw(42, None);

    assert!(!ops.verified_markers.contains_key(&42));
    assert_eq!(
        ops.recheck_marker_with(42, |_| Ok(Some(marker))),
        Err(crate::tree::TreeSignalResult::Denied)
    );
}

#[test]
fn rollback_continuation_accepts_stopped_root_and_descendant_replacements() {
    let root_replacement =
        crate::observation::ProcessStartMarker::macos(2, 0).expect("test marker is valid");
    let descendant_replacement =
        crate::observation::ProcessStartMarker::macos(3, 0).expect("test marker is valid");
    let mut ops = super::MacosTreeOps::new();
    ops.prepare_thaw(42, Some(root_replacement));
    ops.prepare_thaw(43, Some(descendant_replacement));

    assert_eq!(
        ops.recheck_marker_with(42, |_| Ok(Some(root_replacement))),
        Ok(())
    );
    assert_eq!(
        ops.recheck_marker_with(43, |_| Ok(Some(descendant_replacement))),
        Ok(())
    );
}

#[test]
fn rollback_continuation_refuses_when_identity_changes_again() {
    let stopped_replacement =
        crate::observation::ProcessStartMarker::macos(2, 0).expect("test marker is valid");
    let later_replacement =
        crate::observation::ProcessStartMarker::macos(3, 0).expect("test marker is valid");
    let mut ops = super::MacosTreeOps::new();
    ops.prepare_thaw(42, Some(stopped_replacement));

    assert_eq!(
        ops.recheck_marker_with(42, |_| Ok(Some(later_replacement))),
        Err(crate::tree::TreeSignalResult::NotFound)
    );
}

fn in_sockinfo_v4(port: u16, addr: Ipv4Addr) -> InSockinfo {
    InSockinfo {
        insi_fport: 0,
        insi_lport: i32::from(port.to_be()),
        insi_gencnt: 0,
        insi_flags: 0,
        insi_flow: 0,
        insi_vflag: super::INI_IPV4,
        insi_ip_ttl: 0,
        rfu_1: 0,
        insi_faddr: InSocketAddress {
            ina_46: In4In6Addr {
                i46a_pad32: [0; 3],
                i46a_addr4: libc::in_addr { s_addr: 0 },
            },
        },
        insi_laddr: InSocketAddress {
            ina_46: In4In6Addr {
                i46a_pad32: [0; 3],
                i46a_addr4: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.octets()),
                },
            },
        },
        insi_v4: InSockinfoV4 { in4_tos: 0 },
        insi_v6: InSockinfoV6 {
            in6_hlim: 0,
            in6_cksum: 0,
            in6_ifindex: 0,
            in6_hops: 0,
        },
    }
}

fn in_sockinfo_v6(port: u16, addr: Ipv6Addr) -> InSockinfo {
    InSockinfo {
        insi_vflag: super::INI_IPV6,
        insi_lport: i32::from(port.to_be()),
        insi_laddr: InSocketAddress {
            ina_6: libc::in6_addr {
                s6_addr: addr.octets(),
            },
        },
        ..in_sockinfo_v4(port, Ipv4Addr::UNSPECIFIED)
    }
}

fn tcp_socket_fdinfo(native_state: libc::c_int) -> SocketFdinfo {
    let mut info = zeroed_socket_fdinfo();
    info.psi.soi_protocol = libc::IPPROTO_TCP;
    info.psi.soi_family = libc::AF_INET;
    info.psi.soi_kind = super::SOCKINFO_TCP;
    info.psi.soi_so = 0xCAFE;
    info.psi.soi_proto = SocketProtocolInfo {
        pri_tcp: TcpSockinfo {
            tcpsi_ini: in_sockinfo_v4(3000, Ipv4Addr::LOCALHOST),
            tcpsi_state: native_state,
            tcpsi_timer: [0; 4],
            tcpsi_mss: 0,
            tcpsi_flags: 0,
            rfu_1: 0,
            tcpsi_tp: 0,
        },
    };
    info
}

fn procargs2(argument_count: i32, exe: &[u8], argv: &[&[u8]]) -> Vec<u8> {
    let mut bytes = argument_count.to_ne_bytes().to_vec();
    bytes.extend_from_slice(exe);
    bytes.push(0);
    bytes.push(0);
    for arg in argv {
        bytes.extend_from_slice(arg);
        bytes.push(0);
    }
    bytes
}

#[test]
fn darwin_tcp_states_map_to_observation_states() {
    let expected = [
        SocketState::Closed,
        SocketState::Listen,
        SocketState::SynSent,
        SocketState::SynReceived,
        SocketState::Established,
        SocketState::CloseWait,
        SocketState::FinWait1,
        SocketState::Closing,
        SocketState::LastAck,
        SocketState::FinWait2,
        SocketState::TimeWait,
    ];
    for (native, expected) in (0..=10).zip(expected) {
        assert_eq!(super::darwin_tcp_state(native).unwrap(), expected);
        let record = socket_record_from_info(&tcp_socket_fdinfo(native))
            .expect("documented TCP state is valid")
            .expect("every documented TCP state is retained");
        assert_eq!(record.state, expected);
        let pass = super::native_pass_from_records(
            vec![grouped_record(record, &[42])],
            BTreeSet::new(),
            0,
        )
        .expect("documented state survives native observation materialization");
        assert_eq!(pass.rows[0].socket.state, expected);
    }
}

#[test]
fn darwin_tcp_state_preserves_unknown_and_rejects_negative_values() {
    assert_eq!(
        super::darwin_tcp_state(11).unwrap(),
        SocketState::Unknown(11)
    );
    assert_eq!(
        super::darwin_tcp_state(libc::c_int::MAX).unwrap(),
        SocketState::Unknown(u32::try_from(libc::c_int::MAX).unwrap())
    );
    assert_eq!(
        super::darwin_tcp_state(-1).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn tcp_listen_socket_info_becomes_a_port_record() {
    let mut info = zeroed_socket_fdinfo();
    info.psi.soi_protocol = libc::IPPROTO_TCP;
    info.psi.soi_family = libc::AF_INET;
    info.psi.soi_kind = super::SOCKINFO_TCP;
    info.psi.soi_so = 0xCAFE;
    info.psi.soi_proto = SocketProtocolInfo {
        pri_tcp: TcpSockinfo {
            tcpsi_ini: in_sockinfo_v4(3000, Ipv4Addr::LOCALHOST),
            tcpsi_state: TSI_S_LISTEN,
            tcpsi_timer: [0; 4],
            tcpsi_mss: 0,
            tcpsi_flags: 0,
            rfu_1: 0,
            tcpsi_tp: 0,
        },
    };

    let record = socket_record_from_info(&info)
        .expect("valid fdinfo")
        .expect("listen socket is kept");

    assert_eq!(record.protocol, Protocol::Tcp);
    assert_eq!(record.state, SocketState::Listen);
    assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(record.local_port, 3000);
    assert_eq!(record.socket_id, 0xCAFE);
}

#[test]
fn unbound_port_zero_socket_is_outside_endpoint_observations() {
    let mut info = tcp_socket_fdinfo(super::TSI_S_CLOSED);
    info.psi.soi_proto = SocketProtocolInfo {
        pri_tcp: TcpSockinfo {
            tcpsi_ini: in_sockinfo_v4(0, Ipv4Addr::UNSPECIFIED),
            tcpsi_state: super::TSI_S_CLOSED,
            tcpsi_timer: [0; 4],
            tcpsi_mss: 0,
            tcpsi_flags: 0,
            rfu_1: 0,
            tcpsi_tp: 0,
        },
    };

    assert_eq!(
        socket_record_from_info(&info).expect("unbound socket is valid native data"),
        None
    );
}

#[test]
fn udp_socket_info_becomes_a_bound_port_record() {
    let mut info = zeroed_socket_fdinfo();
    info.psi.soi_protocol = libc::IPPROTO_UDP;
    info.psi.soi_family = libc::AF_INET6;
    info.psi.soi_kind = super::SOCKINFO_IN;
    info.psi.soi_so = 77;
    info.psi.soi_proto = SocketProtocolInfo {
        pri_in: in_sockinfo_v6(5353, Ipv6Addr::LOCALHOST),
    };

    let record = socket_record_from_info(&info)
        .expect("valid fdinfo")
        .expect("udp socket is kept");

    assert_eq!(record.protocol, Protocol::Udp);
    assert_eq!(record.state, SocketState::Bound);
    assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(record.local_port, 5353);

    let pass = native_pass_from_records(
        vec![grouped_record(record, &[902])],
        std::collections::BTreeSet::new(),
        0,
    )
    .expect("unavailable native scope is representable");
    assert_eq!(
        pass.rows[0].socket.endpoint.ipv6_scope,
        Some(Ipv6Scope::Unavailable)
    );
}

#[test]
fn dual_stack_socket_uses_the_address_view_selected_by_family() {
    let ipv4 = Ipv4Addr::new(198, 51, 100, 7);
    let mut ipv4_info = in_sockinfo_v4(8079, ipv4);
    ipv4_info.insi_vflag = super::INI_IPV4 | super::INI_IPV6;
    assert_eq!(
        super::decode_local_addr(&ipv4_info, libc::AF_INET),
        Some(IpAddr::V4(ipv4))
    );

    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
    let mut info = in_sockinfo_v6(8080, ipv6);
    info.insi_vflag = super::INI_IPV4 | super::INI_IPV6;

    assert_eq!(
        super::decode_local_addr(&info, libc::AF_INET6),
        Some(IpAddr::V6(ipv6))
    );

    let mapped = Ipv4Addr::new(192, 0, 2, 44).to_ipv6_mapped();
    let mut mapped_info = in_sockinfo_v6(8081, mapped);
    mapped_info.insi_vflag = super::INI_IPV4 | super::INI_IPV6;
    assert_eq!(
        super::decode_local_addr(&mapped_info, libc::AF_INET6),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)))
    );
}

#[test]
fn production_orchestration_emits_endpoint_null_ipv6_scope_evidence() {
    let pass = super::MacosCollector::collect_native_pass_with(
        || Ok(vec![902]),
        |_pid, _| {
            Ok((
                vec![super::SocketRecord {
                    protocol: Protocol::Udp,
                    local_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    local_port: 5353,
                    state: SocketState::Bound,
                    socket_id: 77,
                }],
                BTreeSet::new(),
            ))
        },
    )
    .expect("IPv6 socket remains observable without native scope");

    assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::Scope);
    assert_eq!(pass.evidence_gaps[0].endpoint, None);
    assert_eq!(pass.evidence_gaps[0].pid, None);
}

#[test]
fn native_pass_retains_socket_id_and_shared_owners() {
    let record = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        socket_id: 0xCAFE,
    };

    let pass = native_pass_from_records(
        vec![grouped_record(record, &[100, 101])],
        std::collections::BTreeSet::new(),
        0,
    )
    .expect("native macOS pass is valid");

    assert_eq!(
        pass.rows[0].socket.token,
        PlatformSocketToken::macos_socket_id(0xCAFE)
    );
    assert_eq!(pass.rows[0].owner_pids, [100, 101]);
    assert_eq!(pass.rows[0].socket.timer, None);
    assert_eq!(pass.global_owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(pass.rows[0].owner_completeness, OwnerCompleteness::Complete);
}

#[test]
fn tokenless_same_endpoint_descriptors_remain_distinct_within_one_pid() {
    let fds = [9, 10].map(|proc_fd| libc::proc_fdinfo {
        proc_fd,
        proc_fdtype: u32::try_from(libc::PROX_FDTYPE_SOCKET).unwrap(),
    });
    let record = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        socket_id: 0,
    };
    let mut traversed = 0;

    let (records, losses) =
        collect_pid_socket_records_from_fds(100, &fds, &mut traversed, fds.len(), |_| {
            Ok(Some(record.clone()))
        })
        .expect("tokenless descriptors collect");

    assert_eq!(records, [record.clone(), record]);
    assert!(losses.is_empty());
}

#[test]
fn tokenless_same_endpoint_sockets_do_not_merge_owners_across_pids() {
    let record = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        socket_id: 0,
    };
    let mut records = Vec::new();
    let mut indexes = std::collections::HashMap::new();
    let mut owner_edges = 0;
    let mut losses = std::collections::BTreeSet::new();
    let mut omitted = 0;

    retain_socket_record(
        &mut records,
        &mut indexes,
        &mut owner_edges,
        &mut losses,
        &mut omitted,
        record.clone(),
        100,
    )
    .expect("first tokenless socket is retained");
    retain_socket_record(
        &mut records,
        &mut indexes,
        &mut owner_edges,
        &mut losses,
        &mut omitted,
        record,
        101,
    )
    .expect("second tokenless socket is retained");
    let pass = native_pass_from_records(records, std::collections::BTreeSet::new(), 0)
        .expect("tokenless sockets form a valid pass");

    assert_eq!(pass.rows.len(), 2);
    assert!(pass.rows.iter().all(|row| row.socket.token.is_none()));
    assert_eq!(pass.rows[0].owner_pids, [100]);
    assert_eq!(pass.rows[1].owner_pids, [101]);
    assert!(indexes.is_empty());
}

#[test]
fn repeated_socket_token_with_conflicting_facts_is_a_socket_set_gap() {
    let first = super::SocketRecord {
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 3000,
        state: SocketState::Listen,
        socket_id: 0xCAFE,
    };
    let conflicting = super::SocketRecord {
        state: SocketState::Established,
        ..first.clone()
    };
    let mut records = Vec::new();
    let mut indexes = std::collections::HashMap::new();
    let mut owner_edges = 0;
    let mut losses = std::collections::BTreeSet::new();
    let mut omitted = 0;

    retain_socket_record(
        &mut records,
        &mut indexes,
        &mut owner_edges,
        &mut losses,
        &mut omitted,
        first,
        100,
    )
    .unwrap();
    retain_socket_record(
        &mut records,
        &mut indexes,
        &mut owner_edges,
        &mut losses,
        &mut omitted,
        conflicting,
        101,
    )
    .unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].owner_pids, [100]);
    assert_eq!(
        losses,
        [SocketScanLoss::TokenConflict].into_iter().collect()
    );
    let pass = native_pass_from_records(records, losses, omitted).unwrap();
    assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::SocketSet);
    assert_eq!(pass.evidence_gaps[0].pid, None);
    assert_eq!(pass.evidence_gaps[0].endpoint, None);
}

#[test]
fn pid_scan_denial_is_socket_set_loss_not_owner_loss() {
    let record = super::SocketRecord {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_port: 5353,
        state: SocketState::Bound,
        socket_id: 77,
    };

    let pass = native_pass_from_records(
        vec![grouped_record(record, &[902])],
        [SocketScanLoss::PermissionDenied(42)].into_iter().collect(),
        0,
    )
    .expect("permission loss remains representable");

    assert_eq!(pass.global_owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(pass.rows[0].owner_completeness, OwnerCompleteness::Complete);
    assert_eq!(pass.evidence_gaps[0].endpoint, None);
    assert_eq!(pass.evidence_gaps[0].pid, Some(42));
    assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::SocketSet);
}

#[test]
fn production_orchestration_propagates_process_enumeration_denial() {
    let error = super::MacosCollector::collect_native_pass_with(
        || Err(crate::observation::ObservationError::SocketTablePermissionDenied.into()),
        |_, _| unreachable!("PID scan must not start after process-list denial"),
    )
    .expect_err("total process enumeration denial is operational");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(
            crate::observation::ObservationError::SocketTablePermissionDenied
        )
    ));
}

#[test]
fn production_orchestration_propagates_process_enumeration_failure() {
    let error = super::MacosCollector::collect_native_pass_with(
        || {
            Err(super::platform_error(
                "proc_listallpids",
                "I/O failure".to_owned(),
            ))
        },
        |_, _| unreachable!("PID scan must not start after process-list failure"),
    )
    .expect_err("generic process enumeration failure is operational");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Platform {
            operation: "proc_listallpids",
            ..
        }
    ));
}

#[test]
fn production_orchestration_preserves_rows_while_recording_pid_scan_denial() {
    let pass = super::MacosCollector::collect_native_pass_with(
        || Ok(vec![42, 902]),
        |pid, _| {
            if pid == 42 {
                return Err(std::io::Error::from_raw_os_error(libc::EACCES));
            }
            Ok((
                vec![super::SocketRecord {
                    protocol: Protocol::Udp,
                    local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    local_port: 5353,
                    state: SocketState::Bound,
                    socket_id: 77,
                }],
                BTreeSet::new(),
            ))
        },
    )
    .expect("one denied PID does not erase another PID's authoritative row");

    assert_eq!(pass.rows.len(), 1);
    assert_eq!(pass.rows[0].owner_pids, [902]);
    assert_eq!(pass.evidence_gaps.len(), 1);
    assert_eq!(pass.evidence_gaps[0].pid, Some(42));
    assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::SocketSet);
}

#[test]
fn production_orchestration_maps_pid_scan_failures_to_socket_set_gaps() {
    let cases = [
        (
            std::io::Error::from_raw_os_error(libc::ESRCH),
            crate::observation::EvidenceGapCode::OwnerDisappeared,
        ),
        (
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed fdinfo"),
            crate::observation::EvidenceGapCode::NativeFieldUnavailable,
        ),
        (
            std::io::Error::other("proc_pidinfo failed"),
            crate::observation::EvidenceGapCode::OwnerAttributionIncomplete,
        ),
    ];

    for (error, expected_code) in cases {
        let mut error = Some(error);
        let pass = super::MacosCollector::collect_native_pass_with(
            || Ok(vec![42]),
            |_, _| Err(error.take().expect("one PID scan")),
        )
        .expect("per-PID scan loss remains a partial pass");

        assert_eq!(pass.rows, []);
        assert_eq!(pass.evidence_gaps.len(), 1);
        assert_eq!(pass.evidence_gaps[0].pid, Some(42));
        assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::SocketSet);
        assert_eq!(pass.evidence_gaps[0].code, expected_code);
    }
}

#[test]
fn production_orchestration_distinguishes_fd_limit_and_allocation_failures() {
    let oversized = super::MacosCollector::collect_native_pass_with(
        || Ok(vec![42]),
        |_, _| Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge)),
    )
    .expect_err("aggregate FD exhaustion is an owner-attribution limit failure");
    assert!(matches!(
        oversized,
        crate::collector::CollectorError::Observation(
            crate::observation::ObservationError::OwnerAttributionLimitExceeded
        )
    ));

    let allocation = super::MacosCollector::collect_native_pass_with(
        || Ok(vec![42]),
        |_, _| Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
    )
    .expect_err("FD allocation failure remains an operational platform error");
    assert!(matches!(
        allocation,
        crate::collector::CollectorError::Platform {
            operation: "proc_pidinfo(PROC_PIDLISTFDS)",
            ..
        }
    ));
}

#[test]
fn socket_scan_losses_are_bounded_at_the_native_pass_source() {
    let mut losses = std::collections::BTreeSet::new();
    let mut omitted = 0u64;
    for pid in 1..=u32::try_from(crate::observation::EVIDENCE_GAPS_MAX).unwrap() {
        super::retain_socket_scan_loss(&mut losses, &mut omitted, SocketScanLoss::Disappeared(pid));
    }
    assert_eq!(losses.len(), crate::observation::EVIDENCE_GAPS_MAX);
    assert_eq!(omitted, 0);

    super::retain_socket_scan_loss(
        &mut losses,
        &mut omitted,
        SocketScanLoss::Disappeared(u32::MAX),
    );
    let pass = native_pass_from_records(Vec::new(), losses, omitted)
        .expect("bounded socket losses remain observable");
    assert_eq!(
        pass.evidence_gaps.len(),
        crate::observation::EVIDENCE_GAPS_MAX
    );
    assert_eq!(pass.omitted_evidence_gap_count, 1);
}

#[test]
fn ipv4_mapped_ipv6_socket_info_normalizes_to_ipv4() {
    let mut info = zeroed_socket_fdinfo();
    info.psi.soi_protocol = libc::IPPROTO_UDP;
    info.psi.soi_family = libc::AF_INET6;
    info.psi.soi_kind = super::SOCKINFO_IN;
    info.psi.soi_proto = SocketProtocolInfo {
        pri_in: in_sockinfo_v6(3000, Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
    };

    let record = socket_record_from_info(&info)
        .expect("valid fdinfo")
        .expect("mapped socket is kept");

    assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(record.local_port, 3000);
}

#[test]
fn port_decoding_rejects_zero_and_uses_network_byte_order() {
    assert_eq!(decode_port(i32::from(3000_u16.to_be())), Some(3000));
    assert_eq!(decode_port(0), None);
    assert_eq!(decode_port(i32::from(u16::MAX) + 1), None);
    assert_eq!(decode_port(-1), None);
}

#[test]
fn procargs2_decoding_returns_only_argv_not_environment() {
    let mut bytes = procargs2(3, b"/usr/bin/python3", &[b"python3", b"-m", b"http.server"]);
    bytes.extend_from_slice(b"PORT=3000\0");

    let command = decode_procargs2(&bytes).expect("argv should decode");

    assert_eq!(command, "python3 -m http.server");
    assert!(!command.contains("PORT=3000"));
}

#[test]
fn procargs2_decoding_counts_empty_arguments_without_rendering_extra_spaces() {
    let bytes = procargs2(3, b"/bin/program", &[b"program", b"", b"value"]);

    assert_eq!(decode_procargs2(&bytes).as_deref(), Some("program value"));
}

#[test]
fn procargs2_decoding_rejects_empty_or_malformed_data() {
    assert_eq!(decode_procargs2(&[]), None);
    assert_eq!(decode_procargs2(&0_i32.to_ne_bytes()), None);
    assert_eq!(decode_procargs2(&1_i32.to_ne_bytes()), None);

    let truncated_argv = procargs2(2, b"/bin/test", &[b"test"]);
    assert_eq!(
        decode_procargs2_bounded(&truncated_argv, 64),
        Err(super::ProcArgsDecodeError::Malformed)
    );

    let mut unterminated = 1_i32.to_ne_bytes().to_vec();
    unterminated.extend_from_slice(b"/bin/test\0\0test");
    assert_eq!(
        decode_procargs2_bounded(&unterminated, 64),
        Err(super::ProcArgsDecodeError::Malformed)
    );
}

#[test]
fn unavailable_or_omitted_command_line_marks_metadata_partial() {
    let mut missing = super::ProcessMetadata::default();
    super::apply_command_line_read(
        &mut missing,
        Ok(super::CommandLineRead::Missing),
        crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
    );
    assert!(missing.partial);
    assert!(!missing.budget_omitted);

    let mut omitted = super::ProcessMetadata::default();
    super::apply_command_line_read(
        &mut omitted,
        Ok(super::CommandLineRead::Omitted),
        crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
    );
    assert!(omitted.partial);
    assert!(omitted.budget_omitted);

    let mut malformed = super::ProcessMetadata::default();
    super::apply_command_line_read(
        &mut malformed,
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed procargs2",
        )),
        crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
    );
    assert_eq!(malformed.command_line, None);
    assert!(malformed.partial);
    assert!(!malformed.budget_omitted);
}

#[test]
fn parent_name_exact_fit_is_retained_without_budget_omission() {
    let mut metadata = ProcessMetadata::default();
    let native = [
        b'p'.cast_signed(),
        b'a'.cast_signed(),
        b'r'.cast_signed(),
        b'e'.cast_signed(),
        b'n'.cast_signed(),
        b't'.cast_signed(),
        0,
    ];

    retain_parent_process_name(
        &mut metadata,
        Some(super::c_char_slice_to_parent_name(&native, 6)),
    );

    assert_eq!(metadata.parent_process_name.as_deref(), Some("parent"));
    assert!(!metadata.partial);
    assert!(!metadata.budget_omitted);
}

#[test]
fn parent_name_first_excess_and_zero_remaining_are_budget_omissions() {
    for max_bytes in [5, 0] {
        let mut metadata = ProcessMetadata::default();
        let native = [
            b'p'.cast_signed(),
            b'a'.cast_signed(),
            b'r'.cast_signed(),
            b'e'.cast_signed(),
            b'n'.cast_signed(),
            b't'.cast_signed(),
            0,
        ];

        retain_parent_process_name(
            &mut metadata,
            Some(super::c_char_slice_to_parent_name(&native, max_bytes)),
        );

        assert_eq!(metadata.parent_process_name, None);
        assert!(metadata.partial);
        assert!(metadata.budget_omitted);
        assert_eq!(
            process_observation_from_metadata(metadata).metadata_omission,
            Some(crate::observation::MetadataOmission::BudgetExceeded)
        );
    }
}

#[test]
fn unavailable_parent_name_is_not_a_budget_omission() {
    let mut metadata = ProcessMetadata::default();

    retain_parent_process_name(&mut metadata, Some(super::ParentNameRead::Unavailable));

    assert!(metadata.partial);
    assert!(!metadata.budget_omitted);
}

#[test]
fn cached_parent_name_respects_each_childs_remaining_budget() {
    let cached = super::ParentNameRead::Value("parent".to_owned());

    assert_eq!(
        super::parent_name_for_budget(&cached, 6),
        super::ParentNameRead::Value("parent".to_owned())
    );
    assert_eq!(
        super::parent_name_for_budget(&cached, 5),
        super::ParentNameRead::BudgetExceeded
    );
    assert_eq!(
        super::parent_name_for_budget(&cached, 0),
        super::ParentNameRead::BudgetExceeded
    );
}

#[test]
fn procargs2_seam_enforces_one_mib_final_utf8_boundary() {
    let max = crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
    let exact_argument = vec![b'x'; max];
    let exact = procargs2(1, b"", &[&exact_argument]);
    assert_eq!(
        decode_procargs2_bounded(&exact, max)
            .as_deref()
            .map(str::len),
        Ok(max)
    );

    let oversized_argument = vec![b'x'; max + 1];
    let oversized = procargs2(1, b"", &[&oversized_argument]);
    assert_eq!(
        decode_procargs2_bounded(&oversized, max),
        Err(super::ProcArgsDecodeError::OverLimit)
    );
}

#[test]
fn procargs2_join_budget_counts_separators_and_lossy_utf8_exactly() {
    let exact = procargs2(3, b"", &[b"ab", &[0xff], b"cd"]);
    assert_eq!(
        decode_procargs2_bounded(&exact, 9).as_deref(),
        Ok("ab � cd")
    );
    assert_eq!(
        decode_procargs2_bounded(&exact, 8),
        Err(super::ProcArgsDecodeError::OverLimit)
    );
}

#[test]
fn procargs2_many_arguments_refuse_before_joining_over_budget_output() {
    let arguments = vec![b"x".as_slice(); 65_536];
    let bytes = procargs2(65_536, b"", &arguments);
    assert_eq!(
        decode_procargs2_bounded(&bytes, 31),
        Err(super::ProcArgsDecodeError::OverLimit)
    );
}

#[test]
fn changing_native_read_succeeds_on_the_third_bounded_attempt() {
    let mut reads = 0;
    let mut allocations = Vec::new();
    let buffer = read_changing_native_buffer(8, "native_test", |buffer| {
        let Some(buffer) = buffer else {
            return Ok(4);
        };
        reads += 1;
        allocations.push(buffer.len());
        if reads < 3 {
            return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
        }
        buffer.copy_from_slice(b"test");
        Ok(4)
    })
    .expect("attempt three is accepted");

    assert_eq!(buffer, b"test");
    assert_eq!(reads, 3);
    assert_eq!(allocations, [4, 4, 4]);
}

#[test]
fn changing_native_read_exhausts_after_three_attempts() {
    let mut reads = 0;
    let error = read_changing_native_buffer(8, "native_test", |buffer| {
        if buffer.is_none() {
            return Ok(4);
        }
        reads += 1;
        Err(std::io::Error::from_raw_os_error(libc::ENOMEM))
    })
    .expect_err("a fourth read attempt must not start");

    assert_eq!(reads, crate::observation::NATIVE_RESIZE_ATTEMPTS_MAX);
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("kept growing"));
}

#[test]
fn changing_native_read_checks_budget_before_allocation() {
    let mut buffer_reads = 0;
    let error = read_changing_native_buffer(8, "native_test", |buffer| {
        if buffer.is_some() {
            buffer_reads += 1;
        }
        Ok(9)
    })
    .expect_err("oversized sizing result is rejected");

    assert_eq!(buffer_reads, 0);
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn malformed_socket_fdinfo_cannot_silently_hide_a_socket() {
    let mut info = zeroed_socket_fdinfo();
    info.psi.soi_protocol = libc::IPPROTO_TCP;
    info.psi.soi_family = libc::AF_INET;
    info.psi.soi_kind = super::SOCKINFO_TCP;
    info.psi.soi_proto = SocketProtocolInfo {
        pri_tcp: TcpSockinfo {
            tcpsi_ini: in_sockinfo_v4(0, Ipv4Addr::LOCALHOST),
            tcpsi_state: -1,
            tcpsi_timer: [0; 4],
            tcpsi_mss: 0,
            tcpsi_flags: 0,
            rfu_1: 0,
            tcpsi_tp: 0,
        },
    };
    let fds = [libc::proc_fdinfo {
        proc_fd: 9,
        proc_fdtype: u32::try_from(libc::PROX_FDTYPE_SOCKET).unwrap(),
    }];
    let mut traversed = 0;

    let (_, losses) = collect_pid_socket_records_from_fds(42, &fds, &mut traversed, 1, |_| {
        socket_record_from_info(&info)
    })
    .expect("malformed per-FD data is retained as socket-set loss");

    assert_eq!(
        losses,
        [SocketScanLoss::Malformed(42)].into_iter().collect()
    );
    let pass = native_pass_from_records(Vec::new(), losses, 0).expect("loss is representable");
    assert_eq!(pass.evidence_gaps[0].impact, EvidenceImpact::SocketSet);
}

#[test]
fn malformed_or_truncated_fd_enumeration_is_not_accepted() {
    let record_size = size_of::<libc::proc_fdinfo>();
    assert_eq!(
        fd_record_count(record_size - 1, record_size)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        fd_record_count(record_size * 2, record_size)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(!fd_list_is_complete(16, 16));
    assert!(fd_list_is_complete(15, 16));
}

#[test]
fn production_pid_reader_accepts_exact_maximum_on_attempt_three() {
    let max = crate::observation::CANDIDATE_PROCESS_IDS_MAX;
    let initial = max / 2 - super::PROCESS_LIST_GROWTH_MARGIN;
    let mut attempts = Vec::new();

    let pids = process_ids_with_reader(|buffer, _| {
        let Some(buffer) = buffer else {
            return Ok(libc::c_int::try_from(initial).unwrap());
        };
        attempts.push(buffer.len());
        if attempts.len() < 3 {
            return Ok(libc::c_int::try_from(buffer.len()).unwrap());
        }
        for (index, pid) in buffer[..max].iter_mut().rev().enumerate() {
            *pid = libc::pid_t::try_from(index + 1).unwrap();
        }
        Ok(libc::c_int::try_from(max).unwrap())
    })
    .expect("the exact production PID maximum is accepted");

    assert_eq!(attempts, [max / 2, max, max + 1]);
    assert_eq!(pids.len(), max);
    assert_eq!(pids.first(), Some(&1));
    assert_eq!(pids.last(), Some(&u32::try_from(max).unwrap()));
}

#[test]
fn zero_count_with_errno_is_an_error_and_zero_without_errno_is_success() {
    let error = super::count_result(0, libc::EIO).expect_err("zero with errno is failure");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert_eq!(super::count_result(0, 0).unwrap(), 0);
}

#[test]
fn count_call_clears_stale_errno_before_native_invocation() {
    unsafe {
        // SAFETY: __error returns this test thread's valid errno slot.
        *libc::__error() = libc::EIO;
    }

    assert_eq!(super::call_count_api(|| 0).unwrap(), 0);
    let error = super::call_count_api(|| {
        unsafe {
            // SAFETY: __error returns this test thread's valid errno slot.
            *libc::__error() = libc::EACCES;
        }
        0
    })
    .expect_err("errno set by the invocation makes zero an error");
    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn all_pid_zero_error_cannot_become_an_empty_complete_list() {
    let error = process_ids_with_reader(|_, _| {
        super::count_result(0, libc::EACCES)
            .map_err(|error| super::platform_error("proc_listallpids", error.to_string()))
    })
    .expect_err("zero-on-error must remain an enumeration failure");

    assert!(matches!(
        error,
        crate::collector::CollectorError::Platform {
            operation: "proc_listallpids",
            ..
        }
    ));
    assert_eq!(
        process_ids_with_reader(|_, _| Ok(0)).expect("genuine zero is not a native failure"),
        [] as [u32; 0]
    );
}

#[test]
fn child_pid_reader_preserves_genuine_zero_children_and_zero_error() {
    let mut buffer = vec![0; 4];
    let buffer_bytes = libc::c_int::try_from(std::mem::size_of_val(buffer.as_slice())).unwrap();
    let children = super::child_process_ids_with_reader(&mut buffer, buffer_bytes, |_, _| {
        super::count_result(0, 0)
    })
    .expect("zero children is a valid result");
    assert_eq!(children, [] as [u32; 0]);

    let mut buffer = vec![0; 4];
    let error = super::child_process_ids_with_reader(&mut buffer, buffer_bytes, |_, _| {
        super::count_result(0, libc::EACCES)
    })
    .expect_err("zero with errno is a child enumeration failure");
    assert!(matches!(
        error,
        crate::collector::CollectorError::Platform {
            operation: "proc_listchildpids",
            ..
        }
    ));
}

#[test]
fn production_pid_reader_refuses_max_plus_one_before_allocation() {
    let max = crate::observation::CANDIDATE_PROCESS_IDS_MAX;
    let mut buffer_reads = 0;

    let error = process_ids_with_reader(|buffer, _| {
        if buffer.is_some() {
            buffer_reads += 1;
        }
        Ok(libc::c_int::try_from(max + 1).unwrap())
    })
    .expect_err("one PID beyond the production maximum is refused");

    assert_eq!(buffer_reads, 0);
    assert!(matches!(
        error,
        crate::collector::CollectorError::Observation(
            crate::observation::ObservationError::ProcessIdentityLimitExceeded
        )
    ));
}

#[test]
fn pid_reader_exhausts_after_three_full_results() {
    let mut reads = 0;
    let error = process_ids_with_reader(|buffer, _| {
        if let Some(buffer) = buffer {
            reads += 1;
            Ok(libc::c_int::try_from(buffer.len()).unwrap())
        } else {
            Ok(1)
        }
    })
    .expect_err("a fourth PID buffer read must not start");

    assert_eq!(reads, crate::observation::NATIVE_RESIZE_ATTEMPTS_MAX);
    assert!(error.to_string().contains("kept growing"));
}

#[test]
fn production_fd_reader_accepts_exact_maximum_on_attempt_three() {
    let max = super::MAX_PROCESS_FDS;
    let initial = max / 2 - super::FD_LIST_GROWTH_MARGIN;
    let record_size = size_of::<libc::proc_fdinfo>();
    let mut attempts = Vec::new();

    let fds = list_process_fds_with_reader(
        |buffer, _| {
            let Some(buffer) = buffer else {
                return Ok(libc::c_int::try_from(initial * record_size).unwrap());
            };
            attempts.push(buffer.len());
            if attempts.len() < 3 {
                return Ok(libc::c_int::try_from(std::mem::size_of_val(buffer)).unwrap());
            }
            for (index, fd) in buffer[..max].iter_mut().enumerate() {
                fd.proc_fd = libc::c_int::try_from(index).unwrap();
            }
            Ok(libc::c_int::try_from(max * record_size).unwrap())
        },
        max,
        false,
    )
    .expect("the exact production per-process FD maximum is accepted");

    assert_eq!(attempts, [max / 2, max, max + 1]);
    assert_eq!(fds.len(), max);
    assert_eq!(fds.first().map(|fd| fd.proc_fd), Some(0));
    assert_eq!(
        fds.last().map(|fd| fd.proc_fd),
        Some(libc::c_int::try_from(max - 1).unwrap())
    );
}

#[test]
fn production_fd_reader_refuses_max_plus_one_before_allocation() {
    let max = super::MAX_PROCESS_FDS;
    let record_size = size_of::<libc::proc_fdinfo>();
    let mut buffer_reads = 0;

    let error = list_process_fds_with_reader(
        |buffer, _| {
            if buffer.is_some() {
                buffer_reads += 1;
            }
            Ok(libc::c_int::try_from((max + 1) * record_size).unwrap())
        },
        max,
        false,
    )
    .expect_err("one FD beyond the production maximum is refused");

    assert_eq!(buffer_reads, 0);
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("descriptor allowance"));
}

#[test]
fn fd_reader_exhausts_after_three_full_results() {
    let record_size = size_of::<libc::proc_fdinfo>();
    let mut reads = 0;
    let error = list_process_fds_with_reader(
        |buffer, _| {
            if let Some(buffer) = buffer {
                reads += 1;
                Ok(libc::c_int::try_from(std::mem::size_of_val(buffer)).unwrap())
            } else {
                Ok(libc::c_int::try_from(record_size).unwrap())
            }
        },
        super::MAX_PROCESS_FDS,
        false,
    )
    .expect_err("a fourth FD buffer read must not start");

    assert_eq!(reads, crate::observation::NATIVE_RESIZE_ATTEMPTS_MAX);
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn aggregate_fd_allowance_refuses_before_native_buffer_allocation() {
    let record_size = size_of::<libc::proc_fdinfo>();
    let mut buffer_reads = 0;

    let error = list_process_fds_with_reader(
        |buffer, _| {
            if buffer.is_some() {
                buffer_reads += 1;
            }
            Ok(libc::c_int::try_from(record_size).unwrap())
        },
        0,
        true,
    )
    .expect_err("one FD beyond the remaining aggregate allowance is refused");

    assert_eq!(buffer_reads, 0);
    assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
    assert!(error.to_string().contains("allowance"));
}

#[test]
fn native_returned_lengths_accept_capacity_and_reject_capacity_plus_one() {
    assert_eq!(
        checked_returned_buffer_len(64, 64, "native_test").expect("exact capacity"),
        64
    );
    let error = checked_returned_buffer_len(65, 64, "native_test")
        .expect_err("capacity plus one is malformed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn aggregate_fd_limit_counts_every_entry_before_socket_filtering() {
    let regular_fd_type = 0;
    let fds = [
        libc::proc_fdinfo {
            proc_fd: 1,
            proc_fdtype: regular_fd_type,
        },
        libc::proc_fdinfo {
            proc_fd: 2,
            proc_fdtype: regular_fd_type,
        },
    ];
    let mut traversed = 0;
    let mut socket_reads = 0;
    collect_pid_socket_records_from_fds(7, &fds, &mut traversed, 2, |_| {
        socket_reads += 1;
        Ok(None)
    })
    .expect("the exact aggregate maximum is accepted");
    assert_eq!(traversed, 2);
    assert_eq!(socket_reads, 0);

    let error = collect_pid_socket_records_from_fds(8, &fds[..1], &mut traversed, 2, |_| {
        socket_reads += 1;
        Ok(None)
    })
    .expect_err("maximum plus one is rejected before socket filtering");
    assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
    assert_eq!(traversed, 3);
    assert_eq!(socket_reads, 0);
}

#[test]
fn fresh_tree_evidence_rejects_zero_marker_and_marker_name_race() {
    let mut before = zeroed_bsd_info();
    let mut after = zeroed_bsd_info();
    assert_eq!(
        fresh_process_evidence_from_reads(7, &before, "worker".to_owned(), &after),
        Err(ProcessEvidenceError::IdentityChanged { pid: 7 })
    );

    before.pbi_start_tvsec = 10;
    after.pbi_start_tvsec = 11;
    assert_eq!(
        fresh_process_evidence_from_reads(7, &before, "new-name".to_owned(), &after),
        Err(ProcessEvidenceError::IdentityChanged { pid: 7 })
    );
}

#[test]
fn fresh_name_adapter_accepts_exact_4k_and_refuses_empty_and_max_plus_one() {
    let mut before = zeroed_bsd_info();
    before.pbi_start_tvsec = 10;
    let after = before;
    let limit = crate::observation::PROTECTION_NAME_MAX_BYTES;

    let exact = fresh_process_evidence_from_reads(7, &before, "x".repeat(limit), &after)
        .expect("exact 4 KiB name");
    assert_eq!(exact.name.len(), limit);
    assert_eq!(
        fresh_process_evidence_from_reads(7, &before, String::new(), &after),
        Err(ProcessEvidenceError::NameMissing { pid: 7 })
    );
    assert_eq!(
        fresh_process_evidence_from_reads(7, &before, "x".repeat(limit + 1), &after),
        Err(ProcessEvidenceError::NameOversized {
            pid: 7,
            bytes: limit + 1
        })
    );
}

#[test]
fn bsd_start_marker_rejects_invalid_microseconds() {
    let mut info = zeroed_bsd_info();
    info.pbi_start_tvsec = 10;
    info.pbi_start_tvusec = 1_000_000;
    assert_eq!(
        super::process_start_time_marker_from_bsd_info(&info),
        Err(crate::observation::ProcessMarkerError::InvalidMicroseconds)
    );
}

#[test]
fn non_utf8_executable_path_is_null_and_metadata_partial() {
    let observation = process_observation_from_metadata(ProcessMetadata {
        process_name: Some("worker".to_owned()),
        executable_path: Some(PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff"))),
        partial: false,
        ..ProcessMetadata::default()
    });

    assert!(observation.executable_path.is_none());
    assert_eq!(
        observation.metadata_completeness,
        MetadataCompleteness::Partial
    );
}

fn zeroed_bsd_info() -> libc::proc_bsdinfo {
    unsafe {
        // SAFETY: proc_bsdinfo is a plain-data C struct used as a test fixture.
        MaybeUninit::<libc::proc_bsdinfo>::zeroed().assume_init()
    }
}

#[test]
fn tree_snapshot_row_maps_parent_and_start_marker_from_bsd_info() {
    let mut info = zeroed_bsd_info();
    info.pbi_ppid = 100;
    info.pbi_pgid = 4242;
    info.pbi_start_tvsec = 1_700_000_000;
    info.pbi_start_tvusec = 250_000;

    let row =
        super::tree_process_info_from_bsd(4242, &info, "node".to_owned()).expect("valid BSD info");

    assert_eq!(row.pid, 4242);
    assert_eq!(row.parent_pid, Some(100));
    assert_eq!(row.process_name.as_deref(), Some("node"));
    assert_eq!(row.process_group, Some(4242));
    assert_eq!(
        row.start_time_marker,
        crate::observation::ProcessStartMarker::macos(1_700_000_000, 250_000).ok()
    );

    // A launchd/kernel-rooted process reports parent PID 0, which must map
    // to "no parent", never to a real PID 0 edge.
    info.pbi_ppid = 0;
    let row =
        super::tree_process_info_from_bsd(1, &info, "launchd".to_owned()).expect("valid BSD info");
    assert_eq!(row.parent_pid, None);
}

#[test]
fn tree_snapshot_skips_vanished_and_system_restricted_processes() {
    let vanished = std::io::Error::from_raw_os_error(libc::ESRCH);
    let denied = std::io::Error::from_raw_os_error(libc::EPERM);
    let interrupted = std::io::Error::from_raw_os_error(libc::EINTR);

    assert!(super::should_skip_unreadable_snapshot_error(&vanished));
    assert!(super::should_skip_unreadable_snapshot_error(&denied));
    assert!(!super::should_skip_unreadable_snapshot_error(&interrupted));
}
