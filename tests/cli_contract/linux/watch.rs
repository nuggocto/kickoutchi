use super::*;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the real-binary schema contract asserts every field and nested shape"
)]
fn watch_emits_versioned_baseline_ndjson_and_exits_after_duration() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
    let port = listener.local_addr().expect("listener address").port();
    let port_text = port.to_string();

    let config = format!(
        "[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"watch fixture\"\n"
    );
    let output = kickoutchi_with_config_deadline(
        &[
            "watch",
            "--tcp",
            "--address",
            "127.0.0.1",
            "--port",
            &port_text,
            "--filter",
            "state:listen label:fixture",
            "--interval",
            "100ms",
            "--duration",
            "1s",
            "--json",
        ],
        &config,
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let records = stdout(&output)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(!records.is_empty(), "{}", stdout(&output));
    assert!(
        records.iter().skip(1).enumerate().all(|(index, record)| {
            record["schema"] == "kickoutchi.watch_event"
                && record["version"] == 1
                && record["sequence"] == index + 1
                && record["event"] == "collection_gap"
        }),
        "{}",
        stdout(&output)
    );
    assert_eq!(records[0]["schema"], "kickoutchi.watch_event");
    assert_eq!(records[0]["version"], 1);
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[0]["event"], "baseline");
    assert_eq!(
        records[0]["observation"]["previous_completed_unix_ms"],
        serde_json::Value::Null
    );
    assert_eq!(records[0]["data"]["endpoint"]["port"], port);
    assert_eq!(records[0]["data"]["state"]["kind"], "listen");
    assert_eq!(records[0]["data"]["label"], "watch fixture");
    assert_eq!(
        records[0]["data"]["previous_owners"],
        serde_json::Value::Null
    );
    assert_eq!(records[0]["data"]["filter_result"], "matched");
    assert_json_keys(
        &records[0],
        &[
            "schema",
            "version",
            "sequence",
            "event",
            "observation",
            "data",
        ],
    );
    assert_json_keys(
        &records[0]["observation"],
        &[
            "previous_completed_unix_ms",
            "attempt_started_unix_ms",
            "attempt_completed_unix_ms",
        ],
    );
    assert!(records[0]["observation"]["attempt_started_unix_ms"].is_u64());
    assert!(records[0]["observation"]["attempt_completed_unix_ms"].is_u64());
    assert_json_keys(
        &records[0]["data"],
        &[
            "endpoint",
            "state",
            "previous_owners",
            "current_owners",
            "previous_socket_token",
            "current_socket_token",
            "multiplicity",
            "label",
            "filter_result",
            "certainty",
            "evidence",
            "omitted_evidence_count",
            "evidence_gaps",
            "omitted_evidence_gap_count",
        ],
    );
    assert_json_keys(
        &records[0]["data"]["endpoint"],
        &["protocol", "address", "port", "ipv6_scope"],
    );
    assert!(matches!(
        records[0]["data"]["endpoint"]["protocol"].as_str(),
        Some("tcp" | "udp")
    ));
    assert!(records[0]["data"]["endpoint"]["address"].is_string());
    assert!(records[0]["data"]["endpoint"]["port"].is_u64());
    if !records[0]["data"]["endpoint"]["ipv6_scope"].is_null() {
        assert_json_keys(
            &records[0]["data"]["endpoint"]["ipv6_scope"],
            &["kind", "interface_index"],
        );
    }
    assert_json_keys(&records[0]["data"]["state"], &["kind", "native_code"]);
    assert!(records[0]["data"]["state"]["kind"].is_string());
    assert_json_keys(
        &records[0]["data"]["current_owners"],
        &["owners", "omitted_owner_count", "completeness", "reasons"],
    );
    let owners = records[0]["data"]["current_owners"]["owners"]
        .as_array()
        .expect("current owner set is an array");
    assert_ne!(owners.as_slice(), [] as [serde_json::Value; 0]);
    for owner in owners {
        match owner["kind"].as_str() {
            Some("verified") => {
                assert_json_keys(owner, &["kind", "identity"]);
                assert_json_keys(&owner["identity"], &["pid", "start_marker"]);
                assert!(owner["identity"]["pid"].is_u64());
                let marker = &owner["identity"]["start_marker"];
                match marker["kind"].as_str() {
                    Some("linux_start_ticks") => assert_json_keys(marker, &["kind", "ticks"]),
                    Some("macos_start_time") => {
                        assert_json_keys(marker, &["kind", "seconds", "microseconds"]);
                    }
                    Some("windows_creation_time") => {
                        assert_json_keys(marker, &["kind", "filetime_ticks"]);
                    }
                    other => panic!("unexpected process marker kind: {other:?}"),
                }
            }
            Some("unverified_pid") => {
                assert_json_keys(owner, &["kind", "pid", "reason"]);
                assert!(owner["pid"].is_u64());
                assert!(owner["reason"].is_string());
            }
            other => panic!("unexpected owner kind: {other:?}"),
        }
    }
    assert!(records[0]["data"]["current_owners"]["omitted_owner_count"].is_u64());
    assert!(matches!(
        records[0]["data"]["current_owners"]["completeness"].as_str(),
        Some("complete" | "partial" | "raced")
    ));
    assert!(records[0]["data"]["current_owners"]["reasons"].is_array());
    assert!(records[0]["data"]["previous_socket_token"].is_null());
    if !records[0]["data"]["current_socket_token"].is_null() {
        assert_json_keys(
            &records[0]["data"]["current_socket_token"],
            &["kind", "value"],
        );
        assert!(matches!(
            records[0]["data"]["current_socket_token"]["kind"].as_str(),
            Some("linux_inode" | "macos_socket_id")
        ));
        assert!(records[0]["data"]["current_socket_token"]["value"].is_u64());
    }
    assert!(records[0]["data"]["multiplicity"].is_u64());
    assert!(records[0]["data"]["label"].is_null() || records[0]["data"]["label"].is_string());
    assert!(matches!(
        records[0]["data"]["filter_result"].as_str(),
        Some("not_applied" | "matched" | "indeterminate")
    ));
    assert!(matches!(
        records[0]["data"]["certainty"].as_str(),
        Some("proven" | "estimated" | "heuristic" | "unknown")
    ));
    assert!(records[0]["data"]["evidence"].is_array());
    assert!(records[0]["data"]["omitted_evidence_count"].is_u64());
    assert!(records[0]["data"]["evidence_gaps"].is_array());
    assert!(records[0]["data"]["omitted_evidence_gap_count"].is_u64());
    assert!(!stdout(&output).contains("command_line"));
    drop(listener);
}

#[test]
fn socket_lifecycle_helper_covers_protocol_family_bind_and_sharing_modes() {
    let _host_observation = lock_host_observation();
    let (_binary_guard, binary) = build_socket_lifecycle_helper();
    let mut modes = vec![
        (["tcp4", "exact", "default", "1"], "tcp", "127.0.0.1", 1),
        (["tcp4", "wildcard", "default", "2"], "tcp", "0.0.0.0", 2),
        (["udp4", "exact", "default", "1"], "udp", "127.0.0.1", 1),
        (["udp4", "wildcard", "default", "1"], "udp", "0.0.0.0", 1),
    ];
    let tcp6_supported = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok();
    let udp6_supported = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok();
    let dual_tcp_supported = dual_stack_probe(socket2::Type::STREAM, socket2::Protocol::TCP);
    let dual_udp_supported = dual_stack_probe(socket2::Type::DGRAM, socket2::Protocol::UDP);
    if required_linux_capabilities() {
        assert!(tcp6_supported && udp6_supported && dual_tcp_supported && dual_udp_supported);
    }
    if tcp6_supported {
        modes.extend([
            (["tcp6", "exact", "v6only", "1"], "tcp", "::1", 1),
            (["tcp6", "wildcard", "v6only", "1"], "tcp", "::", 1),
        ]);
    }
    if dual_tcp_supported {
        modes.push((["tcp6", "wildcard", "dual", "1"], "tcp", "::", 1));
    }
    if udp6_supported {
        modes.extend([
            (["udp6", "exact", "v6only", "1"], "udp", "::1", 1),
            (["udp6", "wildcard", "v6only", "1"], "udp", "::", 1),
        ]);
    }
    if dual_udp_supported {
        modes.push((["udp6", "wildcard", "dual", "1"], "udp", "::", 1));
    }

    for (args, protocol, address, multiplicity) in modes {
        let (mut helper, port) = SocketLifecycle::spawn(&binary, &args);
        assert_ne!(port, 0, "mode {args:?} must use a dynamic port");
        let output = kickoutchi(&["list", "--snapshot-json"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let snapshot: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
        let matching = snapshot["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|socket| {
                socket["endpoint"]["protocol"] == protocol
                    && socket["endpoint"]["address"] == address
                    && socket["endpoint"]["port"] == port
            })
            .count();
        assert_eq!(matching, multiplicity, "mode {args:?}: {}", stdout(&output));

        if args[0] == "tcp6" {
            let ipv4 = TcpListener::bind(("0.0.0.0", port));
            assert_eq!(ipv4.is_ok(), args[2] == "v6only", "mode {args:?}");
        } else if args[0] == "udp6" {
            let ipv4 = UdpSocket::bind(("0.0.0.0", port));
            assert_eq!(ipv4.is_ok(), args[2] == "v6only", "mode {args:?}");
        }
        helper.command("CLOSE");
        helper.command("REBIND");
        helper.exit();
    }
}

fn dual_stack_probe(socket_type: socket2::Type, protocol: socket2::Protocol) -> bool {
    let Ok(socket) = socket2::Socket::new(socket2::Domain::IPV6, socket_type, Some(protocol))
    else {
        return false;
    };
    socket.set_only_v6(false).is_ok()
        && socket
            .bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())
            .is_ok()
}

#[test]
fn watch_wildcard_label_reaches_filtered_output() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("watch fixture must bind");
    let port = listener
        .local_addr()
        .expect("watch address is known")
        .port();
    let config = format!(
        "[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = {port}\nlabel = \"wildcard watch fixture\"\n"
    );
    let config_dir = temp_file_path("wildcard-watch-config");
    fs::create_dir(&config_dir).expect("watch config directory must be created");
    let _config_guard = DirectoryGuard(config_dir.clone());
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).expect("watch config must be written");
    let child = Command::new(kickoutchi_binary())
        .arg("--config")
        .arg(&config_path)
        .args([
            "watch",
            "--tcp",
            "--address",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--filter",
            "label:wildcard watch",
            "--interval",
            "100ms",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("wildcard watch process must start");
    let mut child = ChildGuard { child };
    let mut stdout = BufReader::new(
        child
            .child
            .stdout
            .take()
            .expect("wildcard watch stdout must be piped"),
    );
    let (sender, record) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let result = stdout.read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    let record = record
        .recv_timeout(IPC_WAIT)
        .expect("wildcard watch baseline must arrive before its deadline")
        .expect("wildcard watch baseline must be readable");
    let record: serde_json::Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["event"], "baseline");
    assert_eq!(record["data"]["label"], "wildcard watch fixture");
    assert_eq!(record["data"]["filter_result"], "matched");

    let platform_pid = libc::pid_t::try_from(child.id()).expect("watch PID must fit pid_t");
    assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGINT) }, 0);
    let deadline = Instant::now() + KICK_EXIT_WAIT;
    let status = loop {
        if let Some(status) = child
            .child
            .try_wait()
            .expect("watch status must be readable")
        {
            break status;
        }
        assert!(Instant::now() < deadline, "wildcard watch did not exit");
        thread::yield_now();
    };
    reader.join().expect("wildcard watch reader must finish");
    let mut diagnostics = String::new();
    child
        .child
        .stderr
        .take()
        .expect("wildcard watch stderr must be piped")
        .read_to_string(&mut diagnostics)
        .expect("wildcard watch stderr must be readable");
    assert_eq!(status.code(), Some(0), "{diagnostics}");
    assert!(diagnostics.is_empty(), "{diagnostics}");
}

#[test]
fn socket_lifecycle_drop_forces_process_and_reader_cleanup() {
    let _host_observation = lock_host_observation();
    let (_binary_guard, binary) = build_socket_lifecycle_helper();
    let pid = {
        let (helper, _port) = SocketLifecycle::spawn(&binary, &["tcp4", "exact", "default", "1"]);
        helper.id()
    };
    assert!(!pid_exists(pid), "dropped helper process must be reaped");
}

#[test]
fn reader_panic_is_joined_and_reported() {
    let (done_sender, reader_done) = mpsc::channel();
    let mut reader = Some(thread::spawn(move || {
        drop(done_sender);
        panic!("injected reader panic");
    }));

    let error = finish_reader_thread(&mut reader, &reader_done, Instant::now() + IPC_WAIT)
        .expect_err("reader panic must be reported");

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("reader panicked"));
    assert!(reader.is_none(), "panicked reader must still be joined");
}

#[test]
fn deep_chain_drop_terminates_every_owned_process() {
    let _host_observation = lock_host_observation();
    let pids = {
        let helper = spawn_deep_chain_process(4);
        helper.pids.clone()
    };
    for pid in pids {
        assert!(
            pid_is_terminated(pid),
            "dropped deep-chain PID {pid} must exit"
        );
    }
}

#[test]
fn socket_lifecycle_helper_hands_an_endpoint_to_a_replacement_process() {
    let _host_observation = lock_host_observation();
    let (_binary_guard, binary) = build_socket_lifecycle_helper();
    let (mut original, port) = SocketLifecycle::spawn(&binary, &["tcp4", "exact", "default", "1"]);
    let original_pid = original.id();
    original.command("CLOSE");
    let port_text = port.to_string();
    let (mut replacement, replacement_port) = SocketLifecycle::spawn(
        &binary,
        &["tcp4", "exact", "default", "1", port_text.as_str()],
    );
    assert_eq!(replacement_port, port);
    assert_ne!(replacement.id(), original_pid);

    let output = kickoutchi(&["list", "--snapshot-json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let snapshot: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let socket = snapshot["sockets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|socket| {
            socket["endpoint"]["protocol"] == "tcp"
                && socket["endpoint"]["address"] == "127.0.0.1"
                && socket["endpoint"]["port"] == port
        })
        .expect("replacement endpoint must be observed");
    let owner_pids = socket["owners"]["owners"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|owner| owner["identity"]["pid"].as_u64())
        .collect::<Vec<_>>();
    assert_eq!(owner_pids, [u64::from(replacement.id())]);
    assert!(!owner_pids.contains(&u64::from(original_pid)));

    original.exit();
    replacement.exit();
}

#[test]
fn watch_real_binary_observes_baseline_release_and_bind() {
    let _host_observation = lock_host_observation();
    let (_binary_guard, binary) = build_socket_lifecycle_helper();
    let (mut helper, port) = SocketLifecycle::spawn(&binary, &["tcp4", "exact", "default", "1"]);
    let config_home = isolated_config_home();
    let _config_guard = DirectoryGuard(config_home.clone());
    let child = Command::new(kickoutchi_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .args([
            "watch",
            "--tcp",
            "--address",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--interval",
            "100ms",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("watch process must start");
    let mut child = ChildGuard { child };
    let stdout = child
        .child
        .stdout
        .take()
        .expect("watch stdout must be piped");
    let (sender, lines) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let receive_event = |expected: &str| {
        let line = lines
            .recv_timeout(IPC_WAIT)
            .expect("watch event must arrive before its deadline")
            .expect("watch event must be readable");
        let value: serde_json::Value =
            serde_json::from_str(&line).expect("watch event must be JSON");
        assert_eq!(value["event"], expected, "{line}");
        assert_eq!(value["data"]["endpoint"]["port"], port, "{line}");
    };

    receive_event("baseline");
    helper.command("CLOSE");
    receive_event("release");
    helper.command("REBIND");
    receive_event("bind");

    let platform_pid = libc::pid_t::try_from(child.id()).expect("watch PID must fit pid_t");
    assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGINT) }, 0);
    let deadline = Instant::now() + KICK_EXIT_WAIT;
    let status = loop {
        if let Some(status) = child
            .child
            .try_wait()
            .expect("watch status must be readable")
        {
            break status;
        }
        assert!(Instant::now() < deadline, "watch did not exit after SIGINT");
        thread::yield_now();
    };
    reader.join().expect("watch stdout reader must finish");
    let mut diagnostics = String::new();
    child
        .child
        .stderr
        .take()
        .expect("watch stderr must be piped")
        .read_to_string(&mut diagnostics)
        .expect("watch stderr must be readable");
    assert_eq!(status.code(), Some(0), "{diagnostics}");
    assert!(diagnostics.is_empty(), "{diagnostics}");
    helper.exit();
}

#[test]
fn watch_real_binary_recovers_after_one_native_collection_failure() {
    let _host_observation = lock_host_observation();
    let (_library_guard, library) = build_collect_fault_library();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("watch fixture must bind");
    let port = listener
        .local_addr()
        .expect("watch address is known")
        .port();
    let config_home = isolated_config_home();
    let _config_guard = DirectoryGuard(config_home.clone());
    let child = Command::new(kickoutchi_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("LD_PRELOAD", &library)
        .args([
            "watch",
            "--tcp",
            "--address",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--interval",
            "100ms",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("watch recovery process must start");
    let mut child = ChildGuard { child };
    let stdout = child
        .child
        .stdout
        .take()
        .expect("watch recovery stdout must be piped");
    let (sender, lines) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let baseline = lines
        .recv_timeout(IPC_WAIT)
        .expect("watch must emit a baseline before its deadline")
        .expect("baseline must be readable");
    let baseline: serde_json::Value = serde_json::from_str(&baseline).unwrap();
    assert_eq!(baseline["event"], "baseline");
    assert_eq!(baseline["data"]["endpoint"]["port"], port);

    let platform_pid = libc::pid_t::try_from(child.id()).expect("watch PID must fit pid_t");
    assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGUSR2) }, 0);
    let gap = lines
        .recv_timeout(IPC_WAIT)
        .expect("watch must emit the armed collection gap before its deadline")
        .expect("collection gap must be readable");
    let gap: serde_json::Value = serde_json::from_str(&gap).unwrap();
    assert_eq!(gap["event"], "collection_gap");
    assert_eq!(gap["data"]["consecutive_failures"], 1);
    assert_eq!(gap["data"]["certainty"], "unknown");
    assert!(
        matches!(
            lines.recv_timeout(IPC_WAIT),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ),
        "recovery must close stdout without fabricating an event"
    );
    reader.join().expect("watch recovery reader must finish");
    let deadline = Instant::now() + KICK_EXIT_WAIT;
    let status = loop {
        if let Some(status) = child
            .child
            .try_wait()
            .expect("watch recovery status must be readable")
        {
            break status;
        }
        assert!(Instant::now() < deadline, "recovered watch did not exit");
        thread::yield_now();
    };
    let mut diagnostics = String::new();
    child
        .child
        .stderr
        .take()
        .expect("watch recovery stderr must be piped")
        .read_to_string(&mut diagnostics)
        .expect("watch recovery stderr must be readable");
    assert_eq!(status.code(), Some(0), "{diagnostics}");
    assert!(diagnostics.is_empty(), "{diagnostics}");
}

#[test]
fn watch_closed_stdout_is_success() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("watch fixture must bind");
    let port = listener
        .local_addr()
        .expect("watch address is known")
        .port();

    let output = run_subcommand_with_closed_stdout(
        "watch",
        &[
            "--tcp",
            "--address",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
}

#[test]
fn watch_rejects_invalid_arguments_before_collection() {
    for args in [
        vec!["watch", "--interval", "99ms"],
        vec!["watch", "--duration", "7d1s"],
        vec!["watch", "--scope-id", "1"],
        vec!["watch", "--port", "0"],
        vec!["watch", "--filter", "state:not-a-state"],
    ] {
        let output = kickoutchi(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(stdout(&output), "", "{args:?}");
        assert!(stderr(&output).contains("error:"), "{args:?}");
    }
}

#[test]
fn watch_ctrl_c_after_baseline_exits_successfully() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
    let port = listener.local_addr().expect("listener address").port();
    let config_home = isolated_config_home();
    let config_guard = DirectoryGuard(config_home.clone());
    let child = Command::new(kickoutchi_binary())
        .env("XDG_CONFIG_HOME", &config_home)
        .args([
            "watch",
            "--port",
            &port.to_string(),
            "--interval",
            "100ms",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("watch process must start");
    let mut child = ChildGuard { child };
    let pid = child.id();
    let stdout = child
        .child
        .stdout
        .take()
        .expect("watch stdout must be piped");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = ready_tx.send(result);
    });
    let baseline = ready_rx
        .recv_timeout(KICK_EXIT_WAIT)
        .expect("watch must emit a bounded baseline")
        .expect("watch baseline must be readable");
    let value: serde_json::Value = serde_json::from_str(&baseline).expect("baseline is JSON");
    assert_eq!(value["event"], "baseline");

    let platform_pid = libc::pid_t::try_from(pid).expect("child PID must fit pid_t");
    // SAFETY: the PID belongs to this test's child and SIGINT is the behavior under test.
    assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGINT) }, 0);
    let deadline = Instant::now() + KICK_EXIT_WAIT;
    let status = loop {
        if let Some(status) = child
            .child
            .try_wait()
            .expect("watch exit status must be readable")
        {
            break status;
        }
        assert!(Instant::now() < deadline, "watch did not exit after SIGINT");
        thread::sleep(Duration::from_millis(10));
    };
    reader.join().expect("watch stdout reader must finish");
    assert_eq!(status.code(), Some(0));
    drop(config_guard);
    drop(listener);
}
