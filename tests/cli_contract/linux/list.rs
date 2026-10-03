use super::*;

#[test]
fn remounted_procfs_cannot_hide_an_ancestor_socket_co_owner_as_complete() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
    let port = listener.local_addr().expect("test listener address").port();
    let inherited = OwnedFd::from(listener.try_clone().expect("clone test listener"));
    // The outer test retains the socket. The nested process inherits another
    // descriptor as stdin, so one real co-owner is outside its procfs view.
    let script = r#"
        sed -n '/^NSpid:/p' /proc/self/status >&2
        exec "$1" --config /dev/null list --snapshot-json
    "#;
    let output = run_namespace_command(
        Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
                "--mount-proc",
                "sh",
                "-c",
            ])
            .arg(script)
            .arg("sh")
            .arg(kickoutchi_binary())
            .stdin(Stdio::from(inherited)),
    );
    let Some(output) = output else { return };
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let diagnostic = stderr(&output);
    let nspid = diagnostic
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .expect("nested procfs must expose NSpid");
    assert_eq!(nspid.split_whitespace().count(), 1);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("nested snapshot must be JSON");
    let socket = snapshot["sockets"]
        .as_array()
        .expect("socket array")
        .iter()
        .find(|socket| {
            socket["endpoint"]["protocol"] == "tcp"
                && socket["endpoint"]["address"] == "127.0.0.1"
                && socket["endpoint"]["port"] == port
        })
        .expect("inherited listener must remain visible");
    assert!(
        socket["owners"]["owners"]
            .as_array()
            .expect("owner array")
            .iter()
            .any(|owner| owner["kind"] == "verified" && owner["identity"]["pid"] == 1)
    );
    assert_eq!(socket["owners"]["completeness"], "partial");
    assert_eq!(snapshot["owner_completeness"], "partial");
}

#[test]
fn human_list_no_match_prints_diagnostic_to_stderr() {
    let Some(output) = isolated_no_match_diagnostic(false) else {
        return;
    };

    assert_eq!(output.status.code(), Some(3));
    assert!(stdout(&output).contains("no open ports match the filter"));
    assert!(!stdout(&output).contains("Possible related process"));
    assert!(stderr(&output).contains("Possible related process"));
    assert!(stderr(&output).contains("but no socket was confirmed"));
    assert!(!stderr(&output).contains("owns this port"));
}

#[test]
fn json_list_no_match_keeps_diagnostic_out_of_stdout_and_stderr() {
    let Some(output) = isolated_no_match_diagnostic(true) else {
        return;
    };

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stdout(&output), "[]\n");
    assert_eq!(stderr(&output), "");
}

#[test]
fn snapshot_json_real_binary_exposes_versioned_private_deterministic_shape() {
    let _host_observation = lock_host_observation();
    let (helper, port, ready_file) = spawn_listener_process();
    let _ready_file = FileGuard(ready_file);
    let config = format!(
        "[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"snapshot fixture\"\n"
    );

    let output = kickoutchi_with_config(&["list", "--snapshot-json"], &config);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("snapshot stdout must be JSON");
    assert_json_keys(
        &value,
        &[
            "schema",
            "version",
            "capture",
            "scope",
            "completeness",
            "owner_completeness",
            "evidence_gaps",
            "omitted_evidence_gap_count",
            "sockets",
            "processes",
        ],
    );
    assert_eq!(value["schema"], "kickoutchi.snapshot");
    assert_eq!(value["version"], 1);
    assert_json_keys(&value["capture"], &["started_unix_ms", "completed_unix_ms"]);
    assert_json_keys(&value["scope"], &["kind", "identifier", "limitations"]);

    let sockets = value["sockets"]
        .as_array()
        .expect("snapshot sockets must be an array");
    let socket = sockets
        .iter()
        .find(|socket| {
            socket["endpoint"]["protocol"] == "tcp"
                && socket["endpoint"]["address"] == "127.0.0.1"
                && socket["endpoint"]["port"] == port
        })
        .expect("snapshot must contain the controlled listener");
    assert_snapshot_socket(socket, helper.id());

    let processes = value["processes"]
        .as_array()
        .expect("snapshot processes must be an array");
    let process = processes
        .iter()
        .find(|process| process["identity"]["pid"] == helper.id())
        .expect("snapshot must contain the controlled listener process");
    assert_snapshot_process(process);
    assert_json_keys_absent_recursively(&value, &["command_line", "cmdline", "argv", "command"]);

    assert_snapshot_order(sockets, processes);
}

fn assert_snapshot_socket(socket: &serde_json::Value, helper_pid: u32) {
    assert_json_keys(
        socket,
        &[
            "endpoint",
            "state",
            "timer",
            "owners",
            "socket_token",
            "label",
        ],
    );
    assert_json_keys(
        &socket["endpoint"],
        &["protocol", "address", "port", "ipv6_scope"],
    );
    assert_json_keys(&socket["state"], &["kind", "native_code"]);
    assert_json_keys(
        &socket["owners"],
        &["owners", "omitted_owner_count", "completeness", "reasons"],
    );
    assert_eq!(socket["label"], "snapshot fixture");
    let owner = socket["owners"]["owners"]
        .as_array()
        .expect("snapshot owners must be an array")
        .iter()
        .find(|owner| owner["identity"]["pid"] == helper_pid)
        .expect("controlled listener must have its verified owner");
    assert_json_keys(owner, &["kind", "identity"]);
    assert_json_keys(&owner["identity"], &["pid", "start_marker"]);
    assert_json_keys(&owner["identity"]["start_marker"], &["kind", "ticks"]);
}

fn assert_snapshot_process(process: &serde_json::Value) {
    assert_json_keys(
        process,
        &[
            "identity",
            "name",
            "executable_path",
            "parent_pid",
            "metadata_completeness",
        ],
    );
    assert_json_keys(&process["identity"], &["pid", "start_marker"]);
    assert_json_keys(&process["identity"]["start_marker"], &["kind", "ticks"]);
}

fn assert_snapshot_order(sockets: &[serde_json::Value], processes: &[serde_json::Value]) {
    let protocol_order = |socket: &serde_json::Value| match socket["endpoint"]["protocol"]
        .as_str()
        .expect("socket protocol must be a string")
    {
        "tcp" => 0,
        "udp" => 1,
        protocol => panic!("unexpected protocol {protocol:?}"),
    };
    assert!(
        sockets
            .windows(2)
            .all(|pair| protocol_order(&pair[0]) <= protocol_order(&pair[1])),
        "snapshot sockets must be monotonic by protocol"
    );
    assert!(
        processes.windows(2).all(|pair| {
            pair[0]["identity"]["pid"].as_u64() <= pair[1]["identity"]["pid"].as_u64()
        }),
        "snapshot processes must be monotonic by PID"
    );
}

#[test]
fn snapshot_json_preserves_legacy_list_json_array_and_exact_row_keys() {
    let _host_observation = lock_host_observation();
    let (helper, port, ready_file) = spawn_listener_process();
    let _ready_file = FileGuard(ready_file);
    let port = port.to_string();

    let output = kickoutchi(&["list", "--port", port.as_str(), "--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let rows: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("legacy list stdout must be JSON");
    let rows = rows
        .as_array()
        .expect("legacy list JSON must remain a top-level array");
    let row = rows
        .iter()
        .find(|row| row["pid"] == helper.id())
        .expect("legacy list must contain the controlled listener");
    assert_json_keys(
        row,
        &[
            "protocol",
            "local_addr",
            "local_port",
            "state",
            "pid",
            "process_name",
            "executable_path",
            "command_line",
            "parent_pid",
            "parent_process_name",
            "child_pids",
            "protected",
            "platform",
            "permission",
            "label",
        ],
    );
    assert_eq!(row.as_object().map(serde_json::Map::len), Some(15));
}

#[test]
fn snapshot_json_conflicts_exit_before_missing_config_is_loaded() {
    let missing_config = temp_file_path("missing-snapshot-config");
    assert!(!missing_config.exists());
    let missing_config = missing_config.to_string_lossy();
    let conflicts: &[&[&str]] = &[
        &["--json"],
        &["--port", "3000"],
        &["--process", "fixture"],
        &["--filter", "proto:tcp"],
        &["--sort", "port"],
    ];

    for conflict in conflicts {
        let mut args = vec![
            "list",
            "--snapshot-json",
            "--config",
            missing_config.as_ref(),
        ];
        args.extend_from_slice(conflict);
        let output = kickoutchi(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "conflict {conflict:?} must be rejected by argument parsing; stderr: {}",
            stderr(&output)
        );
        assert_eq!(output.stdout, b"", "conflict {conflict:?} wrote stdout");
        assert!(
            !output.stderr.is_empty(),
            "conflict {conflict:?} omitted stderr"
        );
    }
}

#[test]
fn untrusted_newlines_cannot_forge_diagnostic_lines() {
    let missing = temp_file_path("missing\nFORGED_CONFIG_LINE");
    let missing = missing.to_string_lossy();
    let config_error = kickoutchi(&["--config", missing.as_ref(), "list"]);
    assert_eq!(config_error.status.code(), Some(1));
    assert!(
        !stderr(&config_error)
            .lines()
            .any(|line| line == "FORGED_CONFIG_LINE")
    );

    let argument_error = kickoutchi(&["list", "--sort", "bad\nFORGED_ARG_LINE"]);
    assert_eq!(argument_error.status.code(), Some(2));
    assert!(
        !stderr(&argument_error)
            .lines()
            .any(|line| line == "FORGED_ARG_LINE")
    );
    assert!(argument_error.stdout.is_empty());
}

#[test]
fn snapshot_json_is_available_from_kick_alias_and_list_help() {
    let help = kickoutchi(&["list", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        stdout(&help).contains("--snapshot-json"),
        "{}",
        stdout(&help)
    );

    let snapshot = kick(&["list", "--snapshot-json"]);
    assert_eq!(snapshot.status.code(), Some(0), "{}", stderr(&snapshot));
    let value: serde_json::Value =
        serde_json::from_slice(&snapshot.stdout).expect("kick snapshot stdout must be JSON");
    assert_eq!(value["schema"], "kickoutchi.snapshot");
    assert_eq!(value["version"], 1);
}

#[test]
fn snapshot_json_closed_stdout_is_success() {
    let output = run_list_with_closed_stdout(&["--snapshot-json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
}

#[test]
fn snapshot_json_non_pipe_writer_failure_is_operational() {
    let output = run_list_with_full_stdout(&["--snapshot-json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("rendering snapshot JSON failed"));
}

#[test]
fn exact_label_precedes_wildcard_through_search_filter_table_and_json() {
    let _host_observation = lock_host_observation();
    let (_helper, port, ready_file) = spawn_listener_process();
    let _ready_file = FileGuard(ready_file);
    let port_text = port.to_string();
    let config = format!(
        "[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = {port}\nlabel = \"Wildcard Preview\"\n\n[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"Exact Web Dev\"\n"
    );
    let table = kickoutchi_with_config(
        &[
            "list",
            "--port",
            port_text.as_str(),
            "--filter",
            "exact web label:web dev",
        ],
        &config,
    );
    assert_eq!(table.status.code(), Some(0), "{}", stderr(&table));
    assert!(stdout(&table).lines().next().unwrap().ends_with("LABEL"));
    assert!(
        stdout(&table).contains("Exact Web Dev"),
        "{}",
        stdout(&table)
    );
    assert!(
        !stdout(&table).contains("Wildcard Preview"),
        "{}",
        stdout(&table)
    );

    let json = kickoutchi_with_config(
        &[
            "list",
            "--port",
            port_text.as_str(),
            "--filter",
            "label:exact web",
            "--json",
        ],
        &config,
    );
    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let value: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value.as_array().map(Vec::len), Some(1));
    assert_eq!(value[0]["label"], "Exact Web Dev");
    assert!(!stdout(&json).contains("Wildcard Preview"));

    let unconfigured = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(
        unconfigured.status.code(),
        Some(0),
        "{}",
        stderr(&unconfigured)
    );
    assert!(
        !stdout(&unconfigured)
            .lines()
            .next()
            .unwrap()
            .contains("LABEL")
    );
}

#[test]
fn list_rejects_watch_only_state_filter_as_invalid_arguments() {
    let output = kickoutchi(&["list", "--filter", "state:listen"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("not supported by this command"));
}

#[test]
fn udp_ipv6_socket_is_listed_through_the_real_binary() {
    let _host_observation = lock_host_observation();
    let socket = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
            assert!(
                !required_linux_capabilities(),
                "required IPv6 loopback capability is unavailable: {error}"
            );
            eprintln!("IPv6 loopback unavailable: {error}");
            return;
        }
        Err(error) => panic!("IPv6 UDP socket must bind on loopback: {error}"),
    };
    let port = socket
        .local_addr()
        .expect("UDP socket must have a local address")
        .port();
    let port_text = port.to_string();

    let output = kickoutchi(&["list", "--port", port_text.as_str()]);

    assert_eq!(output.status.code(), Some(0));
    let out = stdout(&output);
    assert!(out.contains("UDP"), "{out}");
    assert!(out.contains("::1"), "{out}");
    assert!(out.contains(port_text.as_str()), "{out}");
    assert!(stdout_table_has_pid(&output, std::process::id()), "{out}");
}

#[test]
fn owner_notes_explain_dash_rows_on_stderr_only() {
    let _host_observation = lock_host_observation();
    let output = kickoutchi(&["list"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let table = stdout(&output);
    let notes = stderr(&output);
    // The table stays machine-splittable: no notes leak into stdout.
    assert!(!table.contains("note:"), "{table}");
    let dash_pid_rows = table
        .lines()
        .skip(1)
        .filter(|line| line.split_whitespace().nth(3) == Some("-"))
        .count();
    if dash_pid_rows == 0 {
        assert!(!notes.contains("PID \"-\""), "{notes}");
        return;
    }
    assert!(
        notes.contains("note: PID \"-\" means the socket's owner is not visible:"),
        "{notes}"
    );
    // Every dash row is counted in exactly one reason line.
    let counted = notes
        .lines()
        .filter(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next()?.parse::<usize>().ok())
        .sum::<usize>();
    assert_eq!(counted, dash_pid_rows, "{table}\n{notes}");
}
