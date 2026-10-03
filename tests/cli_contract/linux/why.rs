use super::*;

#[test]
fn why_reports_a_test_owned_tcp_listener_with_versioned_json() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
    let port = listener
        .local_addr()
        .expect("listener address is known")
        .port();
    let port_text = port.to_string();

    let output = why(&[
        port_text.as_str(),
        "--tcp",
        "--address",
        "127.0.0.1",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("why output must be JSON");
    assert_json_keys(
        &value,
        &[
            "schema",
            "version",
            "query",
            "capture",
            "scope",
            "completeness",
            "owner_completeness",
            "results",
            "aggregate_exit_code",
        ],
    );
    assert_eq!(value["schema"], "kickoutchi.why");
    assert_eq!(value["version"], 1);
    assert_eq!(value["aggregate_exit_code"], 3);
    assert_eq!(value["results"][0]["verdict"], "owned");
    assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
    assert!(
        value["results"][0]["evidence"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| {
                item["code"] == "visible_verified_owner" && item["certainty"] == "proven"
            }))
    );
    assert!(!stdout(&output).contains("command_line"));
}

#[test]
fn why_reports_real_permission_limited_owner_evidence() {
    let _host_observation = lock_host_observation();
    let (_helper, port, ready_file) = spawn_listener_process_with_metadata_access(false);
    let _ready_file = FileGuard(ready_file);
    let port_text = port.to_string();

    let output = why(&[
        port_text.as_str(),
        "--tcp",
        "--address",
        "127.0.0.1",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("why output must be JSON");
    assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
    assert_eq!(value["completeness"], "partial");
    assert_eq!(value["owner_completeness"], "partial");
    // The helper holds the socket but cannot be read: its owner is hidden, not
    // an ownerless kernel socket.
    assert_eq!(value["results"][0]["verdict"], "owner_hidden");
    assert_eq!(value["results"][0]["certainty"], "unknown");
    assert!(
        value["results"][0]["evidence"]
            .as_array()
            .is_some_and(|evidence| evidence
                .iter()
                .any(|item| item["code"] == "visible_unreadable_owner"))
    );
    assert!(
        value["results"][0]["evidence_gaps"]
            .as_array()
            .is_some_and(|gaps| gaps.iter().any(|gap| {
                gap["impact"] == "ownership"
                    && matches!(
                        gap["code"].as_str(),
                        Some("owner_permission_denied" | "owner_attribution_incomplete")
                    )
            }))
    );
}

#[test]
fn why_reports_occupied_udp_in_human_output() {
    let _host_observation = lock_host_observation();
    let udp = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP fixture must bind");
    let udp_port = udp.local_addr().expect("UDP address is known").port();
    let udp_port_text = udp_port.to_string();
    let occupied = why(&[udp_port_text.as_str(), "--udp", "--address", "127.0.0.1"]);
    assert_eq!(occupied.status.code(), Some(3), "{}", stderr(&occupied));
    assert_eq!(stderr(&occupied), "");
    let occupied_stdout = stdout(&occupied);
    assert!(
        occupied_stdout.contains("probe=address_in_use"),
        "{occupied_stdout}"
    );
    assert!(
        (occupied_stdout.contains("verdict=owned") && occupied_stdout.contains("certainty=proven"))
            || (occupied_stdout.contains("verdict=reservation_or_policy_unknown")
                && occupied_stdout.contains("certainty=unknown")),
        "{occupied_stdout}"
    );
}

#[test]
fn why_real_binary_preserves_occupied_exit_when_stdout_has_no_reader() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
    let occupied_port = listener.local_addr().expect("TCP address is known").port();
    let occupied_port = occupied_port.to_string();
    let occupied = run_why_with_closed_stdout(&[
        occupied_port.as_str(),
        "--tcp",
        "--address",
        "127.0.0.1",
        "--json",
    ]);
    assert_eq!(occupied.status.code(), Some(3));
    assert!(occupied.stderr.is_empty());
}

#[test]
fn why_real_binary_applies_full_aggregate_exit_precedence() {
    let _host_observation = lock_host_observation();
    let (_library_guard, library) = build_bind_fault_library();
    let args = [
        CONTROLLED_BIND_FAULT_PORT,
        "--all-protocols",
        "--all-addresses",
        "--json",
    ];

    let failure = why_with_bind_faults(&args, &library, "mixed");
    assert_eq!(failure.status.code(), Some(1), "{}", stderr(&failure));
    assert_eq!(stderr(&failure), "");
    let failure_json: serde_json::Value =
        serde_json::from_str(&stdout(&failure)).expect("why output must be JSON");
    let failure_verdicts = failure_json["results"]
        .as_array()
        .expect("results are an array")
        .iter()
        .filter_map(|result| result["verdict"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(failure_json["aggregate_exit_code"], 1);
    assert!(failure_verdicts.contains("indeterminate"));
    assert!(failure_verdicts.contains("permission_denied"));
    assert!(failure_verdicts.contains("reservation_or_policy_unknown"));
    assert!(failure_verdicts.contains("bindable_now"));

    let permission = why_with_bind_faults(&args, &library, "permission");
    assert_eq!(permission.status.code(), Some(4), "{}", stderr(&permission));
    assert_eq!(stderr(&permission), "");
    let permission_json: serde_json::Value =
        serde_json::from_str(&stdout(&permission)).expect("why output must be JSON");
    let permission_verdicts = permission_json["results"]
        .as_array()
        .expect("results are an array")
        .iter()
        .filter_map(|result| result["verdict"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(permission_json["aggregate_exit_code"], 4);
    assert!(permission_verdicts.contains("permission_denied"));
    assert!(permission_verdicts.contains("reservation_or_policy_unknown"));
    assert!(!permission_verdicts.contains("indeterminate"));
}

#[test]
fn why_bare_query_emits_the_default_public_matrix() {
    let _host_observation = lock_host_observation();
    let (_library_guard, library) = build_bind_fault_library();
    let output = why_with_bind_faults(
        &[CONTROLLED_BIND_FAULT_PORT, "--json"],
        &library,
        "unavailable",
    );

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(stderr(&output), "");
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("bare why output must be JSON");
    assert_eq!(value["query"]["protocols"], serde_json::json!(["tcp"]));
    assert_eq!(
        value["query"]["addresses"],
        serde_json::json!(["127.0.0.1", "::1"])
    );
    assert_eq!(value["results"].as_array().map(Vec::len), Some(2));
    assert!(
        value["results"]
            .as_array()
            .is_some_and(|results| results.iter().all(|result| {
                result["verdict"] == "address_unavailable"
                    && result["probe"]["outcome"] == "address_unavailable"
            }))
    );
    assert_eq!(value["aggregate_exit_code"], 3);
}

#[test]
fn why_human_and_json_agree_for_unavailable_and_unsupported_probes() {
    let _host_observation = lock_host_observation();
    let (_library_guard, library) = build_bind_fault_library();

    for (mode, expected) in [
        ("unavailable", "address_unavailable"),
        ("unsupported", "unsupported"),
    ] {
        let base = [
            CONTROLLED_BIND_FAULT_PORT,
            "--tcp",
            "--address",
            "127.0.0.1",
        ];
        let human = why_with_bind_faults(&base, &library, mode);
        let mut json_args = base.to_vec();
        json_args.push("--json");
        let json = why_with_bind_faults(&json_args, &library, mode);

        assert_eq!(human.status.code(), Some(3), "{}", stderr(&human));
        assert_eq!(json.status.code(), Some(3), "{}", stderr(&json));
        assert_eq!(stderr(&human), "");
        assert_eq!(stderr(&json), "");
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&json)).expect("why parity output must be JSON");
        assert_eq!(value["results"][0]["verdict"], expected);
        assert_eq!(value["results"][0]["probe"]["outcome"], expected);
        assert_eq!(value["aggregate_exit_code"], 3);
        let human = stdout(&human);
        assert!(human.contains(&format!("verdict={expected}")), "{human}");
        assert!(human.contains(&format!("probe={expected}")), "{human}");
        assert!(human.contains("aggregate_exit_code=3"), "{human}");
    }
}

#[test]
fn why_applies_exact_and_wildcard_labels_and_rejects_invalid_scope_before_output() {
    let _host_observation = lock_host_observation();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
    let port = listener
        .local_addr()
        .expect("listener address is known")
        .port();
    let port_text = port.to_string();
    for (selector, label) in [
        ("127.0.0.1", "exact web fixture"),
        ("*", "wildcard web fixture"),
    ] {
        let config = format!(
            "[[ports]]\nprotocol = \"tcp\"\naddress = \"{selector}\"\nport = {port}\nlabel = \"{label}\"\n"
        );
        let labeled = why_with_config(
            &[port_text.as_str(), "--address", "127.0.0.1", "--json"],
            &config,
        );
        assert_eq!(labeled.status.code(), Some(3), "{}", stderr(&labeled));
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&labeled)).expect("why output must be JSON");
        assert_eq!(value["results"][0]["label"], label);
    }

    let invalid = why(&[
        port_text.as_str(),
        "--address",
        "127.0.0.1",
        "--scope-id",
        "3",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(stdout(&invalid), "");
    assert!(stderr(&invalid).contains("scope ID is valid only"));

    for invalid_args in [
        vec!["0", "--address", "127.0.0.1"],
        vec!["65536", "--address", "127.0.0.1"],
        vec!["3000", "--address", "fe80::1%3"],
        vec!["3000", "--address", "::1", "--scope-id", "0"],
    ] {
        let output = why(&invalid_args);
        assert_eq!(output.status.code(), Some(2), "{invalid_args:?}");
        assert_eq!(stdout(&output), "");
        assert!(!stderr(&output).is_empty());
    }
}

#[test]
fn why_keeps_linux_ipv6_and_the_complete_expansion_explicit() {
    let _host_observation = lock_host_observation();
    let ipv6 = match TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)) {
        Ok(listener) => listener,
        Err(error) if !required_linux_capabilities() => {
            eprintln!("skipping IPv6 why contract because loopback is unavailable: {error}");
            return;
        }
        Err(error) => panic!("required IPv6 loopback is unavailable: {error}"),
    };
    let ipv6_port = ipv6.local_addr().expect("IPv6 address is known").port();
    let ipv6_port_text = ipv6_port.to_string();
    let ipv6_output = why(&[
        ipv6_port_text.as_str(),
        "--tcp",
        "--address",
        "::1",
        "--json",
    ]);
    assert_eq!(ipv6_output.status.code(), Some(3));
    let ipv6_value: serde_json::Value =
        serde_json::from_str(&stdout(&ipv6_output)).expect("IPv6 why output must be JSON");
    assert_eq!(ipv6_value["results"][0]["endpoint"]["address"], "::1");
    assert_eq!(
        ipv6_value["results"][0]["probe"]["outcome"],
        "address_in_use"
    );
    assert_eq!(
        ipv6_value["results"][0]["verdict"],
        "reservation_or_policy_unknown"
    );
    assert!(
        ipv6_value["results"][0]["evidence"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| {
                item["code"] == "potential_scope_overlap" && item["certainty"] == "unknown"
            }))
    );

    let matrix_output = why(&[
        ipv6_port_text.as_str(),
        "--all-protocols",
        "--all-addresses",
        "--json",
    ]);
    assert_eq!(matrix_output.status.code(), Some(3));
    assert_eq!(stderr(&matrix_output), "");
    let matrix: serde_json::Value =
        serde_json::from_str(&stdout(&matrix_output)).expect("matrix output must be JSON");
    assert_eq!(matrix["results"].as_array().map(Vec::len), Some(8));
    assert_eq!(matrix["aggregate_exit_code"], 3);
    let verdicts = matrix["results"]
        .as_array()
        .expect("matrix results are an array")
        .iter()
        .filter_map(|result| result["verdict"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(verdicts.contains("bindable_now"));
    assert!(verdicts.iter().any(|verdict| *verdict != "bindable_now"));
    assert!(
        matrix["scope"]["limitations"]
            .as_array()
            .is_some_and(|limitations| limitations
                .iter()
                .any(|limitation| { limitation == "scoped_ipv6_exact_matching_unavailable" }))
    );
}
