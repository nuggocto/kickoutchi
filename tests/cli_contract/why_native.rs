use super::{
    REAL_BINARY_EXIT_WAIT, TemporaryConfigFile, kickoutchi_binary, run_command_with_deadline,
};
use std::net::{Ipv6Addr, TcpListener, UdpSocket};
use std::process::{Command, Output};

fn run_why(args: &[&str]) -> Output {
    let config = TemporaryConfigFile::new("why-native", "");
    run_command_with_deadline(
        Command::new(kickoutchi_binary())
            .arg("--config")
            .arg(config.path())
            .arg("why")
            .args(args)
            .arg("--json"),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("why command must run before its deadline")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "why stdout must be JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_native_occupancy(output: &Output) {
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let value = json(output);
    assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
    #[cfg(windows)]
    assert_eq!(value["results"][0]["verdict"], "owned");
    #[cfg(target_os = "macos")]
    assert!(matches!(
        value["results"][0]["verdict"].as_str(),
        Some("owned" | "owner_hidden" | "reservation_or_policy_unknown")
    ));
}

#[test]
fn why_reports_native_tcp_and_udp_occupancy() {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
    let tcp_port = tcp.local_addr().expect("TCP address is known").port();
    let tcp_port = tcp_port.to_string();
    let tcp_output = run_why(&[tcp_port.as_str(), "--tcp", "--address", "127.0.0.1"]);
    assert_native_occupancy(&tcp_output);

    let udp = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP fixture must bind");
    let udp_port = udp.local_addr().expect("UDP address is known").port();
    let udp_port = udp_port.to_string();
    let udp_output = run_why(&[udp_port.as_str(), "--udp", "--address", "127.0.0.1"]);
    assert_native_occupancy(&udp_output);
}

#[test]
fn why_keeps_ipv6_as_an_explicit_native_result() {
    let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
        let output = run_why(&["3000", "--tcp", "--address", "::1"]);
        let value = json(&output);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(value["results"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["results"][0]["endpoint"]["address"], "::1");
        assert!(matches!(
            value["results"][0]["verdict"].as_str(),
            Some("unsupported" | "address_unavailable")
        ));
        return;
    };
    let port = listener.local_addr().expect("IPv6 address is known").port();
    let port = port.to_string();

    let output = run_why(&[port.as_str(), "--tcp", "--address", "::1"]);
    let value = json(&output);

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    assert_eq!(value["results"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["results"][0]["endpoint"]["address"], "::1");
    assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
    #[cfg(windows)]
    assert_eq!(value["results"][0]["verdict"], "owned");
    #[cfg(target_os = "macos")]
    assert_eq!(
        value["results"][0]["verdict"],
        "reservation_or_policy_unknown"
    );
}
