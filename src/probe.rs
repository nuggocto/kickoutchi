//! Exact, side-effect-minimized bind probes.
//!
//! This is the only production boundary around `socket2`. A probe creates one
//! socket, configures it, attempts one bind, and closes it before returning.

use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU16;

use socket2::{Domain, SockAddr, Socket, Type};
use thiserror::Error;

use crate::model::Protocol;
use crate::observation::{EndpointIdentity, EndpointIdentityError, Ipv6Scope};

/// Whether the probe explicitly enables address reuse before binding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ReuseAddressMode {
    #[default]
    Disabled,
    Enabled,
}

/// Requested IPv6 wildcard behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Ipv6Mode {
    #[default]
    SystemDefault,
    V6Only,
    DualStack,
}

/// A validated exact bind request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeRequest {
    protocol: Protocol,
    address: IpAddr,
    port: NonZeroU16,
    ipv6_scope: Option<Ipv6Scope>,
    ipv6_mode: Ipv6Mode,
    reuse_address: ReuseAddressMode,
}

impl ProbeRequest {
    pub(crate) fn new(
        protocol: Protocol,
        address: IpAddr,
        port: u32,
        ipv6_scope: Option<Ipv6Scope>,
        ipv6_mode: Ipv6Mode,
        reuse_address: ReuseAddressMode,
    ) -> Result<Self, ProbeRequestError> {
        // IPv4-mapped normalization, port validation, and address/scope
        // pairing are the endpoint-identity contract; only the probe-specific
        // refusals below are added here.
        let identity = EndpointIdentity::new(protocol, address, port, ipv6_scope)
            .map_err(ProbeRequestError::from)?;
        // A probe binds one exact native address, so an unavailable scope has
        // no bindable representation.
        if identity.ipv6_scope == Some(Ipv6Scope::Unavailable) {
            return Err(ProbeRequestError::UnavailableIpv6Scope);
        }

        // `EndpointIdentity` ignores scope on an IPv4-mapped address. Probes
        // reject that contradictory request.
        if identity.address.is_ipv4() && ipv6_scope.is_some() {
            return Err(ProbeRequestError::Ipv4WithScope);
        }
        if identity.address.is_ipv4() && ipv6_mode != Ipv6Mode::SystemDefault {
            return Err(ProbeRequestError::Ipv4WithIpv6Mode);
        }

        Ok(Self {
            protocol: identity.protocol,
            address: identity.address,
            port: identity.port,
            ipv6_scope: identity.ipv6_scope,
            ipv6_mode,
            reuse_address,
        })
    }

    fn socket_address(self) -> SocketAddr {
        match (self.address, self.ipv6_scope) {
            (IpAddr::V4(address), None) => SocketAddr::from((address, self.port.get())),
            (IpAddr::V6(address), Some(scope)) => {
                let scope_id = match scope {
                    Ipv6Scope::Unscoped => 0,
                    Ipv6Scope::InterfaceIndex(index) => index.get(),
                    Ipv6Scope::Unavailable => {
                        unreachable!("validated probe requests cannot have unavailable scope")
                    }
                };
                SocketAddr::V6(SocketAddrV6::new(address, self.port.get(), 0, scope_id))
            }
            _ => unreachable!("validated probe address and scope must agree"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ProbeRequestError {
    #[error("probe port must be in 1..=65535")]
    InvalidPort,
    #[error("IPv4 probe targets cannot carry an IPv6 scope")]
    Ipv4WithScope,
    #[error("IPv6 probe targets require an explicit scope")]
    Ipv6WithoutScope,
    #[error("an unavailable IPv6 scope cannot be probed exactly")]
    UnavailableIpv6Scope,
    #[error("IPv6-only and dual-stack modes are invalid for IPv4 probe targets")]
    Ipv4WithIpv6Mode,
}

impl From<EndpointIdentityError> for ProbeRequestError {
    fn from(error: EndpointIdentityError) -> Self {
        match error {
            EndpointIdentityError::InvalidPort => Self::InvalidPort,
            EndpointIdentityError::Ipv4WithScope => Self::Ipv4WithScope,
            EndpointIdentityError::Ipv6WithoutScope => Self::Ipv6WithoutScope,
            EndpointIdentityError::InvalidInterfaceIndex => {
                unreachable!("`EndpointIdentity::new` performs no interface-index validation")
            }
        }
    }
}

/// Stable result category for one exact bind attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    BindableNow,
    AddressInUse,
    PermissionDenied,
    AddressUnavailable,
    Unsupported,
    Other,
}

/// Owned result data; no socket or native handle escapes the probe call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeResult {
    pub(crate) outcome: ProbeOutcome,
    pub(crate) raw_os_error: Option<i32>,
    pub(crate) os_error_message: Option<Box<str>>,
}

impl ProbeResult {
    fn bindable_now() -> Self {
        Self {
            outcome: ProbeOutcome::BindableNow,
            raw_os_error: None,
            os_error_message: None,
        }
    }

    fn from_error(error: &io::Error) -> Self {
        let outcome = classify_error(error);
        Self {
            outcome,
            raw_os_error: error.raw_os_error(),
            os_error_message: Some(error.to_string().into_boxed_str()),
        }
    }
}

/// Attempt the requested bind exactly once and close the socket before return.
pub(crate) fn probe(request: ProbeRequest) -> ProbeResult {
    probe_bind(
        request.protocol,
        request.socket_address(),
        request.ipv6_mode,
        request.reuse_address,
    )
}

fn probe_bind(
    requested_protocol: Protocol,
    address: SocketAddr,
    ipv6_mode: Ipv6Mode,
    reuse_address: ReuseAddressMode,
) -> ProbeResult {
    let (domain, socket_type, protocol) = match (address.is_ipv4(), requested_protocol) {
        (true, Protocol::Tcp) => (Domain::IPV4, Type::STREAM, socket2::Protocol::TCP),
        (true, Protocol::Udp) => (Domain::IPV4, Type::DGRAM, socket2::Protocol::UDP),
        (false, Protocol::Tcp) => (Domain::IPV6, Type::STREAM, socket2::Protocol::TCP),
        (false, Protocol::Udp) => (Domain::IPV6, Type::DGRAM, socket2::Protocol::UDP),
    };

    let socket = match Socket::new(domain, socket_type, Some(protocol)) {
        Ok(socket) => socket,
        Err(error) => return ProbeResult::from_error(&error),
    };
    let reuse_address = reuse_address == ReuseAddressMode::Enabled;
    if let Err(error) = socket.set_reuse_address(reuse_address) {
        return ProbeResult::from_error(&error);
    }
    let only_v6 = match ipv6_mode {
        Ipv6Mode::SystemDefault => None,
        Ipv6Mode::V6Only => Some(true),
        Ipv6Mode::DualStack => Some(false),
    };
    if let Some(only_v6) = only_v6
        && let Err(error) = socket.set_only_v6(only_v6)
    {
        return ProbeResult::from_error(&error);
    }

    match socket.bind(&SockAddr::from(address)) {
        Ok(()) => ProbeResult::bindable_now(),
        Err(error) => ProbeResult::from_error(&error),
    }
}

fn classify_error(error: &io::Error) -> ProbeOutcome {
    match error.kind() {
        io::ErrorKind::AddrInUse => ProbeOutcome::AddressInUse,
        io::ErrorKind::PermissionDenied => ProbeOutcome::PermissionDenied,
        io::ErrorKind::AddrNotAvailable => ProbeOutcome::AddressUnavailable,
        io::ErrorKind::Unsupported => ProbeOutcome::Unsupported,
        _ if error.raw_os_error().is_some_and(is_unsupported_code) => ProbeOutcome::Unsupported,
        _ => ProbeOutcome::Other,
    }
}

#[cfg(unix)]
fn is_unsupported_code(code: i32) -> bool {
    code == libc::EAFNOSUPPORT
        || code == libc::EPROTONOSUPPORT
        || code == libc::ENOPROTOOPT
        || code == libc::EOPNOTSUPP
}

#[cfg(windows)]
fn is_unsupported_code(code: i32) -> bool {
    use windows_sys::Win32::Networking::WinSock::{
        WSAEAFNOSUPPORT, WSAENOPROTOOPT, WSAEOPNOTSUPP, WSAEPROTONOSUPPORT,
    };

    code == WSAEAFNOSUPPORT
        || code == WSAENOPROTOOPT
        || code == WSAEOPNOTSUPP
        || code == WSAEPROTONOSUPPORT
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
    use std::num::NonZeroU32;

    use super::*;

    fn request(
        protocol: Protocol,
        address: IpAddr,
        port: u16,
        ipv6_mode: Ipv6Mode,
        reuse_address: ReuseAddressMode,
    ) -> ProbeRequest {
        let scope = address.is_ipv6().then_some(Ipv6Scope::Unscoped);
        ProbeRequest::new(
            protocol,
            address,
            u32::from(port),
            scope,
            ipv6_mode,
            reuse_address,
        )
        .expect("test probe request must be valid")
    }

    fn native_ipv6_capability(
        protocol: Protocol,
        address: Ipv6Addr,
        ipv6_mode: Ipv6Mode,
        reuse_address: ReuseAddressMode,
    ) -> io::Result<()> {
        let (socket_type, native_protocol) = match protocol {
            Protocol::Tcp => (Type::STREAM, socket2::Protocol::TCP),
            Protocol::Udp => (Type::DGRAM, socket2::Protocol::UDP),
        };
        let socket = Socket::new(Domain::IPV6, socket_type, Some(native_protocol))?;
        socket.set_reuse_address(reuse_address == ReuseAddressMode::Enabled)?;
        match ipv6_mode {
            Ipv6Mode::SystemDefault => {}
            Ipv6Mode::V6Only => socket.set_only_v6(true)?,
            Ipv6Mode::DualStack => socket.set_only_v6(false)?,
        }
        socket.bind(&SockAddr::from(SocketAddr::from((address, 0))))
    }

    #[test]
    fn request_rejects_invalid_port_boundaries() {
        for port in [0, 65_536] {
            assert_eq!(
                ProbeRequest::new(
                    Protocol::Tcp,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port,
                    None,
                    Ipv6Mode::SystemDefault,
                    ReuseAddressMode::Disabled,
                ),
                Err(ProbeRequestError::InvalidPort)
            );
        }

        for port in [1, 65_535] {
            assert!(
                ProbeRequest::new(
                    Protocol::Tcp,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port,
                    None,
                    Ipv6Mode::SystemDefault,
                    ReuseAddressMode::Disabled,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn request_rejects_incompatible_address_controls() {
        let ipv4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let index = Ipv6Scope::InterfaceIndex(NonZeroU32::new(1).expect("one is nonzero"));

        assert_eq!(
            ProbeRequest::new(
                Protocol::Tcp,
                ipv4,
                1,
                Some(index),
                Ipv6Mode::SystemDefault,
                ReuseAddressMode::Disabled,
            ),
            Err(ProbeRequestError::Ipv4WithScope)
        );
        assert_eq!(
            ProbeRequest::new(
                Protocol::Tcp,
                ipv6,
                1,
                None,
                Ipv6Mode::SystemDefault,
                ReuseAddressMode::Disabled,
            ),
            Err(ProbeRequestError::Ipv6WithoutScope)
        );
        assert_eq!(
            ProbeRequest::new(
                Protocol::Tcp,
                ipv6,
                1,
                Some(Ipv6Scope::Unavailable),
                Ipv6Mode::SystemDefault,
                ReuseAddressMode::Disabled,
            ),
            Err(ProbeRequestError::UnavailableIpv6Scope)
        );
        assert_eq!(
            ProbeRequest::new(
                Protocol::Tcp,
                ipv4,
                1,
                None,
                Ipv6Mode::DualStack,
                ReuseAddressMode::Disabled,
            ),
            Err(ProbeRequestError::Ipv4WithIpv6Mode)
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_targets_are_normalized_before_scope_validation() {
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert_eq!(
            ProbeRequest::new(
                Protocol::Tcp,
                mapped,
                80,
                Some(Ipv6Scope::Unscoped),
                Ipv6Mode::SystemDefault,
                ReuseAddressMode::Disabled,
            ),
            Err(ProbeRequestError::Ipv4WithScope)
        );

        let request = ProbeRequest::new(
            Protocol::Tcp,
            mapped,
            80,
            None,
            Ipv6Mode::SystemDefault,
            ReuseAddressMode::Disabled,
        )
        .expect("unscoped mapped address must normalize to IPv4");
        assert_eq!(request.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn interface_index_is_retained_in_the_native_socket_address() {
        let request = ProbeRequest::new(
            Protocol::Udp,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            53,
            Some(Ipv6Scope::InterfaceIndex(
                NonZeroU32::new(7).expect("seven is nonzero"),
            )),
            Ipv6Mode::V6Only,
            ReuseAddressMode::Disabled,
        )
        .expect("scoped IPv6 request must be valid");

        let SocketAddr::V6(address) = request.socket_address() else {
            panic!("scoped IPv6 request must produce an IPv6 socket address");
        };
        assert_eq!(address.scope_id(), 7);
        assert_eq!(address.flowinfo(), 0);
    }

    #[test]
    fn native_ipv4_matrix_binds_ephemeral_ports() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for address in [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED] {
                for reuse in [ReuseAddressMode::Disabled, ReuseAddressMode::Enabled] {
                    let result = probe_bind(
                        protocol,
                        SocketAddr::from((address, 0)),
                        Ipv6Mode::SystemDefault,
                        reuse,
                    );
                    assert_eq!(result.outcome, ProbeOutcome::BindableNow);
                    assert_eq!(result.raw_os_error, None);
                    assert_eq!(result.os_error_message, None);

                    let rebound = probe_bind(
                        protocol,
                        SocketAddr::from((address, 0)),
                        Ipv6Mode::SystemDefault,
                        reuse,
                    );
                    assert_eq!(rebound.outcome, ProbeOutcome::BindableNow);
                }
            }
        }
    }

    #[test]
    fn native_ipv6_matrix_binds_ephemeral_ports() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for address in [Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED] {
                for ipv6_mode in [
                    Ipv6Mode::SystemDefault,
                    Ipv6Mode::V6Only,
                    Ipv6Mode::DualStack,
                ] {
                    for reuse in [ReuseAddressMode::Disabled, ReuseAddressMode::Enabled] {
                        let capability =
                            native_ipv6_capability(protocol, address, ipv6_mode, reuse);
                        let result =
                            probe_bind(protocol, SocketAddr::from((address, 0)), ipv6_mode, reuse);
                        let expected = match capability {
                            Ok(()) => ProbeOutcome::BindableNow,
                            Err(error) if classify_error(&error) == ProbeOutcome::Unsupported => {
                                ProbeOutcome::Unsupported
                            }
                            Err(error) => panic!(
                                "independent IPv6 capability check failed unexpectedly: {error}"
                            ),
                        };
                        assert_eq!(
                            result.outcome, expected,
                            "IPv6 matrix result was {result:?}"
                        );
                        let rebound =
                            probe_bind(protocol, SocketAddr::from((address, 0)), ipv6_mode, reuse);
                        assert_eq!(rebound.outcome, result.outcome);
                    }
                }
            }
        }
    }

    #[test]
    fn occupied_tcp_and_udp_ports_are_reported_with_raw_errors() {
        let tcp =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("test host must bind TCP listener");
        let udp =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("test host must bind UDP socket");

        for (protocol, port) in [
            (
                Protocol::Tcp,
                tcp.local_addr().expect("TCP address must exist").port(),
            ),
            (
                Protocol::Udp,
                udp.local_addr().expect("UDP address must exist").port(),
            ),
        ] {
            let result = probe(request(
                protocol,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                Ipv6Mode::SystemDefault,
                ReuseAddressMode::Disabled,
            ));
            assert_eq!(result.outcome, ProbeOutcome::AddressInUse);
            assert!(result.raw_os_error.is_some());
            assert!(result.os_error_message.is_some());
        }
    }

    #[test]
    fn owned_errors_map_to_stable_categories() {
        let cases = [
            (io::ErrorKind::AddrInUse, ProbeOutcome::AddressInUse),
            (
                io::ErrorKind::PermissionDenied,
                ProbeOutcome::PermissionDenied,
            ),
            (
                io::ErrorKind::AddrNotAvailable,
                ProbeOutcome::AddressUnavailable,
            ),
            (io::ErrorKind::Unsupported, ProbeOutcome::Unsupported),
            (io::ErrorKind::ConnectionRefused, ProbeOutcome::Other),
        ];

        for (kind, expected) in cases {
            let error = io::Error::new(kind, "controlled test error");
            let result = ProbeResult::from_error(&error);
            assert_eq!(result.outcome, expected);
            assert_eq!(result.raw_os_error, None);
        }
    }

    #[test]
    fn native_error_codes_map_without_losing_the_code() {
        #[cfg(unix)]
        let cases = [
            (libc::EADDRINUSE, ProbeOutcome::AddressInUse),
            (libc::EACCES, ProbeOutcome::PermissionDenied),
            (libc::EADDRNOTAVAIL, ProbeOutcome::AddressUnavailable),
            (libc::EAFNOSUPPORT, ProbeOutcome::Unsupported),
        ];
        #[cfg(windows)]
        let cases = {
            use windows_sys::Win32::Networking::WinSock::{
                WSAEACCES, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT,
            };
            [
                (WSAEADDRINUSE, ProbeOutcome::AddressInUse),
                (WSAEACCES, ProbeOutcome::PermissionDenied),
                (WSAEADDRNOTAVAIL, ProbeOutcome::AddressUnavailable),
                (WSAEAFNOSUPPORT, ProbeOutcome::Unsupported),
            ]
        };

        for (raw_code, expected) in cases {
            let error = io::Error::from_raw_os_error(raw_code);
            let result = ProbeResult::from_error(&error);
            assert_eq!(result.outcome, expected);
            assert_eq!(result.raw_os_error, Some(raw_code));
        }
    }

    #[test]
    fn unknown_native_code_is_other_without_losing_the_code() {
        let raw_code = 20_000;
        let error = io::Error::from_raw_os_error(raw_code);
        let result = ProbeResult::from_error(&error);

        assert_eq!(result.outcome, ProbeOutcome::Other);
        assert_eq!(result.raw_os_error, Some(raw_code));
    }
}
