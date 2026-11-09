//! Socket option helpers.

use std::io;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};

/// Enables TCP keepalive: first probe after `idle`, then every `interval`,
/// giving up after `retries` probes where the platform supports setting them.
pub(crate) fn set_keepalive<'a>(
    sock: impl Into<SockRef<'a>>,
    idle: Duration,
    interval: Duration,
    retries: Option<u32>,
) -> io::Result<()> {
    let ka = TcpKeepalive::new().with_time(idle);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    ))]
    let ka = ka.with_interval(interval);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    let ka = match retries {
        Some(r) => ka.with_retries(r),
        None => ka,
    };
    let _ = (interval, retries);
    sock.into().set_tcp_keepalive(&ka)
}

/// A UDP socket on an ephemeral port that reaches both IPv4 and IPv6
/// targets: an IPv6 socket with `IPV6_V6ONLY` off (Windows turns it on by
/// default), or an IPv4 socket where IPv6 is unavailable.
pub(crate) fn bind_udp_dual_stack() -> io::Result<tokio::net::UdpSocket> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use socket2::{Domain, Protocol, Socket, Type};

    let dual = || -> io::Result<Socket> {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
        Ok(s)
    };
    let sock = match dual() {
        Ok(s) => s,
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
            s
        }
    };
    sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(sock.into())
}
