//! How the server reaches targets.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::Error;

/// Who a request comes from.
#[derive(Debug, Clone, Default)]
pub struct ConnInfo {
    /// The client's address, when known.
    pub peer: Option<SocketAddr>,
    /// The user label an [`Identifier`](super::Identifier) assigned.
    pub user: Option<Arc<str>>,
}

/// A datagram socket the server relays UDP sessions through.
pub trait PacketSocket: Send + Sync + 'static {
    /// Receives one datagram.
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>>;
    /// Sends one datagram.
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;
}

impl PacketSocket for UdpSocket {
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        UdpSocket::poll_recv_from(self, cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buf, target)
    }
}

/// Connects the server to targets. Implement it to route upstream traffic
/// elsewhere (a router, another proxy); [`Direct`] dials directly.
///
/// Errors from [`Outbound::connect`] are reported to the client with the
/// official error codes: wrap a name-resolution failure in [`DnsError`] to get
/// code 100, and use the standard [`io::ErrorKind`]s for refused (6), reset
/// (4) and timed-out (5) connections.
pub trait Outbound: Send + Sync + 'static {
    /// Upstream TCP connection.
    type Tcp: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Socket for one UDP session.
    type Udp: PacketSocket;

    /// Opens a TCP connection to `host:port` (`host` may be a name or an IP
    /// literal).
    fn connect(
        &self,
        info: &ConnInfo,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Self::Tcp>> + Send;

    /// Opens the socket for a UDP session.
    fn bind_udp(&self, info: &ConnInfo) -> impl Future<Output = io::Result<Self::Udp>> + Send;

    /// Resolves a UDP target name.
    fn resolve(
        &self,
        info: &ConnInfo,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<SocketAddr>> + Send;

    /// Whether UDP replies report IPv4 sources as IPv4-mapped IPv6, as a
    /// dual-stack socket sees them (the official server's behavior outside
    /// macOS).
    fn udp_sources_ipv6(&self) -> bool {
        true
    }
}

/// Name resolution failed. Reported to the client as code 100, "DNS Failed".
#[derive(Debug)]
pub struct DnsError(pub String);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS lookup failed: {}", self.0)
    }
}

impl std::error::Error for DnsError {}

impl DnsError {
    /// An [`io::Error`] carrying a `DnsError`.
    pub fn io(host: &str) -> io::Error {
        io::Error::other(DnsError(host.to_owned()))
    }
}

/// Outbound IP family policy (`dns-ip-preference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpPreference {
    /// Use the first resolved address.
    #[default]
    Default,
    /// Prefer IPv4, fall back to IPv6.
    PreferIpv4,
    /// Prefer IPv6, fall back to IPv4.
    PreferIpv6,
    /// IPv4 only; IPv6 literal targets are rejected.
    Ipv4Only,
    /// IPv6 only; IPv4 literal targets are rejected.
    Ipv6Only,
}

impl IpPreference {
    /// Whether targets of this address family are allowed.
    pub fn allows(self, ip: IpAddr) -> bool {
        match self {
            IpPreference::Ipv4Only => ip.to_canonical().is_ipv4(),
            IpPreference::Ipv6Only => !ip.to_canonical().is_ipv4(),
            _ => true,
        }
    }

    /// Picks the address to connect to, as the official server does: one
    /// address, the first of the preferred family when there is one.
    fn pick(self, addrs: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
        let addrs: Vec<SocketAddr> = addrs.filter(|a| self.allows(a.ip())).collect();
        let want_v4 = match self {
            IpPreference::PreferIpv4 => Some(true),
            IpPreference::PreferIpv6 => Some(false),
            _ => None,
        };
        want_v4
            .and_then(|v4| addrs.iter().find(|a| a.ip().to_canonical().is_ipv4() == v4))
            .or_else(|| addrs.first())
            .copied()
    }
}

impl FromStr for IpPreference {
    type Err = Error;

    /// Accepts the official spellings and their aliases.
    fn from_str(s: &str) -> Result<Self, Error> {
        match s.trim().to_ascii_lowercase().as_str() {
            "default" | "first-result" => Ok(IpPreference::Default),
            "prefer-ipv4" | "ipv4-preferred" => Ok(IpPreference::PreferIpv4),
            "prefer-ipv6" | "ipv6-preferred" => Ok(IpPreference::PreferIpv6),
            "ipv4-only" | "only-ipv4" => Ok(IpPreference::Ipv4Only),
            "ipv6-only" | "only-ipv6" => Ok(IpPreference::Ipv6Only),
            _ => Err(Error::Config("unknown dns-ip-preference")),
        }
    }
}

/// Dials targets directly with tokio, resolving names with the system
/// resolver.
#[derive(Debug, Clone, Default)]
pub struct Direct {
    /// Address family policy.
    pub ip_preference: IpPreference,
    /// Connect timeout. `None` leaves it to the kernel, as the official server
    /// does.
    pub connect_timeout: Option<Duration>,
    /// TCP keepalive idle time on upstream connections (`None`: off).
    pub keepalive: Option<Duration>,
}

impl Direct {
    async fn pick(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| DnsError::io(host))?;
        self.ip_preference
            .pick(addrs)
            .ok_or_else(|| DnsError::io(host))
    }
}

impl Outbound for Direct {
    type Tcp = TcpStream;
    type Udp = UdpSocket;

    async fn connect(&self, _info: &ConnInfo, host: &str, port: u16) -> io::Result<TcpStream> {
        let addr = self.pick(host, port).await?;
        let connect = TcpStream::connect(addr);
        let stream = match self.connect_timeout {
            Some(t) => tokio::time::timeout(t, connect)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
            None => connect.await?,
        };
        stream.set_nodelay(true)?;
        if let Some(idle) = self.keepalive {
            crate::sys::set_keepalive(&stream, idle, idle, None)?;
        }
        Ok(stream)
    }

    async fn bind_udp(&self, _info: &ConnInfo) -> io::Result<UdpSocket> {
        // The official macOS server relays over an IPv4 socket, elsewhere over
        // a dual-stack one.
        if cfg!(target_os = "macos") {
            UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await
        } else {
            crate::sys::bind_udp_dual_stack()
        }
    }

    async fn resolve(&self, _info: &ConnInfo, host: &str, port: u16) -> io::Result<SocketAddr> {
        self.pick(host, port).await
    }

    fn udp_sources_ipv6(&self) -> bool {
        !cfg!(target_os = "macos")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_follows_preference() {
        let v4: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let v6: SocketAddr = "[2606:4700::1111]:1".parse().unwrap();
        let both = [v6, v4];
        assert_eq!(IpPreference::Default.pick(both.into_iter()), Some(v6));
        assert_eq!(IpPreference::PreferIpv4.pick(both.into_iter()), Some(v4));
        assert_eq!(
            IpPreference::PreferIpv6.pick([v4, v6].into_iter()),
            Some(v6)
        );
        assert_eq!(IpPreference::Ipv4Only.pick(both.into_iter()), Some(v4));
        assert_eq!(IpPreference::Ipv6Only.pick([v4].into_iter()), None);
        assert_eq!(IpPreference::PreferIpv6.pick([v4].into_iter()), Some(v4));
        assert_eq!(
            "only-ipv4".parse::<IpPreference>().unwrap(),
            IpPreference::Ipv4Only
        );
    }
}
