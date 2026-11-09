//! The inner Snell request/response protocol, shared by every wire.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::codec::MAX_PAYLOAD;
use crate::error::{Error, Result};

/// First byte of every client request (unchanged since v1).
pub(crate) const VERSION: u8 = 1;

pub(crate) const CMD_PING: u8 = 0;
pub(crate) const CMD_CONNECT: u8 = 1;
/// Reuse-capable connect.
pub(crate) const CMD_CONNECT_V2: u8 = 5;
pub(crate) const CMD_UDP: u8 = 6;

/// First byte of each UDP-over-TCP request datagram.
pub(crate) const UDP_FORWARD: u8 = 1;

pub(crate) const RESP_TUNNEL: u8 = 0;
pub(crate) const RESP_PONG: u8 = 1;
pub(crate) const RESP_ERROR: u8 = 2;

/// The UDP session request: version, command, empty client ID.
pub(crate) const UDP_REQUEST: [u8; 3] = [VERSION, CMD_UDP, 0];

/// A proxy target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// An IP address and port.
    Socket(SocketAddr),
    /// A host name (resolved by the server) and port.
    Domain(String, u16),
}

impl Address {
    /// The port.
    pub fn port(&self) -> u16 {
        match self {
            Address::Socket(a) => a.port(),
            Address::Domain(_, p) => *p,
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(a: SocketAddr) -> Self {
        Address::Socket(a)
    }
}

impl From<(IpAddr, u16)> for Address {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        Address::Socket(SocketAddr::new(ip, port))
    }
}

impl From<(String, u16)> for Address {
    fn from((host, port): (String, u16)) -> Self {
        Address::Domain(host, port)
    }
}

impl From<(&str, u16)> for Address {
    fn from((host, port): (&str, u16)) -> Self {
        match host.parse::<IpAddr>() {
            Ok(ip) => Address::Socket(SocketAddr::new(ip, port)),
            Err(_) => Address::Domain(host.to_owned(), port),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Socket(a) => a.fmt(f),
            Address::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// Encodes a TCP CONNECT request: version, command, empty client ID, host,
/// port.
pub(crate) fn connect_request(host: &str, port: u16, reuse: bool) -> Result<Vec<u8>> {
    let len = u8::try_from(host.len()).map_err(|_| Error::Config("host name too long"))?;
    let mut buf = Vec::with_capacity(6 + host.len());
    buf.extend_from_slice(&[
        VERSION,
        if reuse { CMD_CONNECT_V2 } else { CMD_CONNECT },
        0,
        len,
    ]);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(buf)
}

/// A request parsed by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    Ping,
    Connect {
        host: String,
        port: u16,
        reuse: bool,
    },
    Udp,
}

/// Parses a request from the front of `buf`. Returns the request and its
/// length, or `None` when more bytes are needed.
pub(crate) fn parse_request(buf: &[u8]) -> Result<Option<(Request, usize)>> {
    let Some(&version) = buf.first() else {
        return Ok(None);
    };
    if version != VERSION {
        return Err(Error::Request("unknown protocol version"));
    }
    let Some(&cmd) = buf.get(1) else {
        return Ok(None);
    };
    if cmd == CMD_PING {
        return Ok(Some((Request::Ping, 2)));
    }
    let Some(&id_len) = buf.get(2) else {
        return Ok(None);
    };
    let mut off = 3 + usize::from(id_len);
    match cmd {
        CMD_CONNECT | CMD_CONNECT_V2 => {
            let Some(&host_len) = buf.get(off) else {
                return Ok(None);
            };
            off += 1;
            let host_end = off + usize::from(host_len);
            if buf.len() < host_end + 2 {
                return Ok(None);
            }
            // Snell host names are opaque bytes; anything that is not UTF-8
            // cannot resolve and fails as a DNS error.
            let host = String::from_utf8_lossy(&buf[off..host_end]).into_owned();
            let port = u16::from_be_bytes([buf[host_end], buf[host_end + 1]]);
            Ok(Some((
                Request::Connect {
                    host,
                    port,
                    reuse: cmd == CMD_CONNECT_V2,
                },
                host_end + 2,
            )))
        }
        CMD_UDP => {
            if buf.len() < off {
                return Ok(None);
            }
            Ok(Some((Request::Udp, off)))
        }
        _ => Err(Error::Request("unknown command")),
    }
}

/// The official v6 server parses a request header out of the single frame that
/// starts the session. Returns how many zero bytes complete a CONNECT whose
/// frame ends inside its 2-byte port (the official server reads the missing
/// port bytes as zero), or `None` when the frame cannot hold the header.
/// Other versions and commands are left to [`parse_request`].
pub(crate) fn v6_request_check(b: &[u8]) -> Option<usize> {
    if b.len() < 2 || b[0] != VERSION {
        return (!b.is_empty()).then_some(0);
    }
    let id_len = usize::from(*b.get(2)?);
    let mut off = 3 + id_len;
    if b.len() < off {
        return None;
    }
    if matches!(b[1], CMD_CONNECT | CMD_CONNECT_V2) {
        off += 1 + usize::from(*b.get(off)?);
        if b.len() < off {
            return None;
        }
        return Some(2usize.saturating_sub(b.len() - off));
    }
    Some(0)
}

/// Encodes an error response: `02 | code | len | message`.
pub(crate) fn error_response(code: u8, msg: &str) -> Vec<u8> {
    let msg = &msg.as_bytes()[..msg.len().min(250)];
    let mut buf = Vec::with_capacity(3 + msg.len());
    buf.extend_from_slice(&[RESP_ERROR, code, msg.len() as u8]);
    buf.extend_from_slice(msg);
    buf
}

/// Encodes the address part of a client UDP request (after the 0x01 command):
/// `len | host | port` for a domain, `00 04 | ip | port` / `00 06 | ip | port`
/// for an address.
pub(crate) fn udp_request_head(target: &Address, head: &mut Vec<u8>) -> Result<()> {
    head.clear();
    head.push(UDP_FORWARD);
    match target {
        Address::Domain(host, port) => {
            let len = u8::try_from(host.len()).map_err(|_| Error::Config("host name too long"))?;
            if len == 0 {
                return Err(Error::Config("empty host name"));
            }
            head.push(len);
            head.extend_from_slice(host.as_bytes());
            head.extend_from_slice(&port.to_be_bytes());
        }
        Address::Socket(SocketAddr::V4(a)) => {
            head.extend_from_slice(&[0, 4]);
            head.extend_from_slice(&a.ip().octets());
            head.extend_from_slice(&a.port().to_be_bytes());
        }
        Address::Socket(SocketAddr::V6(a)) => {
            head.extend_from_slice(&[0, 6]);
            head.extend_from_slice(&a.ip().octets());
            head.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    Ok(())
}

/// Largest UDP payload that fits one frame after `head`.
pub(crate) fn udp_max_payload(head: &[u8]) -> usize {
    MAX_PAYLOAD.saturating_sub(head.len())
}

/// A UDP datagram request parsed by the server.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UdpRequest<'a> {
    pub(crate) target: Address,
    /// The address was sent as an IPv6 (type 6) address.
    pub(crate) ipv6_type: bool,
    pub(crate) payload: &'a [u8],
}

/// Parses one client UDP request datagram.
pub(crate) fn parse_udp_request(p: &[u8]) -> Result<UdpRequest<'_>> {
    if p.len() < 2 || p[0] != UDP_FORWARD {
        return Err(Error::Request("invalid UDP request"));
    }
    let host_len = usize::from(p[1]);
    if host_len != 0 {
        let off = 2 + host_len;
        // The official server requires at least one payload byte here.
        if p.len() <= off + 2 {
            return Err(Error::Request("invalid UDP domain request"));
        }
        let host = String::from_utf8_lossy(&p[2..off]).into_owned();
        let port = u16::from_be_bytes([p[off], p[off + 1]]);
        return Ok(UdpRequest {
            target: Address::Domain(host, port),
            ipv6_type: false,
            payload: &p[off + 2..],
        });
    }
    let (ip, off, ipv6_type) = match p.get(2) {
        Some(4) if p.len() >= 3 + 4 + 2 => {
            let o: [u8; 4] = p[3..7].try_into().expect("4 bytes");
            (IpAddr::V4(Ipv4Addr::from(o)), 7, false)
        }
        Some(6) if p.len() >= 3 + 16 + 2 => {
            let o: [u8; 16] = p[3..19].try_into().expect("16 bytes");
            (IpAddr::V6(Ipv6Addr::from(o)).to_canonical(), 19, true)
        }
        _ => return Err(Error::Request("invalid UDP address")),
    };
    let port = u16::from_be_bytes([p[off], p[off + 1]]);
    Ok(UdpRequest {
        target: Address::Socket(SocketAddr::new(ip, port)),
        ipv6_type,
        payload: &p[off + 2..],
    })
}

/// Encodes the source address of a server UDP response: `04 | ip | port` or
/// `06 | ip | port`. With `as_ipv6`, IPv4 sources are sent IPv4-mapped, as the
/// official server's dual-stack socket reports them.
pub(crate) fn udp_response_head(src: SocketAddr, as_ipv6: bool, head: &mut Vec<u8>) {
    head.clear();
    match src {
        SocketAddr::V4(a) if !as_ipv6 => {
            head.push(4);
            head.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V4(a) => {
            head.push(6);
            head.extend_from_slice(&a.ip().to_ipv6_mapped().octets());
        }
        SocketAddr::V6(a) => {
            head.push(6);
            head.extend_from_slice(&a.ip().octets());
        }
    }
    head.extend_from_slice(&src.port().to_be_bytes());
}

/// Parses a server UDP response datagram into its source and payload.
/// IPv4-mapped sources are returned as IPv4.
pub(crate) fn parse_udp_response(p: &[u8]) -> Result<(SocketAddr, &[u8])> {
    let (ip, off) = match p.first() {
        Some(4) if p.len() >= 1 + 4 + 2 => {
            let o: [u8; 4] = p[1..5].try_into().expect("4 bytes");
            (IpAddr::V4(Ipv4Addr::from(o)), 5)
        }
        Some(6) if p.len() >= 1 + 16 + 2 => {
            let o: [u8; 16] = p[1..17].try_into().expect("16 bytes");
            (IpAddr::V6(Ipv6Addr::from(o)).to_canonical(), 17)
        }
        _ => return Err(Error::Frame("invalid UDP response")),
    };
    let port = u16::from_be_bytes([p[off], p[off + 1]]);
    Ok((SocketAddr::new(ip, port), &p[off + 2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_round_trip() {
        let req = connect_request("example.com", 443, true).unwrap();
        let (parsed, n) = parse_request(&req).unwrap().unwrap();
        assert_eq!(n, req.len());
        assert_eq!(
            parsed,
            Request::Connect {
                host: "example.com".into(),
                port: 443,
                reuse: true
            }
        );
        for cut in 0..req.len() {
            assert_eq!(parse_request(&req[..cut]).unwrap(), None, "cut {cut}");
        }
        assert!(connect_request(&"a".repeat(256), 1, false).is_err());
    }

    #[test]
    fn v6_single_frame_check() {
        let req = connect_request("a.b", 80, true).unwrap();
        assert_eq!(v6_request_check(&req), Some(0));
        assert_eq!(v6_request_check(&req[..req.len() - 1]), Some(1));
        assert_eq!(v6_request_check(&req[..req.len() - 2]), Some(2));
        assert_eq!(v6_request_check(&req[..req.len() - 3]), None);
        assert_eq!(v6_request_check(&[1]), Some(0)); // left to the parser
        assert_eq!(v6_request_check(&[1, 1]), None);
        assert_eq!(v6_request_check(&UDP_REQUEST), Some(0));
        assert_eq!(v6_request_check(&[9, 9]), Some(0)); // left to the parser
    }

    #[test]
    fn udp_request_round_trip() {
        let mut head = Vec::new();
        for target in [
            Address::Domain("dns.google".into(), 53),
            Address::Socket("1.2.3.4:5".parse().unwrap()),
            Address::Socket("[2001:db8::1]:443".parse().unwrap()),
        ] {
            udp_request_head(&target, &mut head).unwrap();
            let mut pkt = head.clone();
            pkt.extend_from_slice(b"payload");
            let req = parse_udp_request(&pkt).unwrap();
            assert_eq!(req.target, target);
            assert_eq!(req.payload, b"payload");
        }
        // A domain request needs at least one payload byte.
        udp_request_head(&Address::Domain("a".into(), 1), &mut head).unwrap();
        assert!(parse_udp_request(&head).is_err());
    }

    #[test]
    fn udp_response_ipv6_encoding() {
        let mut head = Vec::new();
        let src: SocketAddr = "8.8.8.8:53".parse().unwrap();
        udp_response_head(src, true, &mut head);
        assert_eq!(head.len(), 1 + 16 + 2);
        assert_eq!(head[0], 6);
        let mut pkt = head.clone();
        pkt.push(0xaa);
        assert_eq!(parse_udp_response(&pkt).unwrap(), (src, &[0xaa][..]));
        udp_response_head(src, false, &mut head);
        assert_eq!(head[0], 4);
    }
}
