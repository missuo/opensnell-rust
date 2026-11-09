//! Snell v5 QUIC proxy mode (a port of opensnell `quic.go`).
//!
//! The server also listens on UDP at its TCP port. The first datagram of a
//! client flow is a Snell envelope carrying the target and a QUIC Initial
//! packet, so the target never appears on the wire; after that, datagrams in
//! both directions are relayed as raw QUIC.
//!
//! ```text
//! [salt 16, bit 0x40 of byte 0 clear]
//! [sealed header 23: 04 00 00 | padLen | payLen]          nonce 0
//! [padding padLen]
//! [sealed payload: 01 01 00 | hostLen | host | port | QUIC packet]   nonce 1
//! ```
//!
//! The server tells envelopes from raw QUIC by that bit: every QUIC packet
//! sets it (the QUIC fixed bit).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::codec::{HEADER_LEN, SEALED_HEADER_LEN, parse_header, put_header};
use crate::crypto::{Cipher, SALT_LEN, TAG_LEN, random_salt};
use crate::error::{Error, Result};
use crate::key::{Key, Wire};
use crate::server::{ConnInfo, Outbound};

/// The QUIC fixed bit.
const FIXED_BIT: u8 = 0x40;
/// A flow idle this long is closed.
const FLOW_IDLE: Duration = Duration::from_secs(300);
/// Datagram buffer size.
const MAX_PACKET: usize = 65536;

fn v5_psk(key: &Key) -> Result<&[u8]> {
    match key.wire() {
        Wire::V5 => Ok(key.psk()),
        _ => Err(Error::Config("QUIC proxy mode is a v5 feature")),
    }
}

/// Wraps a QUIC packet for `host:port` into a Snell envelope.
pub fn encode_envelope(key: &Key, host: &str, port: u16, quic: &[u8]) -> Result<Vec<u8>> {
    let psk = v5_psk(key)?;
    let host_len = u8::try_from(host.len()).map_err(|_| Error::Config("host name too long"))?;
    if quic.is_empty() {
        return Err(Error::Config("QUIC packet missing"));
    }
    let pay = 4 + host.len() + 2 + quic.len();
    if pay > usize::from(u16::MAX) {
        return Err(Error::Config("QUIC packet too large"));
    }
    let mut salt = random_salt();
    salt[0] &= !FIXED_BIT;
    let mut cipher = Cipher::new(psk, &salt)?;

    let mut out = vec![0u8; SALT_LEN + SEALED_HEADER_LEN + pay + TAG_LEN];
    out[..SALT_LEN].copy_from_slice(&salt);
    let (hdr, rest) = out[SALT_LEN..].split_at_mut(SEALED_HEADER_LEN);
    put_header(hdr, 0, pay);
    let (h, tag) = hdr.split_at_mut(HEADER_LEN);
    cipher.seal(&[], h, tag);

    let (pt, tag) = rest.split_at_mut(pay);
    pt[..4].copy_from_slice(&[1, 1, 0, host_len]);
    pt[4..4 + host.len()].copy_from_slice(host.as_bytes());
    pt[4 + host.len()..6 + host.len()].copy_from_slice(&port.to_be_bytes());
    pt[6 + host.len()..].copy_from_slice(quic);
    cipher.seal(&[], pt, tag);
    Ok(out)
}

/// An unwrapped envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Target host (name or IP literal).
    pub host: String,
    /// Target port.
    pub port: u16,
    /// The QUIC packet to forward.
    pub quic: Vec<u8>,
}

/// Unwraps a Snell envelope.
pub fn decode_envelope(key: &Key, packet: &[u8]) -> Result<Envelope> {
    let psk = v5_psk(key)?;
    if packet.len() < SALT_LEN + SEALED_HEADER_LEN + TAG_LEN {
        return Err(Error::Frame("envelope too short"));
    }
    let salt: [u8; SALT_LEN] = packet[..SALT_LEN].try_into().expect("salt length");
    let mut cipher = Cipher::new(psk, &salt)?;
    let mut rest = packet[SALT_LEN..].to_vec();
    let n = cipher.open(&[], &mut rest[..SEALED_HEADER_LEN])?;
    let (pad, pay) = parse_header(&rest[..n])?;
    let start = SEALED_HEADER_LEN + pad;
    let end = start + pay + TAG_LEN;
    if end > rest.len() {
        return Err(Error::Frame("envelope payload truncated"));
    }
    let n = cipher.open(&[], &mut rest[start..end])?;
    parse_request(&rest[start..start + n])
}

fn parse_request(p: &[u8]) -> Result<Envelope> {
    if p.len() < 5 {
        return Err(Error::Request("envelope request too short"));
    }
    if p[0] != 1 {
        return Err(Error::Request("unsupported version"));
    }
    if p[1] == 0 {
        return Err(Error::Request("invalid command"));
    }
    let mut off = 3 + usize::from(p[2]);
    let host_len = usize::from(
        *p.get(off)
            .ok_or(Error::Request("client id overruns payload"))?,
    );
    off += 1;
    if off + host_len + 2 > p.len() {
        return Err(Error::Request("host overruns payload"));
    }
    let host = String::from_utf8_lossy(&p[off..off + host_len]).into_owned();
    let port = u16::from_be_bytes([p[off + host_len], p[off + host_len + 1]]);
    let quic = p[off + host_len + 2..].to_vec();
    if quic.is_empty() {
        return Err(Error::Request("QUIC packet missing"));
    }
    Ok(Envelope { host, port, quic })
}

/// The official QUIC proxy forwards to public addresses only: loopback,
/// private, link-local, unspecified, multicast and broadcast targets are
/// dropped.
pub fn target_blocked(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4 == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local unicast
        }
    }
}

struct Flow {
    host: String,
    port: u16,
    upstream: Arc<UdpSocket>,
    last: Arc<std::sync::Mutex<Instant>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serves QUIC proxy mode on `socket` until it fails. Targets are resolved
/// with `outbound`; flows idle for 5 minutes are dropped.
pub async fn serve<O: Outbound>(key: &Key, socket: UdpSocket, outbound: &O) -> io::Result<()> {
    v5_psk(key)?;
    let socket = Arc::new(socket);
    let flows: Arc<Mutex<HashMap<SocketAddr, Flow>>> = Arc::default();
    let mut buf = vec![0u8; MAX_PACKET];
    let mut reap = tokio::time::interval(FLOW_IDLE / 4);
    info!(addr = ?socket.local_addr(), "snell quic listening");
    loop {
        let (n, client) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            },
            _ = reap.tick() => {
                let now = Instant::now();
                flows.lock().await.retain(|_, f| now.duration_since(*f.last.lock().expect("flow clock")) < FLOW_IDLE);
                continue;
            }
        };
        let pkt = &buf[..n];
        let mut table = flows.lock().await;
        if pkt.first().is_some_and(|b| b & FIXED_BIT != 0) {
            // Raw QUIC for an existing flow; dropped without one.
            if let Some(f) = table.get(&client) {
                if f.upstream.send(pkt).await.is_err() {
                    table.remove(&client);
                } else {
                    *f.last.lock().expect("flow clock") = Instant::now();
                }
            }
            continue;
        }
        let env = match decode_envelope(key, pkt) {
            Ok(e) => e,
            Err(e) => {
                debug!(%client, error = %e, "quic envelope decode failed");
                continue;
            }
        };
        if let Some(f) = table.get(&client)
            && f.host == env.host
            && f.port == env.port
        {
            if f.upstream.send(&env.quic).await.is_err() {
                table.remove(&client);
            }
            continue;
        }
        drop(table);

        let info = ConnInfo {
            peer: Some(client),
            user: None,
        };
        let target = match outbound.resolve(&info, &env.host, env.port).await {
            Ok(t) if !target_blocked(t.ip()) => t,
            Ok(t) => {
                debug!(target = %t, "quic target not allowed");
                continue;
            }
            Err(e) => {
                debug!(host = env.host, error = %e, "quic upstream resolve failed");
                continue;
            }
        };
        let bind: SocketAddr = if target.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let upstream = match UdpSocket::bind(bind).await {
            Ok(u) if u.connect(target).await.is_ok() => Arc::new(u),
            _ => {
                debug!(%target, "quic upstream dial failed");
                continue;
            }
        };
        debug!(%client, %target, inner_size = env.quic.len(), "snell quic flow");
        if upstream.send(&env.quic).await.is_err() {
            continue;
        }
        let last = Arc::new(std::sync::Mutex::new(Instant::now()));
        let task = tokio::spawn(reverse(
            upstream.clone(),
            socket.clone(),
            client,
            last.clone(),
        ));
        flows.lock().await.insert(
            client,
            Flow {
                host: env.host,
                port: env.port,
                upstream,
                last,
                task,
            },
        );
    }
}

/// Relays upstream datagrams back to the client.
async fn reverse(
    upstream: Arc<UdpSocket>,
    listener: Arc<UdpSocket>,
    client: SocketAddr,
    last: Arc<std::sync::Mutex<Instant>>,
) {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let n = match tokio::time::timeout(FLOW_IDLE, upstream.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        if listener.send_to(&buf[..n], client).await.is_err() {
            return;
        }
        *last.lock().expect("flow clock") = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let key = Key::v5("quic-psk").unwrap();
        for _ in 0..32 {
            let env = encode_envelope(&key, "example.com", 443, &[0xc3; 1200]).unwrap();
            assert_eq!(env[0] & FIXED_BIT, 0);
            let got = decode_envelope(&key, &env).unwrap();
            assert_eq!(
                (got.host.as_str(), got.port, got.quic.len()),
                ("example.com", 443, 1200)
            );
        }
        let other = Key::v5("other").unwrap();
        let env = encode_envelope(&key, "a", 1, b"x").unwrap();
        assert!(decode_envelope(&other, &env).is_err());
        assert!(
            encode_envelope(
                &Key::v6("0123456789abcdef", crate::Mode::Default).unwrap(),
                "a",
                1,
                b"x"
            )
            .is_err()
        );
    }

    #[test]
    fn blocked_targets() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(target_blocked(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "100.64.0.1", "2606:4700::1111"] {
            assert!(!target_blocked(ip.parse().unwrap()), "{ip}");
        }
    }
}
