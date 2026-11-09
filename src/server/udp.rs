//! Server side of a UDP-over-TCP session.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::task::{Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use super::outbound::{ConnInfo, Outbound, PacketSocket};
use crate::codec::MAX_PAYLOAD;
use crate::protocol::{self, Address};
use crate::stream::{SnellReader, SnellStream, SnellWriter};

/// Longest encoded response source (`06 | 16-byte address | port`).
const MAX_RESPONSE_HEAD: usize = 1 + 16 + 2;

/// Per-session cache of resolved target names.
struct ResolveCache(HashMap<String, IpAddr>);

impl ResolveCache {
    const MAX: usize = 256;

    fn get(&self, host: &str) -> Option<IpAddr> {
        self.0.get(host).copied()
    }

    fn put(&mut self, host: &str, ip: IpAddr) {
        if self.0.len() >= Self::MAX
            && let Some(k) = self.0.keys().next().cloned()
        {
            self.0.remove(&k);
        }
        self.0.insert(host.to_owned(), ip);
    }
}

/// Relays datagrams until the client ends the session or a side fails.
pub(super) async fn relay<S, O>(
    stream: SnellStream<S>,
    socket: O::Udp,
    outbound: &O,
    info: &ConnInfo,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    O: Outbound,
{
    let (rd, wr) = stream.into_split();
    tokio::select! {
        r = client_to_targets(rd, &socket, outbound, info) => r,
        r = targets_to_client(wr, &socket, outbound.udp_sources_ipv6()) => r,
    }
}

async fn client_to_targets<R, O>(
    mut rd: SnellReader<R>,
    socket: &O::Udp,
    outbound: &O,
    info: &ConnInfo,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    O: Outbound,
{
    let mut pkt = Vec::with_capacity(MAX_PAYLOAD);
    let mut cache = ResolveCache(HashMap::new());
    loop {
        let more = poll_fn(|cx| {
            let frame = ready!(rd.r.poll_frame(&mut rd.io, cx))?;
            pkt.clear();
            pkt.extend_from_slice(frame);
            Poll::Ready(Ok::<_, io::Error>(!pkt.is_empty()))
        })
        .await?;
        if !more {
            return Ok(());
        }
        let req = protocol::parse_udp_request(&pkt)?;
        // No IP family policy applies to UDP: dns-ip-preference only steers
        // name resolution.
        let target = match &req.target {
            Address::Socket(a) => *a,
            Address::Domain(host, port) => match cache.get(host) {
                Some(ip) => SocketAddr::new(ip, *port),
                None => match outbound.resolve(info, host, *port).await {
                    Ok(a) => {
                        cache.put(host, a.ip());
                        a
                    }
                    Err(e) => {
                        debug!(target = %req.target, error = %e, "udp resolve failed");
                        continue;
                    }
                },
            },
        };
        debug!(%target, ipv6_type = req.ipv6_type, len = req.payload.len(), "snell udp forward");
        // A failed send drops this datagram; the session goes on.
        if let Err(e) = poll_fn(|cx| socket.poll_send_to(cx, req.payload, target)).await {
            debug!(%target, error = %e, "udp write to remote failed");
        }
    }
}

async fn targets_to_client<W, U>(
    mut wr: SnellWriter<W>,
    socket: &U,
    as_ipv6: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    U: PacketSocket,
{
    let mut buf = vec![0u8; MAX_PAYLOAD - MAX_RESPONSE_HEAD];
    let mut head = Vec::with_capacity(MAX_RESPONSE_HEAD);
    loop {
        let (src, n) = poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut buf);
            let src = ready!(socket.poll_recv_from(cx, &mut rb))?;
            Poll::Ready(Ok::<_, io::Error>((src, rb.filled().len())))
        })
        .await?;
        protocol::udp_response_head(src, as_ipv6, &mut head);
        poll_fn(|cx| wr.w.poll_write_packet(&mut wr.io, cx, &head, &buf[..n])).await?;
        poll_fn(|cx| wr.w.poll_flush(&mut wr.io, cx)).await?;
    }
}
