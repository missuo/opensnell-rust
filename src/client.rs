//! Snell client: TCP tunnels and UDP-over-TCP sessions over a transport the
//! caller has already connected to the server.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::key::Key;
use crate::obfs::{Obfs, ObfsStream};
use crate::protocol::{self, Address};
use crate::stream::{ReadState, SnellStream, WriteState};

/// A client stream: a [`SnellStream`] over a possibly obfuscated transport.
pub type ClientStream<S> = SnellStream<ObfsStream<S>>;

type ReadHalf<S> = tokio::io::ReadHalf<ObfsStream<S>>;
type WriteHalf<S> = tokio::io::WriteHalf<ObfsStream<S>>;

/// Client settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Key, version and mode.
    pub key: Key,
    /// Obfuscation (v4/v5 only).
    pub obfs: Obfs,
    /// Ask the server to keep the connection for further sessions (see
    /// [`crate::Pool`]).
    pub reuse: bool,
}

impl ClientConfig {
    /// A configuration without obfuscation or reuse.
    pub fn new(key: Key) -> Self {
        Self {
            key,
            obfs: Obfs::None,
            reuse: false,
        }
    }
}

/// A Snell client. Cheap to clone.
///
/// The client does not dial: pass it a transport already connected to the
/// server (a `TcpStream`, or anything implementing `AsyncRead + AsyncWrite`).
///
/// ```no_run
/// # async fn demo() -> std::io::Result<()> {
/// use opensnell::{Client, ClientConfig, Key, Mode};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// let key = Key::v6("my-pre-shared-key", Mode::Default)?;
/// let client = Client::new(ClientConfig::new(key))?;
/// let tcp = tokio::net::TcpStream::connect("203.0.113.1:6160").await?;
/// let mut stream = client.connect(tcp, "example.com", 80).await?;
/// stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
/// let mut reply = Vec::new();
/// stream.read_to_end(&mut reply).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    cfg: ClientConfig,
}

impl Client {
    /// Builds a client. Obfuscation is rejected on v6, which obfuscates by
    /// itself.
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        if cfg.key.version().is_v6() && cfg.obfs != Obfs::None {
            return Err(Error::Config(
                "obfs is a v4/v5 option; v6 has built-in obfuscation",
            ));
        }
        Ok(Self { cfg })
    }

    /// The client's key.
    pub fn key(&self) -> &Key {
        &self.cfg.key
    }

    /// The client's settings.
    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    fn wrap<S>(&self, io: S) -> Result<ClientStream<S>> {
        SnellStream::new_client(ObfsStream::client(io, &self.cfg.obfs), &self.cfg.key)
    }

    /// Opens a TCP tunnel to `host:port` over `io`, a transport connected to
    /// the server. The request is sent before this returns; the server's
    /// answer is checked on the first read, which fails with
    /// [`Error::Server`] if the server refused.
    pub async fn connect<S>(&self, io: S, host: &str, port: u16) -> io::Result<ClientStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut stream = self.wrap(io)?;
        self.request(&mut stream, host, port).await?;
        Ok(stream)
    }

    /// Opens a new session on a stream whose previous session ended cleanly
    /// (see [`crate::Pool`]).
    pub async fn reconnect<S>(
        &self,
        mut stream: ClientStream<S>,
        host: &str,
        port: u16,
    ) -> io::Result<ClientStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.request(&mut stream, host, port).await?;
        Ok(stream)
    }

    async fn request<S>(
        &self,
        stream: &mut ClientStream<S>,
        host: &str,
        port: u16,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // The official v6 client (Surge) always sends the reuse-capable
        // command; v4/v5 only with reuse on.
        let v2 = self.cfg.reuse || self.cfg.key.version().is_v6();
        let req = protocol::connect_request(host, port, v2)?;
        stream.begin_session();
        stream.write_all_batch(&req).await?;
        stream.flush_all().await
    }

    /// Starts a UDP-over-TCP session over `io`. Like Surge, the session
    /// request is sent together with the first datagram and the server's
    /// answer is read with the first reply, so nothing goes out until the
    /// first [`UdpSession::send_to`].
    ///
    /// The official v5 server drops datagrams that arrive together with the
    /// session request, so against v4/v5 servers the first datagram is lost,
    /// exactly as with Surge. UDP applications retransmit; v6 servers keep it.
    pub fn udp<S>(&self, io: S) -> io::Result<UdpSession<S>> {
        let mut stream = self.wrap(io)?;
        stream.begin_session();
        Ok(UdpSession {
            io: stream.io,
            recv: UdpRecvState { r: stream.r },
            send: UdpSendState::new(stream.w),
        })
    }
}

/// A UDP-over-TCP session: each datagram travels as one Snell frame.
#[derive(Debug)]
pub struct UdpSession<S> {
    io: ObfsStream<S>,
    recv: UdpRecvState,
    send: UdpSendState,
}

impl<S: AsyncRead + AsyncWrite + Unpin> UdpSession<S> {
    /// Sends `payload` to `target`. Domain targets are resolved by the server.
    pub async fn send_to(&mut self, payload: &[u8], target: &Address) -> io::Result<()> {
        self.send.send_to(&mut self.io, payload, target).await
    }

    /// Receives one datagram into `buf` (truncated if `buf` is too small) and
    /// returns its length and source.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.recv.poll_recv_from(&mut self.io, cx, buf)).await
    }

    /// Splits the session with [`tokio::io::split`], so sending and receiving
    /// can run on different tasks. Prefer [`UdpSession::map_split`] when the
    /// transport has its own split.
    pub fn into_split(self) -> (UdpReceiver<ReadHalf<S>>, UdpSender<WriteHalf<S>>) {
        self.map_split(tokio::io::split)
    }
}

impl<S> UdpSession<S> {
    /// Splits the session with `split`.
    pub fn map_split<R, W>(
        self,
        split: impl FnOnce(ObfsStream<S>) -> (R, W),
    ) -> (UdpReceiver<R>, UdpSender<W>) {
        let (r, w) = split(self.io);
        (
            UdpReceiver {
                io: r,
                recv: self.recv,
            },
            UdpSender {
                io: w,
                send: self.send,
            },
        )
    }
}

#[derive(Debug)]
struct UdpRecvState {
    r: ReadState,
}

impl UdpRecvState {
    fn poll_recv_from<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let frame = ready!(self.r.poll_frame(io, cx))?;
        if frame.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        let (src, payload) = protocol::parse_udp_response(frame)?;
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Poll::Ready(Ok((n, src)))
    }
}

#[derive(Debug)]
struct UdpSendState {
    w: WriteState,
    requested: bool,
    head: Vec<u8>,
}

impl UdpSendState {
    fn new(w: WriteState) -> Self {
        Self {
            w,
            requested: false,
            head: Vec::with_capacity(1 + 2 + 255 + 2),
        }
    }

    /// Queues one datagram once the previous output is written. `Ready(Ok)`
    /// means the datagram was accepted; it is on the wire after a flush.
    fn poll_send_to<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        payload: &[u8],
        target: &Address,
    ) -> Poll<io::Result<()>> {
        ready!(self.w.poll_drain(io, cx))?;
        protocol::udp_request_head(target, &mut self.head)?;
        if payload.len() > protocol::udp_max_payload(&self.head) {
            return Poll::Ready(Err(Error::Config("UDP payload too large").into()));
        }
        if !self.requested {
            // The session request and the first datagram leave together.
            self.w.queue(&protocol::UDP_REQUEST)?;
            self.requested = true;
        }
        self.w.queue_packet(&self.head, payload)?;
        if let Poll::Ready(Err(e)) = self.w.poll_drain(io, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(()))
    }

    async fn send_to<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        payload: &[u8],
        target: &Address,
    ) -> io::Result<()> {
        poll_fn(|cx| self.poll_send_to(io, cx, payload, target)).await?;
        poll_fn(|cx| self.w.poll_flush(io, cx)).await
    }
}

/// Receiving half of a [`UdpSession`].
#[derive(Debug)]
pub struct UdpReceiver<R> {
    io: R,
    recv: UdpRecvState,
}

impl<R: AsyncRead + Unpin> UdpReceiver<R> {
    /// See [`UdpSession::recv_from`].
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.recv.poll_recv_from(&mut self.io, cx, buf)).await
    }

    /// Poll form of [`UdpReceiver::recv_from`].
    pub fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.recv.poll_recv_from(&mut self.io, cx, buf)
    }
}

/// Sending half of a [`UdpSession`].
#[derive(Debug)]
pub struct UdpSender<W> {
    io: W,
    send: UdpSendState,
}

impl<W: AsyncWrite + Unpin> UdpSender<W> {
    /// See [`UdpSession::send_to`].
    pub async fn send_to(&mut self, payload: &[u8], target: &Address) -> io::Result<()> {
        self.send.send_to(&mut self.io, payload, target).await
    }

    /// Poll form of [`UdpSender::send_to`]: `Ready(Ok)` means the datagram
    /// was queued; [`UdpSender::poll_flush`] puts it on the wire.
    pub fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
        target: &Address,
    ) -> Poll<io::Result<()>> {
        self.send.poll_send_to(&mut self.io, cx, payload, target)
    }

    /// Writes out queued datagrams.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.w.poll_flush(&mut self.io, cx)
    }
}
