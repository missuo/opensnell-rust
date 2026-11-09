//! Snell server.
//!
//! [`Server::serve`] accepts on a listener; [`Server::serve_connection`]
//! serves one connection the caller accepted. Upstream traffic goes through an
//! [`Outbound`] ([`Direct`] by default).

mod outbound;
mod relay;
mod udp;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, warn};

pub use outbound::{ConnInfo, Direct, DnsError, IpPreference, Outbound, PacketSocket};

use crate::codec::Decoder;
use crate::error::{Error, Result};
use crate::key::{Key, Mode, V6_PREFIX_LEN};
use crate::obfs::{ObfsMode, ObfsStream};
use crate::protocol::{self, RESP_PONG, Request};
use crate::stream::{Eof, SnellStream};

/// Error codes the server reports to clients (the official server's).
pub mod code {
    /// Generic failure, a disabled address family, or UDP disabled.
    pub const GENERIC: u8 = 1;
    /// The upstream reset the connection.
    pub const RESET: u8 = 4;
    /// Connecting to the upstream timed out.
    pub const TIMEOUT: u8 = 5;
    /// The upstream refused the connection.
    pub const REFUSED: u8 = 6;
    /// The target name did not resolve.
    pub const DNS_FAILED: u8 = 100;
    /// The upstream closed before sending anything (reuse session).
    pub const REMOTE_EOF: u8 = 101;
    /// The upstream closed before sending anything.
    pub const EOF: u8 = 255;
}

/// Picks the key of a new default-mode v6 connection from its first
/// [`V6_PREFIX_LEN`] bytes, letting one listener serve many PSKs. Only the
/// matching key's Argon2 runs, so unknown traffic costs no key derivation.
///
/// [`Key::match_prefix`] (or an index built from [`Key::prefix_template`])
/// does the matching. Called on every new connection: keep it fast.
pub trait Identifier: Send + Sync + 'static {
    /// Returns the key and a user label for `prefix`, or `None`.
    fn identify(&self, prefix: &[u8]) -> Option<(Key, Arc<str>)>;
}

/// A fixed table of keys, matched linearly.
impl Identifier for Vec<(Key, Arc<str>)> {
    fn identify(&self, prefix: &[u8]) -> Option<(Key, Arc<str>)> {
        self.iter().find(|(k, _)| k.match_prefix(prefix)).cloned()
    }
}

/// The key(s) a server accepts.
#[derive(Clone)]
pub enum Keys {
    /// One key.
    Single(Key),
    /// Many default-mode v6 keys, picked per connection. A connection that
    /// matches no key is handled exactly like one with a wrong PSK on a
    /// single-key server, using `decoy` (any default-mode v6 key; a random one
    /// is a good choice), so probes cannot tell the two apart.
    Identify {
        /// Picks the key.
        identifier: Arc<dyn Identifier>,
        /// Key unidentified connections are run against.
        decoy: Key,
    },
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keys::Single(k) => f.debug_tuple("Single").field(k).finish(),
            Keys::Identify { .. } => f.write_str("Identify"),
        }
    }
}

/// Server settings.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Accepted key(s). They also fix the version and mode.
    pub keys: Keys,
    /// Obfuscation (v4/v5 only).
    pub obfs: ObfsMode,
    /// Accept UDP-over-TCP sessions.
    pub udp: bool,
    /// Address family policy for targets. IP literal targets of a disabled
    /// family are refused; [`Direct`] also follows it when resolving.
    pub ip_preference: IpPreference,
    /// A connection must complete its first request within this time.
    pub handshake_timeout: Duration,
    /// How long a reuse connection may idle between sessions.
    pub reuse_idle_timeout: Duration,
}

impl ServerConfig {
    /// Settings matching the official server for `key`'s version: UDP on,
    /// a 10 s handshake timeout, 180 s reuse idle timeout, and the default IP
    /// policy of that version (v5: IPv4 only, v6: first result).
    pub fn new(key: Key) -> Self {
        let ip_preference = if key.version().is_v6() {
            IpPreference::Default
        } else {
            IpPreference::Ipv4Only
        };
        Self {
            keys: Keys::Single(key),
            obfs: ObfsMode::None,
            udp: true,
            ip_preference,
            handshake_timeout: Duration::from_secs(10),
            reuse_idle_timeout: Duration::from_secs(180),
        }
    }

    /// Settings for serving many default-mode v6 keys (see [`Keys::Identify`]).
    pub fn identify(identifier: Arc<dyn Identifier>, decoy: Key) -> Self {
        Self {
            keys: Keys::Identify { identifier, decoy },
            obfs: ObfsMode::None,
            udp: true,
            ip_preference: IpPreference::Default,
            handshake_timeout: Duration::from_secs(10),
            reuse_idle_timeout: Duration::from_secs(180),
        }
    }

    /// A random default-mode v6 key, for use as [`Keys::Identify`]'s decoy.
    pub fn random_decoy() -> Key {
        Key::v6(random_psk(), Mode::Default).expect("random v6 psk is valid")
    }

    fn primary_key(&self) -> &Key {
        match &self.keys {
            Keys::Single(k) => k,
            Keys::Identify { decoy, .. } => decoy,
        }
    }
}

fn random_psk() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut b = [0u8; 32];
    crate::crypto::random_bytes(&mut b);
    b.iter()
        .map(|&x| char::from(ALPHABET[usize::from(x) % ALPHABET.len()]))
        .collect()
}

struct Inner<O> {
    cfg: ServerConfig,
    outbound: O,
    v6: bool,
}

/// A Snell server. Cheap to clone.
pub struct Server<O = Direct> {
    inner: Arc<Inner<O>>,
}

impl<O> Clone for Server<O> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Server<Direct> {
    /// A server that dials targets directly, following `cfg.ip_preference`
    /// and the official keepalive policy (v5 upstreams get keepalive, v6 ones
    /// do not).
    pub fn new(cfg: ServerConfig) -> Result<Self> {
        let direct = Direct {
            ip_preference: cfg.ip_preference,
            connect_timeout: None,
            keepalive: (!cfg.primary_key().version().is_v6()).then_some(Duration::from_secs(15)),
        };
        Self::with_outbound(cfg, direct)
    }
}

impl<O: Outbound> Server<O> {
    /// A server that reaches targets through `outbound`.
    pub fn with_outbound(cfg: ServerConfig, outbound: O) -> Result<Self> {
        let key = cfg.primary_key();
        let v6 = key.version().is_v6();
        if v6 && cfg.obfs != ObfsMode::None {
            return Err(Error::Config(
                "obfs is a v4/v5 option; v6 has built-in obfuscation",
            ));
        }
        if matches!(cfg.keys, Keys::Identify { .. }) && key.region_len().is_none() {
            return Err(Error::Config(
                "identifying keys requires default-mode v6 keys",
            ));
        }
        Ok(Self {
            inner: Arc::new(Inner { cfg, outbound, v6 }),
        })
    }

    /// The settings.
    pub fn config(&self) -> &ServerConfig {
        &self.inner.cfg
    }

    /// Accepts connections on `listener` and serves each on its own task,
    /// until accepting fails.
    pub async fn serve(&self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) if is_out_of_descriptors(&e) => {
                    // Back off instead of spinning until descriptors free up.
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) if is_transient_accept_error(&e) => {
                    debug!(error = %e, "accept failed");
                    continue;
                }
                Err(e) => return Err(e),
            };
            if let Err(e) = self.tune_accepted(&tcp) {
                debug!(%peer, error = %e, "setting socket options failed");
            }
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.serve_connection(tcp, Some(peer)).await {
                    debug!(%peer, error = %e, "connection ended");
                }
            });
        }
    }

    /// TCP options the official server sets on client connections: no Nagle,
    /// and keepalive (v6: libuv's 60 s idle, 1 s interval, 10 probes).
    fn tune_accepted(&self, tcp: &TcpStream) -> io::Result<()> {
        tcp.set_nodelay(true)?;
        if self.inner.v6 {
            crate::sys::set_keepalive(
                tcp,
                Duration::from_secs(60),
                Duration::from_secs(1),
                Some(10),
            )
        } else {
            crate::sys::set_keepalive(tcp, Duration::from_secs(15), Duration::from_secs(15), None)
        }
    }

    /// Serves Snell v5 QUIC proxy mode on `socket` (normally bound to the TCP
    /// listen address), resolving targets with the outbound. See
    /// [`crate::quic`].
    pub async fn serve_quic(&self, socket: UdpSocket) -> io::Result<()> {
        crate::quic::serve(self.inner.cfg.primary_key(), socket, &self.inner.outbound).await
    }

    /// Serves one connection until it ends.
    pub async fn serve_connection<S>(&self, io: S, peer: Option<SocketAddr>) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let cfg = &self.inner.cfg;
        let io = ObfsStream::server(io, cfg.obfs);
        let mut info = ConnInfo { peer, user: None };
        // One deadline covers key identification and the first request.
        let mut deadline = Instant::now() + cfg.handshake_timeout;
        let Some(mut stream) = self.open(io, &mut info, deadline).await? else {
            return Ok(());
        };
        let mut buf = Vec::new();
        loop {
            stream.begin_session();
            let request =
                match tokio::time::timeout_at(deadline, self.read_request(&mut stream, &mut buf))
                    .await
                {
                    Ok(Ok(Some(r))) => r,
                    Ok(Ok(None)) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        debug!(?peer, "handshake timed out");
                        return Ok(());
                    }
                };
            let reuse = match request {
                (Request::Ping, _) => {
                    stream.write_all_batch(&[RESP_PONG]).await?;
                    stream.flush_all().await?;
                    false
                }
                (Request::Connect { host, port, reuse }, held) => {
                    self.handle_tcp(&mut stream, &info, &host, port, reuse, held)
                        .await?
                }
                (Request::Udp, _) if !cfg.udp => {
                    send_error(&mut stream, code::GENERIC, "UDP disabled").await?;
                    false
                }
                (Request::Udp, _) => return self.handle_udp(stream, &info).await,
            };
            if !reuse {
                return Ok(());
            }
            deadline = Instant::now() + cfg.reuse_idle_timeout;
        }
    }

    /// Builds the stream, identifying the key first when serving many.
    async fn open<S>(
        &self,
        mut io: ObfsStream<S>,
        info: &mut ConnInfo,
        deadline: Instant,
    ) -> io::Result<Option<SnellStream<ObfsStream<S>>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let cfg = &self.inner.cfg;
        let (identifier, decoy) = match &cfg.keys {
            Keys::Single(key) => {
                return Ok(Some(SnellStream::new_server(
                    io,
                    key,
                    Decoder::new(key),
                    &[],
                )?));
            }
            Keys::Identify { identifier, decoy } => (identifier, decoy),
        };
        let identified = tokio::time::timeout_at(deadline, async {
            let mut region = vec![0u8; V6_PREFIX_LEN];
            let n = read_full(&mut io, &mut region).await?;
            if n < V6_PREFIX_LEN {
                region.truncate(n);
                return Ok::<_, io::Error>(Err(region));
            }
            let Some((key, user)) = identifier.identify(&region) else {
                return Ok(Err(region));
            };
            // Only default-mode v6 keys carry a salt region to identify by.
            let Some(region_len) = key.region_len() else {
                return Ok(Err(region));
            };
            region.resize(region_len, 0);
            let n = read_full(&mut io, &mut region[V6_PREFIX_LEN..]).await?;
            if n < region_len - V6_PREFIX_LEN || !key.match_region(&region) {
                region.truncate(V6_PREFIX_LEN + n);
                return Ok(Err(region));
            }
            Ok(Ok((key, user, region)))
        })
        .await;
        match identified {
            Ok(Ok(Ok((key, user, region)))) => {
                info.user = Some(user);
                Ok(Some(SnellStream::new_server(
                    io,
                    &key,
                    Decoder::v6_with_region(&key, &region)?,
                    &[],
                )?))
            }
            Ok(Ok(Err(consumed))) => {
                // Fail the way a single-key server fails a wrong PSK: the decoy
                // reads the first frame, it does not authenticate, and the
                // connection closes.
                let mut stream =
                    SnellStream::new_server(io, decoy, Decoder::new(decoy), &consumed)?;
                let mut buf = Vec::new();
                let read = self.read_request(&mut stream, &mut buf);
                let _ = tokio::time::timeout_at(deadline, read).await;
                debug!(peer = ?info.peer, "v6 connection not identified");
                Ok(None)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    /// Reads one request. Returns it with the client data that came with it,
    /// or `None` when the client closed or sent an invalid v6 request.
    async fn read_request<S>(
        &self,
        stream: &mut SnellStream<S>,
        buf: &mut Vec<u8>,
    ) -> io::Result<Option<(Request, Vec<u8>)>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        buf.clear();
        let mut frame = Vec::new();
        if !stream.read_frame(&mut frame).await? {
            return Ok(None);
        }
        if self.inner.v6 {
            // The official v6 server parses the request header out of the
            // single frame that starts the session and closes on a frame too
            // short for it.
            let Some(pad) = protocol::v6_request_check(&frame) else {
                debug!("invalid request");
                return Ok(None);
            };
            frame.resize(frame.len() + pad, 0);
        }
        buf.extend_from_slice(&frame);
        loop {
            if let Some((req, n)) = protocol::parse_request(buf)? {
                return Ok(Some((req, buf.split_off(n))));
            }
            if !stream.read_frame(&mut frame).await? {
                return Ok(None);
            }
            buf.extend_from_slice(&frame);
        }
    }

    /// Serves one CONNECT session. Returns whether the connection carries
    /// another session.
    async fn handle_tcp<S>(
        &self,
        stream: &mut SnellStream<S>,
        info: &ConnInfo,
        host: &str,
        port: u16,
        reuse: bool,
        mut held: Vec<u8>,
    ) -> io::Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let v6 = self.inner.v6;
        debug!(peer = ?info.peer, user = info.user.as_deref(), target = %format_target(host, port), reuse, "snell tcp");

        if let Ok(ip) = host.parse::<IpAddr>()
            && !self.inner.cfg.ip_preference.allows(ip)
        {
            let family = if ip.to_canonical().is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            };
            debug!(target = %format_target(host, port), family, "target rejected: IP family disabled by server configuration");
            // v5.0.1 answers a disabled family with DNS Failed.
            let (code, msg) = if v6 {
                (
                    code::GENERIC,
                    format!("{family} target is disabled by server configuration"),
                )
            } else {
                (code::DNS_FAILED, "DNS Failed".to_owned())
            };
            send_error(stream, code, &msg).await?;
            return Ok(false);
        }

        // Client data that arrived with the request goes to the upstream the
        // moment it connects, before the upstream is read.
        while stream.r.eof() == Eof::No && stream.r.has_buffered()? {
            let frame = stream.r.frame();
            held.extend_from_slice(frame);
            let n = frame.len();
            stream.r.consume(n);
        }

        let mut upstream = match self.inner.outbound.connect(info, host, port).await {
            Ok(u) => u,
            Err(e) => {
                let (code, msg) = classify(&e);
                debug!(target = %format_target(host, port), code, error = %e, "upstream dial failed");
                send_error(stream, code, msg).await?;
                return Ok(false);
            }
        };
        if !held.is_empty() {
            // A failed write shows up as an upstream error in the relay.
            let _ = upstream.write_all(&held).await;
        }

        let (replied, error) = match relay::relay(stream, &mut upstream, v6).await {
            relay::Outcome::ClientClosed => return Ok(false),
            relay::Outcome::Done { replied, error } => (replied, error),
        };
        drop(upstream);

        if !replied {
            // The upstream accepted, then closed or reset before sending a byte.
            let (code, msg) = match &error {
                Some(e) => classify(e),
                None if reuse => (code::REMOTE_EOF, "Remote EOF"),
                None => (code::EOF, "end of file"),
            };
            debug!(target = %format_target(host, port), code, "upstream closed before sending data");
            send_error(stream, code, msg).await?;
            return Ok(false);
        }
        if !reuse {
            return Ok(false);
        }
        // End the session with our zero chunk, then wait for the client's
        // (deliberately without a deadline, like the official server).
        std::future::poll_fn(|cx| stream.w.poll_close_session(&mut stream.io, cx)).await?;
        while stream.r.eof() == Eof::No {
            let mut scratch = [0u8; 4096];
            if stream.read(&mut scratch).await? == 0 && stream.r.eof() != Eof::ZeroChunk {
                return Ok(false);
            }
        }
        Ok(stream.r.eof() == Eof::ZeroChunk)
    }

    async fn handle_udp<S>(&self, mut stream: SnellStream<S>, info: &ConnInfo) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        debug!(peer = ?info.peer, user = info.user.as_deref(), "snell udp session start");
        stream.write_all_batch(&[protocol::RESP_TUNNEL]).await?;
        stream.flush_all().await?;
        let socket = match self.inner.outbound.bind_udp(info).await {
            Ok(s) => s,
            Err(e) => {
                let code = e.raw_os_error().map_or(0, |c| c as u8);
                return send_error(&mut stream, code, &e.to_string()).await;
            }
        };
        if !self.inner.v6 {
            // snell-server v5.0.1 drops every datagram that arrived together
            // with the session request.
            while stream.r.eof() == Eof::No && stream.r.has_buffered()? {
                let n = stream.r.frame().len();
                stream.r.consume(n);
            }
            if stream.r.eof() != Eof::No {
                return Ok(());
            }
        }
        udp::relay(stream, socket, &self.inner.outbound, info).await
    }
}

/// Reads until `buf` is full or EOF; returns the bytes read.
async fn read_full<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]).await? {
            0 => break,
            m => n += m,
        }
    }
    Ok(n)
}

async fn send_error<S>(stream: &mut SnellStream<S>, code: u8, msg: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all_batch(&protocol::error_response(code, msg))
        .await?;
    stream.flush_all().await
}

/// The official server's code and message for an upstream error.
fn classify(e: &io::Error) -> (u8, &'static str) {
    if e.get_ref().is_some_and(|inner| inner.is::<DnsError>()) {
        return (code::DNS_FAILED, "DNS Failed");
    }
    match e.kind() {
        io::ErrorKind::ConnectionRefused => (code::REFUSED, "connection refused"),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => {
            (code::RESET, "connection reset by peer")
        }
        io::ErrorKind::TimedOut => (code::TIMEOUT, "connection timed out"),
        _ => (code::GENERIC, "connection failed"),
    }
}

fn format_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn is_transient_accept_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    )
}

/// EMFILE / ENFILE.
fn is_out_of_descriptors(e: &io::Error) -> bool {
    e.raw_os_error().is_some_and(|c| c == 23 || c == 24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_errors() {
        assert_eq!(classify(&DnsError::io("x")).0, code::DNS_FAILED);
        assert_eq!(
            classify(&io::ErrorKind::ConnectionRefused.into()).0,
            code::REFUSED
        );
        assert_eq!(
            classify(&io::ErrorKind::ConnectionReset.into()).0,
            code::RESET
        );
        assert_eq!(classify(&io::ErrorKind::TimedOut.into()).0, code::TIMEOUT);
        assert_eq!(classify(&io::ErrorKind::Other.into()).0, code::GENERIC);
    }

    #[test]
    fn config_validation() {
        let v6 = Key::v6("0123456789abcdef", Mode::Default).unwrap();
        let mut cfg = ServerConfig::new(v6.clone());
        cfg.obfs = ObfsMode::Http;
        assert!(Server::new(cfg).is_err());
        let ids: Arc<dyn Identifier> = Arc::new(vec![(v6, Arc::<str>::from("u"))]);
        let unshaped = Key::v6("0123456789abcdef", Mode::Unshaped).unwrap();
        assert!(Server::new(ServerConfig::identify(ids.clone(), unshaped)).is_err());
        assert!(Server::new(ServerConfig::identify(ids, ServerConfig::random_decoy())).is_ok());
        assert_eq!(
            ServerConfig::new(Key::v5("p").unwrap()).ip_preference,
            IpPreference::Ipv4Only
        );
    }
}
