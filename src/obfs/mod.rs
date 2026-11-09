//! simple-obfs style HTTP and TLS wrappers used by Snell v4/v5 (`obfs = http`
//! / `obfs = tls`). v6 has built-in obfuscation and does not use them.

mod http;
mod tls;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use http::{HttpObfsClient, HttpObfsServer};
pub use tls::{TlsObfsClient, TlsObfsServer};

/// Client obfuscation settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Obfs {
    /// No obfuscation.
    #[default]
    None,
    /// HTTP Upgrade request/response.
    Http {
        /// Host name sent in the `Host` header.
        host: String,
        /// Port sent in the `Host` header (normally the server port).
        port: u16,
    },
    /// Fake TLS 1.2 handshake.
    Tls {
        /// Host name sent as SNI.
        host: String,
    },
}

/// Server obfuscation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObfsMode {
    /// No obfuscation.
    #[default]
    None,
    /// HTTP Upgrade request/response.
    Http,
    /// Fake TLS 1.2 handshake.
    Tls,
}

impl std::str::FromStr for ObfsMode {
    type Err = crate::Error;

    /// Accepts `off`/`none`/empty, `http` and `tls`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" => Ok(ObfsMode::None),
            "http" => Ok(ObfsMode::Http),
            "tls" => Ok(ObfsMode::Tls),
            _ => Err(crate::Error::Config(
                "unknown obfs mode (use off, http or tls)",
            )),
        }
    }
}

/// A transport, possibly wrapped in obfuscation.
#[derive(Debug)]
pub enum ObfsStream<S> {
    /// No obfuscation.
    Plain(S),
    /// HTTP obfuscation, client side.
    HttpClient(HttpObfsClient<S>),
    /// HTTP obfuscation, server side.
    HttpServer(HttpObfsServer<S>),
    /// TLS obfuscation, client side.
    TlsClient(TlsObfsClient<S>),
    /// TLS obfuscation, server side.
    TlsServer(TlsObfsServer<S>),
}

impl<S> ObfsStream<S> {
    /// Wraps a client transport.
    pub fn client(io: S, obfs: &Obfs) -> Self {
        match obfs {
            Obfs::None => ObfsStream::Plain(io),
            Obfs::Http { host, port } => {
                ObfsStream::HttpClient(HttpObfsClient::new(io, host, *port))
            }
            Obfs::Tls { host } => ObfsStream::TlsClient(TlsObfsClient::new(io, host)),
        }
    }

    /// Wraps a server transport.
    pub fn server(io: S, mode: ObfsMode) -> Self {
        match mode {
            ObfsMode::None => ObfsStream::Plain(io),
            ObfsMode::Http => ObfsStream::HttpServer(HttpObfsServer::new(io)),
            ObfsMode::Tls => ObfsStream::TlsServer(TlsObfsServer::new(io)),
        }
    }

    /// The underlying transport.
    pub fn get_ref(&self) -> &S {
        match self {
            ObfsStream::Plain(s) => s,
            ObfsStream::HttpClient(s) => &s.io,
            ObfsStream::HttpServer(s) => &s.io,
            ObfsStream::TlsClient(s) => &s.io,
            ObfsStream::TlsServer(s) => &s.io,
        }
    }

    /// The underlying transport. Reading or writing it directly corrupts the
    /// stream.
    pub fn get_mut(&mut self) -> &mut S {
        match self {
            ObfsStream::Plain(s) => s,
            ObfsStream::HttpClient(s) => &mut s.io,
            ObfsStream::HttpServer(s) => &mut s.io,
            ObfsStream::TlsClient(s) => &mut s.io,
            ObfsStream::TlsServer(s) => &mut s.io,
        }
    }
}

macro_rules! delegate {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            ObfsStream::Plain($s) => {
                let $s = Pin::new($s);
                $e
            }
            ObfsStream::HttpClient($s) => {
                let $s = Pin::new($s);
                $e
            }
            ObfsStream::HttpServer($s) => {
                let $s = Pin::new($s);
                $e
            }
            ObfsStream::TlsClient($s) => {
                let $s = Pin::new($s);
                $e
            }
            ObfsStream::TlsServer($s) => {
                let $s = Pin::new($s);
                $e
            }
        }
    };
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate!(self, s => s.poll_read(cx, buf))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        delegate!(self, s => s.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => s.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => s.poll_shutdown(cx))
    }
}

/// Bytes queued for the transport ahead of passthrough writes.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    buf: Vec<u8>,
    pos: usize,
}

impl Pending {
    pub(crate) fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub(crate) fn buf_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    pub(crate) fn poll_drain<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.pos < self.buf.len() {
            let n = ready!(Pin::new(&mut *io).poll_write(cx, &self.buf[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.buf.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

/// Base64 with `=` padding, standard or URL-safe alphabet.
pub(crate) fn base64(data: &[u8], url_safe: bool) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let table = if url_safe { URL } else { STD };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(table[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_rfc4648() {
        for (input, std, url) in [
            (&b""[..], "", ""),
            (b"f", "Zg==", "Zg=="),
            (b"fo", "Zm8=", "Zm8="),
            (b"foo", "Zm9v", "Zm9v"),
            (&[0xfb, 0xff, 0xbf], "+/+/", "-_-_"),
        ] {
            assert_eq!(super::base64(input, false), std);
            assert_eq!(super::base64(input, true), url);
        }
    }
}
