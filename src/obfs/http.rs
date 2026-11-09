//! HTTP obfuscation: the first client write rides in the body of a fake
//! WebSocket upgrade request, the first server write follows a
//! `101 Switching Protocols` response. Everything after the headers is the
//! raw stream.

use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Pending, base64};

/// Upper bound on an HTTP head before the stream is rejected.
const MAX_HEAD: usize = 16 * 1024;

/// Reads an HTTP head off the transport, then passes the stream through.
#[derive(Debug)]
struct HeadReader {
    /// Bytes read so far; after the head is parsed, the stream bytes that
    /// followed it.
    buf: BytesMut,
    parsed: bool,
}

impl HeadReader {
    fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            parsed: false,
        }
    }

    /// Reads into `out`, first parsing the head with `check` (which returns
    /// `false` to end the stream).
    fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        io: &mut S,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        check: impl Fn(&str) -> io::Result<bool>,
    ) -> Poll<io::Result<()>> {
        while !self.parsed {
            if let Some(end) = find_head_end(&self.buf) {
                let head = std::str::from_utf8(&self.buf[..end])
                    .map_err(|_| invalid("non UTF-8 HTTP head"))?;
                if !check(head)? {
                    return Poll::Ready(Ok(()));
                }
                self.buf.advance(end);
                self.parsed = true;
                break;
            }
            if self.buf.len() > MAX_HEAD {
                return Poll::Ready(Err(invalid("HTTP head too large")));
            }
            self.buf.reserve(4096);
            if ready!(tokio_util::io::poll_read_buf(
                Pin::new(&mut *io),
                cx,
                &mut self.buf
            ))? == 0
            {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
        if !self.buf.is_empty() {
            let n = self.buf.len().min(out.remaining());
            out.put_slice(&self.buf[..n]);
            self.buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(io).poll_read(cx, out)
    }
}

/// Length of the head including the blank line, if complete.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Value of the first header named `name` (case-insensitive).
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// HTTP obfuscation, client side.
#[derive(Debug)]
pub struct HttpObfsClient<S> {
    pub(crate) io: S,
    host: String,
    sent_request: bool,
    pending: Pending,
    reader: HeadReader,
}

impl<S> HttpObfsClient<S> {
    /// Wraps `io`; `host:port` goes into the `Host` header.
    pub fn new(io: S, host: &str, port: u16) -> Self {
        Self {
            io,
            host: format!("{host}:{port}"),
            sent_request: false,
            pending: Pending::default(),
            reader: HeadReader::new(),
        }
    }

    /// The request as Go's `http.Request.Write` lays it out.
    fn request(&self, body: &[u8], out: &mut Vec<u8>) {
        let mut rng = rand::rng();
        let mut key = [0u8; 16];
        crate::crypto::random_bytes(&mut key);
        let mut head = String::with_capacity(256);
        let _ = write!(
            head,
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.{}.{}\r\n",
            self.host,
            rng.random_range(0..54),
            rng.random_range(0..2)
        );
        if !body.is_empty() {
            let _ = write!(head, "Content-Length: {}\r\n", body.len());
        }
        let _ = write!(
            head,
            "Connection: Upgrade\r\nSec-Websocket-Key: {}\r\nUpgrade: websocket\r\n\r\n",
            base64(&key, true)
        );
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(body);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpObfsClient<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reader.poll_read(&mut this.io, cx, buf, |head| {
            let status = head.split(' ').nth(1).unwrap_or_default();
            if status != "101" {
                return Err(invalid("unexpected HTTP obfs response status"));
            }
            Ok(true)
        })
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfsClient<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.pending.poll_drain(&mut this.io, cx))?;
        if this.sent_request {
            return Pin::new(&mut this.io).poll_write(cx, buf);
        }
        let mut req = std::mem::take(this.pending.buf_mut());
        this.request(buf, &mut req);
        *this.pending.buf_mut() = req;
        this.sent_request = true;
        if let Poll::Ready(Err(e)) = this.pending.poll_drain(&mut this.io, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.pending.poll_drain(&mut this.io, cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.pending.poll_drain(&mut this.io, cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// HTTP obfuscation, server side.
#[derive(Debug)]
pub struct HttpObfsServer<S> {
    pub(crate) io: S,
    sent_response: bool,
    pending: Pending,
    reader: HeadReader,
}

impl<S> HttpObfsServer<S> {
    /// Wraps `io`.
    pub fn new(io: S) -> Self {
        Self {
            io,
            sent_response: false,
            pending: Pending::default(),
            reader: HeadReader::new(),
        }
    }
}

/// `101 Switching Protocols` as the official server sends it.
fn response(out: &mut Vec<u8>) {
    let mut rng = rand::rng();
    let mut accept = [0u8; 16];
    crate::crypto::random_bytes(&mut accept);
    let mut head = String::with_capacity(256);
    let _ = write!(
        head,
        "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.{}.{}\r\nDate: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        rng.random_range(0..11),
        rng.random_range(0..12),
        http_date(SystemTime::now()),
        base64(&accept, false)
    );
    out.extend_from_slice(head.as_bytes());
}

/// RFC 1123 date in GMT ("Sat, 07 Nov 2026 07:52:23 GMT").
fn http_date(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpObfsServer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Not a GET upgrade request: the official server treats the
        // connection as ended.
        this.reader.poll_read(&mut this.io, cx, buf, |head| {
            Ok(head.starts_with("GET ") && header(head, "Connection") == Some("Upgrade"))
        })
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfsServer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.pending.poll_drain(&mut this.io, cx))?;
        if this.sent_response {
            return Pin::new(&mut this.io).poll_write(cx, buf);
        }
        response(this.pending.buf_mut());
        this.pending.push(buf);
        this.sent_response = true;
        if let Poll::Ready(Err(e)) = this.pending.poll_drain(&mut this.io, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.pending.poll_drain(&mut this.io, cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.pending.poll_drain(&mut this.io, cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn date_format() {
        let t = UNIX_EPOCH + Duration::from_secs(1_794_037_943); // 2026-11-07 07:52:23 UTC
        assert_eq!(http_date(t), "Sat, 07 Nov 2026 07:52:23 GMT");
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn header_lookup() {
        let head = "GET / HTTP/1.1\r\nHost: a:1\r\nconnection: Upgrade\r\n\r\n";
        assert_eq!(header(head, "Connection"), Some("Upgrade"));
        assert_eq!(header(head, "Upgrade"), None);
    }
}
