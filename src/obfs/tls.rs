//! TLS obfuscation: the first client write rides in the session-ticket
//! extension of a fake ClientHello, the first server write follows a fake
//! ServerHello; later writes are framed as TLS application-data records.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Pending;

/// Largest payload per record.
const CHUNK: usize = 16 * 1024;
/// Bytes before the first payload length in the server's reply: ServerHello
/// record (96), ChangeCipherSpec (6) and the handshake record type+version (3).
const SERVER_HELLO_SKIP: usize = 105;
/// Bytes before the session-ticket length in the client's ClientHello.
const CLIENT_HELLO_SKIP: usize = 140;
/// SNI extension bytes before the server-name length.
const SNI_SKIP: usize = 7;
/// ClientHello extensions after the server name.
const TRAILING_EXTS: usize = 66;
/// Record type and version before each record length.
const RECORD_SKIP: usize = 3;

const CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];
const CLIENT_TAIL: [u8; 66] = [
    // ec_point_formats
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, // supported_groups
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00,
    0x18, // signature_algorithms
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02,
    0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x02, 0x03, // encrypt_then_mac, extended_master_secret
    0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
];

fn unix_time() -> [u8; 4] {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs as u32).to_be_bytes()
}

fn put_u16(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u16).to_be_bytes());
}

fn put_random(out: &mut Vec<u8>, n: usize) {
    let start = out.len();
    out.resize(start + n, 0);
    crate::crypto::random_bytes(&mut out[start..]);
}

fn client_hello(data: &[u8], server: &str, out: &mut Vec<u8>) {
    let (d, s) = (data.len(), server.len());
    out.extend_from_slice(&[0x16, 0x03, 0x01]);
    put_u16(out, 212 + d + s);
    out.extend_from_slice(&[0x01, 0x00]);
    put_u16(out, 208 + d + s);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&unix_time());
    put_random(out, 28);
    out.push(32);
    put_random(out, 32);
    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&CIPHER_SUITES);
    out.extend_from_slice(&[0x01, 0x00]);
    put_u16(out, 79 + d + s);
    // session_ticket carrying the data
    out.extend_from_slice(&[0x00, 0x23]);
    put_u16(out, d);
    out.extend_from_slice(data);
    // server_name
    out.extend_from_slice(&[0x00, 0x00]);
    put_u16(out, s + 5);
    put_u16(out, s + 3);
    out.push(0);
    put_u16(out, s);
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(&CLIENT_TAIL);
}

fn server_hello(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 91, 0x02, 0x00, 0x00, 87, 0x03, 0x03]);
    out.extend_from_slice(&unix_time());
    put_random(out, 28);
    out.push(32);
    put_random(out, 32);
    out.extend_from_slice(&[0xcc, 0xa8, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
    out.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // ChangeCipherSpec, then the handshake record with the data
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03]);
    put_u16(out, data.len());
    out.extend_from_slice(data);
}

fn app_record(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    put_u16(out, data.len());
    out.extend_from_slice(data);
}

/// What follows a skipped run of bytes.
#[derive(Debug, Clone, Copy)]
enum Then {
    /// A 2-byte record length, then the record payload.
    RecordLen,
    /// The 2-byte server-name length of the ClientHello SNI extension.
    NameLen,
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Skip(usize, Then),
    Len(Then),
    Data(usize),
}

/// Parses the record framing out of the transport.
#[derive(Debug)]
struct RecordReader {
    buf: BytesMut,
    step: Step,
    /// Server side: the rest of the ClientHello follows the first payload.
    hello_tail: bool,
}

impl RecordReader {
    fn new(first_skip: usize, hello_tail: bool) -> Self {
        Self {
            buf: BytesMut::new(),
            step: Step::Skip(first_skip, Then::RecordLen),
            hello_tail,
        }
    }

    /// Buffers at least `need` bytes. Returns `false` on a clean EOF: the
    /// transport ended with nothing buffered.
    fn poll_fill<S: AsyncRead + Unpin>(
        &mut self,
        io: &mut S,
        cx: &mut Context<'_>,
        need: usize,
    ) -> Poll<io::Result<bool>> {
        while self.buf.len() < need {
            self.buf.reserve(need.max(CHUNK + 5));
            if ready!(tokio_util::io::poll_read_buf(
                Pin::new(&mut *io),
                cx,
                &mut self.buf
            ))? == 0
            {
                if self.buf.is_empty() {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
        Poll::Ready(Ok(true))
    }

    fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        io: &mut S,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.step {
                Step::Skip(n, then) => {
                    // The stream may end cleanly between records.
                    if !ready!(self.poll_fill(io, cx, n))? {
                        if matches!(then, Then::RecordLen) && n == RECORD_SKIP {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.buf.advance(n);
                    self.step = Step::Len(then);
                }
                Step::Len(then) => {
                    if !ready!(self.poll_fill(io, cx, 2))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let len = usize::from(self.buf.get_u16());
                    self.step = match then {
                        Then::RecordLen => Step::Data(len),
                        // Skip the name and the trailing extensions, then the
                        // next record's type and version.
                        Then::NameLen => {
                            Step::Skip(len + TRAILING_EXTS + RECORD_SKIP, Then::RecordLen)
                        }
                    };
                }
                Step::Data(0) => {
                    self.step = if std::mem::take(&mut self.hello_tail) {
                        Step::Skip(SNI_SKIP, Then::NameLen)
                    } else {
                        Step::Skip(RECORD_SKIP, Then::RecordLen)
                    };
                }
                Step::Data(left) => {
                    if out.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    if !ready!(self.poll_fill(io, cx, 1))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let n = left.min(self.buf.len()).min(out.remaining());
                    out.put_slice(&self.buf[..n]);
                    self.buf.advance(n);
                    self.step = Step::Data(left - n);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

/// The hello message the first write is embedded in.
#[derive(Debug)]
enum Hello {
    /// ClientHello with this SNI.
    Client(String),
    Server,
}

/// Frames writes as records; the first one goes out inside the hello.
#[derive(Debug)]
struct RecordWriter {
    pending: Pending,
    hello: Option<Hello>,
}

impl RecordWriter {
    fn new(hello: Hello) -> Self {
        Self {
            pending: Pending::default(),
            hello: Some(hello),
        }
    }

    fn poll_write<S: AsyncWrite + Unpin>(
        &mut self,
        io: &mut S,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.pending.poll_drain(io, cx))?;
        let mut chunks = data.chunks(CHUNK);
        if let Some(hello) = self.hello.take() {
            let first = chunks.next().unwrap_or_default();
            match hello {
                Hello::Client(sni) => client_hello(first, &sni, self.pending.buf_mut()),
                Hello::Server => server_hello(first, self.pending.buf_mut()),
            }
        }
        for chunk in chunks {
            app_record(chunk, self.pending.buf_mut());
        }
        if let Poll::Ready(Err(e)) = self.pending.poll_drain(io, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(data.len()))
    }
}

macro_rules! impl_tls_io {
    ($ty:ident) => {
        impl<S: AsyncRead + Unpin> AsyncRead for $ty<S> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                this.reader.poll_read(&mut this.io, cx, buf)
            }
        }

        impl<S: AsyncWrite + Unpin> AsyncWrite for $ty<S> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                this.writer.poll_write(&mut this.io, cx, buf)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                ready!(this.writer.pending.poll_drain(&mut this.io, cx))?;
                Pin::new(&mut this.io).poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                ready!(this.writer.pending.poll_drain(&mut this.io, cx))?;
                Pin::new(&mut this.io).poll_shutdown(cx)
            }
        }
    };
}

/// TLS obfuscation, client side.
#[derive(Debug)]
pub struct TlsObfsClient<S> {
    pub(crate) io: S,
    reader: RecordReader,
    writer: RecordWriter,
}

impl<S> TlsObfsClient<S> {
    /// Wraps `io`; `server` is sent as SNI.
    pub fn new(io: S, server: &str) -> Self {
        Self {
            io,
            reader: RecordReader::new(SERVER_HELLO_SKIP, false),
            writer: RecordWriter::new(Hello::Client(server.to_owned())),
        }
    }
}

impl_tls_io!(TlsObfsClient);

/// TLS obfuscation, server side.
#[derive(Debug)]
pub struct TlsObfsServer<S> {
    pub(crate) io: S,
    reader: RecordReader,
    writer: RecordWriter,
}

impl<S> TlsObfsServer<S> {
    /// Wraps `io`.
    pub fn new(io: S) -> Self {
        Self {
            io,
            reader: RecordReader::new(CLIENT_HELLO_SKIP, true),
            writer: RecordWriter::new(Hello::Server),
        }
    }
}

impl_tls_io!(TlsObfsServer);

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn hello_lengths() {
        let mut out = Vec::new();
        client_hello(b"0123456789", "example.com", &mut out);
        assert_eq!(out.len(), 5 + 212 + 10 + 11);
        assert_eq!(
            &out[CLIENT_HELLO_SKIP..CLIENT_HELLO_SKIP + 2],
            &10u16.to_be_bytes()
        );
        out.clear();
        server_hello(b"abc", &mut out);
        assert_eq!(out.len(), SERVER_HELLO_SKIP + 2 + 3);
    }

    #[tokio::test]
    async fn round_trip() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut client = TlsObfsClient::new(a, "example.com");
        let mut server = TlsObfsServer::new(b);
        let big = vec![0x42u8; 40_000];

        client.write_all(b"hello").await.unwrap();
        client.write_all(&big).await.unwrap();
        let mut got = vec![0; 5 + big.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..5], b"hello");
        assert_eq!(&got[5..], &big[..]);

        server.write_all(b"world").await.unwrap();
        server.write_all(&big).await.unwrap();
        let mut got = vec![0; 5 + big.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..5], b"world");
        assert_eq!(&got[5..], &big[..]);
    }
}

#[cfg(test)]
mod bulk_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bulk_server_to_client() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = TlsObfsClient::new(a, "example.com");
        let mut server = TlsObfsServer::new(b);
        let data: Vec<u8> = (0..4_000_000u32).map(|i| (i % 251) as u8).collect();
        client.write_all(b"req").await.unwrap();
        let mut req = [0u8; 3];
        server.read_exact(&mut req).await.unwrap();
        let d2 = data.clone();
        let w = tokio::spawn(async move {
            for c in d2.chunks(256 * 1024) {
                server.write_all(c).await.unwrap();
            }
            server.flush().await.unwrap();
            server.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        w.await.unwrap();
        assert!(got == data);
    }
}
