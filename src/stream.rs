//! The Snell stream: framing and encryption over any async byte transport.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::codec::{Decoded, Decoder, Encoder};
use crate::error::Error;
use crate::key::Key;
use crate::protocol::{RESP_ERROR, RESP_PONG, RESP_TUNNEL};

/// Receive buffer growth step (one read can pull this much).
const READ_CHUNK: usize = 64 * 1024;
/// Largest plaintext accepted by one `poll_write`: one write is one batch
/// for the chunk policy, and the official server reads upstreams 256 KiB at a
/// time (+1 for the status byte the server merges into the first batch).
pub(crate) const MAX_WRITE_BATCH: usize = 256 * 1024 + 1;
/// The send buffer is released after a flush once it grew beyond this.
const MAX_RETAINED_WRITE_BUF: usize = 512 * 1024;

/// How the peer ended its side of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Eof {
    No,
    /// The peer sent a zero chunk (Snell half-close).
    ZeroChunk,
    /// The transport reached EOF.
    Transport,
}

/// Client-side parsing of the server's response status.
#[derive(Debug)]
enum Reply {
    Done,
    Status,
    ErrorCode,
    ErrorLen(u8),
    ErrorMsg { code: u8, len: usize, msg: Vec<u8> },
}

/// Receive side: raw buffer, decoder and the current frame's plaintext.
pub(crate) struct ReadState {
    dec: Decoder,
    buf: BytesMut,
    /// Plaintext of the current frame is `buf[pos..end]`; the frame occupies
    /// `buf[..frame_len]` and is dropped once the plaintext is consumed.
    pos: usize,
    end: usize,
    frame_len: usize,
    eof: Eof,
    reply: Reply,
    /// A frame failed to decode; the stream is unusable.
    failed: bool,
}

impl ReadState {
    pub(crate) fn new(dec: Decoder, buffered: &[u8], client: bool) -> Self {
        let mut buf = BytesMut::with_capacity(buffered.len().max(READ_CHUNK));
        buf.extend_from_slice(buffered);
        Self {
            dec,
            buf,
            pos: 0,
            end: 0,
            frame_len: 0,
            eof: Eof::No,
            reply: if client { Reply::Status } else { Reply::Done },
            failed: false,
        }
    }

    /// Decodes from the buffered bytes only. Returns `None` when plaintext or
    /// an end of stream is ready, or the buffer length needed otherwise.
    fn step(&mut self) -> Result<Option<usize>, Error> {
        if self.failed {
            return Err(Error::Frame("stream failed earlier"));
        }
        let result = self.decode_buffered();
        self.failed = result.is_err();
        result
    }

    fn decode_buffered(&mut self) -> Result<Option<usize>, Error> {
        loop {
            if self.pos < self.end || self.eof != Eof::No {
                return Ok(None);
            }
            if self.frame_len > 0 {
                self.buf.advance(self.frame_len);
                (self.pos, self.end, self.frame_len) = (0, 0, 0);
            }
            match self.dec.decode(&mut self.buf)? {
                Decoded::NeedMore(n) => return Ok(Some(n)),
                Decoded::Advance(n) => self.buf.advance(n),
                Decoded::Frame {
                    consumed,
                    start,
                    end,
                } => {
                    (self.pos, self.end, self.frame_len) = (start, end, consumed);
                }
                Decoded::ZeroChunk(n) => {
                    self.buf.advance(n);
                    self.eof = Eof::ZeroChunk;
                }
            }
        }
    }

    /// Makes plaintext (or the end of stream) available, reading as needed.
    pub(crate) fn poll_fill<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let Some(need) = self.step()? else {
                return Poll::Ready(Ok(()));
            };
            let want = need.saturating_sub(self.buf.len()).max(1);
            if self.buf.capacity() - self.buf.len() < want {
                self.buf.reserve(want.max(READ_CHUNK));
            }
            let n = ready!(tokio_util::io::poll_read_buf(
                Pin::new(&mut *io),
                cx,
                &mut self.buf
            ))?;
            if n == 0 {
                if !self.buf.is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                self.eof = Eof::Transport;
            }
        }
    }

    /// Whether plaintext (or the end of stream) is available without reading
    /// the transport.
    pub(crate) fn has_buffered(&mut self) -> io::Result<bool> {
        Ok(self.step()?.is_none())
    }

    /// Plaintext left in the current frame (empty at end of stream).
    pub(crate) fn frame(&self) -> &[u8] {
        &self.buf[self.pos..self.end]
    }

    pub(crate) fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    pub(crate) fn eof(&self) -> Eof {
        self.eof
    }

    /// Consumes the server's response status, once per session.
    fn poll_reply<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if matches!(self.reply, Reply::Done) {
                return Poll::Ready(Ok(()));
            }
            ready!(self.poll_fill(io, cx))?;
            if self.pos == self.end {
                return Poll::Ready(Err(match self.eof {
                    Eof::ZeroChunk => Error::Frame("zero chunk before the response").into(),
                    _ => io::ErrorKind::UnexpectedEof.into(),
                }));
            }
            let b = self.buf[self.pos];
            let server_error = |code, msg: &[u8]| {
                Poll::Ready(Err(Error::Server {
                    code,
                    message: String::from_utf8_lossy(msg).into_owned(),
                }
                .into()))
            };
            self.reply = match std::mem::replace(&mut self.reply, Reply::Done) {
                Reply::Status => {
                    self.pos += 1;
                    match b {
                        RESP_TUNNEL | RESP_PONG => Reply::Done,
                        RESP_ERROR => Reply::ErrorCode,
                        _ => return Poll::Ready(Err(Error::Frame("unknown response code").into())),
                    }
                }
                Reply::ErrorCode => {
                    self.pos += 1;
                    Reply::ErrorLen(b)
                }
                Reply::ErrorLen(code) => {
                    self.pos += 1;
                    if b == 0 {
                        return server_error(code, &[]);
                    }
                    Reply::ErrorMsg {
                        code,
                        len: usize::from(b),
                        msg: Vec::with_capacity(usize::from(b)),
                    }
                }
                Reply::ErrorMsg { code, len, mut msg } => {
                    let n = (len - msg.len()).min(self.end - self.pos);
                    msg.extend_from_slice(&self.buf[self.pos..self.pos + n]);
                    self.pos += n;
                    if msg.len() == len {
                        return server_error(code, &msg);
                    }
                    Reply::ErrorMsg { code, len, msg }
                }
                Reply::Done => Reply::Done,
            };
        }
    }

    pub(crate) fn poll_read<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_reply(io, cx))?;
        ready!(self.poll_fill(io, cx))?;
        let pt = self.frame();
        let n = pt.len().min(out.remaining());
        out.put_slice(&pt[..n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }

    /// Reads the rest of the current frame (one datagram on a UDP session).
    /// An empty frame means the end of stream.
    pub(crate) fn poll_frame<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<&[u8]>> {
        ready!(self.poll_reply(io, cx))?;
        ready!(self.poll_fill(io, cx))?;
        let frame = &self.buf[self.pos..self.end];
        self.pos = self.end;
        Poll::Ready(Ok(frame))
    }

    /// Starts a new session on a reused connection.
    fn reset_session(&mut self, client: bool) {
        if self.eof == Eof::ZeroChunk {
            self.eof = Eof::No;
        }
        if client {
            self.reply = Reply::Status;
        }
    }
}

impl std::fmt::Debug for ReadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadState")
            .field("eof", &self.eof)
            .field("buffered", &self.buf.len())
            .finish_non_exhaustive()
    }
}

/// Send side: encoder plus the encoded bytes not yet written.
pub(crate) struct WriteState {
    enc: Encoder,
    buf: Vec<u8>,
    pos: usize,
    zero_chunk_sent: bool,
}

impl WriteState {
    pub(crate) fn new(enc: Encoder) -> Self {
        Self {
            enc,
            buf: Vec::new(),
            pos: 0,
            zero_chunk_sent: false,
        }
    }

    /// Writes out every encoded byte.
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
        if self.buf.capacity() > MAX_RETAINED_WRITE_BUF {
            self.buf = Vec::new();
        }
        Poll::Ready(Ok(()))
    }

    /// Encodes with `f` once the previous output is written, then starts
    /// writing the new output. Write errors after encoding surface here or on
    /// the next call.
    fn poll_encode<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut Encoder, &mut Vec<u8>) -> Result<(), Error>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(io, cx))?;
        f(&mut self.enc, &mut self.buf)?;
        if let Poll::Ready(Err(e)) = self.poll_drain(io, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(()))
    }

    /// Encodes one write without writing anything out.
    pub(crate) fn queue(&mut self, data: &[u8]) -> Result<(), Error> {
        self.enc.encode(data, &mut self.buf)
    }

    /// Encodes `head ++ body` as one frame without writing anything out.
    pub(crate) fn queue_packet(&mut self, head: &[u8], body: &[u8]) -> Result<(), Error> {
        self.enc.encode_packet(head, body, &mut self.buf)
    }

    pub(crate) fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_WRITE_BATCH);
        ready!(self.poll_encode(io, cx, |e, out| e.encode(&data[..n], out)))?;
        Poll::Ready(Ok(n))
    }

    /// Writes `head ++ body` as exactly one frame.
    pub(crate) fn poll_write_packet<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        head: &[u8],
        body: &[u8],
    ) -> Poll<io::Result<()>> {
        self.poll_encode(io, cx, |e, out| e.encode_packet(head, body, out))
    }

    pub(crate) fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    /// Sends the zero chunk (once per session) and flushes. The transport
    /// itself stays open.
    pub(crate) fn poll_close_session<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.zero_chunk_sent {
            ready!(self.poll_encode(io, cx, |e, out| e.encode(&[], out)))?;
            self.zero_chunk_sent = true;
        }
        self.poll_flush(io, cx)
    }
}

impl std::fmt::Debug for WriteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteState")
            .field("pending", &(self.buf.len() - self.pos))
            .field("zero_chunk_sent", &self.zero_chunk_sent)
            .finish_non_exhaustive()
    }
}

/// A Snell stream over the transport `S`.
///
/// Reads return the peer's plaintext; a zero chunk from the peer (Snell's
/// half-close) reads as end of stream. Each `poll_write` call is one write
/// for the wire's chunk policy. [`AsyncWrite::poll_shutdown`] sends a zero
/// chunk and flushes but leaves the transport open, so the peer's remaining
/// data can still be read; drop the stream to close the connection.
///
/// Client streams come from [`crate::Client`]; their first read consumes the
/// server's response and fails with [`Error::Server`] if the server refused
/// the request.
pub struct SnellStream<S> {
    pub(crate) io: S,
    pub(crate) r: ReadState,
    pub(crate) w: WriteState,
    client: bool,
    sessions: u32,
}

impl<S> SnellStream<S> {
    pub(crate) fn new_client(io: S, key: &Key) -> Result<Self, Error> {
        Ok(Self {
            io,
            r: ReadState::new(Decoder::new(key), &[], true),
            w: WriteState::new(Encoder::new(key)?),
            client: true,
            sessions: 0,
        })
    }

    pub(crate) fn new_server(
        io: S,
        key: &Key,
        dec: Decoder,
        buffered: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            io,
            r: ReadState::new(dec, buffered, false),
            w: WriteState::new(Encoder::new(key)?),
            client: false,
            sessions: 0,
        })
    }

    /// The transport.
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// The transport. Reading or writing it directly corrupts the stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Whether the peer ended its side of the current session with a zero
    /// chunk (as opposed to closing the transport).
    pub fn peer_half_closed(&self) -> bool {
        self.r.eof() == Eof::ZeroChunk
    }

    /// Number of sessions (requests) opened on this connection.
    pub fn sessions(&self) -> u32 {
        self.sessions
    }

    pub(crate) fn begin_session(&mut self) {
        if self.sessions > 0 {
            self.r.reset_session(self.client);
            self.w.zero_chunk_sent = false;
        }
        self.sessions += 1;
    }

    /// Splits the stream into independently usable halves with `split`, for
    /// example `stream.map_split(TcpStream::into_split)`. Buffered data is
    /// kept.
    pub fn map_split<R, W>(
        self,
        split: impl FnOnce(S) -> (R, W),
    ) -> (SnellReader<R>, SnellWriter<W>) {
        let (r, w) = split(self.io);
        (
            SnellReader { io: r, r: self.r },
            SnellWriter { io: w, w: self.w },
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SnellStream<S> {
    /// Splits the stream with [`tokio::io::split`]. Prefer
    /// [`SnellStream::map_split`] when the transport has its own split.
    pub fn into_split(
        self,
    ) -> (
        SnellReader<tokio::io::ReadHalf<S>>,
        SnellWriter<tokio::io::WriteHalf<S>>,
    ) {
        self.map_split(tokio::io::split)
    }

    /// Reads the rest of the current frame into `out` (cleared first).
    /// Returns `false` at end of stream.
    pub(crate) async fn read_frame(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        out.clear();
        poll_fn(|cx| {
            let frame = ready!(self.r.poll_frame(&mut self.io, cx))?;
            out.extend_from_slice(frame);
            Poll::Ready(Ok::<_, io::Error>(()))
        })
        .await?;
        Ok(!out.is_empty())
    }

    pub(crate) async fn write_all_batch(&mut self, data: &[u8]) -> io::Result<()> {
        let mut rest = data;
        while !rest.is_empty() {
            let n = poll_fn(|cx| self.w.poll_write(&mut self.io, cx, rest)).await?;
            rest = &rest[n..];
        }
        Ok(())
    }

    pub(crate) async fn flush_all(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.w.poll_flush(&mut self.io, cx)).await
    }

    /// Ends the current session for reuse: sends the zero chunk if it was not
    /// sent yet, then discards whatever the peer still sends until its zero
    /// chunk arrives, waiting at most `timeout`. Returns whether the stream
    /// is clean and can carry another session.
    pub(crate) async fn end_session(&mut self, timeout: Duration) -> io::Result<bool> {
        poll_fn(|cx| self.w.poll_close_session(&mut self.io, cx)).await?;
        let drain = async {
            loop {
                if self.r.eof() != Eof::No {
                    return Ok::<_, io::Error>(self.r.eof() == Eof::ZeroChunk);
                }
                poll_fn(|cx| self.r.poll_frame(&mut self.io, cx).map_ok(|_| ())).await?;
            }
        };
        Ok(matches!(
            tokio::time::timeout(timeout, drain).await,
            Ok(Ok(true))
        ))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SnellStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.r.poll_read(&mut this.io, cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SnellStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.w.poll_write(&mut this.io, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.w.poll_flush(&mut this.io, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.w.poll_close_session(&mut this.io, cx)
    }
}

impl<S> std::fmt::Debug for SnellStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellStream")
            .field("client", &self.client)
            .field("sessions", &self.sessions)
            .field("eof", &self.r.eof)
            .finish_non_exhaustive()
    }
}

/// The read half of a [`SnellStream`].
pub struct SnellReader<R> {
    pub(crate) io: R,
    pub(crate) r: ReadState,
}

impl<R> SnellReader<R> {
    /// Whether the peer ended its side with a zero chunk.
    pub fn peer_half_closed(&self) -> bool {
        self.r.eof() == Eof::ZeroChunk
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for SnellReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.r.poll_read(&mut this.io, cx, buf)
    }
}

impl<R> std::fmt::Debug for SnellReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellReader")
            .field("eof", &self.r.eof)
            .finish_non_exhaustive()
    }
}

/// The write half of a [`SnellStream`].
pub struct SnellWriter<W> {
    pub(crate) io: W,
    pub(crate) w: WriteState,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for SnellWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.w.poll_write(&mut this.io, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.w.poll_flush(&mut this.io, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.w.poll_close_session(&mut this.io, cx)
    }
}

impl<W> std::fmt::Debug for SnellWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellWriter")
            .field("zero_chunk_sent", &self.w.zero_chunk_sent)
            .finish_non_exhaustive()
    }
}
