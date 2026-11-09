//! Server-side TCP relay with the official half-close and lazy-reply
//! behavior.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocol::RESP_TUNNEL;
use crate::stream::{Eof, SnellStream};

/// Client→upstream read size.
const CLIENT_READ: usize = 32 * 1024;
/// Upstream→client read size. The official server reads upstreams in 256 KiB
/// batches, and each batch is one write for the chunk policy.
const UPSTREAM_READ: usize = 256 * 1024;

/// How a relay ended.
pub(super) enum Outcome {
    /// The client transport closed (v6: without a zero chunk). Nothing more is
    /// sent.
    ClientClosed,
    /// The upstream finished.
    Done {
        /// Whether anything was sent to the client (the tunnel reply rides on
        /// the first upstream data).
        replied: bool,
        /// Upstream read error, if it ended with one.
        error: Option<io::Error>,
    },
}

enum ToUpstream {
    Reading,
    Writing { pos: usize, len: usize },
    Shutdown,
    Done,
}

enum ToClient {
    Reading,
    Writing { start: usize, end: usize },
}

/// Relays until the upstream finishes, or the client goes away.
///
/// The tunnel status byte is not sent on its own: it is merged into the
/// first upstream data. A zero chunk from the client half-closes the upstream
/// and the response keeps flowing.
pub(super) async fn relay<S, U>(stream: &mut SnellStream<S>, up: &mut U, v6: bool) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut c2u_buf = vec![0u8; CLIENT_READ].into_boxed_slice();
    // Byte 0 is reserved for the status byte so the first batch goes out as
    // `RESP_TUNNEL ++ data` without a copy.
    let mut u2c_buf = vec![0u8; 1 + UPSTREAM_READ].into_boxed_slice();
    let mut c2u = ToUpstream::Reading;
    let mut u2c = ToClient::Reading;
    let mut replied = false;
    let mut need_flush = false;

    poll_fn(|cx| {
        if poll_to_upstream(cx, stream, up, &mut c2u, &mut c2u_buf, v6).is_ready() {
            return Poll::Ready(Outcome::ClientClosed);
        }
        poll_to_client(
            cx,
            stream,
            up,
            &mut u2c,
            &mut u2c_buf,
            &mut replied,
            &mut need_flush,
        )
        .map(|end| match end {
            Ok(error) => Outcome::Done { replied, error },
            Err(ClientGone) => Outcome::ClientClosed,
        })
    })
    .await
}

/// Drives client→upstream. Ready only when the client went away.
fn poll_to_upstream<S, U>(
    cx: &mut Context<'_>,
    stream: &mut SnellStream<S>,
    up: &mut U,
    state: &mut ToUpstream,
    buf: &mut [u8],
    v6: bool,
) -> Poll<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncWrite + Unpin,
{
    loop {
        match state {
            ToUpstream::Reading => {
                let mut rb = ReadBuf::new(buf);
                match Pin::new(&mut *stream).poll_read(cx, &mut rb) {
                    Poll::Pending => {
                        // Nothing to read: make sure written data is not stuck.
                        let _ = Pin::new(&mut *up).poll_flush(cx);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(())) if !rb.filled().is_empty() => {
                        *state = ToUpstream::Writing {
                            pos: 0,
                            len: rb.filled().len(),
                        };
                    }
                    Poll::Ready(result) => {
                        // A zero chunk half-closes the upstream. On v6 any
                        // other end means the client is gone; v5 half-closes
                        // the upstream for it too.
                        let half_close = result.is_ok() && stream.r.eof() == Eof::ZeroChunk;
                        if v6 && !half_close {
                            return Poll::Ready(());
                        }
                        *state = ToUpstream::Shutdown;
                    }
                }
            }
            ToUpstream::Writing { pos, len } => {
                match Pin::new(&mut *up).poll_write(cx, &buf[*pos..*len]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(n)) if n > 0 => {
                        *pos += n;
                        if *pos == *len {
                            *state = ToUpstream::Reading;
                        }
                    }
                    // The upstream stopped taking data; its read side reports why.
                    Poll::Ready(_) => *state = ToUpstream::Done,
                }
            }
            ToUpstream::Shutdown => {
                ready!(Pin::new(&mut *up).poll_shutdown(cx)).ok();
                *state = ToUpstream::Done;
            }
            ToUpstream::Done => return Poll::Pending,
        }
    }
}

/// Writing to the client failed.
struct ClientGone;

/// Drives upstream→client. Ready when the upstream finished (with its read
/// error, if any) and everything was flushed to the client.
fn poll_to_client<S, U>(
    cx: &mut Context<'_>,
    stream: &mut SnellStream<S>,
    up: &mut U,
    state: &mut ToClient,
    buf: &mut [u8],
    replied: &mut bool,
    need_flush: &mut bool,
) -> Poll<Result<Option<io::Error>, ClientGone>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + Unpin,
{
    loop {
        match state {
            ToClient::Reading => {
                let mut rb = ReadBuf::new(&mut buf[1..]);
                let result = match Pin::new(&mut *up).poll_read(cx, &mut rb) {
                    Poll::Pending => {
                        if *need_flush {
                            ready!(stream.w.poll_flush(&mut stream.io, cx)).ok();
                            *need_flush = false;
                        }
                        return Poll::Pending;
                    }
                    Poll::Ready(r) => r,
                };
                let n = rb.filled().len();
                if let (Ok(()), true) = (&result, n > 0) {
                    let start = if *replied {
                        1
                    } else {
                        buf[0] = RESP_TUNNEL;
                        *replied = true;
                        0
                    };
                    *state = ToClient::Writing { start, end: 1 + n };
                    continue;
                }
                // Upstream finished: flush what the client still has to get.
                if ready!(stream.w.poll_flush(&mut stream.io, cx)).is_err() {
                    return Poll::Ready(Err(ClientGone));
                }
                return Poll::Ready(Ok(result.err()));
            }
            ToClient::Writing { start, end } => {
                match stream.w.poll_write(&mut stream.io, cx, &buf[*start..*end]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(n)) => {
                        *start += n;
                        if *start == *end {
                            *need_flush = true;
                            *state = ToClient::Reading;
                        }
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(ClientGone)),
                }
            }
        }
    }
}
