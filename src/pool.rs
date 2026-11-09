//! Client connection reuse (a port of opensnell `pool.go`).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::ClientStream;
use crate::key::Key;

/// Idle connections are closed after this long (Surge's value).
const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
/// How often idle connections are checked.
const SWEEP_PERIOD: Duration = Duration::from_secs(20);
/// How long to wait for the server's zero chunk when returning a connection.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
/// Most idle connections kept.
const MAX_IDLE: usize = 10;
/// snell-server v5.0.1 closes a reuse connection after its second session.
const V5_MAX_SESSIONS: u32 = 2;

struct Idle<S> {
    stream: ClientStream<S>,
    since: Instant,
}

struct Inner<S> {
    idle: Mutex<VecDeque<Idle<S>>>,
    max_sessions: Option<u32>,
    sweeping: std::sync::atomic::AtomicBool,
}

/// A pool of idle reuse-mode connections to one server.
///
/// Requires [`crate::ClientConfig::reuse`] on v4/v5 (v6 clients always ask
/// for reuse). The connection idle the longest is handed out first; idle
/// connections are closed after 180 s.
///
/// ```no_run
/// # async fn demo(client: opensnell::Client, pool: opensnell::Pool<tokio::net::TcpStream>) -> std::io::Result<()> {
/// let stream = match pool.take() {
///     Some(idle) => client.reconnect(idle, "example.com", 443).await?,
///     None => {
///         let tcp = tokio::net::TcpStream::connect("203.0.113.1:6160").await?;
///         client.connect(tcp, "example.com", 443).await?
///     }
/// };
/// // ... relay ...
/// pool.release(stream).await;
/// # Ok(()) }
/// ```
pub struct Pool<S> {
    inner: Arc<Inner<S>>,
}

impl<S> Clone for Pool<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Pool<S> {
    /// A pool for connections using `key`. v4/v5 connections are dropped after
    /// two sessions, as the v5 server closes them then; v6 ones are not
    /// limited.
    pub fn new(key: &Key) -> Self {
        Self {
            inner: Arc::new(Inner {
                idle: Mutex::new(VecDeque::new()),
                max_sessions: (!key.version().is_v6()).then_some(V5_MAX_SESSIONS),
                sweeping: Default::default(),
            }),
        }
    }

    /// Takes an idle connection, if any. Open a session on it with
    /// [`crate::Client::reconnect`].
    pub fn take(&self) -> Option<ClientStream<S>> {
        self.inner
            .idle
            .lock()
            .expect("pool lock")
            .pop_front()
            .map(|i| i.stream)
    }

    /// Number of idle connections.
    pub fn idle(&self) -> usize {
        self.inner.idle.lock().expect("pool lock").len()
    }

    /// Ends the stream's session (zero chunk, then waits briefly for the
    /// server's) and keeps the connection if it is clean and reusable;
    /// otherwise drops it.
    pub async fn release(&self, mut stream: ClientStream<S>) {
        if self
            .inner
            .max_sessions
            .is_some_and(|max| stream.sessions() >= max)
        {
            return;
        }
        if !matches!(stream.end_session(DRAIN_TIMEOUT).await, Ok(true)) {
            return;
        }
        {
            let mut idle = self.inner.idle.lock().expect("pool lock");
            if idle.len() >= MAX_IDLE {
                return;
            }
            idle.push_back(Idle {
                stream,
                since: Instant::now(),
            });
        }
        if !self
            .inner
            .sweeping
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            tokio::spawn(sweep(Arc::downgrade(&self.inner)));
        }
    }
}

/// Closes connections idle for [`IDLE_TIMEOUT`] until the pool is dropped.
async fn sweep<S>(pool: Weak<Inner<S>>) {
    let mut tick = tokio::time::interval(SWEEP_PERIOD);
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(pool) = pool.upgrade() else { return };
        let now = Instant::now();
        // Close outside the lock.
        let expired: VecDeque<Idle<S>> = {
            let mut idle = pool.idle.lock().expect("pool lock");
            let (keep, expired) = idle
                .drain(..)
                .partition(|i| now.duration_since(i.since) < IDLE_TIMEOUT);
            *idle = keep;
            expired
        };
        drop(expired);
    }
}

impl<S> std::fmt::Debug for Pool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("max_sessions", &self.inner.max_sessions)
            .finish_non_exhaustive()
    }
}
