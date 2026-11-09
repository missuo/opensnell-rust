//! Socket option helpers.

use std::io;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};

/// Enables TCP keepalive: first probe after `idle`, then every `interval`,
/// giving up after `retries` probes where the platform supports setting them.
pub(crate) fn set_keepalive<'a>(
    sock: impl Into<SockRef<'a>>,
    idle: Duration,
    interval: Duration,
    retries: Option<u32>,
) -> io::Result<()> {
    let ka = TcpKeepalive::new().with_time(idle);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        windows
    ))]
    let ka = ka.with_interval(interval);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    let ka = match retries {
        Some(r) => ka.with_retries(r),
        None => ka,
    };
    let _ = (interval, retries);
    sock.into().set_tcp_keepalive(&ka)
}
