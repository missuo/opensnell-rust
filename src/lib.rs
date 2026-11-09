//! Snell proxy protocol, v4/v5 and v6, for tokio.
//!
//! The client and the server work over any `AsyncRead + AsyncWrite`
//! transport, so the crate drops into an existing proxy: dial the server
//! yourself, then hand the connection to [`Client::connect`] (TCP) or
//! [`Client::udp`] (UDP over TCP).
//!
//! The v6 wire is the official v6.0.0 one, in all three modes: `default`
//! (PSK-derived traffic shaping, byte-for-byte what the official server and
//! Surge send), `unshaped` and `unsafe-raw`.
//!
//! ```no_run
//! use opensnell::{Client, ClientConfig, Key, Mode};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # async fn demo() -> std::io::Result<()> {
//! let key = Key::v6("my-pre-shared-key", Mode::Default)?;
//! let client = Client::new(ClientConfig::new(key))?;
//!
//! let tcp = tokio::net::TcpStream::connect("203.0.113.1:6160").await?;
//! let mut stream = client.connect(tcp, "example.com", 80).await?;
//! stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
//! let mut page = Vec::new();
//! stream.read_to_end(&mut page).await?;
//! # Ok(()) }
//! ```
//!
//! A server:
//!
//! ```no_run
//! use opensnell::{Key, Server, ServerConfig};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let key = Key::v5("my-pre-shared-key")?;
//! let server = Server::new(ServerConfig::new(key))?;
//! server.serve(tokio::net::TcpListener::bind("0.0.0.0:6160").await?).await?;
//! # Ok(()) }
//! ```

#![warn(missing_docs)]

mod client;
mod codec;
mod crypto;
mod error;
mod key;
pub mod obfs;
mod pool;
mod protocol;
pub mod quic;
pub mod server;
mod stream;
mod sys;
mod v6;

pub use client::{Client, ClientConfig, ClientStream, UdpReceiver, UdpSender, UdpSession};
pub use error::Error;
pub use key::{Key, Mode, V6_PREFIX_LEN, Version};
pub use obfs::{Obfs, ObfsMode, ObfsStream};
pub use pool::Pool;
pub use protocol::Address;
pub use server::{Server, ServerConfig};
pub use stream::{SnellReader, SnellStream, SnellWriter};

#[cfg(test)]
mod assertions {
    use super::*;

    fn send_sync_unpin<T: Send + Sync + Unpin + std::fmt::Debug>() {}

    #[test]
    fn types_embed_in_async_code() {
        send_sync_unpin::<ClientStream<tokio::net::TcpStream>>();
        send_sync_unpin::<UdpSession<tokio::net::TcpStream>>();
        send_sync_unpin::<Key>();
        send_sync_unpin::<Client>();
    }
}
