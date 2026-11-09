//! A minimal Snell server.
//!
//! ```text
//! cargo run --release --example server -- 0.0.0.0:6160 <psk> [v5|v6] [mode] [obfs]
//! ```

use opensnell::{Key, ObfsMode, Server, ServerConfig};
use tokio::net::{TcpListener, UdpSocket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let [listen, psk, rest @ ..] = args.as_slice() else {
        eprintln!(
            "usage: server <listen> <psk> [v5|v6] [default|unshaped|unsafe-raw] [off|http|tls]"
        );
        std::process::exit(2);
    };
    let arg = |i: usize| rest.get(i).map(String::as_str).unwrap_or_default();
    let key = Key::new(psk, arg(0).parse()?, arg(1).parse()?)?;
    let mut cfg = ServerConfig::new(key.clone());
    cfg.obfs = arg(2).parse::<ObfsMode>()?;
    let server = Server::new(cfg)?;

    let listener = TcpListener::bind(listen).await?;
    tracing::info!(addr = %listener.local_addr()?, version = %key.version(), mode = %key.mode(), "listening");
    if !key.version().is_v6() {
        // v5 also offers QUIC proxy mode on the same port.
        let udp = UdpSocket::bind(listener.local_addr()?).await?;
        let quic = server.clone();
        tokio::spawn(async move { quic.serve_quic(udp).await });
    }
    server.serve(listener).await?;
    Ok(())
}
