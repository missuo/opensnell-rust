//! Snell server.
//!
//! ```text
//! opensnell-server --listen 0.0.0.0:6160 --psk <psk> [--version v6] [--mode default]
//! ```

#[path = "common/args.rs"]
mod args;

use opensnell::{Key, ObfsMode, Server, ServerConfig};
use tokio::net::{TcpListener, UdpSocket};

const USAGE: &str = "\
usage: opensnell-server --listen <addr:port> --psk <psk> [options]

options:
  --version <v4|v5|v6>                       protocol version (default v5)
  --mode <default|unshaped|unsafe-raw>       v6 encryption mode (default default)
  --obfs <off|http|tls>                      v4/v5 obfuscation (default off)
  --ip-preference <default|prefer-ipv4|prefer-ipv6|ipv4-only|ipv6-only>
                                             target address family policy
                                             (default: v5 ipv4-only, v6 default)
  --no-udp                                   refuse UDP sessions
  --no-quic                                  v5: do not serve QUIC proxy mode
";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = args::Args::parse(USAGE, &["no-udp", "no-quic"]);
    let key = Key::new(
        args.required("psk"),
        args.get_or("version", "v5").parse()?,
        args.get_or("mode", "default").parse()?,
    )?;
    let mut cfg = ServerConfig::new(key.clone());
    cfg.obfs = args.get_or("obfs", "off").parse::<ObfsMode>()?;
    cfg.udp = !args.flag("no-udp");
    if let Some(p) = args.get("ip-preference") {
        cfg.ip_preference = p.parse()?;
    }
    let server = Server::new(cfg)?;

    let listener = TcpListener::bind(args.required("listen")).await?;
    tracing::info!(addr = %listener.local_addr()?, version = %key.version(), mode = %key.mode(), "snell server listening");
    if !key.version().is_v6() && !args.flag("no-quic") {
        // v5 also serves QUIC proxy mode on the same port.
        let udp = UdpSocket::bind(listener.local_addr()?).await?;
        let quic = server.clone();
        tokio::spawn(async move { quic.serve_quic(udp).await });
    }
    server.serve(listener).await?;
    Ok(())
}
