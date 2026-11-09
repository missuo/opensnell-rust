//! Fetches a page through a Snell server.
//!
//! ```text
//! cargo run --release --example client -- <server:port> <psk> <host> [v5|v6] [mode] [off|http|tls]
//! ```

use opensnell::{Client, ClientConfig, Key, Obfs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [server, psk, host, rest @ ..] = args.as_slice() else {
        eprintln!(
            "usage: client <server:port> <psk> <host> [v5|v6] [default|unshaped|unsafe-raw] [off|http|tls]"
        );
        std::process::exit(2);
    };
    let arg = |i: usize| rest.get(i).map(String::as_str).unwrap_or_default();
    let key = Key::new(psk, arg(0).parse()?, arg(1).parse()?)?;
    let server_port: u16 = server
        .rsplit_once(':')
        .ok_or("server must be host:port")?
        .1
        .parse()?;
    let obfs = match arg(2) {
        "http" => Obfs::Http {
            host: "bing.com".into(),
            port: server_port,
        },
        "tls" => Obfs::Tls {
            host: "bing.com".into(),
        },
        _ => Obfs::None,
    };
    let client = Client::new(ClientConfig {
        key,
        obfs,
        reuse: false,
    })?;

    let tcp = TcpStream::connect(server).await?;
    tcp.set_nodelay(true)?;
    let mut stream = client.connect(tcp, host, 80).await?;
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    println!("{}", String::from_utf8_lossy(&response));
    Ok(())
}
