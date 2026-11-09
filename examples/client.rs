//! Snell client with a local SOCKS5 proxy (CONNECT and UDP ASSOCIATE).
//!
//! ```text
//! opensnell-client --server <host:port> --psk <psk> [--listen 127.0.0.1:1080] [--version v6]
//! ```

#[path = "common/args.rs"]
mod args;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use opensnell::{Address, Client, ClientConfig, ClientStream, Key, Obfs, Pool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

const USAGE: &str = "\
usage: opensnell-client --server <host:port> --psk <psk> [options]

options:
  --listen <addr:port>                     local SOCKS5 address (default 127.0.0.1:1080)
  --version <v4|v5|v6>                     protocol version (default v5)
  --mode <default|unshaped|unsafe-raw>     v6 encryption mode (default default)
  --obfs <off|http|tls>                    v4/v5 obfuscation (default off)
  --obfs-host <host>                       obfuscation host (default: the server host)
  --reuse                                  reuse server connections
  --username <name> --password <pass>      require SOCKS5 username/password
";

struct App {
    client: Client,
    server: String,
    pool: Option<Pool<TcpStream>>,
    auth: Option<(String, String)>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = args::Args::parse(USAGE, &["reuse"]);
    let server = args.required("server").to_owned();
    let (server_host, server_port) = server
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h.trim_matches(['[', ']']), p.parse::<u16>().ok()?)))
        .ok_or("--server must be host:port")?;
    let key = Key::new(
        args.required("psk"),
        args.get_or("version", "v5").parse()?,
        args.get_or("mode", "default").parse()?,
    )?;
    let obfs_host = args.get_or("obfs-host", server_host).to_owned();
    let obfs = match args.get_or("obfs", "off").parse::<opensnell::ObfsMode>()? {
        opensnell::ObfsMode::None => Obfs::None,
        opensnell::ObfsMode::Http => Obfs::Http {
            host: obfs_host,
            port: server_port,
        },
        opensnell::ObfsMode::Tls => Obfs::Tls { host: obfs_host },
    };
    let reuse = args.flag("reuse");
    let auth = match (args.get("username"), args.get("password")) {
        (Some(u), Some(p)) => Some((u.to_owned(), p.to_owned())),
        (None, None) => None,
        _ => return Err("--username and --password go together".into()),
    };
    let client = Client::new(ClientConfig {
        key: key.clone(),
        obfs,
        reuse,
    })?;
    let app = Arc::new(App {
        client,
        server,
        pool: reuse.then(|| Pool::new(&key)),
        auth,
    });

    let listener = TcpListener::bind(args.get_or("listen", "127.0.0.1:1080")).await?;
    info!(addr = %listener.local_addr()?, server = %app.server, version = %key.version(), mode = %key.mode(), "SOCKS5 proxy listening");
    if app.auth.is_none() && !listener.local_addr()?.ip().is_loopback() {
        warn!(
            "SOCKS5 listener has no authentication; bind to 127.0.0.1 or set --username/--password"
        );
    }
    loop {
        let (conn, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = app.serve(conn).await {
                debug!(%peer, error = %e, "SOCKS5 session ended");
            }
        });
    }
}

impl App {
    async fn dial(&self) -> io::Result<TcpStream> {
        let tcp = TcpStream::connect(&self.server).await?;
        tcp.set_nodelay(true)?;
        Ok(tcp)
    }

    async fn serve(&self, mut conn: TcpStream) -> io::Result<()> {
        conn.set_nodelay(true)?;
        socks_auth(&mut conn, self.auth.as_ref()).await?;
        let mut head = [0u8; 4];
        conn.read_exact(&mut head).await?;
        if head[0] != 5 {
            return Err(invalid("not a SOCKS5 request"));
        }
        let target = read_addr(&mut conn, head[3]).await?;
        match head[1] {
            1 => self.connect(conn, target).await,
            3 => self.udp_associate(conn).await,
            _ => {
                conn.write_all(&reply(7, None)).await?;
                Err(invalid("unsupported SOCKS5 command"))
            }
        }
    }

    async fn connect(&self, mut conn: TcpStream, target: Address) -> io::Result<()> {
        info!(%target, "snell tcp");
        let (host, port) = match &target {
            Address::Socket(a) => (a.ip().to_string(), a.port()),
            Address::Domain(h, p) => (h.clone(), *p),
        };
        let mut upstream: ClientStream<TcpStream> = match self.pool.as_ref().and_then(Pool::take) {
            Some(idle) => match self.client.reconnect(idle, &host, port).await {
                Ok(s) => s,
                Err(_) => self.client.connect(self.dial().await?, &host, port).await?,
            },
            None => self.client.connect(self.dial().await?, &host, port).await?,
        };
        conn.write_all(&reply(0, None)).await?;
        let result = tokio::io::copy_bidirectional(&mut conn, &mut upstream).await;
        if let (Some(pool), Ok(_)) = (&self.pool, &result) {
            pool.release(upstream).await;
        }
        result.map(drop)
    }

    /// Relays a SOCKS5 UDP association until its TCP control connection
    /// closes. The Snell session opens with the first datagram.
    async fn udp_associate(&self, mut ctrl: TcpStream) -> io::Result<()> {
        // Bind the relay where the client reached us, never on every interface.
        let local = ctrl.local_addr()?;
        let client_ip = ctrl.peer_addr()?.ip();
        let relay = Arc::new(UdpSocket::bind((local.ip(), 0)).await?);
        ctrl.write_all(&reply(
            0,
            Some(SocketAddr::new(local.ip(), relay.local_addr()?.port())),
        ))
        .await?;

        let mut sender = None;
        let mut client_addr: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65536];
        let mut ctrl_buf = [0u8; 64];
        loop {
            tokio::select! {
                r = ctrl.read(&mut ctrl_buf) => {
                    if matches!(r, Ok(0) | Err(_)) {
                        return Ok(());
                    }
                }
                r = relay.recv_from(&mut buf) => {
                    let (n, src) = match r {
                        Ok(r) => r,
                        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                        Err(e) => return Err(e),
                    };
                    // Only the client that opened the association may use it,
                    // and replies go to the first source it sent from.
                    if src.ip() != client_ip || client_addr.is_some_and(|a| a != src) {
                        continue;
                    }
                    client_addr = Some(src);
                    let Some((target, payload)) = parse_socks_udp(&buf[..n]) else { continue };
                    if sender.is_none() {
                        let session = self.client.udp(self.dial().await?)?;
                        let (receiver, tx) = session.into_split();
                        tokio::spawn(pump_replies(receiver, relay.clone(), src));
                        sender = Some(tx);
                    }
                    let tx = sender.as_mut().expect("session opened above");
                    tx.send_to(payload, &target).await?;
                }
            }
        }
    }
}

/// Server replies -> SOCKS5 client.
async fn pump_replies<R: tokio::io::AsyncRead + Unpin>(
    mut rx: opensnell::UdpReceiver<R>,
    relay: Arc<UdpSocket>,
    client: SocketAddr,
) {
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::with_capacity(65536);
    while let Ok((n, from)) = rx.recv_from(&mut buf).await {
        out.clear();
        out.extend_from_slice(&[0, 0, 0]);
        push_addr(&mut out, from);
        out.extend_from_slice(&buf[..n]);
        if relay.send_to(&out, client).await.is_err() {
            return;
        }
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Method negotiation, plus RFC 1929 username/password when configured.
async fn socks_auth(conn: &mut TcpStream, auth: Option<&(String, String)>) -> io::Result<()> {
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(invalid("not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    conn.read_exact(&mut methods).await?;
    let want = if auth.is_some() { 2 } else { 0 };
    if !methods.contains(&want) {
        conn.write_all(&[5, 0xff]).await?;
        return Err(invalid("no acceptable SOCKS5 method"));
    }
    conn.write_all(&[5, want]).await?;
    let Some((user, pass)) = auth else {
        return Ok(());
    };
    let mut ver = [0u8; 2];
    conn.read_exact(&mut ver).await?;
    let mut u = vec![0u8; usize::from(ver[1])];
    conn.read_exact(&mut u).await?;
    let mut plen = [0u8; 1];
    conn.read_exact(&mut plen).await?;
    let mut p = vec![0u8; usize::from(plen[0])];
    conn.read_exact(&mut p).await?;
    let ok = ver[0] == 1 && u == user.as_bytes() && p == pass.as_bytes();
    conn.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if ok {
        Ok(())
    } else {
        Err(invalid("SOCKS5 authentication failed"))
    }
}

async fn read_addr(conn: &mut TcpStream, atyp: u8) -> io::Result<Address> {
    let ip = match atyp {
        1 => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b).await?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        4 => {
            let mut b = [0u8; 16];
            conn.read_exact(&mut b).await?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        3 => {
            let len = conn.read_u8().await?;
            let mut host = vec![0u8; usize::from(len)];
            conn.read_exact(&mut host).await?;
            let port = conn.read_u16().await?;
            let host = String::from_utf8(host).map_err(|_| invalid("bad host name"))?;
            return Ok(Address::Domain(host, port));
        }
        _ => return Err(invalid("bad SOCKS5 address type")),
    };
    Ok(Address::Socket(SocketAddr::new(ip, conn.read_u16().await?)))
}

/// `05 rep 00 | addr | port`.
fn reply(rep: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![5, rep, 0];
    push_addr(
        &mut out,
        bound.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
    );
    out
}

fn push_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Parses a SOCKS5 UDP datagram (`00 00 frag | addr | port | data`);
/// fragments are dropped.
fn parse_socks_udp(p: &[u8]) -> Option<(Address, &[u8])> {
    if p.len() < 4 || p[2] != 0 {
        return None;
    }
    let (target, rest) = match p[3] {
        1 if p.len() >= 10 => {
            let ip: [u8; 4] = p[4..8].try_into().ok()?;
            (
                SocketAddr::from((ip, u16::from_be_bytes([p[8], p[9]]))).into(),
                &p[10..],
            )
        }
        4 if p.len() >= 22 => {
            let ip: [u8; 16] = p[4..20].try_into().ok()?;
            (
                SocketAddr::from((ip, u16::from_be_bytes([p[20], p[21]]))).into(),
                &p[22..],
            )
        }
        3 => {
            let len = usize::from(*p.get(4)?);
            let end = 5 + len;
            let host = std::str::from_utf8(p.get(5..end)?).ok()?.to_owned();
            let port = u16::from_be_bytes([*p.get(end)?, *p.get(end + 1)?]);
            (Address::Domain(host, port), p.get(end + 2..)?)
        }
        _ => return None,
    };
    Some((target, rest))
}
