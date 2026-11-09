//! Client <-> server over loopback TCP, for every wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opensnell::server::{Identifier, IpPreference, code};
use opensnell::{
    Address, Client, ClientConfig, Error, Key, Mode, Obfs, ObfsMode, Pool, Server, ServerConfig,
    Version,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const V6_PSK: &str = "e2e-test-psk-0123456789";

fn keys() -> Vec<(Key, Obfs)> {
    let http = Obfs::Http {
        host: "bing.com".into(),
        port: 80,
    };
    let tls = Obfs::Tls {
        host: "bing.com".into(),
    };
    vec![
        (Key::v5("e2e-v5").unwrap(), Obfs::None),
        (Key::v5("e2e-v5").unwrap(), http),
        (Key::v5("e2e-v5").unwrap(), tls),
        (
            Key::new("e2e-v4", Version::V4, Mode::Default).unwrap(),
            Obfs::None,
        ),
        (Key::v6(V6_PSK, Mode::Default).unwrap(), Obfs::None),
        (Key::v6(V6_PSK, Mode::Unshaped).unwrap(), Obfs::None),
        (Key::v6(V6_PSK, Mode::UnsafeRaw).unwrap(), Obfs::None),
    ]
}

fn obfs_mode(o: &Obfs) -> ObfsMode {
    match o {
        Obfs::None => ObfsMode::None,
        Obfs::Http { .. } => ObfsMode::Http,
        Obfs::Tls { .. } => ObfsMode::Tls,
    }
}

async fn start_server(cfg: ServerConfig) -> SocketAddr {
    let server = Server::new(cfg).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move { server.serve(ln).await });
    addr
}

/// Echoes everything back, then half-closes when the client does.
async fn start_echo() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = ln.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    port
}

/// Sends `size` bytes to every connection, then closes.
async fn start_source(size: usize) -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = ln.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = s.write_all(&pattern(size)).await;
            });
        }
    });
    port
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

fn client(key: &Key, obfs: Obfs, reuse: bool) -> Client {
    Client::new(ClientConfig {
        key: key.clone(),
        obfs,
        reuse,
    })
    .unwrap()
}

/// Test fixtures listen on 127.0.0.1, so names must resolve to IPv4.
fn server_cfg(key: &Key, obfs: &Obfs) -> ServerConfig {
    let mut cfg = ServerConfig::new(key.clone());
    cfg.obfs = obfs_mode(obfs);
    if key.version() == Version::V6 {
        cfg.ip_preference = IpPreference::PreferIpv4;
    }
    cfg
}

#[tokio::test]
async fn tcp_echo_every_wire() {
    let echo = start_echo().await;
    for (key, obfs) in keys() {
        let server = start_server(server_cfg(&key, &obfs)).await;
        let c = client(&key, obfs.clone(), false);
        let tcp = TcpStream::connect(server).await.unwrap();
        let mut s = c.connect(tcp, "127.0.0.1", echo).await.unwrap();

        let data = pattern(3 << 20);
        let (mut r, mut w) = tokio::io::split(&mut s);
        let send = async {
            for chunk in data.chunks(40_000) {
                w.write_all(chunk).await.unwrap();
            }
            w.shutdown().await.unwrap(); // zero chunk: half-close
        };
        let mut got = Vec::new();
        let recv = r.read_to_end(&mut got);
        let (_, n) = tokio::join!(send, recv);
        n.unwrap();
        assert!(
            got == data,
            "{key:?} {obfs:?}: echo mismatch ({} of {} bytes)",
            got.len(),
            data.len()
        );
    }
}

#[tokio::test]
async fn bulk_download_every_wire() {
    let size = 16 << 20;
    let source = start_source(size).await;
    for (key, obfs) in keys() {
        let server = start_server(server_cfg(&key, &obfs)).await;
        let tcp = TcpStream::connect(server).await.unwrap();
        let mut s = client(&key, obfs.clone(), false)
            .connect(tcp, "localhost", source)
            .await
            .unwrap();
        let mut got = Vec::with_capacity(size);
        s.read_to_end(&mut got).await.unwrap();
        assert!(got == pattern(size), "{key:?} {obfs:?}");
    }
}

async fn first_read_error(key: &Key, server: SocketAddr, host: &str, port: u16) -> (u8, String) {
    let tcp = TcpStream::connect(server).await.unwrap();
    let mut s = client(key, Obfs::None, false)
        .connect(tcp, host, port)
        .await
        .unwrap();
    let err = s.read(&mut [0u8; 16]).await.unwrap_err();
    match Error::from_io(&err) {
        Some(Error::Server { code, message }) => (*code, message.clone()),
        other => panic!("expected a server error, got {other:?} ({err})"),
    }
}

#[tokio::test]
async fn server_error_codes() {
    let closed = {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ln.local_addr().unwrap().port()
    };
    let empty = start_source(0).await;

    let v6 = Key::v6(V6_PSK, Mode::Default).unwrap();
    let server = start_server(ServerConfig::new(v6.clone())).await;
    assert_eq!(
        first_read_error(&v6, server, "127.0.0.1", closed).await,
        (code::REFUSED, "connection refused".into())
    );
    // Skipped where the system resolver answers everything (fake-IP DNS).
    if tokio::net::lookup_host("no-such-host.invalid:80")
        .await
        .is_err()
    {
        assert_eq!(
            first_read_error(&v6, server, "no-such-host.invalid", 80).await,
            (code::DNS_FAILED, "DNS Failed".into())
        );
    }
    // v6 clients always send the reuse command, so a silent upstream is "Remote EOF".
    assert_eq!(
        first_read_error(&v6, server, "127.0.0.1", empty).await.0,
        code::REMOTE_EOF
    );

    let v5 = Key::v5("e2e-v5").unwrap();
    let server = start_server(ServerConfig::new(v5.clone())).await;
    assert_eq!(
        first_read_error(&v5, server, "127.0.0.1", empty).await,
        (code::EOF, "end of file".into())
    );
    // v5 defaults to IPv4 only and answers a disabled family with DNS Failed.
    assert_eq!(
        first_read_error(&v5, server, "::1", 80).await.0,
        code::DNS_FAILED
    );

    let mut cfg = ServerConfig::new(v6.clone());
    cfg.ip_preference = IpPreference::Ipv4Only;
    let server = start_server(cfg).await;
    assert_eq!(
        first_read_error(&v6, server, "::1", 80).await,
        (
            code::GENERIC,
            "IPv6 target is disabled by server configuration".into()
        )
    );
}

#[tokio::test]
async fn reuse_through_pool() {
    let echo = start_echo().await;
    for (key, max_sessions) in [
        (Key::v6(V6_PSK, Mode::Default).unwrap(), 5),
        (Key::v5("e2e-v5").unwrap(), 2),
    ] {
        let server = start_server(ServerConfig::new(key.clone())).await;
        let c = client(&key, Obfs::None, true);
        let pool: Pool<TcpStream> = Pool::new(&key);
        let mut dials = 0;
        for i in 0..5 {
            let mut s = match pool.take() {
                Some(idle) => c.reconnect(idle, "127.0.0.1", echo).await.unwrap(),
                None => {
                    dials += 1;
                    c.connect(TcpStream::connect(server).await.unwrap(), "127.0.0.1", echo)
                        .await
                        .unwrap()
                }
            };
            let msg = format!("session {i}");
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut got = vec![0; msg.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg.as_bytes());
            pool.release(s).await;
        }
        assert_eq!(dials, 5usize.div_ceil(max_sessions), "{key:?}");
    }
}

#[tokio::test]
async fn udp_every_wire() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    for (key, obfs) in keys() {
        let server = start_server(server_cfg(&key, &obfs)).await;
        let tcp = TcpStream::connect(server).await.unwrap();
        let mut udp = client(&key, obfs.clone(), false).udp(tcp).unwrap();
        if !key.version().is_v6() {
            // v5 servers drop datagrams that arrive with the session request.
            udp.send_to(b"warm-up", &Address::Socket(echo_addr))
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(300), udp.recv_from(&mut [0u8; 64]))
                .await;
        }
        for (i, target) in [
            Address::Socket(echo_addr),
            Address::Domain("localhost".into(), echo_addr.port()),
        ]
        .iter()
        .enumerate()
        {
            for j in 0..3 {
                let msg = format!("datagram {i}.{j}");
                udp.send_to(msg.as_bytes(), target).await.unwrap();
                let mut buf = [0u8; 64];
                let (n, from) =
                    tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&buf[..n], msg.as_bytes(), "{key:?} {obfs:?}");
                assert_eq!(from, echo_addr);
            }
        }
    }
}

#[tokio::test]
async fn many_keys_on_one_listener() {
    let echo = start_echo().await;
    let table: Vec<(Key, Arc<str>)> = (0..20)
        .map(|i| {
            (
                Key::v6(format!("user-{i:02}-psk-0123456789"), Mode::Default).unwrap(),
                Arc::from(format!("user-{i}")),
            )
        })
        .collect();
    let identifier: Arc<dyn Identifier> = Arc::new(table.clone());
    let server = start_server(ServerConfig::identify(
        identifier,
        ServerConfig::random_decoy(),
    ))
    .await;

    for (key, _) in [&table[3], &table[17]] {
        let tcp = TcpStream::connect(server).await.unwrap();
        let mut s = client(key, Obfs::None, false)
            .connect(tcp, "127.0.0.1", echo)
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }

    let stranger = Key::v6("not-in-the-table-0123", Mode::Default).unwrap();
    let tcp = TcpStream::connect(server).await.unwrap();
    let mut s = client(&stranger, Obfs::None, false)
        .connect(tcp, "127.0.0.1", echo)
        .await
        .unwrap();
    s.write_all(b"hello").await.unwrap();
    let res = tokio::time::timeout(Duration::from_secs(5), s.read(&mut [0u8; 5]))
        .await
        .unwrap();
    assert!(
        matches!(res, Ok(0) | Err(_)),
        "unknown key must be refused: {res:?}"
    );
}

#[tokio::test]
async fn wrong_psk_is_rejected() {
    let echo = start_echo().await;
    for (good, bad) in [
        (Key::v5("right").unwrap(), Key::v5("wrong").unwrap()),
        (
            Key::v6(V6_PSK, Mode::Default).unwrap(),
            Key::v6("another-psk-0123456789", Mode::Default).unwrap(),
        ),
        (
            Key::v6(V6_PSK, Mode::Unshaped).unwrap(),
            Key::v6("another-psk-0123456789", Mode::Unshaped).unwrap(),
        ),
    ] {
        let server = start_server(ServerConfig::new(good)).await;
        let tcp = TcpStream::connect(server).await.unwrap();
        let mut s = client(&bad, Obfs::None, false)
            .connect(tcp, "127.0.0.1", echo)
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), s.read(&mut [0u8; 5]))
            .await
            .unwrap();
        assert!(matches!(res, Ok(0) | Err(_)), "{res:?}");
    }
}
