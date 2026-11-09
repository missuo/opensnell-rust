//! Interop with the Go reference implementation (opensnell). Skipped unless
//! `OPENSNELL_GO_BIN` names a directory holding its `snell-server` and
//! `snell-client` binaries.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use opensnell::{
    Address, Client, ClientConfig, Key, Mode, Obfs, ObfsMode, Pool, Server, ServerConfig, Version,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct Case {
    version: &'static str,
    mode: &'static str,
    obfs: &'static str,
}

const CASES: &[Case] = &[
    Case {
        version: "v5",
        mode: "",
        obfs: "off",
    },
    Case {
        version: "v5",
        mode: "",
        obfs: "http",
    },
    Case {
        version: "v5",
        mode: "",
        obfs: "tls",
    },
    Case {
        version: "v6",
        mode: "default",
        obfs: "off",
    },
    Case {
        version: "v6",
        mode: "unshaped",
        obfs: "off",
    },
    Case {
        version: "v6",
        mode: "unsafe-raw",
        obfs: "off",
    },
];

const PSK: &str = "InteropPSK-0123456789abcdef";

fn go_bin() -> Option<PathBuf> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    std::env::var_os("OPENSNELL_GO_BIN").map(PathBuf::from)
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_listening(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} never opened");
}

fn spawn(bin: PathBuf, args: &[&str], conf: String) -> Proc {
    let dir = std::env::temp_dir().join(format!("opensnell-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.conf", free_port()));
    std::fs::write(&path, conf).unwrap();
    let mut cmd = Command::new(bin);
    let log = if std::env::var_os("OPENSNELL_GO_LOG").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    cmd.arg("-c")
        .arg(&path)
        .args(args)
        .stdout(Stdio::null())
        .stderr(log);
    Proc(cmd.spawn().unwrap())
}

fn key(c: &Case) -> Key {
    Key::new(
        PSK,
        c.version.parse::<Version>().unwrap(),
        c.mode.parse::<Mode>().unwrap(),
    )
    .unwrap()
}

fn obfs(c: &Case, port: u16) -> Obfs {
    match c.obfs {
        "http" => Obfs::Http {
            host: "bing.com".into(),
            port,
        },
        "tls" => Obfs::Tls {
            host: "bing.com".into(),
        },
        _ => Obfs::None,
    }
}

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

async fn start_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect()
}

async fn echo_round_trip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    size: usize,
) {
    let data = pattern(size);
    let (mut r, mut w) = tokio::io::split(s);
    let send = async {
        for chunk in data.chunks(64 * 1024) {
            w.write_all(chunk).await.unwrap();
        }
        w.shutdown().await.unwrap();
    };
    let mut got = Vec::new();
    let (_, res) = tokio::join!(send, r.read_to_end(&mut got));
    res.unwrap();
    assert!(
        got == data,
        "echo mismatch: {} of {} bytes",
        got.len(),
        data.len()
    );
}

/// Our client against the Go server: TCP echo, a bulk echo, reuse and UDP.
#[tokio::test(flavor = "multi_thread")]
async fn rust_client_go_server() {
    let Some(bin) = go_bin() else { return };
    let echo = start_echo().await;
    let udp_echo = start_udp_echo().await;
    // Like snell-server v5.0.1, the Go server CLI serves only HTTP obfs and
    // runs `obfs = tls` without obfuscation.
    for c in CASES.iter().filter(|c| c.obfs != "tls") {
        let port = free_port();
        let conf = format!(
            "[snell-server]\nlisten = 127.0.0.1:{port}\npsk = {PSK}\nobfs = {}\nmode = {}\nipv6 = true\nudp = true\n",
            c.obfs, c.mode
        );
        let args: &[&str] = if c.version == "v6" { &["--v6"] } else { &[] };
        let _server = spawn(
            bin.join("snell-server"),
            &[args, &["-l", "verbose"]].concat(),
            conf,
        );
        wait_listening(port).await;

        let key = key(c);
        let label = format!("{} {} {}", c.version, c.mode, c.obfs);
        let client = Client::new(ClientConfig {
            key: key.clone(),
            obfs: obfs(c, port),
            reuse: true,
        })
        .unwrap();

        for size in [100, 4 << 20] {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut s = client.connect(tcp, "127.0.0.1", echo).await.unwrap();
            echo_round_trip(&mut s, size).await;
        }

        // Reuse: several sessions over pooled connections.
        let pool: Pool<TcpStream> = Pool::new(&key);
        for i in 0..4 {
            let mut s = match pool.take() {
                Some(idle) => client.reconnect(idle, "127.0.0.1", echo).await.unwrap(),
                None => client
                    .connect(
                        TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
                        "127.0.0.1",
                        echo,
                    )
                    .await
                    .unwrap(),
            };
            let msg = format!("{label} session {i}");
            s.write_all(msg.as_bytes()).await.unwrap();
            let mut got = vec![0; msg.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg.as_bytes(), "{label}");
            pool.release(s).await;
        }

        // UDP (obfs is not applied to UDP sessions by the Go server either).
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut udp = client.udp(tcp).unwrap();
        let target = Address::Socket(udp_echo);
        let mut ok = 0;
        for i in 0..6 {
            let msg = format!("{label} datagram {i}");
            udp.send_to(msg.as_bytes(), &target).await.unwrap();
            let mut buf = [0u8; 256];
            if let Ok(r) =
                tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut buf)).await
            {
                let (n, from) = r.unwrap();
                assert_eq!(&buf[..n], msg.as_bytes(), "{label}");
                assert_eq!(from, udp_echo, "{label}");
                ok += 1;
            }
        }
        // v5 drops the datagram sent with the session request.
        assert!(ok >= 5, "{label}: {ok} of 6 datagrams echoed");
        eprintln!("rust client -> go server ok: {label}");
    }
}

/// SOCKS5 CONNECT to 127.0.0.1:`port` through a local SOCKS5 proxy.
async fn socks_connect(proxy: u16, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "SOCKS5 connect failed");
    s
}

/// The Go client (through its SOCKS5 entry) against our server.
#[tokio::test(flavor = "multi_thread")]
async fn go_client_rust_server() {
    let Some(bin) = go_bin() else { return };
    let echo = start_echo().await;
    for c in CASES {
        let key = key(c);
        let mut cfg = ServerConfig::new(key.clone());
        cfg.obfs = c.obfs.parse::<ObfsMode>().unwrap();
        let server = Server::new(cfg).unwrap();
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = ln.local_addr().unwrap().port();
        tokio::spawn(async move { server.serve(ln).await });

        let label = format!("{} {} {}", c.version, c.mode, c.obfs);
        for reuse in [false, true] {
            let socks = free_port();
            let conf = format!(
                "[snell-client]\nlisten = 127.0.0.1:{socks}\nserver = 127.0.0.1:{server_port}\npsk = {PSK}\nversion = {}\nmode = {}\nobfs = {}\nobfs-host = bing.com\nreuse = {reuse}\n",
                c.version, c.mode, c.obfs
            );
            let _client = spawn(bin.join("snell-client"), &["-v"], conf);
            wait_listening(socks).await;
            for size in [100, 4 << 20, 1000, 1000] {
                let mut s = socks_connect(socks, echo).await;
                // Read the whole echo before half-closing: the Go client's
                // HalfClose resets its response parser, so a half-close
                // while the response is still arriving breaks the Go client
                // whatever the server (Go or Rust).
                let data = pattern(size);
                let (mut r, mut w) = s.split();
                let send = async { w.write_all(&data).await.unwrap() };
                let mut got = vec![0; size];
                let (_, res) = tokio::join!(send, r.read_exact(&mut got));
                res.unwrap();
                assert!(got == data, "{label}: echo mismatch");
                w.shutdown().await.unwrap();
                assert_eq!(
                    r.read(&mut [0u8; 1]).await.unwrap(),
                    0,
                    "{label}: expected EOF"
                );
            }
        }
        eprintln!("go client -> rust server ok: {label}");
    }
}
