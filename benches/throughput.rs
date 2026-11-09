//! Download throughput through client -> server -> upstream over loopback TCP.

use std::net::SocketAddr;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use opensnell::{Client, ClientConfig, Key, Mode, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

const SIZE: usize = 64 << 20;

/// Upstream that sends SIZE bytes to every connection.
async fn source() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    tokio::spawn(async move {
        let chunk = vec![0x5au8; 256 * 1024];
        loop {
            let (mut s, _) = ln.accept().await.unwrap();
            let chunk = chunk.clone();
            tokio::spawn(async move {
                let mut left = SIZE;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if s.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    left -= n;
                }
            });
        }
    });
    port
}

async fn server(key: &Key) -> SocketAddr {
    let server = Server::new(ServerConfig::new(key.clone())).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move { server.serve(ln).await });
    addr
}

fn bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let src = rt.block_on(source());
    let mut group = c.benchmark_group("download");
    group.throughput(Throughput::Bytes(SIZE as u64));
    group.sample_size(10);
    let psk = "bench-psk-0123456789abcdef";
    for (name, key) in [
        ("v5", Key::v5(psk).unwrap()),
        ("v6-default", Key::v6(psk, Mode::Default).unwrap()),
        ("v6-unshaped", Key::v6(psk, Mode::Unshaped).unwrap()),
        ("v6-unsafe-raw", Key::v6(psk, Mode::UnsafeRaw).unwrap()),
    ] {
        let addr = rt.block_on(server(&key));
        let client = Client::new(ClientConfig::new(key)).unwrap();
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                let tcp = TcpStream::connect(addr).await.unwrap();
                tcp.set_nodelay(true).unwrap();
                let mut s = client.connect(tcp, "127.0.0.1", src).await.unwrap();
                let mut buf = vec![0u8; 256 * 1024];
                let mut total = 0;
                loop {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                assert_eq!(total, SIZE);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
