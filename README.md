# opensnell

Snell proxy protocol for Rust and tokio: client and server, v4/v5 and v6.

- **v6.0.0** in all three modes: `default` (PSK-derived traffic shaping, byte-for-byte what the official server and Surge put on the wire), `unshaped` and `unsafe-raw`
- **v4/v5**, with `http`/`tls` obfs and the v5 QUIC proxy mode
- TCP tunnels, UDP over TCP, connection reuse
- Works over any `AsyncRead + AsyncWrite` transport, so it slots into an existing proxy
- Server: pluggable outbound, many PSKs on one v6 listener

## Install

```toml
[dependencies]
opensnell = { git = "https://github.com/missuo/opensnell-rust" }
```

AES-GCM comes from `aws-lc-rs` by default; use `default-features = false, features = ["ring"]` for `ring`.

## Client

The client does not dial. Connect to the server yourself and hand over the connection:

```rust
use opensnell::{Client, ClientConfig, Key, Mode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

let key = Key::v6("my-pre-shared-key", Mode::Default)?;
let client = Client::new(ClientConfig::new(key))?;

let tcp = tokio::net::TcpStream::connect("203.0.113.1:6160").await?;
let mut stream = client.connect(tcp, "example.com", 80).await?;
stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
let mut page = Vec::new();
stream.read_to_end(&mut page).await?;
```

The stream is `AsyncRead + AsyncWrite`. `shutdown()` sends Snell's half-close and keeps reading. If the server refuses the request, the first read fails with `opensnell::Error::Server { code, message }` (use `Error::from_io`).

UDP:

```rust
use opensnell::Address;

let tcp = tokio::net::TcpStream::connect("203.0.113.1:6160").await?;
let mut udp = client.udp(tcp)?;
udp.send_to(b"query", &Address::Domain("dns.google".into(), 53)).await?;
let mut buf = [0u8; 2048];
let (n, from) = udp.recv_from(&mut buf).await?;
```

Reuse (`ClientConfig { reuse: true, .. }` on v4/v5; v6 always asks for it):

```rust
let pool = opensnell::Pool::new(client.key());
let stream = match pool.take() {
    Some(idle) => client.reconnect(idle, "example.com", 443).await?,
    None => client.connect(dial().await?, "example.com", 443).await?,
};
// ...
pool.release(stream).await;
```

v4/v5 obfs: set `ClientConfig::obfs` to `Obfs::Http { host, port }` or `Obfs::Tls { host }`.

## Server

```rust
use opensnell::{Key, Server, ServerConfig};

let server = Server::new(ServerConfig::new(Key::v5("my-pre-shared-key")?))?;
server.serve(tokio::net::TcpListener::bind("0.0.0.0:6160").await?).await?;
```

`ServerConfig` covers obfs, UDP, `dns-ip-preference` and timeouts, with the official server's defaults. To route upstream traffic elsewhere, implement `server::Outbound` and use `Server::with_outbound`. To serve many v6 PSKs on one port, use `ServerConfig::identify` with a `server::Identifier`. It picks the key from the first 32 bytes of each connection before doing any key derivation. `Server::serve_connection` serves a connection you accepted yourself.

## Examples

```sh
cargo run --release --example server -- 0.0.0.0:6160 <psk> v6
cargo run --release --example client -- 127.0.0.1:6160 <psk> example.com v6
```

## Tests

```sh
cargo test
cargo bench
```

`tests/interop.rs` runs against the Go [opensnell](https://github.com/missuo/opensnell) binaries when `OPENSNELL_GO_BIN` points at a directory holding `snell-server` and `snell-client`.

## License

GPL-3.0-or-later. Ported from [opensnell](https://github.com/missuo/opensnell).
