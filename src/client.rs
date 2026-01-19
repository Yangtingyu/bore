//! Client implementation for the `bore` service.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tracing::{error, info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{ClientMessage, Delimited, ServerMessage, CONTROL_PORT, NETWORK_TIMEOUT};

/// State structure for the client.
pub struct Client {
    /// Control connection to the server.
    conn: Option<Delimited<TcpStream>>,

    /// Destination address of the server.
    to: String,

    // Local host that is forwarded.
    local_host: String,

    /// Local port that is forwarded.
    local_port: u16,

    /// Port that is publicly available on the remote.
    remote_port: u16,

    /// Optional secret used to authenticate clients.
    auth: Option<Authenticator>,

    /// Whether this client is acting as a SOCKS5 proxy.
    is_proxy: bool,

    /// Upstream SOCKS5 proxy (used to reach the bore server).
    upstream_proxy: Option<String>,
}

impl Client {
    /// Create a new client.
    pub async fn new(
        local_host: &str,
        local_port: u16,
        to: &str,
        port: u16,
        secret: Option<&str>,
        upstream_proxy: Option<&str>,
    ) -> Result<Self> {
        let mut stream = Delimited::new(connect_with_timeout(to, CONTROL_PORT, upstream_proxy).await?);
        let auth = secret.map(Authenticator::new);
        if let Some(auth) = &auth {
            auth.client_handshake(&mut stream).await?;
        }

        stream.send(ClientMessage::Hello(port)).await?;
        let remote_port = match stream.recv_timeout().await? {
            Some(ServerMessage::Hello(remote_port)) => remote_port,
            Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
            Some(ServerMessage::Challenge(_)) => {
                bail!("server requires authentication, but no client secret was provided");
            }
            Some(_) => bail!("unexpected initial non-hello message"),
            None => bail!("unexpected EOF"),
        };
        info!(remote_port, "connected to server");
        info!("listening at {to}:{remote_port}");

        Ok(Client {
            conn: Some(stream),
            to: to.to_string(),
            local_host: local_host.to_string(),
            local_port,
            remote_port,
            auth,
            is_proxy: false,
            upstream_proxy: upstream_proxy.map(|s| s.to_string()),
        })
    }

    /// Create a new client acting as a SOCKS5 proxy.
    pub async fn new_proxy(to: &str, port: u16, secret: Option<&str>, upstream_proxy: Option<&str>) -> Result<Self> {
        let mut stream = Delimited::new(connect_with_timeout(to, CONTROL_PORT, upstream_proxy).await?);
        let auth = secret.map(Authenticator::new);
        if let Some(auth) = &auth {
            auth.client_handshake(&mut stream).await?;
        }

        stream.send(ClientMessage::Hello(port)).await?;
        let remote_port = match stream.recv_timeout().await? {
            Some(ServerMessage::Hello(remote_port)) => remote_port,
            Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
            Some(ServerMessage::Challenge(_)) => {
                bail!("server requires authentication, but no client secret was provided");
            }
            Some(_) => bail!("unexpected initial non-hello message"),
            None => bail!("unexpected EOF"),
        };
        info!(remote_port, "connected to server in proxy mode");
        info!("SOCKS5 proxy listening at {to}:{remote_port}");

        Ok(Client {
            conn: Some(stream),
            to: to.to_string(),
            local_host: String::new(),
            local_port: 0,
            remote_port,
            auth,
            is_proxy: true,
            upstream_proxy: upstream_proxy.map(|s| s.to_string()),
        })
    }

    /// Returns the port publicly available on the remote.
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Start the client, listening for new connections.
    pub async fn listen(mut self) -> Result<()> {
        let mut conn = self.conn.take().unwrap();
        let this = Arc::new(self);
        loop {
            match conn.recv().await? {
                Some(ServerMessage::Hello(_)) => warn!("unexpected hello"),
                Some(ServerMessage::Challenge(_)) => warn!("unexpected challenge"),
                Some(ServerMessage::Heartbeat) => (),
                Some(ServerMessage::Connection(id)) => {
                    let this = Arc::clone(&this);
                    tokio::spawn(
                        async move {
                            info!("new connection");
                            match this.handle_connection(id).await {
                                Ok(_) => info!("connection exited"),
                                Err(err) => warn!(%err, "connection exited with error"),
                            }
                        }
                        .instrument(info_span!("proxy", %id)),
                    );
                }
                Some(ServerMessage::Error(err)) => error!(%err, "server error"),
                None => return Ok(()),
            }
        }
    }

    async fn handle_connection(&self, id: Uuid) -> Result<()> {
        let mut remote_conn =
            Delimited::new(connect_with_timeout(&self.to[..], CONTROL_PORT, self.upstream_proxy.as_deref()).await?);
        if let Some(auth) = &self.auth {
            auth.client_handshake(&mut remote_conn).await?;
        }
        remote_conn.send(ClientMessage::Accept(id)).await?;

        let mut parts = remote_conn.into_parts();
        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");

        if self.is_proxy {
            use std::io::Cursor;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Combine the pre-read buffer and the underlying IO stream
            let mut prefix = Cursor::new(parts.read_buf);
            let mut stream = parts.io;

            async fn read_full<R: tokio::io::AsyncRead + Unpin, P: tokio::io::AsyncRead + Unpin>(
                prefix: &mut P,
                stream: &mut R,
                buf: &mut [u8],
            ) -> Result<()> {
                let n = prefix.read(buf).await?;
                if n < buf.len() {
                    stream.read_exact(&mut buf[n..]).await?;
                }
                Ok(())
            }

            // --- Protocol Detection ---
            let mut first_byte = [0u8; 1];
            read_full(&mut prefix, &mut stream, &mut first_byte).await?;

            if first_byte[0] == 0x05 {
                // --- SOCKS5 Greeting ---
                let mut buf = [0u8; 1];
                read_full(&mut prefix, &mut stream, &mut buf).await?;
                let nmethods = buf[0] as usize;
                let mut methods = vec![0u8; nmethods];
                read_full(&mut prefix, &mut stream, &mut methods).await?;
                stream.write_all(&[0x05, 0x00]).await?; // No auth

                // --- SOCKS5 Request ---
                let mut buf = [0u8; 4];
                read_full(&mut prefix, &mut stream, &mut buf).await?;
                if buf[0] != 0x05 || buf[1] != 0x01 {
                    bail!("only CONNECT command is supported");
                }

                let address = match buf[3] {
                    0x01 => {
                        // IPv4
                        let mut addr = [0u8; 4];
                        read_full(&mut prefix, &mut stream, &mut addr).await?;
                        std::net::IpAddr::from(addr).to_string()
                    }
                    0x03 => {
                        // Domain name
                        let mut len_buf = [0u8; 1];
                        read_full(&mut prefix, &mut stream, &mut len_buf).await?;
                        let len = len_buf[0] as usize;
                        let mut domain = vec![0u8; len];
                        read_full(&mut prefix, &mut stream, &mut domain).await?;
                        String::from_utf8(domain)?
                    }
                    0x04 => {
                        // IPv6
                        let mut addr = [0u8; 16];
                        read_full(&mut prefix, &mut stream, &mut addr).await?;
                        std::net::IpAddr::from(addr).to_string()
                    }
                    _ => bail!("unsupported address type"),
                };
                
                let mut port_buf = [0u8; 2];
                read_full(&mut prefix, &mut stream, &mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);

                info!(%address, port, "SOCKS5 proxying connection");

                // --- Connect to target (through upstream proxy if available) ---
                match connect_with_timeout(address.as_str(), port, self.upstream_proxy.as_deref()).await {
                    Ok(mut target) => {
                        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                        tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
                    }
                    Err(_) => {
                        stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                    }
                }
            } else if (first_byte[0] >= b'A' && first_byte[0] <= b'Z') || (first_byte[0] >= b'a' && first_byte[0] <= b'z') {
                // --- HTTP Proxy ---
                let mut header = vec![first_byte[0]];
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 { break; }
                    header.extend_from_slice(&buf[..n]);
                    if header.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if header.len() > 8192 { bail!("header too large"); }
                }

                let header_str = String::from_utf8_lossy(&header);
                let first_line = header_str.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let url = parts.next().unwrap_or("");

                if method == "CONNECT" {
                    // HTTPS Proxy (CONNECT)
                    let host_port = url;
                    info!(%host_port, "HTTP CONNECT proxying");

                    let (host, port_str) = host_port.rsplit_once(':').unwrap_or((host_port, "443"));
                    let port = port_str.parse().unwrap_or(443);

                    match connect_with_timeout(host, port, self.upstream_proxy.as_deref()).await {
                        Ok(mut target) => {
                            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
                        }
                        Err(_) => {
                            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                        }
                    }
                } else {
                    // Normal HTTP Proxy
                    let url_obj = if url.starts_with("http://") {
                        &url[7..]
                    } else if url.starts_with("https://") {
                        &url[8..]
                    } else {
                        url
                    };
                    let host_path: Vec<&str> = url_obj.splitn(2, '/').collect();
                    let host_port = host_path[0];
                    let (host, port_str) = host_port.rsplit_once(':').unwrap_or((host_port, "80"));
                    let port = port_str.parse().unwrap_or(80);

                    info!(%host, port, "HTTP proxying message");
                    match connect_with_timeout(host, port, self.upstream_proxy.as_deref()).await {
                        Ok(mut target) => {
                            target.write_all(&header).await?;
                            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
                        }
                        Err(_) => {
                            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                        }
                    }
                }
            } else {
                bail!("unsupported protocol (first byte: 0x{:02x})", first_byte[0]);
            }
        } else {
            let mut local_conn = connect_with_timeout(&self.local_host, self.local_port, self.upstream_proxy.as_deref()).await?;
            local_conn.write_all(&parts.read_buf).await?; // mostly of the cases, this will be empty
            tokio::io::copy_bidirectional(&mut local_conn, &mut parts.io).await?;
        }
        Ok(())
    }
}

async fn connect_with_timeout(to: &str, port: u16, upstream_proxy: Option<&str>) -> Result<TcpStream> {
    if let Some(proxy) = upstream_proxy {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let proxy_stream = timeout(NETWORK_TIMEOUT, TcpStream::connect(proxy)).await??;
        let mut delimited = proxy_stream;

        // Simplified SOCKS5 Handshake for upstream
        delimited.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        delimited.read_exact(&mut resp).await?;
        
        // SOCKS5 Request
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        req.push(to.len() as u8);
        req.extend_from_slice(to.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        delimited.write_all(&req).await?;

        let mut status = [0u8; 4];
        delimited.read_exact(&mut status).await?;
        if status[1] != 0x00 {
            bail!("upstream proxy connection failed with status: 0x{:02x}", status[1]);
        }
        
        // Skip BND.ADDR and BND.PORT
        match status[3] {
            0x01 => { let mut buf = [0u8; 6]; delimited.read_exact(&mut buf).await?; }
            0x03 => {
                let len = delimited.read_u8().await?;
                let mut buf = vec![0u8; len as usize + 2];
                delimited.read_exact(&mut buf).await?;
            }
            0x04 => { let mut buf = [0u8; 18]; delimited.read_exact(&mut buf).await?; }
            _ => bail!("unsupported address type in proxy response"),
        }

        Ok(delimited)
    } else {
        match timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port))).await {
            Ok(res) => res,
            Err(err) => Err(err.into()),
        }
        .with_context(|| format!("could not connect to {to}:{port}"))
    }
}
