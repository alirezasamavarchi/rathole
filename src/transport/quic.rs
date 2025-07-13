use super::{AddrMaybeCached, SocketOpts, Transport};
use crate::config::{TlsConfig, TransportConfig};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use std::fmt::{Debug, Formatter};
use std::io::{Error, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::Mutex;
use tokio_native_tls::native_tls::Certificate;

pub const ALPN_QUIC_TUNNEL: &[&[u8]] = &[b"qt"];
pub const DEFAULT_MAX_IDLE_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_KEEP_ALIVE_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_DATAGRAM_BUFFER_SIZE: usize = 65536;

pub struct QuicTransport {
    config: TlsConfig,
    client_crypto: Option<rustls::ClientConfig>,
}

impl Debug for QuicTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let client_crypto = self.client_crypto.as_ref().map(|_| "ClientConfig{}");
        f.debug_struct("QuicTransport")
            .field("config", &self.config)
            .field("client_crypto", &client_crypto)
            .finish()
    }
}

#[derive(Debug)]
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    fn from_tuple((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv)
            .poll_read(cx, buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_shutdown(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write_vectored(cx, bufs)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn is_write_vectored(&self) -> bool {
        self.send.is_write_vectored()
    }
}

#[async_trait]
impl Transport for QuicTransport {
    type Acceptor = Arc<Mutex<(quinn::Endpoint, quinn::Incoming)>>;
    type RawStream = (quinn::SendStream, quinn::RecvStream);
    type Stream = QuicStream;

    /// Creates a new QUIC transport with the given TLS configuration.
    async fn new(config: &TransportConfig) -> Result<Self> {
        let tls_config = config
            .tls
            .as_ref()
            .ok_or_else(|| anyhow!("Missing TLS configuration for QUIC transport"))?;

        let client_crypto = if let Some(trusted_root) = &tls_config.trusted_root {
            let cert_data = fs::read_to_string(trusted_root)
                .await
                .with_context(|| format!("Failed to read trusted root from {:?}", trusted_root))?;
            let cert = Certificate::from_pem(cert_data.as_bytes()).with_context(|| {
                format!("Failed to parse certificate from {:?}", trusted_root)
            })?;

            let mut roots = rustls::RootCertStore::empty();
            roots.add(&rustls::Certificate(cert.to_der().with_context(|| {
                "Could not encode trusted root certificate as DER"
            })?))
            .map_err(|e| anyhow!("Failed to add trusted root certificate: {}", e))?;

            let mut client_crypto = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_crypto.alpn_protocols = ALPN_QUIC_TUNNEL.iter().map(|&x| x.to_vec()).collect();
            Some(client_crypto)
        } else {
            None
        };

        Ok(QuicTransport {
            config: tls_config.clone(),
            client_crypto,
        })
    }

    /// Applies socket options to the QUIC stream (currently a no-op as QUIC does not use TCP).
    fn hint(_conn: &Self::Stream, _opts: SocketOpts) {
        // QUIC does not use TCP socket options, so this is a no-op.
    }

    /// Binds the QUIC transport to the specified address, returning an acceptor.
    async fn bind<A: ToSocketAddrs + Send + Sync>(&self, addr: A) -> Result<Self::Acceptor> {
        let pkcs12_path = self
            .config
            .pkcs12
            .as_ref()
            .ok_or_else(|| anyhow!("Missing PKCS12 file path in TLS configuration"))?;
        let pkcs12_password = self
            .config
            .pkcs12_password
            .as_ref()
            .ok_or_else(|| anyhow!("Missing PKCS12 password in TLS configuration"))?;

        let buf = fs::read(pkcs12_path)
            .await
            .with_context(|| format!("Failed to read PKCS12 file from {:?}", pkcs12_path))?;
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&buf)
            .with_context(|| format!("Failed to parse PKCS12 file from {:?}", pkcs12_path))?;
        let parsed = pkcs12
            .parse(pkcs12_password)
            .with_context(|| "Failed to decrypt PKCS12 file")?;

        let mut chain: Vec<rustls::Certificate> = parsed
            .chain
            .map_or_else(Vec::new, |c| {
                c.into_iter()
                    .map(|cert| rustls::Certificate(cert.to_der().unwrap()))
                    .rev()
                    .collect()
            });
        chain.insert(
            0,
            rustls::Certificate(
                parsed
                    .cert
                    .to_der()
                    .with_context(|| "Could not encode server certificate as DER")?,
            ),
        );

        let key = rustls::PrivateKey(
            parsed
                .pkey
                .private_key_to_der()
                .with_context(|| "Could not encode private key as DER")?,
        );

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| anyhow!("Invalid server certificate or key: {}", e))?;
        server_crypto.alpn_protocols = ALPN_QUIC_TUNNEL.iter().map(|&x| x.to_vec()).collect();

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.transport_config(Arc::new(
            quinn::TransportConfig::default()
                .datagram_receive_buffer_size(Some(DEFAULT_DATAGRAM_BUFFER_SIZE))
                .datagram_send_buffer_size(DEFAULT_DATAGRAM_BUFFER_SIZE)
                .max_idle_timeout(Some(
                    Duration::from_secs(DEFAULT_MAX_IDLE_TIMEOUT_SECS)
                        .try_into()
                        .map_err(|e| anyhow!("Invalid max idle timeout: {}", e))?,
                )),
        ));
        server_config.use_retry(true);

        let socket = UdpSocket::bind(&addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket to {:?}", addr))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket.into_std()?,
        )
        .with_context(|| "Failed to create QUIC endpoint")?;

        Ok(Arc::new(Mutex::new(endpoint)))
    }

    /// Accepts a new QUIC connection, returning a stream and the remote address.
    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        let mut guard = a.lock().await;
        let (_endpoint, incoming) = &mut *guard;
        let connecting = incoming
            .next()
            .await
            .ok_or_else(|| anyhow!("QUIC endpoint closed unexpectedly"))?;
        let addr = connecting.remote_address();
        let connection = connecting
            .await
            .with_context(|| "Failed to establish QUIC connection")?;
        let (send, recv) = connection
            .open_bi()
            .await
            .with_context(|| "Failed to open bidirectional stream")?;
        Ok(((send, recv), addr))
    }

    /// Performs a handshake on the raw QUIC stream (no-op for QUIC as handshake is handled by quinn).
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        Ok(QuicStream::from_tuple(conn))
    }

    /// Connects to a remote QUIC server at the specified address.
    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let socket_addr = addr
            .socket_addr
            .ok_or_else(|| anyhow!("Address {} not resolved", addr.addr))?;
        let hostname = self
            .config
            .hostname
            .as_ref()
            .ok_or_else(|| anyhow!("Missing hostname in TLS configuration"))?;

        let client_crypto = self
            .client_crypto
            .as_ref()
            .ok_or_else(|| anyhow!("Missing client TLS configuration"))?;
        let mut config = quinn::ClientConfig::new(Arc::new(client_crypto.clone()));
        config.transport_config(Arc::new(
            quinn::TransportConfig::default()
                .keep_alive_interval(Some(
                    Duration::from_secs(DEFAULT_KEEP_ALIVE_INTERVAL_SECS)
                        .try_into()
                        .map_err(|e| anyhow!("Invalid keep-alive interval: {}", e))?,
                ))
                .datagram_receive_buffer_size(Some(DEFAULT_DATAGRAM_BUFFER_SIZE))
                .datagram_send_buffer_size(DEFAULT_DATAGRAM_BUFFER_SIZE),
        ));

        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())
            .with_context(|| "Failed to open QUIC client socket")?;
        endpoint.set_default_client_config(config);

        let connection = endpoint
            .connect(socket_addr, hostname)
            .with_context(|| format!("Failed to connect to QUIC server at {}", addr))?;
        let new_conn = connection
            .await
            .with_context(|| format!("Failed to establish QUIC connection to {}", addr))?;
        let (send, recv) = new_conn
            .connection
            .open_bi()
            .await
            .with_context(|| format!("Failed to open bidirectional stream to {}", addr))?;

        Ok(QuicStream::from_tuple((send, recv)))
    }
}
