use crate::config::{ClientServiceConfig, ServerServiceConfig, TcpConfig, TransportConfig};
use crate::helper::{to_socket_addr, try_set_tcp_keepalive};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};
use tracing::{error, info, trace};

pub const DEFAULT_NODELAY: bool = true;
pub const DEFAULT_KEEPALIVE_SECS: u64 = 20;
pub const DEFAULT_KEEPALIVE_INTERVAL: u64 = 8;

#[derive(Clone)]
pub struct AddrMaybeCached {
    pub addr: String,
    pub socket_addr: Option<SocketAddr>,
}

impl AddrMaybeCached {
    /// Creates a new `AddrMaybeCached` with the given address string.
    pub fn new(addr: &str) -> AddrMaybeCached {
        AddrMaybeCached {
            addr: addr.to_string(),
            socket_addr: None,
        }
    }

    /// Resolves the address to a `SocketAddr`, caching the result if successful.
    /// Returns immediately if already resolved.
    pub async fn resolve(&mut self) -> Result<()> {
        if self.socket_addr.is_some() {
            trace!("Using cached socket address for {}", self.addr);
            return Ok(());
        }
        match to_socket_addr(&self.addr).await {
            Ok(s) => {
                trace!("Resolved address {} to {}", self.addr, s);
                self.socket_addr = Some(s);
                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("Failed to resolve address: {}", self.addr)),
        }
    }
}

impl Display for AddrMaybeCached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.socket_addr {
            Some(s) => f.write_fmt(format_args!("{}", s)),
            None => f.write_str(&self.addr),
        }
    }
}

/// Specifies a transport layer (e.g., TCP, TLS, QUIC) for network communication.
#[async_trait]
pub trait Transport: Debug + Send + Sync {
    type Acceptor: Send + Sync;
    type RawStream: Send + Sync;
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    /// Creates a new transport instance from the given configuration.
    fn new(config: &TransportConfig) -> Result<Self>
    where
        Self: Sized;

    /// Applies socket options to the given stream, if supported by the transport.
    fn hint(conn: &Self::Stream, opts: SocketOpts);

    /// Binds the transport to the specified address, returning an acceptor.
    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor>;

    /// Accepts a new connection from the acceptor. Must be cancel-safe.
    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)>;

    /// Performs a handshake on the raw stream to establish a secure connection, if applicable.
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream>;

    /// Establishes a connection to the specified address.
    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream>;
}

mod tcp;
pub use tcp::TcpTransport;

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!("Only one of `native-tls` or `rustls` can be enabled");

#[cfg(feature = "native-tls")]
mod native_tls;
#[cfg(feature = "native-tls")]
use native_tls as tls;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
use rustls as tls;

#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub use tls::TlsTransport;

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!("At least one TLS feature (`native-tls` or `rustls`) must be enabled for TlsTransport");

#[cfg(feature = "noise")]
mod noise;
#[cfg(feature = "noise")]
pub use noise::NoiseTransport;

#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
pub use quic::QuicTransport;

#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
mod websocket;
#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
pub use websocket::WebsocketTransport;

#[cfg(not(any(feature = "websocket-native-tls", feature = "websocket-rustls")))]
compile_error!("At least one WebSocket feature (`websocket-native-tls` or `websocket-rustls`) must be enabled for WebsocketTransport");

#[derive(Debug, Clone, Copy)]
struct Keepalive {
    pub keepalive_secs: u64,
    pub keepalive_interval: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SocketOpts {
    nodelay: Option<bool>,
    keepalive: Option<Keepalive>,
}

impl SocketOpts {
    /// Creates a `SocketOpts` with no changes to socket settings.
    fn none() -> SocketOpts {
        SocketOpts {
            nodelay: None,
            keepalive: None,
        }
    }

    /// Creates socket options optimized for the control channel.
    pub fn for_control_channel() -> SocketOpts {
        SocketOpts {
            nodelay: Some(true),
            keepalive: Some(Keepalive {
                keepalive_secs: DEFAULT_KEEPALIVE_SECS,
                keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            }),
        }
    }

    /// Creates socket options from a `TcpConfig`, ensuring valid keepalive settings.
    pub fn from_cfg(cfg: &TcpConfig) -> SocketOpts {
        let keepalive = if cfg.keepalive_secs > 0 && cfg.keepalive_interval > 0 {
            Some(Keepalive {
                keepalive_secs: cfg.keepalive_secs,
                keepalive_interval: cfg.keepalive_interval,
            })
        } else {
            None
        };
        SocketOpts {
            nodelay: Some(cfg.nodelay),
            keepalive,
        }
    }

    /// Creates socket options from a `ClientServiceConfig`.
    pub fn from_client_cfg(cfg: &ClientServiceConfig) -> SocketOpts {
        SocketOpts {
            nodelay: cfg.nodelay,
            ..SocketOpts::none()
        }
    }

    /// Creates socket options from a `ServerServiceConfig`.
    pub fn from_server_cfg(cfg: &ServerServiceConfig) -> SocketOpts {
        SocketOpts {
            nodelay: cfg.nodelay,
            ..SocketOpts::none()
        }
    }

    /// Applies the socket options to the given `TcpStream`.
    pub fn apply(&self, conn: &TcpStream) -> Result<()> {
        if let Some(v) = self.keepalive {
            self.apply_keepalive(conn, v)?;
        }
        if let Some(nodelay) = self.nodelay {
            self.apply_nodelay(conn, nodelay)?;
        }
        Ok(())
    }

    /// Applies TCP keepalive settings to the connection.
    fn apply_keepalive(&self, conn: &TcpStream, keepalive: Keepalive) -> Result<()> {
        let keepalive_duration = Duration::from_secs(keepalive.keepalive_secs);
        let keepalive_interval = Duration::from_secs(keepalive.keepalive_interval);
        try_set_tcp_keepalive(conn, keepalive_duration, keepalive_interval)
            .with_context(|| "Failed to set TCP keepalive")?;
        info!(
            "Set keepalive: secs={}, interval={}",
            keepalive.keepalive_secs, keepalive.keepalive_interval
        );
        Ok(())
    }

    /// Applies TCP nodelay setting to the connection.
    fn apply_nodelay(&self, conn: &TcpStream, nodelay: bool) -> Result<()> {
        conn.set_nodelay(nodelay)
            .with_context(|| "Failed to set TCP nodelay")?;
        info!("Set nodelay: {}", nodelay);
        Ok(())
    }
}
