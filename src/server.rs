use crate::config::{Config, ServerConfig, ServerServiceConfig, ServiceType, TransportType};
use crate::config_watcher::{ConfigChange, ServerServiceChange};
use crate::constants::{listen_backoff, UDP_BUFFER_SIZE};
use crate::helper::{retry_notify_with_deadline, write_and_flush};
use crate::multi_map::MultiMap;
use crate::protocol::Hello::{ControlChannelHello, DataChannelHello};
use crate::protocol::{
    self, read_auth, read_hello, Ack, ControlChannelCmd, DataChannelCmd, Hello, UdpTraffic,
    HASH_WIDTH_IN_BYTES,
};
use crate::transport::{SocketOpts, TcpTransport, QuicTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::ExponentialBackoff;
use dashmap::DashMap;
use rand::RngCore;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc};
use tokio::time;
use tracing::{debug, error, info, info_span, warn, instrument, Span};
use backoff::backoff::Backoff;

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use crate::transport::TlsTransport;
#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
use crate::transport::WebsocketTransport;

const TCP_POOL_SIZE: usize = 8; // Number of cached TCP connections
const UDP_POOL_SIZE: usize = 2; // Number of cached UDP connections
const CHAN_SIZE: usize = 2048; // Channel capacity for mpsc channels
const HANDSHAKE_TIMEOUT_SECS: u64 = 5; // Timeout for transport handshake

/// Entry point for running the server with the specified transport type.
pub async fn run_server(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = config
        .server
        .ok_or_else(|| anyhow!("Missing [server] configuration block"))?;

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut server = Server::<TcpTransport>::from(config).await?;
            server.run(shutdown_rx, update_rx).await?;
        }
        TransportType::Tls => {
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            {
                let mut server = Server::<TlsTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
            crate::helper::feature_neither_compile("native-tls", "rustls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut server = Server::<NoiseTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Quic => {
            #[cfg(feature = "quic")]
            {
                let mut server = Server::<QuicTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "quic"))]
            crate::helper::feature_not_compile("quic")
        }
        TransportType::Websocket => {
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            {
                let mut server = Server::<WebsocketTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(any(feature = "websocket-native-tls", feature = "websocket-rustls")))]
            crate::helper::feature_neither_compile("websocket-native-tls", "websocket-rustls")
        }
    }

    Ok(())
}

/// A hash map of control channels, indexed by ServiceDigest or Nonce.
type ControlChannelMap<T> = MultiMap<ServiceDigest, Nonce, ControlChannelHandle<T>>;

/// Server state, managing services and control channels.
struct Server<T: Transport> {
    config: Arc<ServerConfig>,
    services: Arc<DashMap<ServiceDigest, ServerServiceConfig>>,
    control_channels: Arc<DashMap<ServiceDigest, ControlChannelMap<T>>>,
    transport: Arc<T>,
}

/// Generates a hash map of services indexed by their digest.
fn generate_service_hashmap(
    server_config: &ServerConfig,
) -> DashMap<ServiceDigest, ServerServiceConfig> {
    let map = DashMap::new();
    for (name, cfg) in &server_config.services {
        map.insert(protocol::digest(name.as_bytes()), cfg.clone());
    }
    map
}

impl<T: 'static + Transport> Server<T> {
    /// Creates a new server instance from the server configuration.
    pub async fn from(config: ServerConfig) -> Result<Self> {
        let config = Arc::new(config);
        let services = Arc::new(generate_service_hashmap(&config));
        let control_channels = Arc::new(DashMap::new());
        let transport = Arc::new(T::new(&config.transport)?);
        Ok(Server {
            config,
            services,
            control_channels,
            transport,
        })
    }

    /// Runs the server, listening for connections and handling config updates.
    #[instrument(skip_all, fields(bind_addr = %self.config.bind_addr))]
    pub async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        let acceptor = self
            .transport
            .bind(&self.config.bind_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.config.bind_addr))?;
        info!("Listening at {}", self.config.bind_addr);

        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_millis(100),
            max_elapsed_time: None,
            ..Default::default()
        };

        loop {
            tokio::select! {
                ret = self.transport.accept(&acceptor) => {
                    match ret {
                        Ok((conn, addr)) => {
                            backoff.reset();
                            self.handle_connection(conn, addr).await;
                        }
                        Err(err) => {
                            if let Some(io_err) = err.downcast_ref::<io::Error>() {
                                if let Some(d) = backoff.next_backoff() {
                                    error!("Accept failed: {}. Retrying in {:?}", io_err, d);
                                    time::sleep(d).await;
                                } else {
                                    error!("Too many retries. Aborting...");
                                    return Err(err);
                                }
                            } else {
                                warn!("Transport error: {}", err);
                            }
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down gracefully...");
                    break;
                }
                Some(change) = update_rx.recv() => {
                    self.handle_hot_reload(change).await;
                }
            }
        }

        info!("Server shutdown");
        Ok(())
    }

    /// Handles a new connection with a timeout for the transport handshake.
    async fn handle_connection(&self, conn: T::RawStream, addr: SocketAddr) {
        match time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), self.transport.handshake(conn)).await {
            Ok(Ok(conn)) => {
                let services = self.services.clone();
                let control_channels = self.control_channels.clone();
                let server_config = self.config.clone();
                tokio::spawn(
                    async move {
                        if let Err(err) = handle_connection(conn, services, control_channels, server_config).await {
                            error!("Connection error from {}: {:#}", addr, err);
                        }
                    }
                    .instrument(info_span!("connection", %addr)),
                );
            }
            Ok(Err(err)) => error!("Transport handshake failed: {:#}", err),
            Err(err) => error!("Transport handshake timeout: {}", err),
        }
    }

    /// Handles configuration updates for hot reloading.
    async fn handle_hot_reload(&self, change: ConfigChange) {
        match change {
            ConfigChange::ServerChange(server_change) => match server_change {
                ServerServiceChange::Add(cfg) => {
                    let hash = protocol::digest(cfg.name.as_bytes());
                    self.services.insert(hash, cfg.clone());
                    self.control_channels.remove(&hash);
                    info!("Added service: {}", cfg.name);
                }
                ServerServiceChange::Delete(name) => {
                    let hash = protocol::digest(name.as_bytes());
                    self.services.remove(&hash);
                    self.control_channels.remove(&hash);
                    info!("Deleted service: {}", name);
                }
            },
            other => warn!("Ignored config change: {:?}", other),
        }
    }
}

/// Handles incoming connections, determining if they are control or data channels.
async fn handle_connection<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<DashMap<ServiceDigest, ServerServiceConfig>>,
    control_channels: Arc<DashMap<ServiceDigest, ControlChannelMap<T>>>,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    let hello = read_hello(&mut conn)
        .await
        .with_context(|| "Failed to read hello message")?;
    match hello {
        ControlChannelHello(_, service_digest) => {
            do_control_channel_handshake(conn, services, control_channels, service_digest, server_config)
                .await
                .with_context(|| "Control channel handshake failed")?;
        }
        DataChannelHello(_, nonce) => {
            do_data_channel_handshake(conn, control_channels, nonce)
                .await
                .with_context(|| "Data channel handshake failed")?;
        }
    }
    Ok(())
}

/// Performs handshake for a control channel, authenticating the client.
async fn do_control_channel_handshake<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<DashMap<ServiceDigest, ServerServiceConfig>>,
    control_channels: Arc<DashMap<ServiceDigest, ControlChannelMap<T>>>,
    service_digest: ServiceDigest,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    info!("Initiating control channel handshake");

    T::hint(&conn, SocketOpts::for_control_channel());

    let mut nonce = vec![0u8; HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_digest = nonce.clone().try_into().map_err(|_| {
        anyhow!("Failed to convert nonce to digest: invalid length")
    })?;

    let hello_send = Hello::ControlChannelHello(protocol::CURRENT_PROTO_VERSION, nonce_digest);
    let hello_data = bincode::serialize(&hello_send)
        .map_err(|e| anyhow!("Failed to serialize hello message: {}", e))?;
    write_and_flush(&mut conn, &hello_data)
        .await
        .with_context(|| "Failed to send hello message")?;

    let service_config = services
        .get(&service_digest)
        .ok_or_else(|| anyhow!("Service {} not found", hex::encode(service_digest)))?
        .clone();
    let service_name = &service_config.name;

    let mut concat = Vec::from(service_config.token.as_ref().ok_or_else(|| {
        anyhow!("Missing token in service configuration for {}", service_name)
    })?.as_bytes());
    concat.extend(&nonce);

    let protocol::Auth(d) = read_auth(&mut conn)
        .await
        .with_context(|| "Failed to read auth message")?;

    let session_key = protocol::digest(&concat);
    if session_key != d {
        let ack_data = bincode::serialize(&Ack::AuthFailed)
            .map_err(|e| anyhow!("Failed to serialize AuthFailed: {}", e))?;
        write_and_flush(&mut conn, &ack_data)
            .await
            .with_context(|| "Failed to send auth failed response")?;
        bail!(
            "Authentication failed for service {}: expected {}, got {}",
            service_name,
            hex::encode(session_key),
            hex::encode(d)
        );
    }

    let ack_data = bincode::serialize(&Ack::Ok)
        .map_err(|e| anyhow!("Failed to serialize Ack::Ok: {}", e))?;
    write_and_flush(&mut conn, &ack_data)
        .await
        .with_context(|| "Failed to send auth success response")?;

    let mut channels = control_channels
        .entry(service_digest)
        .or_insert_with(ControlChannelMap::new);
    if channels.remove1(&service_digest).is_some() {
        warn!("Dropped previous control channel for service {}", service_name);
    }

    info!("Control channel established for service {}", service_name);
    let handle = ControlChannelHandle::new(conn, service_config, server_config.heartbeat_interval);
    channels.insert(service_digest, session_key, handle);

    Ok(())
}

/// Performs handshake for a data channel, forwarding it to the appropriate control channel.
async fn do_data_channel_handshake<T: 'static + Transport>(
    conn: T::Stream,
    control_channels: Arc<DashMap<ServiceDigest, ControlChannelMap<T>>>,
    nonce: Nonce,
) -> Result<()> {
    info!("Initiating data channel handshake");

    let handle = control_channels
        .iter()
        .find_map(|entry| entry.value().get2(&nonce))
        .ok_or_else(|| anyhow!("Invalid nonce for data channel"))?;

    T::hint(&conn, SocketOpts::from_server_cfg(&handle.service));

    handle
        .data_ch_tx
        .send(conn)
        .await
        .map_err(|_| anyhow!("Failed to send data channel: control channel closed"))?;

    Ok(())
}

/// Handle for a control channel, managing its lifecycle and data channels.
pub struct ControlChannelHandle<T: Transport> {
    _shutdown_tx: broadcast::Sender<bool>,
    data_ch_tx: mpsc::Sender<T::Stream>,
    service: ServerServiceConfig,
}

impl<T: 'static + Transport> ControlChannelHandle<T> {
    /// Creates a new control channel handle, spawning tasks for connection pooling.
    #[instrument(name = "control_channel", skip_all, fields(service = %service.name))]
    fn new(
        conn: T::Stream,
        service: ServerServiceConfig,
        heartbeat_interval: u64,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<bool>(1);
        let (data_ch_tx, data_ch_rx) = mpsc::channel(CHAN_SIZE * 2);
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::unbounded_channel();

        let pool_size = match service.service_type {
            ServiceType::Tcp => TCP_POOL_SIZE,
            ServiceType::Udp => UDP_POOL_SIZE,
        };

        for _ in 0..pool_size {
            if data_ch_req_tx.send(true).is_err() {
                error!("Failed to request initial data channel for {}", service.name);
            }
        }

        let bind_addr = service.bind_addr.clone();
        match service.service_type {
            ServiceType::Tcp => {
                tokio::spawn(
                    async move {
                        if let Err(e) = run_tcp_connection_pool::<T>(
                            bind_addr,
                            data_ch_rx,
                            data_ch_req_tx,
                            shutdown_rx,
                        )
                        .await
                        .with_context(|| format!("TCP connection pool failed for {}", service.name))
                        {
                            error!("{:#}", e);
                        }
                    }
                    .instrument(Span::current()),
                );
            }
            ServiceType::Udp => {
                tokio::spawn(
                    async move {
                        if let Err(e) = run_udp_connection_pool::<T>(
                            bind_addr,
                            data_ch_rx,
                            data_ch_req_tx,
                            shutdown_rx,
                        )
                        .await
                        .with_context(|| format!("UDP connection pool failed for {}", service.name))
                        {
                            error!("{:#}", e);
                        }
                    }
                    .instrument(Span::current()),
                );
            }
        }

        tokio::spawn(
            async move {
                let ch = ControlChannel::<T> {
                    conn,
                    shutdown_rx,
                    data_ch_req_rx,
                    heartbeat_interval,
                };
                if let Err(err) = ch.run().await {
                    error!("Control channel error: {:#}", err);
                }
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle {
            _shutdown_tx: shutdown_tx,
            data_ch_tx,
            service,
        }
    }
}

/// Control channel for managing data channel requests and heartbeats.
struct ControlChannel<T: Transport> {
    conn: T::Stream,
    shutdown_rx: broadcast::Receiver<bool>,
    data_ch_req_rx: mpsc::UnboundedReceiver<bool>,
    heartbeat_interval: u64,
}

impl<T: 'static + Transport> ControlChannel<T> {
    /// Writes and flushes data to the control channel.
    async fn write_and_flush(&mut self, data: &[u8]) -> Result<()> {
        write_and_flush(&mut self.conn, data)
            .await
            .with_context(|| "Failed to write and flush control channel data")?;
        Ok(())
    }

    /// Runs the control channel, handling data channel requests and heartbeats.
    #[instrument(skip_all)]
    async fn run(mut self) -> Result<()> {
        let create_ch_cmd = bincode::serialize(&ControlChannelCmd::CreateDataChannel)
            .map_err(|e| anyhow!("Failed to serialize CreateDataChannel: {}", e))?;
        let heartbeat = bincode::serialize(&ControlChannelCmd::HeartBeat)
            .map_err(|e| anyhow!("Failed to serialize HeartBeat: {}", e))?;

        loop {
            tokio::select! {
                Some(_) = self.data_ch_req_rx.recv() => {
                    if let Err(e) = self.write_and_flush(&create_ch_cmd).await {
                        error!("Failed to send data channel request: {:#}", e);
                        break;
                    }
                }
                _ = time::sleep(Duration::from_secs(self.heartbeat_interval)), if self.heartbeat_interval != 0 => {
                    if let Err(e) = self.write_and_flush(&heartbeat).await {
                        error!("Failed to send heartbeat: {:#}", e);
                        break;
                    }
                }
                _ = self.shutdown_rx.recv() => {
                    info!("Control channel shutting down");
                    break;
                }
                else => break,
            }
        }

        Ok(())
    }
}

/// Listens for TCP connections and forwards them to the connection pool.
fn tcp_listen_and_send(
    addr: String,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> mpsc::Receiver<TcpStream> {
    let (tx, rx) = mpsc::channel(CHAN_SIZE);

    tokio::spawn(
        async move {
            let listener = retry_notify_with_deadline(
                listen_backoff(),
                || async { Ok(TcpListener::bind(&addr).await?) },
                |e, duration| error!("Failed to bind TCP listener to {}: {:#}. Retrying in {:?}", addr, e, duration),
                &mut shutdown_rx,
            )
            .await
            .with_context(|| format!("Failed to bind TCP listener to {}", addr));

            let listener = match listener {
                Ok(listener) => listener,
                Err(e) => {
                    error!("{:#}", e);
                    return;
                }
            };

            info!("TCP listener started at {}", addr);

            let mut backoff = ExponentialBackoff {
                max_interval: Duration::from_secs(1),
                max_elapsed_time: None,
                ..Default::default()
            };

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                backoff.reset();
                                debug!("New TCP connection from {}", addr);
                                if data_ch_req_tx.send(true).is_err() {
                                    error!("Failed to request data channel: control channel closed");
                                    break;
                                }
                                if tx.send(stream).await.is_err() {
                                    error!("Failed to send TCP stream to pool: receiver closed");
                                    break;
                                }
                            }
                            Err(e) => {
                                if let Some(d) = backoff.next_backoff() {
                                    error!("Accept failed: {}. Retrying in {:?}", e, d);
                                    time::sleep(d).await;
                                } else {
                                    error!("Too many retries. Aborting...");
                                    break;
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("TCP listener shutting down");
                        break;
                    }
                }
            }
        }
        .instrument(Span::current()),
    );

    rx
}

/// Runs a connection pool for TCP services.
#[instrument(skip_all)]
// src/server.rs
async fn run_tcp_connection_pool<T: 'static + Transport>(
    &self,
    shutdown_rx: &mut broadcast::Receiver<bool>,
) -> Result<()> {
    let mut visitor_rx = tcp_listen_and_send(bind_addr, data_ch_req_tx.clone(), shutdown_rx);

    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp)
        .map_err(|e| anyhow!("Failed to serialize StartForwardTcp: {}", e))?;

    while let Some(mut visitor) = visitor_rx.recv().await {
        loop {
            tokio::select! {
                Some(mut ch) = data_ch_rx.recv() => {
                    if write_and_flush(&mut ch, &cmd).await.is_ok() {
                        tokio::spawn(async move {
                            if let Err(e) = copy_bidirectional(&mut ch, &mut visitor).await {
                                error!("TCP forwarding failed: {:#}", e);
                            }
                        });
                        break;
                    } else if data_ch_req_tx.send(true).is_err() {
                        error!("Failed to request new data channel: control channel closed");
                        break;
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("TCP connection pool shutting down");
                    return Ok(());
                }
                else => {
                    info!("No more data channels available");
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Runs a connection pool for UDP services.
#[instrument(skip_all)]
async fn run_udp_connection_pool<T: 'static + Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let socket = retry_notify_with_deadline(
        listen_backoff(),
        || async { Ok(UdpSocket::bind(&bind_addr).await?) },
        |e, duration| warn!("Failed to bind UDP socket to {}: {:#}. Retrying in {:?}", bind_addr, e, duration),
        &mut shutdown_rx,
    )
    .await
    .with_context(|| format!("Failed to bind UDP socket to {}", bind_addr))?;

    info!("UDP listener started at {}", bind_addr);

    let cmd = bincode::serialize(&DataChannelCmd::StartForwardUdp)
        .map_err(|e| anyhow!("Failed to serialize StartForwardUdp: {}", e))?;

    let mut conn = data_ch_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("No available data channels"))?;
    write_and_flush(&mut conn, &cmd)
        .await
        .with_context(|| "Failed to send UDP forward command")?;

    let mut buf = vec![0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                let (n, from) = result
                    .with_context(|| "Failed to receive UDP data")?;
                UdpTraffic::write_slice(&mut conn, from, &buf[..n])
                    .await
                    .with_context(|| "Failed to forward UDP data to client")?;
            }
            result = conn.read_u8() => {
                let hdr_len = result
                    .with_context(|| "Failed to read UDP header length")?;
                let traffic = UdpTraffic::read(&mut conn, hdr_len)
                    .await
                    .with_context(|| "Failed to read UDP traffic")?;
                socket
                    .send_to(&traffic.data, traffic.from)
                    .await
                    .with_context(|| "Failed to send UDP data to visitor")?;
            }
            _ = shutdown_rx.recv() => {
                info!("UDP connection pool shutting down");
                break;
            }
            else => break,
        }
    }

    Ok(())
}
