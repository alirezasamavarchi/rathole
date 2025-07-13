use crate::config::{ClientConfig, ClientServiceConfig, Config, ServiceType, TransportType};
use crate::config_watcher::{ClientServiceChange, ConfigChange};
use crate::helper::udp_connect;
use crate::protocol::Hello::{self, ControlChannelHello, DataChannelHello};
use crate::protocol::{
    self, read_ack, read_control_cmd, read_data_cmd, read_hello, Ack, Auth, ControlChannelCmd,
    DataChannelCmd, UdpTraffic, CURRENT_PROTO_VERSION, HASH_WIDTH_IN_BYTES,
};
use crate::transport::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::future::retry_notify;
use backoff::ExponentialBackoff;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, error, info, instrument, trace, warn, Instrument, Span};

#[cfg(feature = "quic")]
use crate::transport::QuicTransport;
#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use crate::transport::TlsTransport;
#[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
use crate::transport::WebsocketTransport;

use crate::constants::{run_control_chan_backoff, UDP_BUFFER_SIZE, UDP_SENDQ_SIZE, UDP_TIMEOUT};

pub type ServiceDigest = protocol::Digest;
pub type Nonce = protocol::Digest;
/// Entry point for running the client with the specified transport type.
pub async fn run_client(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = config.client.ok_or_else(|| {
        anyhow!("Missing [client] configuration block")
    })?;

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut client = Client::<TcpTransport>::from(config).await?;
            client.run(shutdown_rx, update_rx).await
        }
        TransportType::Tls => {
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            {
                let mut client = Client::<TlsTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
            crate::helper::feature_neither_compile("native-tls", "rustls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut client = Client::<NoiseTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Quic => {
            #[cfg(feature = "quic")]
            {
                let mut client = Client::<QuicTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(feature = "quic"))]
            crate::helper::feature_not_compile("quic")
        }
        TransportType::Websocket => {
            #[cfg(any(feature = "websocket-native-tls", feature = "websocket-rustls"))]
            {
                let mut client = Client::<WebsocketTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(any(feature = "websocket-native-tls", feature = "websocket-rustls")))]
            crate::helper::feature_neither_compile("websocket-native-tls", "websocket-rustls")
        }
    }
}

type ServiceDigest = protocol::Digest;
type Nonce = protocol::Digest;

/// Client state, managing services and their control channels.
struct Client<T: Transport> {
    config: ClientConfig,
    service_handles: HashMap<String, ControlChannelHandle>,
    transport: Arc<T>,
}

impl<T: 'static + Transport> Client<T> {
    /// Creates a new client instance from the client configuration.
    pub async fn from(config: ClientConfig) -> Result<Self> {
        let transport = Arc::new(
            T::new(&config.transport)
                .with_context(|| "Failed to initialize transport layer")?,
        );
        Ok(Self {
            config,
            service_handles: HashMap::new(),
            transport,
        })
    }

    /// Runs the client, starting control channels for each service and handling updates.
    #[instrument(skip_all, fields(remote_addr = %self.config.remote_addr))]
    pub async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        for (name, config) in &self.config.services {
            let handle = ControlChannelHandle::new(
                config.clone(),
                self.config.remote_addr.clone(),
                self.transport.clone(),
                self.config.heartbeat_timeout,
            );
            self.service_handles.insert(name.clone(), handle);
        }

        loop {
            tokio::select! {
                result = shutdown_rx.recv() => {
                    match result {
                        Ok(_) => info!("Received shutdown signal"),
                        Err(err) => error!("Failed to receive shutdown signal: {}", err),
                    }
                    break;
                }
                Some(change) = update_rx.recv() => {
                    self.handle_hot_reload(change).await;
                }
            }
        }

        for (name, handle) in self.service_handles.drain() {
            info!("Shutting down service {}", name);
            handle.shutdown();
        }

        Ok(())
    }

    /// Handles configuration updates for hot reloading.
    async fn handle_hot_reload(&mut self, change: ConfigChange) {
        match change {
            ConfigChange::ClientChange(client_change) => match client_change {
                ClientServiceChange::Add(cfg) => {
                    let name = cfg.name.clone();
                    info!("Adding service {}", name);
                    let handle = ControlChannelHandle::new(
                        cfg,
                        self.config.remote_addr.clone(),
                        self.transport.clone(),
                        self.config.heartbeat_timeout,
                    );
                    self.service_handles.insert(name, handle);
                }
                ClientServiceChange::Delete(name) => {
                    if let Some(handle) = self.service_handles.remove(&name) {
                        info!("Deleting service {}", name);
                        handle.shutdown();
                    }
                }
            },
            other => warn!("Ignored config change: {:?}", other),
        }
    }
}

/// Arguments for running a data channel.
struct RunDataChannelArgs<T: Transport> {
    session_key: Nonce,
    remote_addr: AddrMaybeCached,
    connector: Arc<T>,
    socket_opts: SocketOpts,
    service: ClientServiceConfig,
}

/// Performs handshake for a data channel.
async fn do_data_channel_handshake<T: Transport>(
    args: Arc<RunDataChannelArgs<T>>,
) -> Result<T::Stream> {
    let backoff = ExponentialBackoff {
        max_interval: Duration::from_millis(100),
        max_elapsed_time: Some(Duration::from_secs(10)),
        ..Default::default()
    };

    let hello_data = bincode::serialize(&DataChannelHello(
        CURRENT_PROTO_VERSION,
        args.session_key
            .try_into()
            .map_err(|_| anyhow!("Invalid session key length"))?,
    ))
    .map_err(|e| anyhow!("Failed to serialize hello message: {}", e))?;

    let mut conn = retry_notify(
        backoff,
        || async {
            let conn = args
                .connector
                .connect(&args.remote_addr)
                .await
                .with_context(|| format!("Failed to connect to {}", args.remote_addr))?;
            Ok(conn)
        },
        |e, duration| warn!("Connect failed: {:#}. Retrying in {:?}", e, duration),
    )
    .await?;

    T::hint(&conn, args.socket_opts);

    conn.write_all(&hello_data)
        .await
        .with_context(|| "Failed to send hello message")?;
    conn.flush().await?;

    Ok(conn)
}

/// Runs a data channel, forwarding traffic based on the service type.
#[instrument(skip(args))]
async fn run_data_channel<T: Transport>(args: Arc<RunDataChannelArgs<T>>) -> Result<()> {
    match args.service.service_type {
        ServiceType::Tcp if !matches!(args.service.service_type, ServiceType::Tcp) => {
            bail!("Expected TCP service, got {:?}", args.service.service_type)
        }
        ServiceType::Udp if !matches!(args.service.service_type, ServiceType::Udp) => {
            bail!("Expected UDP service, got {:?}", args.service.service_type)
        }
        _ => {}
    }

    let mut conn = do_data_channel_handshake(args.clone())
        .await
        .with_context(|| format!("Data channel handshake failed for {}", args.service.name))?;

    match read_data_cmd(&mut conn)
        .await
        .with_context(|| "Failed to read data channel command")?
    {
        DataChannelCmd::StartForwardTcp => {
            run_data_channel_for_tcp::<T>(conn, &args.service.local_addr)
                .await
                .with_context(|| format!("TCP forwarding failed for {}", args.service.name))?;
        }
        DataChannelCmd::StartForwardUdp => {
            run_data_channel_for_udp::<T>(conn, &args.service.local_addr, args.service.prefer_ipv6)
                .await
                .with_context(|| format!("UDP forwarding failed for {}", args.service.name))?;
        }
    }
    Ok(())
}

/// Forwards TCP traffic bidirectionally between the data channel and local service.
#[instrument(skip(conn))]
async fn run_data_channel_for_tcp<T: Transport>(
    mut conn: T::Stream,
    local_addr: &str,
) -> Result<()> {
    debug!("Starting TCP data channel forwarding");

    let mut local = TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("Failed to connect to local address {}", local_addr))?;
    copy_bidirectional(&mut conn, &mut local)
        .await
        .with_context(|| "TCP bidirectional forwarding failed")?;
    Ok(())
}

/// Forwards UDP traffic between the data channel and local service.
#[instrument(skip(conn))]
async fn run_data_channel_for_udp<T: Transport>(
    conn: T::Stream,
    local_addr: &str,
    prefer_ipv6: bool,
) -> Result<()> {
    debug!("Starting UDP data channel forwarding");

    let port_map: Arc<DashMap<SocketAddr, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpTraffic>(UDP_SENDQ_SIZE);
    let (mut rd, mut wr) = io::split(conn);

    tokio::spawn(async move {
        while let Some(traffic) = outbound_rx.recv().await {
            trace!("Sending outbound UDP traffic: {:?}", traffic);
            if let Err(e) = traffic
                .write(&mut wr)
                .await
                .with_context(|| "Failed to send UDP traffic to server")
            {
                error!("{:#}", e);
                break;
            }
        }
    });

    loop {
        let hdr_len = rd
            .read_u8()
            .await
            .with_context(|| "Failed to read UDP header length")?;
        let packet = UdpTraffic::read(&mut rd, hdr_len)
            .await
            .with_context(|| "Failed to read UDP traffic from server")?;

        if !port_map.contains_key(&packet.from) {
            let socket = udp_connect(local_addr, prefer_ipv6)
                .await
                .with_context(|| format!("Failed to connect to local UDP address {}", local_addr))?;
            let (inbound_tx, inbound_rx) = mpsc::channel(UDP_SENDQ_SIZE);
            port_map.insert(packet.from, inbound_tx);
            tokio::spawn(
                run_udp_forwarder(socket, inbound_rx, outbound_tx.clone(), packet.from, port_map.clone())
                    .instrument(Span::current()),
            );
        }

        if let Some(tx) = port_map.get(&packet.from) {
            tx.send(packet.data)
                .await
                .map_err(|_| anyhow!("Failed to send UDP packet to forwarder"))?;
        }
    }
}

/// Forwards UDP packets between a local socket and the data channel.
#[instrument(skip_all, fields(from))]
async fn run_udp_forwarder<T: Transport>(
    socket: UdpSocket,
    mut inbound_rx: mpsc::Receiver<Bytes>,
    outbound_tx: mpsc::Sender<UdpTraffic>,
    from: SocketAddr,
    port_map: Arc<DashMap<SocketAddr, mpsc::Sender<Bytes>>>,
) -> Result<()> {
    debug!("UDP forwarder started for {}", from);
    let mut buf = BytesMut::new();
    buf.resize(UDP_BUFFER_SIZE, 0);

    loop {
        tokio::select! {
            Some(data) = inbound_rx.recv() => {
                socket
                    .send(&data)
                    .await
                    .with_context(|| "Failed to send UDP packet to local service")?;
            }
            result = socket.recv(&mut buf) => {
                let len = result
                    .with_context(|| "Failed to receive UDP packet from local service")?;
                let traffic = UdpTraffic {
                    from,
                    data: Bytes::copy_from_slice(&buf[..len]),
                };
                outbound_tx
                    .send(traffic)
                    .await
                    .map_err(|_| anyhow!("Failed to send UDP traffic to server"))?;
            }
            _ = time::sleep(Duration::from_secs(UDP_TIMEOUT)) => {
                debug!("UDP forwarder timed out for {}", from);
                break;
            }
        }
    }

    port_map.remove(&from);
    debug!("UDP forwarder stopped for {}", from);
    Ok(())
}

/// Control channel for managing data channel creation and heartbeats.
struct ControlChannel<T: Transport> {
    digest: ServiceDigest,
    service: ClientServiceConfig,
    shutdown_rx: oneshot::Receiver<u8>,
    remote_addr: String,
    transport: Arc<T>,
    heartbeat_timeout: u64,
}

/// Handle for a control channel, allowing shutdown.
struct ControlChannelHandle {
    shutdown_tx: oneshot::Sender<u8>,
}

impl<T: 'static + Transport> ControlChannel<T> {
    /// Runs the control channel, handling handshake, authentication, and commands.
    #[instrument(skip_all, fields(service = %self.service.name))]
    async fn run(&mut self) -> Result<()> {
        let mut remote_addr = AddrMaybeCached::new(&self.remote_addr);
        remote_addr
            .resolve()
            .await
            .with_context(|| format!("Failed to resolve remote address {}", self.remote_addr))?;

        let hello_data = bincode::serialize(&ControlChannelHello(
            CURRENT_PROTO_VERSION,
            self.digest
                .try_into()
                .map_err(|_| anyhow!("Invalid digest length"))?,
        ))
        .map_err(|e| anyhow!("Failed to serialize hello message: {}", e))?;

        let mut conn = self
            .transport
            .connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", self.remote_addr))?;
        T::hint(&conn, SocketOpts::for_control_channel());

        debug!("Sending control channel hello");
        conn.write_all(&hello_data)
            .await
            .with_context(|| "Failed to send hello message")?;
        conn.flush().await?;

        debug!("Reading server hello");
        let nonce = match read_hello(&mut conn)
            .await
            .with_context(|| "Failed to read server hello")?
        {
            ControlChannelHello(_, d) => d,
            other => bail!("Expected ControlChannelHello, got {:?}", other),
        };

        debug!("Sending authentication");
        let mut concat = Vec::from(self.service.token.as_ref().as_bytes());
        concat.extend_from_slice(&nonce);
        let session_key = protocol::digest(&concat);
        let auth_data = bincode::serialize(&Auth(session_key))
            .map_err(|e| anyhow!("Failed to serialize auth message: {}", e))?;
        conn.write_all(&auth_data)
            .await
            .with_context(|| "Failed to send auth message")?;
        conn.flush().await?;

        debug!("Reading server ack");
        match read_ack(&mut conn)
            .await
            .with_context(|| "Failed to read server ack")?
        {
            Ack::Ok => {}
            ack => bail!("Authentication failed for {}: {:?}", self.service.name, ack),
        }

        info!("Control channel established for {}", self.service.name);

        let socket_opts = SocketOpts::from_client_cfg(&self.service);
        let data_ch_args = Arc::new(RunDataChannelArgs {
            session_key,
            remote_addr,
            connector: self.transport.clone(),
            socket_opts,
            service: self.service.clone(),
        });

        loop {
            tokio::select! {
                result = read_control_cmd(&mut conn) => {
                    match result {
                        Ok(ControlChannelCmd::CreateDataChannel) => {
                            debug!("Received data channel creation request");
                            let args = data_ch_args.clone();
                            tokio::spawn(
                                async move {
                                    if let Err(e) = run_data_channel(args).await {
                                        warn!("Data channel error: {:#}", e);
                                    }
                                }
                                .instrument(Span::current()),
                            );
                        }
                        Ok(ControlChannelCmd::HeartBeat) => debug!("Received heartbeat"),
                        Err(e) => {
                            error!("Control channel error: {:#}", e);
                            break;
                        }
                    }
                }
                _ = time::sleep(Duration::from_secs(self.heartbeat_timeout)), if self.heartbeat_timeout != 0 => {
                    error!("Heartbeat timeout for {}", self.service.name);
                    return Err(anyhow!("Heartbeat timeout"));
                }
                _ = &mut self.shutdown_rx => {
                    info!("Control channel shutting down for {}", self.service.name);
                    break;
                }
            }
        }

        Ok(())
    }
}

impl ControlChannelHandle {
    /// Creates a new control channel handle, spawning a task to run the channel.
    #[instrument(name = "control_channel", skip_all, fields(service = %service.name))]
    fn new<T: 'static + Transport>(
        service: ClientServiceConfig,
        remote_addr: String,
        transport: Arc<T>,
        heartbeat_timeout: u64,
    ) -> Self {
        let digest = protocol::digest(service.name.as_bytes());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let mut channel = ControlChannel {
            digest,
            service,
            shutdown_rx,
            remote_addr,
            transport,
            heartbeat_timeout,
        };

        tokio::spawn(
            async move {
                let mut backoff = run_control_chan_backoff(channel.service.retry_interval);
                let mut start = Instant::now();

                loop {
                    match channel.run().await {
                        Ok(()) => break,
                        Err(err) => {
                            if channel.shutdown_rx.try_recv().is_ok() {
                                break;
                            }
                            if start.elapsed() > Duration::from_secs(3) {
                                backoff.reset();
                            }
                            if let Some(duration) = backoff.next_backoff() {
                                error!("Control channel error: {:#}. Retrying in {:?}", err, duration);
                                time::sleep(duration).await;
                            } else {
                                panic!("Control channel failed after retries: {:#}", err);
                            }
                            start = Instant::now();
                        }
                    }
                }
            }
            .instrument(Span::current()),
        );

        Self { shutdown_tx }
    }

    /// Shuts down the control channel.
    fn shutdown(self) {
        let _ = self.shutdown_tx.send(0u8);
    }
}
