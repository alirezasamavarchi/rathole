use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use tokio::fs;
use url::Url;

use crate::transport::{DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_KEEPALIVE_SECS, DEFAULT_NODELAY};

/// Default application-layer heartbeat interval in seconds.
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
/// Default heartbeat timeout in seconds.
const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 40;
/// Default retry interval for client connections in seconds.
const DEFAULT_CLIENT_RETRY_INTERVAL_SECS: u64 = 1;

/// A string type that masks its contents when debugged, used for sensitive data like tokens.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone)]
pub struct MaskedString(String);

impl Debug for MaskedString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("MASKED")
    }
}

impl AsRef<str> for MaskedString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for MaskedString {
    fn from(s: &str) -> MaskedString {
        MaskedString(String::from(s))
    }
}

/// Supported transport protocols.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    #[default]
    Tcp,
    Tls,
    Noise,
    Websocket,
    Quic,
}

/// Configuration for a client-side service.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientServiceConfig {
    #[serde(rename = "type", default = "default_service_type")]
    pub service_type: ServiceType,
    #[serde(skip)]
    pub name: String,
    pub local_addr: String,
    #[serde(default)]
    pub prefer_ipv6: bool,
    pub token: MaskedString,
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_client_retry_interval")]
    pub retry_interval: u64,
}

impl ClientServiceConfig {
    /// Creates a new `ClientServiceConfig` with the given name and default values.
    pub fn with_name(name: &str) -> Self {
        Self {
            name: name.to_string(),
            service_type: default_service_type(),
            local_addr: String::new(),
            prefer_ipv6: false,
            token: MaskedString::default(),
            nodelay: default_nodelay(),
            retry_interval: default_client_retry_interval(),
        }
    }

    /// Validates the configuration, ensuring all required fields are valid.
    pub fn validate(&self) -> Result<()> {
        if self.local_addr.is_empty() {
            bail!("Missing local_addr for service {}", self.name);
        }
        if self.token.as_ref().is_empty() {
            bail!("Missing token for service {}", self.name);
        }
        self.local_addr
            .to_socket_addrs()
            .map_err(|e| anyhow!("Invalid local_addr {}: {}", self.local_addr, e))?;
        Ok(())
    }
}

/// Supported service types (TCP or UDP).
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    #[default]
    Tcp,
    Udp,
}

fn default_service_type() -> ServiceType {
    ServiceType::Tcp
}

/// Configuration for a server-side service.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerServiceConfig {
    #[serde(rename = "type", default = "default_service_type")]
    pub service_type: ServiceType,
    #[serde(skip)]
    pub name: String,
    pub bind_addr: String,
    pub token: MaskedString,
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
}

impl ServerServiceConfig {
    /// Creates a new `ServerServiceConfig` with the given name and default values.
    pub fn with_name(name: &str) -> Self {
        Self {
            name: name.to_string(),
            service_type: default_service_type(),
            bind_addr: String::new(),
            token: MaskedString::default(),
            nodelay: default_nodelay(),
        }
    }

    /// Validates the configuration, ensuring all required fields are valid.
    pub fn validate(&self) -> Result<()> {
        if self.bind_addr.is_empty() {
            bail!("Missing bind_addr for service {}", self.name);
        }
        if self.token.as_ref().is_empty() {
            bail!("Missing token for service {}", self.name);
        }
        self.bind_addr
            .to_socket_addrs()
            .map_err(|e| anyhow!("Invalid bind_addr {}: {}", self.bind_addr, e))?;
        Ok(())
    }
}

/// TLS configuration for secure transports.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub hostname: Option<String>,
    pub trusted_root: Option<String>,
    pub pkcs12: Option<String>,
    pub pkcs12_password: Option<MaskedString>,
}

impl TlsConfig {
    /// Validates the TLS configuration for server or client.
    pub fn validate(&self, is_server: bool) -> Result<()> {
        if is_server {
            if self.pkcs12.is_none() || self.pkcs12_password.is_none() {
                bail!("Missing pkcs12 or pkcs12_password for server TLS configuration");
            }
        } else if self.trusted_root.is_none() {
            bail!("Missing trusted_root for client TLS configuration");
        }
        Ok(())
    }
}

/// Noise protocol configuration.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NoiseConfig {
    #[serde(default = "default_noise_pattern")]
    pub pattern: String,
    pub local_private_key: Option<MaskedString>,
    pub remote_public_key: Option<String>,
}

impl NoiseConfig {
    /// Validates the Noise configuration for server or client.
    pub fn validate(&self, is_server: bool) -> Result<()> {
        if is_server {
            if self.local_private_key.is_none() {
                bail!("Missing local_private_key for server Noise configuration");
            }
        } else if self.remote_public_key.is_none() {
            bail!("Missing remote_public_key for client Noise configuration");
        }
        if !self.pattern.starts_with("Noise_") {
            bail!("Invalid Noise pattern: {}", self.pattern);
        }
        Ok(())
    }
}

fn default_noise_pattern() -> String {
    "Noise_NK_25519_ChaChaPoly_BLAKE2s".to_string()
}

/// WebSocket configuration.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebsocketConfig {
    #[serde(default)]
    pub tls: bool,
}

/// TCP-specific configuration.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,
    pub proxy: Option<Url>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            nodelay: default_nodelay(),
            keepalive_secs: default_keepalive_secs(),
            keepalive_interval: default_keepalive_interval(),
            proxy: None,
        }
    }
}

impl TcpConfig {
    /// Validates the TCP configuration.
    pub fn validate(&self) -> Result<()> {
        if let Some(proxy) = &self.proxy {
            match proxy.scheme() {
                "socks5" | "http" => {
                    if proxy.host().is_none() {
                        bail!("Invalid proxy URL: missing host in {}", proxy);
                    }
                }
                scheme => bail!("Unsupported proxy scheme: {}", scheme),
            }
        }
        Ok(())
    }
}

fn default_nodelay() -> bool {
    DEFAULT_NODELAY
}

fn default_keepalive_secs() -> u64 {
    DEFAULT_KEEPALIVE_SECS
}

fn default_keepalive_interval() -> u64 {
    DEFAULT_KEEPALIVE_INTERVAL
}

fn default_heartbeat_timeout() -> u64 {
    DEFAULT_HEARTBEAT_TIMEOUT_SECS
}

fn default_client_retry_interval() -> u64 {
    DEFAULT_CLIENT_RETRY_INTERVAL_SECS
}

fn default_heartbeat_interval() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL_SECS
}

/// Client configuration.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub remote_addr: String,
    pub default_token: MaskedString,
    #[serde(default)]
    pub prefer_ipv6: bool,
    pub services: HashMap<String, ClientServiceConfig>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,
    #[serde(default = "default_client_retry_interval")]
    pub retry_interval: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            remote_addr: String::new(),
            default_token: MaskedString::default(),
            prefer_ipv6: false,
            services: HashMap::new(),
            transport: TransportConfig::default(),
            heartbeat_timeout: default_heartbeat_timeout(),
            retry_interval: default_client_retry_interval(),
        }
    }
}

/// Server configuration.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub default_token: MaskedString,
    pub services: HashMap<String, ServerServiceConfig>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: String::new(),
            default_token: MaskedString::default(),
            services: HashMap::new(),
            transport: TransportConfig::default(),
            heartbeat_interval: default_heartbeat_interval(),
        }
    }
}

/// Top-level configuration structure.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub transport_type: TransportType,
    #[serde(default)]
    pub tcp: TcpConfig,
    pub tls: Option<TlsConfig>,
    pub noise: Option<NoiseConfig>,
    pub websocket: Option<WebsocketConfig>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Tcp,
            tcp: TcpConfig::default(),
            tls: None,
            noise: None,
            websocket: None,
        }
    }
}

impl Config {
    /// Parses a configuration from a TOML string.
    pub fn from_str(s: &str) -> Result<Self> {
        let mut config: Self = toml::from_str(s)
            .with_context(|| "Failed to parse TOML configuration")?;

        if let Some(server) = config.server.as_mut() {
            Self::validate_server_config(server)?;
        }

        if let Some(client) = config.client.as_mut() {
            Self::validate_client_config(client)?;
        }

        if config.server.is_none() && config.client.is_none() {
            bail!("Neither [server] nor [client] configuration is defined");
        }

        Ok(config)
    }

    /// Reads and parses a configuration from a file.
    pub async fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read configuration file {:?}", path))?;
        Self::from_str(&content).with_context(|| {
            format!("Invalid configuration in file {:?}", path)
        })
    }

    /// Validates the server configuration.
    fn validate_server_config(server: &mut ServerConfig) -> Result<()> {
        if server.bind_addr.is_empty() {
            bail!("Missing bind_addr in server configuration");
        }
        server
            .bind_addr
            .to_socket_addrs()
            .map_err(|e| anyhow!("Invalid bind_addr {}: {}", server.bind_addr, e))?;

        for (name, service) in &mut server.services {
            service.name = name.clone();
            if service.token.as_ref().is_empty() {
                service.token = server.default_token.clone();
            }
            service.validate()?;
        }

        server.transport.validate(true)?;
        Ok(())
    }

    /// Validates the client configuration.
    fn validate_client_config(client: &mut ClientConfig) -> Result<()> {
        if client.remote_addr.is_empty() {
            bail!("Missing remote_addr in client configuration");
        }
        client
            .remote_addr
            .to_socket_addrs()
            .map_err(|e| anyhow!("Invalid remote_addr {}: {}", client.remote_addr, e))?;

        for (name, service) in &mut client.services {
            service.name = name.clone();
            if service.token.as_ref().is_empty() {
                service.token = client.default_token.clone();
            }
            service.validate()?;
        }

        client.transport.validate(false)?;
        Ok(())
    }
}

impl TransportConfig {
    /// Validates the transport configuration for server or client.
    pub fn validate(&self, is_server: bool) -> Result<()> {
        self.tcp.validate()?;

        match self.transport_type {
            TransportType::Tcp => Ok(()),
            TransportType::Tls | TransportType::Quic => {
                let tls = self
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing TLS configuration for {}", self.transport_type))?;
                tls.validate(is_server)
            }
            TransportType::Noise => {
                let noise = self
                    .noise
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing Noise configuration"))?;
                noise.validate(is_server)
            }
            TransportType::Websocket => {
                self.websocket
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing WebSocket configuration"))?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Lists all TOML configuration files in a directory recursively.
    fn list_config_files<T: AsRef<Path>>(root: T) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "toml") {
                files.push(path);
            } else if path.is_dir() {
                files.extend(list_config_files(&path)?);
            }
        }
        Ok(files)
    }

    #[test]
    fn test_example_config() -> Result<()> {
        let temp_dir = TempDir::new()?;
        // Simulate example configs in a temporary directory
        fs::write(temp_dir.path().join("example.toml"), r#"
            [server]
            bind_addr = "127.0.0.1:8080"
            default_token = "secret"
            heartbeat_interval = 30

            [server.services.test]
            type = "tcp"
            bind_addr = "127.0.0.1:80"
        "#)?;
        let paths = list_config_files(temp_dir.path())?;
        for path in paths {
            let content = fs::read_to_string(&path)?;
            Config::from_str(&content)?;
        }
        Ok(())
    }

    #[test]
    fn test_valid_config() -> Result<()> {
        let temp_dir = TempDir::new()?;
        fs::write(temp_dir.path().join("valid.toml"), r#"
            [client]
            remote_addr = "127.0.0.1:8080"
            default_token = "secret"
            retry_interval = 1

            [client.services.test]
            type = "tcp"
            local_addr = "127.0.0.1:80"
        "#)?;
        let paths = list_config_files(temp_dir.path())?;
        for path in paths {
            let content = fs::read_to_string(&path)?;
            Config::from_str(&content)?;
        }
        Ok(())
    }

    #[test]
    fn test_invalid_config() -> Result<()> {
        let temp_dir = TempDir::new()?;
        fs::write(temp_dir.path().join("invalid.toml"), r#"
            [server]
            bind_addr = "invalid_addr"
            default_token = ""
        "#)?;
        let paths = list_config_files(temp_dir.path())?;
        for path in paths {
            let content = fs::read_to_string(&path)?;
            assert!(Config::from_str(&content).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_validate_server_config() -> Result<()> {
        let mut cfg = ServerConfig {
            bind_addr: "127.0.0.1:8080".to_string(),
            default_token: "secret".into(),
            ..Default::default()
        };

        cfg.services.insert(
            "test".to_string(),
            ServerServiceConfig {
                name: "test".to_string(),
                service_type: ServiceType::Tcp,
                bind_addr: "127.0.0.1:80".to_string(),
                token: MaskedString::default(),
                nodelay: true,
            },
        );

        assert!(Config::validate_server_config(&mut cfg).is_ok());
        assert_eq!(cfg.services.get("test").unwrap().token.as_ref(), "secret");

        cfg.services.get_mut("test").unwrap().token = "custom".into();
        assert!(Config::validate_server_config(&mut cfg).is_ok());
        assert_eq!(cfg.services.get("test").unwrap().token.as_ref(), "custom");

        cfg.bind_addr = "invalid".to_string();
        assert!(Config::validate_server_config(&mut cfg).is_err());

        Ok(())
    }

    #[test]
    fn test_validate_client_config() -> Result<()> {
        let mut cfg = ClientConfig {
            remote_addr: "127.0.0.1:8080".to_string(),
            default_token: "secret".into(),
            ..Default::default()
        };

        cfg.services.insert(
            "test".to_string(),
            ClientServiceConfig {
                name: "test".to_string(),
                service_type: ServiceType::Tcp,
                local_addr: "127.0.0.1:80".to_string(),
                token: MaskedString::default(),
                nodelay: true,
                retry_interval: 1,
            },
        );

        assert!(Config::validate_client_config(&mut cfg).is_ok());
        assert_eq!(cfg.services.get("test").unwrap().token.as_ref(), "secret");

        cfg.services.get_mut("test").unwrap().token = "custom".into();
        assert!(Config::validate_client_config(&mut cfg).is_ok());
        assert_eq!(cfg.services.get("test").unwrap().token.as_ref(), "custom");

        cfg.remote_addr = "invalid".to_string();
        assert!(Config::validate_client_config(&mut cfg).is_err());

        Ok(())
    }

    #[test]
    fn test_transport_config_validation() -> Result<()> {
        let mut config = TransportConfig {
            transport_type: TransportType::Tls,
            tls: Some(TlsConfig {
                hostname: Some("example.com".to_string()),
                trusted_root: Some("cert.pem".to_string()),
                pkcs12: Some("server.p12".to_string()),
                pkcs12_password: Some("password".into()),
            }),
            ..Default::default()
        };

        assert!(config.validate(true).is_ok());
        config.tls.as_mut().unwrap().pkcs12 = None;
        assert!(config.validate(true).is_err());

        config.transport_type = TransportType::Noise;
        config.tls = None;
        config.noise = Some(NoiseConfig {
            pattern: default_noise_pattern(),
            local_private_key: Some("key".into()),
            remote_public_key: None,
        });
        assert!(config.validate(true).is_ok());
        assert!(config.validate(false).is_err());

        Ok(())
    }
}
