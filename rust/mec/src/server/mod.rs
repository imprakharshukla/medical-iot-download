//! Server module implementing the MEC server functionality
//! 
//! Provides the core server implementation including request handling,
//! device management, and Redis integration.

use crate::encryption::{WbAES, KeyPair};
use crate::priority::analyzer::Analyzer;
use parking_lot::RwLock;
use redis::Client as RedisClient;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use actix_web::{web, App, HttpServer};
use common::{Result, DiscoveryError, DeviceInfo, NetworkInfo, DeviceStatus, DiscoveryPacket, DiscoveryConfig};
use redis::RedisError;
use crate::discovery::{DeviceRegistry, PacketValidator};
use log::{info, error, debug, warn};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use uuid::Uuid;
use chrono::Utc;
use crate::models::{SensorData, EncryptedSensorData, Priority};
use serde_json::json;
use base64;

pub mod handlers;

/// Configuration for Redis connection and behavior
#[derive(Clone)]
pub struct RedisConfig {
    /// Redis server URL
    pub url: String,
    /// Maximum number of connections in the pool
    pub pool_size: u32,
    /// Number of connection retry attempts
    pub retry_attempts: u32,
    /// Delay between retry attempts
    pub retry_delay: Duration,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6000".to_string(),
            pool_size: 20,
            retry_attempts: 3,
            retry_delay: Duration::from_millis(100),
        }
    }
}

/// Main MEC server structure handling data processing and device management
pub struct MECServer {
    /// Priority analyzer for incoming data
    pub analyzer: Analyzer,
    /// Redis client for data persistence
    pub redis_client: RedisClient,
    /// Thread-safe map of connected devices and their status
    pub connected_devices: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Encryption keys for securing data
    key_pair: KeyPair,
    /// Redis configuration
    redis_config: RedisConfig,
    port: u16,
    device_registry: Arc<DeviceRegistry>,
    packet_validator: Arc<PacketValidator>,
    pub metadata_key: WbAES,
    signing_key: Arc<Keypair>,
    discovery_config: DiscoveryConfig,
}

impl MECServer {
    /// Creates a new MEC server instance
    /// 
    /// # Arguments
    /// * `analyzer` - Priority analyzer instance
    /// * `redis_client` - Redis client for data persistence
    pub fn new(
        analyzer: Analyzer,
        redis_client: RedisClient,
        device_registry: Arc<DeviceRegistry>,
        metadata_key: WbAES,
    ) -> Result<Self> {
        let signing_key = Arc::new(Keypair::generate(&mut OsRng));
        
        let key_pair = KeyPair::new(metadata_key.clone());

        Ok(Self {
            analyzer,
            redis_client,
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            key_pair,
            redis_config: RedisConfig::default(),
            port: 8080,
            device_registry,
            packet_validator: Arc::new(PacketValidator::new(Default::default())?),
            metadata_key,
            signing_key,
            discovery_config: DiscoveryConfig::default(),
        })
    }

    /// Returns the metadata encryption key
    pub fn get_metadata_key(&self) -> &WbAES {
        &self.metadata_key
    }

    /// Checks the Redis connection and returns an error if unavailable
    pub async fn check_redis_connection(&self) -> std::result::Result<(), RedisError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        
        let response: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await?;

        if response == "PONG" {
            Ok(())
        } else {
            Err(RedisError::from(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unexpected Redis response"
            )))
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting MEC server...");
        
        // Create shared device registry with Redis client
        let device_registry = web::Data::new(DeviceRegistry::new(self.redis_client.clone())?);
        
        // Share the server instance
        let server = web::Data::new(self.clone());

        info!("Starting HTTP server on port {}", self.port);
        let http_server = HttpServer::new(move || {
            App::new()
                .app_data(device_registry.clone())  // Share device registry
                .app_data(server.clone())  // Share server instance
                .service(handlers::announce_device)
                .service(
                    web::scope("/api")
                        .service(web::resource("/status").to(handlers::get_status))
                        .service(web::resource("/devices").to(handlers::get_devices))
                        .service(web::resource("/devices/{device_id}").to(handlers::get_device))
                        .service(web::resource("/devices/{device_id}/data").to(handlers::get_device_data))
                        .service(web::resource("/key").to(handlers::get_encryption_key))
                        .service(web::resource("/handshake").to(handlers::handle_handshake))
                        .service(web::resource("/ingest/encrypted").route(web::post().to(handlers::ingest_encrypted_data)))
                )
                .wrap(
                    actix_cors::Cors::default()
                        .allow_any_origin()
                        .allow_any_method()
                        .allow_any_header()
                )
        })
        .bind(format!("0.0.0.0:{}", self.port))?;

        // Start HTTP server
        let server_handle = http_server.run();
        info!("HTTP server started successfully");

        // Start key rotation task
        let key_rotation_handle = {
            let server = self.clone();
            info!("Spawning key rotation task...");
            tokio::spawn(async move {
                info!("Starting key rotation service");
                if let Err(e) = server.start_key_rotation().await {
                    error!("Key rotation service failed: {}", e);
                }
            })
        };

        // Start announcement service
        let announcement_handle = {
            let server = self.clone();
            info!("Starting server announcement service...");
            tokio::spawn(async move {
                if let Err(e) = server.start_announcements().await {
                    error!("Server announcement service failed: {}", e);
                }
            })
        };

        info!("All services started, waiting for completion...");
        
        // Run all services
        tokio::select! {
            result = server_handle => {
                info!("HTTP server stopped: {:?}", result);
            }
            _ = key_rotation_handle => {
                info!("Key rotation service stopped");
            }
            _ = announcement_handle => {
                info!("Announcement service stopped");
            }
        }

        Ok(())
    }

    pub async fn start_key_rotation(&self) -> Result<()> {
        let rotation_interval = Duration::from_secs(30); // 30 seconds for testing
        
        info!("Key rotation service initialized with {} second interval", rotation_interval.as_secs());
        
        loop {
            info!("Waiting for next key rotation in 30 seconds...");
            tokio::time::sleep(rotation_interval).await;
            
            info!("Starting key rotation...");
            match self.key_pair.rotate_keys().await {
                Ok(_) => {
                    let current = self.key_pair.get_active_key();
                    info!("Successfully rotated encryption keys. Current version: {} (created at {})", 
                        current.version, 
                        current.created_at.to_rfc3339()
                    );
                }
                Err(e) => {
                    error!("Failed to rotate keys: {}", e);
                    return Err(common::DiscoveryError::SecurityError(e.to_string()));
                }
            }
        }
    }

    async fn start_announcements(&self) -> Result<()> {
        info!("Initializing server announcements");
        
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        socket.set_broadcast(true)
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        info!("Setting up multicast...");
        socket.join_multicast_v4(
            "239.255.255.250".parse().unwrap(),
            "0.0.0.0".parse().unwrap()
        ).map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        let server_info = DeviceInfo {
            device_id: Uuid::new_v4().to_string(),
            device_type: "mec_server".to_string(),
            capabilities: vec!["data_processing".to_string()],
            last_seen: Utc::now(),
            status: DeviceStatus::Online,
            network_info: NetworkInfo {
                ip_address: get_local_ip()
                    .ok_or_else(|| DiscoveryError::NetworkError("Failed to get local IP".to_string()))?,
                port: self.port,
                mac_address: get_device_mac()?,
            },
            firmware_version: "1.0.0".to_string(),
            protocol_version: "1.0".to_string(),
        };

        info!("Starting announcement broadcasts for server {} on port {}", 
            server_info.device_id, self.port);

        loop {
            let packet = DiscoveryPacket {
                device_info: server_info.clone(),
                timestamp: Utc::now(),
                nonce: [0u8; 32],
                signature: None,
            };

            let data = serde_json::to_vec(&packet)?;
            
            // Send to both multicast and broadcast
            for addr in ["239.255.255.250:1900", "255.255.255.255:1900", "127.0.0.1:1900"] {
                match socket.send_to(&data, addr).await {
                    Ok(bytes) => {
                        debug!("Sent {} bytes announcement to {}", bytes, addr);
                    },
                    Err(e) => {
                        warn!("Failed to send announcement to {}: {}", addr, e);
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn process_encrypted_data(&self, data: &EncryptedSensorData) -> Result<Priority> {
        // Decrypt metadata for priority analysis only
        let metadata = self.metadata_key.decrypt(&data.encrypted_metadata)?;
        let metadata: serde_json::Value = serde_json::from_slice(&metadata)?;

        // Decrypt payload for priority analysis only
        let payload = self.metadata_key.decrypt(&data.encrypted_payload)?;
        let readings: HashMap<String, serde_json::Value> = serde_json::from_slice(&payload)?;

        // Create SensorData for analysis
        let sensor_data = SensorData {
            device_id: data.device_id.clone(),
            type_: metadata["type"].as_str().unwrap_or("unknown").to_string(),
            timestamp: metadata["timestamp"].as_str().unwrap_or("").to_string(),
            readings,
        };

        // Process through analyzer
        let priority = self.analyzer.analyze(&sensor_data).await;

        // Store in Redis - store both raw and base64 versions
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        // Store raw encrypted data
        let raw_key = format!("device:{}:raw", data.device_id);
        redis::cmd("LPUSH")
            .arg(&raw_key)
            .arg(&data.encrypted_payload)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        // Store metadata with base64 for readability
        let encrypted_key = format!("device:{}:encrypted", data.device_id);
        let encrypted_data = json!({
            "metadata": base64::encode(&data.encrypted_metadata),
            "payload": base64::encode(&data.encrypted_payload),
            "timestamp": Utc::now().to_rfc3339(),
            "priority": priority.as_str(),
        });

        redis::cmd("LPUSH")
            .arg(&encrypted_key)
            .arg(serde_json::to_string(&encrypted_data)?)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        // Add to active devices
        redis::cmd("SADD")
            .arg("active_devices")
            .arg(&data.device_id)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        Ok(priority)
    }
}

// Make MECServer cloneable
impl Clone for MECServer {
    fn clone(&self) -> Self {
        Self {
            analyzer: self.analyzer.clone(),
            redis_client: self.redis_client.clone(),
            connected_devices: Arc::clone(&self.connected_devices),
            key_pair: self.key_pair.clone(),
            redis_config: self.redis_config.clone(),
            port: self.port,
            device_registry: Arc::clone(&self.device_registry),
            packet_validator: Arc::clone(&self.packet_validator),
            metadata_key: self.metadata_key.clone(),
            signing_key: Arc::clone(&self.signing_key),
            discovery_config: self.discovery_config.clone(),
        }
    }
}

// Helper function to get MAC address
fn get_device_mac() -> Result<String> {
    use mac_address::get_mac_address;
    match get_mac_address() {
        Ok(Some(addr)) => Ok(addr.to_string()),
        Ok(None) => Ok("00:00:00:00:00:00".to_string()),
        Err(e) => Err(DiscoveryError::NetworkError(e.to_string()))
    }
}

// Helper function to get local IP
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}