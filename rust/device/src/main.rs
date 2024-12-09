use common::{DiscoveryConfig, Result, DiscoveryError};
use common::types::{DeviceInfo, NetworkInfo, DiscoveryPacket, DeviceStatus};
use common::encryption::{EncryptedData, EncryptedMetadata, wbaes::WbAES};
use tokio::net::UdpSocket;
use std::{time::Duration, collections::HashMap, sync::Arc};
use log::{info, debug, error, warn, LevelFilter};
use chrono::Utc;
use uuid::Uuid;
use clap::Parser;
use reqwest::Client;
use serde::{Serialize, Deserialize};
use common::encryption::handshake::{HandshakeRequest, HandshakeResponse, generate_session_key};
use rand::Rng;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde_json::json;
use ring::{agreement, rand as ring_rand};
use env_logger::Builder;
use env_logger::fmt::Color;
use std::io::Write;
use chrono::Local;

const BANNER: &str = r#"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║    ██████╗ ███████╗██   ██╗██╗ ██████╗███████╗                 ║
║    ██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔════╝                 ║
║    ██║  ██║█████╗  ██║   ██║██║██║     █████╗                   ║
║    ██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ██╔══╝                  ║
║    ██████╔╝███████╗ ╚████╔╝ ██║╚██████╗███████╗                 ║
║    ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝                 ║
║                                                                   ║
║    IoT Device Client v1.0.0                                      ║
║    Copyright © 2024 - All Rights Reserved                        ║
╚═══════════════════════════════════════════════════════════════════╝
"#;

fn setup_logger() {
    let mut builder = Builder::from_default_env();
    
    builder
        .format(|buf, record| {
            let mut timestamp_style = buf.style();
            let mut level_style = buf.style();
            let mut target_style = buf.style();
            let mut message_style = buf.style();

            let level_color = match record.level() {
                log::Level::Error => Color::Red,
                log::Level::Warn => Color::Yellow,
                log::Level::Info => Color::Green,
                log::Level::Debug => Color::Cyan,
                log::Level::Trace => Color::White,
            };

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            writeln!(
                buf,
                "{} {} [{}] {}",
                timestamp_style.set_color(Color::Rgb(100, 100, 100)).value(timestamp),
                level_style.set_color(level_color).value(record.level()),
                target_style.set_color(Color::Blue).value(record.target()),
                message_style.set_color(Color::White).value(record.args())
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
}

// Data structures for sending readings
#[derive(Debug, Serialize, Deserialize)]
struct SensorData {
    device_id: String,
    #[serde(rename = "type_")]
    type_: String,
    timestamp: String,
    readings: HashMap<String, serde_json::Value>,
}

#[derive(Clone)]
struct ResourceConstraints {
    cpu_cores: usize,
    memory_mb: usize,
    enable_processing_delay: bool,
}

impl ResourceConstraints {
    fn from_env() -> Self {
        Self {
            cpu_cores: std::env::var("DEVICE_CPU_CORES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            memory_mb: std::env::var("DEVICE_MEMORY_MB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512),
            enable_processing_delay: std::env::var("DEVICE_ENABLE_DELAYS")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
        }
    }

    fn apply(&self) {
        if self.enable_processing_delay {
            info!("Enabled processing delays to simulate constrained device");
        }

        // Set CPU affinity to limit cores
        #[cfg(target_os = "linux")]
        {
            use core_affinity;
            let core_ids = core_affinity::get_core_ids().unwrap();
            let available_cores = core_ids.into_iter()
                .take(self.cpu_cores)
                .collect::<Vec<_>>();
            
            if let Some(core_id) = available_cores.first() {
                core_affinity::set_for_current(*core_id);
                info!("Limited process to {} CPU core(s)", self.cpu_cores);
            }
        }

        // Set memory limit
        #[cfg(target_os = "linux")]
        {
            use rlimit::{Resource, setrlimit};
            
            let resource = Resource::AS;
            let memory_limit = u64::try_from(self.memory_mb * 1024 * 1024)
                .unwrap_or_else(|_| {
                    warn!("Memory limit conversion failed, using default");
                    512 * 1024 * 1024
                });
            
            if let Err(e) = setrlimit(resource, memory_limit, memory_limit) {
                warn!("Failed to set memory limit: {}", e);
            } else {
                info!("Set memory limit to {}MB", self.memory_mb);
            }
        }
    }
}

struct Device {
    config: DiscoveryConfig,
    device_info: DeviceInfo,
    socket: Arc<UdpSocket>,
    http_client: Client,
    server_url: String,
    capabilities: Vec<String>,
    constraints: ResourceConstraints,
}

impl Device {
    async fn new(device_type: &str, capabilities: Vec<String>, server_url: &str) -> Result<Self> {
        let config = DiscoveryConfig::default();
        
        // Bind to specific port for discovery
        let socket = UdpSocket::bind("0.0.0.0:1900").await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        // Enable broadcast and reuse address
        socket.set_broadcast(true)
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        // Join multicast group
        socket.join_multicast_v4(
            "239.255.255.250".parse().unwrap(),
            "0.0.0.0".parse().unwrap()
        ).map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        // Get the actual IP address of the device
        let ip_address = get_local_ip()
            .ok_or_else(|| DiscoveryError::NetworkError("Failed to get local IP".to_string()))?;

        socket.set_multicast_ttl_v4(2)
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        let device_info = DeviceInfo {
            device_id: Uuid::new_v4().to_string(),
            device_type: device_type.to_string(),
            capabilities: capabilities.clone(),
            last_seen: Utc::now(),
            status: DeviceStatus::Online,
            network_info: NetworkInfo {
                ip_address: ip_address.to_string(),
                port: socket.local_addr()?.port(),
                mac_address: get_device_mac()?,
            },
            firmware_version: "1.0.0".to_string(),
            protocol_version: "1.0".to_string(),
        };

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        let constraints = ResourceConstraints::from_env();

        Ok(Self {
            config,
            device_info,
            socket: Arc::new(socket),
            http_client,
            server_url: server_url.to_string(),
            capabilities,
            constraints,
        })
    }

    async fn start(&self) -> Result<()> {
        // Start discovery first to find the MEC server
        info!("Starting server discovery...");
        let server_url = self.discover_server().await?;
        info!("Found MEC server at: {}", server_url);
        
        // Update server URL
        let device = {
            let mut new_device = self.clone();
            new_device.server_url = server_url;
            new_device
        };

        // Start announcement task
        let announcement_handle = {
            let device = device.clone();
            tokio::spawn(async move {
                if let Err(e) = device.start_announcements().await {
                    error!("Announcement error: {}", e);
                }
            })
        };

        // Start data sending task
        let data_handle = {
            let device = device.clone();
            tokio::spawn(async move {
                if let Err(e) = device.start_sending_data().await {
                    error!("Data sending error: {}", e);
                }
            })
        };

        tokio::try_join!(announcement_handle, data_handle)
            .map_err(|e| DiscoveryError::InternalError(e.to_string()))?;

        Ok(())
    }

    async fn discover_server(&self) -> Result<String> {
        info!("Starting server discovery process");
        
        let mut buffer = vec![0u8; 2048];

        loop {
            info!("Listening for MEC server announcement");
            
            match tokio::time::timeout(
                Duration::from_secs(5),
                self.socket.recv_from(&mut buffer)
            ).await {
                Ok(Ok((len, addr))) => {
                    info!("Received {} bytes from {}", len, addr);
                    match serde_json::from_slice::<DiscoveryPacket>(&buffer[..len]) {
                        Ok(packet) => {
                            info!("Parsed packet from device type: {}", packet.device_info.device_type);
                            if packet.device_info.device_type == "mec_server" {
                                let server_ip = addr.ip().to_string();
                                let server_port = packet.device_info.network_info.port;
                                let server_url = format!("http://{}:{}", server_ip, server_port);
                                info!("Found MEC server at {}", server_url);
                                return Ok(server_url);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to parse discovery packet: {}", e);
                            debug!("Raw packet: {:?}", String::from_utf8_lossy(&buffer[..len]));
                        }
                    }
                },
                Ok(Err(e)) => {
                    error!("Socket receive error: {}", e);
                },
                Err(_) => {
                    debug!("No announcement received in timeout period");
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn start_announcements(&self) -> Result<()> {
        info!("Starting device announcements");
        info!("Device ID: {}", self.device_info.device_id);
        info!("Type: {}", self.device_info.device_type);
        info!("Capabilities: {:?}", self.device_info.capabilities);

        loop {
            let packet = DiscoveryPacket {
                device_info: self.device_info.clone(),
                timestamp: Utc::now(),
                nonce: [0u8; 32],
                signature: None,
            };

            let data = serde_json::to_vec(&packet)
                .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;

            debug!("Sending announcement");
            self.socket.send_to(&data, format!("{}:{}", 
                self.config.multicast_addr, 
                self.config.port
            )).await
                .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn start_sending_data(&self) -> Result<()> {
        info!("Starting data transmission");
        
        // Get encryption key and create cipher
        let encryption_key = self.get_encryption_key().await?;
        let cipher = WbAES::new(encryption_key)?;
        
        loop {
            // Generate reading
            let reading = self.generate_reading();
            
            // Create metadata
            let metadata = EncryptedMetadata {
                timestamp: Utc::now().to_rfc3339(),
                data_type: reading.type_.clone(),
                reading_count: reading.readings.len(),
                device_id: reading.device_id.clone(),
            };

            // Serialize and encrypt
            let metadata_bytes = serde_json::to_vec(&metadata)?;
            let reading_bytes = serde_json::to_vec(&reading)?;
            
            let encrypted_metadata = cipher.encrypt(&metadata_bytes)?;
            let encrypted_payload = cipher.encrypt(&reading_bytes)?;
            
            let encrypted_data = EncryptedData {
                device_id: self.device_info.device_id.clone(),
                encrypted_payload,
                encrypted_metadata,
                payload_nonce: vec![0; 12],
                metadata_nonce: vec![0; 12],
            };
            
            // Try to send data with retries
            let mut send_retry_count = 0;
            let max_send_retries = 3;
            
            while send_retry_count < max_send_retries {
                info!("Sending encrypted reading to {}/api/ingest/encrypted (attempt {}/{})", 
                    self.server_url, send_retry_count + 1, max_send_retries);
                    
                match self.http_client
                    .post(format!("{}/api/ingest/encrypted", self.server_url))
                    .json(&encrypted_data)
                    .send()
                    .await {
                        Ok(response) => {
                            if response.status().is_success() {
                                let response_text = response.text().await
                                    .unwrap_or_else(|_| "no response body".to_string());
                                info!("Successfully sent encrypted reading. Response: {}", response_text);
                                break;  // Success, exit retry loop
                            } else {
                                error!("Failed to send reading: {} - {}", 
                                    response.status(),
                                    response.text().await.unwrap_or_else(|_| "no error message".to_string())
                                );
                            }
                        }
                        Err(e) => error!("Error sending reading: {}", e),
                    }
                
                send_retry_count += 1;
                if send_retry_count < max_send_retries {
                    info!("Retrying in 5 seconds...");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }

            info!("Waiting 1 second before next reading");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn get_encryption_key(&self) -> Result<Vec<u8>> {
        let response = self.http_client
            .get(format!("{}/api/key", self.server_url))
            .send()
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(DiscoveryError::NetworkError(format!(
                "Failed to get key: {}", response.status()
            )));
        }

        let key = response.bytes().await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        // Ensure key is 32 bytes (256 bits) for AES-256
        if key.len() != 32 {
            return Err(DiscoveryError::SecurityError(format!(
                "Invalid key length: got {} bytes, expected 32", key.len()
            )));
        }

        Ok(key.to_vec())
    }

    fn generate_reading(&self) -> SensorData {
        let mut rng = rand::thread_rng();
        let mut readings = HashMap::new();
        
        for capability in &self.capabilities {
            let value = match capability.as_str() {
                "heartRate" => rng.gen_range(60.0, 100.0),
                "bloodPressure" => rng.gen_range(90.0, 140.0),
                "bodyTemperature" => rng.gen_range(36.5, 37.5),
                "spo2" => rng.gen_range(95.0, 100.0),
                "respiratoryRate" => rng.gen_range(12.0, 20.0),
                _ => rng.gen_range(0.0, 100.0),
            };
            readings.insert(capability.clone(), json!(value));
        }

        let reading = SensorData {
            device_id: self.device_info.device_id.clone(),
            type_: self.device_info.device_type.clone(),
            timestamp: Utc::now().to_rfc3339(),
            readings,
        };

        debug!("Generated reading with {} values", reading.readings.len());
        reading
    }

    async fn perform_key_exchange(&self) -> Result<Vec<u8>> {
        // Use thread_rng for generating random bytes
        let mut rng = rand::thread_rng();
        let client_random: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        
        // Use ring's SystemRandom only for key generation
        let system_rng = ring_rand::SystemRandom::new();
        let client_keypair = agreement::EphemeralPrivateKey::generate(
            &agreement::ECDH_P256,
            &system_rng,
        ).map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;
        
        let client_public_key = client_keypair
            .compute_public_key()
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;

        // Use thread_rng for nonce generation
        let nonce: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

        let request = HandshakeRequest {
            client_random,
            supported_versions: vec![1],
            client_public_key: client_public_key.as_ref().to_vec(),
            timestamp: Utc::now().timestamp(),
            nonce,
        };

        let response = self.http_client
            .post(format!("{}/api/handshake", self.server_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?
            .json::<HandshakeResponse>()
            .await
            .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;

        // Verify timestamp to prevent replay attacks
        let now = Utc::now().timestamp();
        if (now - response.timestamp).abs() > 300 {
            return Err(DiscoveryError::SecurityError("Invalid timestamp".into()));
        }

        // Verify server signature
        self.verify_signature(&response)
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;

        // Generate session key
        let session_key = generate_session_key(
            &request.client_random,
            &response.server_random,
            &response.encrypted_key,
        );

        Ok(session_key)
    }

    fn verify_signature(&self, response: &HandshakeResponse) -> Result<()> {
        // Get server's public key
        let server_public_key = PublicKey::from_bytes(&[/* server's public key bytes */])
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;

        // Create message to verify
        let mut message = Vec::new();
        message.extend(&response.server_random);
        message.extend(&response.encrypted_key);
        message.extend(&response.key_version.to_le_bytes());
        message.extend(&response.timestamp.to_le_bytes());

        // Verify signature
        let signature = Signature::from_bytes(&response.signature)
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;

        server_public_key
            .verify(&message, &signature)
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;

        Ok(())
    }

    async fn send_reading(&self) -> Result<()> {
        if self.constraints.enable_processing_delay {
            self.simulate_processing_delay();
        }

        let mut readings = HashMap::new();
        
        for capability in &self.device_info.capabilities {
            let value = {
                let mut rng = rand::thread_rng();
                match capability.as_str() {
                    "heartRate" => rng.gen_range(60.0, 100.0),
                    "bloodPressure" => rng.gen_range(90.0, 140.0),
                    "ecg" => rng.gen_range(-0.5, 0.5),
                    _ => rng.gen_range(0.0, 100.0),
                }
            };
            readings.insert(capability.clone(), json!(value));
        }

        let reading = SensorData {
            device_id: self.device_info.device_id.clone(),
            type_: self.device_info.device_type.clone(),
            timestamp: Utc::now().to_rfc3339(),
            readings,
        };

        // Add detailed logging for endpoint and payload
        let url = format!("{}/api/ingest/data", self.server_url);
        info!("Device {} sending reading to endpoint: {}", self.device_info.device_id, url);
        debug!("Reading payload: {:?}", reading);

        match self.http_client
            .post(&url)
            .json(&reading)
            .send()
            .await {
                Ok(response) => {
                    let status = response.status();
                    info!("Device {} got response status: {}", self.device_info.device_id, status);
                    
                    if !status.is_success() {
                        let error_text = response.text().await
                            .unwrap_or_else(|_| "Could not get error text".to_string());
                        warn!("Device {} got error response: {} - {}", 
                            self.device_info.device_id, status, error_text);
                        return Err(DiscoveryError::NetworkError(format!(
                            "Server error: {} - {}", status, error_text
                        )));
                    }
                    
                    debug!("Device {} successfully sent reading", self.device_info.device_id);
                    Ok(())
                }
                Err(e) => {
                    warn!("Device {} failed to send reading: {}", self.device_info.device_id, e);
                    Err(DiscoveryError::NetworkError(e.to_string()))
                }
            }
    }

    fn simulate_processing_delay(&self) {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(50) {
            std::hint::spin_loop();
        }
    }
}

impl Clone for Device {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            device_info: self.device_info.clone(),
            socket: Arc::clone(&self.socket),
            http_client: self.http_client.clone(),
            server_url: self.server_url.clone(),
            capabilities: self.capabilities.clone(),
            constraints: self.constraints.clone(),
        }
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "sensor")]
    device_type: String,

    #[arg(long, value_delimiter = ',')]
    capabilities: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize custom logger
    setup_logger();

    // Print banner
    println!("{}", BANNER);
    
    info!("Starting IoT Device Client...");
    info!("Initializing system components...");

    let args = Args::parse();
    info!(" Command line arguments parsed successfully");
    info!("Device Type: {}", args.device_type);
    info!("Capabilities: {:?}", args.capabilities);

    // Apply resource constraints from environment
    info!("🔧 Configuring resource constraints...");
    let constraints = ResourceConstraints::from_env();
    constraints.apply();
    info!("✓ Resource constraints applied");

    info!("🔌 Initializing device...");
    let device = Device::new(
        &args.device_type,
        args.capabilities,
        "", // Empty server URL, will be discovered
    ).await?;
    info!("✓ Device initialized successfully");
    info!("Device ID: {}", device.device_info.device_id);
    info!("Network Info:");
    info!("  - IP: {}", device.device_info.network_info.ip_address);
    info!("  - MAC: {}", device.device_info.network_info.mac_address);
    info!("  - Port: {}", device.device_info.network_info.port);

    info!("🚀 Starting device operations...");
    match device.start().await {
        Ok(_) => {
            info!("Device shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            error!("❌ Device encountered an error: {}", e);
            Err(e)
        }
    }
}

// Add helper function to get local IP
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    
    // This connects to a public DNS server but doesn't send any data
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    
    Some(addr.ip().to_string())
}

// Rename our helper function to avoid conflict
fn get_device_mac() -> Result<String> {
    use mac_address::get_mac_address;
    match get_mac_address() {
        Ok(Some(addr)) => Ok(addr.to_string()),
        Ok(None) => Ok("00:00:00:00:00:00".to_string()),  // Fallback if no MAC found
        Err(e) => Err(DiscoveryError::NetworkError(e.to_string()))
    }
} 