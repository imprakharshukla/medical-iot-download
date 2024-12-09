use common::types::{DeviceInfo, NetworkInfo, DiscoveryPacket, DeviceStatus};
use common::{DiscoveryError, Result, DiscoveryConfig};
use tokio::net::UdpSocket;
use std::sync::Arc;
use log::{info, error, debug};
use crate::discovery::registry::DeviceRegistry;
use chrono::Utc;
use uuid::Uuid;
use redis::Client as RedisClient;

pub struct DiscoveryListener {
    config: DiscoveryConfig,
    socket: Arc<UdpSocket>,
    registry: Arc<DeviceRegistry>,
}

impl DiscoveryListener {
    pub async fn new(config: DiscoveryConfig, registry: Arc<DeviceRegistry>) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", config.port)).await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;
        
        socket.join_multicast_v4(
            config.multicast_addr.parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
        ).map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        info!("Discovery listener bound to port {}", config.port);
        debug!("Using multicast address: {}", config.multicast_addr);

        Ok(Self {
            config,
            socket: Arc::new(socket),
            registry,
        })
    }

    pub async fn start_listening(&self) -> Result<()> {
        info!("Starting discovery listener on port {}", self.config.port);
        let mut buf = vec![0; self.config.max_packet_size];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    match serde_json::from_slice::<DiscoveryPacket>(&buf[..len]) {
                        Ok(packet) => {
                            debug!("Received discovery packet from {}: {:?}", addr, packet);
                            if let Err(e) = self.handle_packet(packet, addr).await {
                                error!("Error handling packet from {}: {}", addr, e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to deserialize packet from {}: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                    continue;
                }
            }
        }
    }

    async fn handle_packet(&self, packet: DiscoveryPacket, addr: std::net::SocketAddr) -> Result<()> {
        if !self.validate_packet(&packet) {
            error!("Invalid packet received from {}", addr);
            return Ok(());
        }

        let device_info = DeviceInfo {
            device_id: packet.device_info.device_id.clone(),
            device_type: packet.device_info.device_type.clone(),
            capabilities: packet.device_info.capabilities.clone(),
            last_seen: Utc::now(),
            status: DeviceStatus::Online,
            network_info: NetworkInfo {
                ip_address: addr.ip().to_string(),
                port: addr.port(),
                mac_address: String::new(),
            },
            firmware_version: packet.device_info.firmware_version.clone(),
            protocol_version: packet.device_info.protocol_version.clone(),
        };

        self.register_device(device_info).await?;
        
        debug!("Successfully processed discovery packet from {}", addr);
        Ok(())
    }

    fn validate_packet(&self, packet: &DiscoveryPacket) -> bool {
        if !self.validate_device_id(&packet.device_info.device_id) {
            error!("Invalid device ID format");
            return false;
        }

        if !self.validate_device_type(&packet.device_info.device_type) {
            error!("Invalid device type");
            return false;
        }

        if !self.validate_capabilities(&packet.device_info.capabilities) {
            error!("Invalid capabilities");
            return false;
        }

        true
    }

    fn validate_device_id(&self, device_id: &str) -> bool {
        match Uuid::parse_str(device_id) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn validate_device_type(&self, device_type: &str) -> bool {
        let valid_types = ["sensor", "actuator", "gateway", "controller"];
        valid_types.contains(&device_type)
    }

    fn validate_capabilities(&self, capabilities: &[String]) -> bool {
        if capabilities.is_empty() {
            return false;
        }

        let valid_capabilities = [
            "temperature", "humidity", "pressure", "motion",
            "light", "sound", "acceleration", "gyroscope",
            "magnetometer", "proximity", "air_quality",
        ];

        capabilities.iter().all(|cap| valid_capabilities.contains(&cap.as_str()))
    }

    async fn register_device(&self, device_info: DeviceInfo) -> Result<()> {
        info!("Registering device {}", device_info.device_id);
        let device_id = device_info.device_id.clone();
        self.registry.register_device(device_info).await
    }

    pub fn get_socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::test;
    use redis::Client as RedisClient;

    #[test]
    async fn test_listener_creation() {
        let config = DiscoveryConfig {
            port: 8888,
            multicast_addr: "239.255.255.250".to_string(),
            max_packet_size: 1024,
            ..Default::default()
        };
        
        let redis_client = RedisClient::open("redis://127.0.0.1:6379").unwrap();
        let registry = Arc::new(DeviceRegistry::new(redis_client).unwrap());
        let listener = DiscoveryListener::new(config, registry).await;
        assert!(listener.is_ok());
    }

    #[test]
    async fn test_packet_validation() {
        let config = DiscoveryConfig::default();
        let redis_client = RedisClient::open("redis://127.0.0.1:6379").unwrap();
        let registry = Arc::new(DeviceRegistry::new(redis_client).unwrap());
        let listener = DiscoveryListener::new(config, registry).await.unwrap();

        let valid_uuid = Uuid::new_v4().to_string();
        let device_info = DeviceInfo {
            device_id: valid_uuid,
            device_type: "sensor".to_string(),
            capabilities: vec!["temperature".to_string()],
            last_seen: Utc::now(),
            status: DeviceStatus::Online,
            network_info: NetworkInfo {
                ip_address: "127.0.0.1".to_string(),
                port: 8080,
                mac_address: "00:11:22:33:44:55".to_string(),
            },
            firmware_version: "1.0.0".to_string(),
            protocol_version: "1.0".to_string(),
        };

        let packet = DiscoveryPacket {
            device_info,
            timestamp: Utc::now(),
            nonce: [0u8; 32],
            signature: None,
        };

        assert!(listener.validate_packet(&packet));
    }
} 