use std::sync::Arc;
use tokio::time::interval;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use common::{DeviceInfo, DiscoveryConfig, Result};
use crate::discovery::SecurityManager;

#[derive(Serialize, Deserialize)]
struct AnnouncementPacket {
    device_info: DeviceInfo,
    timestamp: i64,
    signature: Vec<u8>,
}

pub struct DeviceAnnouncer {
    device_info: DeviceInfo,
    config: DiscoveryConfig,
    security_manager: Arc<SecurityManager>,
    socket: UdpSocket,
}

impl DeviceAnnouncer {
    pub async fn new(device_info: DeviceInfo, config: DiscoveryConfig) -> Result<Self> {
        let security_manager = Arc::new(SecurityManager::new(&config.security)?);
        
        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        // Enable broadcast
        socket.set_broadcast(true)?;
        
        // Set TTL for multicast
        socket.set_multicast_ttl_v4(2)?;
        
        Ok(Self {
            device_info,
            config,
            security_manager,
            socket,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let mut interval = interval(self.config.announcement_interval);
        
        log::info!(
            "Starting device announcer for device {} on multicast {}",
            self.device_info.device_id,
            self.config.multicast_addr
        );
        
        loop {
            interval.tick().await;
            if let Err(e) = self.announce().await {
                log::error!("Failed to send announcement: {}", e);
            }
        }
    }

    pub async fn announce(&self) -> Result<()> {
        let packet = AnnouncementPacket {
            device_info: self.device_info.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            signature: vec![], 
        };

        let announcement = serde_json::to_vec(&packet)?;
        
        let multicast_addr: SocketAddr = format!(
            "{}:{}", 
            self.config.multicast_addr, 
            self.config.port
        ).parse()?;

        self.socket.send_to(&announcement, multicast_addr).await?;

        log::debug!(
            "Sent announcement for device {} ({} bytes)",
            self.device_info.device_id,
            announcement.len()
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_announcer_creation() {
        let device_info = DeviceInfo {
            device_id: "test_device".to_string(),
            device_type: "test".to_string(),
            network_info: common::NetworkInfo {
                ip_address: "127.0.0.1:0".parse().unwrap(),
                mac_address: Some("00:11:22:33:44:55".to_string()),
                hostname: Some("test-device".to_string()),
            },
        };

        let config = DiscoveryConfig {
            multicast_addr: "239.255.255.250".to_string(),
            port: 1234,
            announcement_interval: Duration::from_secs(5),
            security: common::SecurityConfig::default(),
        };

        let announcer = DeviceAnnouncer::new(device_info, config).await;
        assert!(announcer.is_ok());
    }
} 