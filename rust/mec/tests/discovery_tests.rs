use common::{DiscoveryConfig, Result};
use common::types::{DeviceInfo, NetworkInfo, DiscoveryPacket, DeviceStatus};
use mec_server::discovery::{DeviceRegistry, start_discovery};
use std::sync::Arc;
use tokio;
use std::time::Duration;
use log::{info, debug};
use chrono::Utc;
use uuid::Uuid;
use tokio::net::UdpSocket;
use redis::Client as RedisClient;

async fn simulate_device(config: &DiscoveryConfig) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| common::DiscoveryError::NetworkError(e.to_string()))?;

    socket.set_multicast_ttl_v4(2)
        .map_err(|e| common::DiscoveryError::NetworkError(e.to_string()))?;

    let packet = create_test_packet();
    let data = serde_json::to_vec(&packet)
        .map_err(|e| common::DiscoveryError::SerializationError(e.to_string()))?;

    // Send announcements every second for 10 seconds
    for _ in 0..10 {
        debug!("Simulated device sending announcement");
        socket.send_to(&data, format!("{}:{}", config.multicast_addr, config.port)).await
            .map_err(|e| common::DiscoveryError::NetworkError(e.to_string()))?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

mod tests {
    use super::*;

    #[tokio::test]
    async fn test_device_discovery() -> Result<()> {
        env_logger::init();

        let config = DiscoveryConfig {
            multicast_addr: "239.255.255.250".to_string(),
            port: 1234,
            announcement_interval: Duration::from_secs(5),
            ..Default::default()
        };

        let redis_client = RedisClient::open("redis://127.0.0.1:6379")?;
        let registry = Arc::new(DeviceRegistry::new(redis_client)?);
        let registry_clone = registry.clone();

        // Start the discovery service
        let discovery_handle = tokio::spawn({
            let config = config.clone();
            async move {
                if let Err(e) = start_discovery(config, registry).await {
                    eprintln!("Discovery service error: {}", e);
                }
            }
        });

        // Give the discovery service time to start
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Start the simulated device
        let device_handle = tokio::spawn({
            let config = config.clone();
            async move {
                if let Err(e) = simulate_device(&config).await {
                    eprintln!("Simulated device error: {}", e);
                }
            }
        });

        // Wait for device announcements
        tokio::time::sleep(Duration::from_secs(12)).await;

        let devices = registry_clone.get_all_devices().await?;
        let device_count = devices.len();
        info!("Discovered devices: {}", device_count);

        // Log device details
        for device in devices {
            info!("Device ID: {}", device.device_id);
            info!("Type: {}", device.device_type);
            info!("Capabilities: {:?}", device.capabilities);
            info!("Status: {:?}", device.status);
            info!("---");
        }

        // Cleanup
        discovery_handle.abort();
        device_handle.abort();

        // Verify we discovered at least one device
        assert!(device_count > 0, "No devices were discovered");
        Ok(())
    }

    #[tokio::test]
    async fn test_packet_processing() -> Result<()> {
        let redis_client = RedisClient::open("redis://127.0.0.1:6379")?;
        let registry = Arc::new(DeviceRegistry::new(redis_client)?);
        let packet = create_test_packet();

        let device_id = packet.device_info.device_id.clone();
        registry.register_device(packet.device_info).await?;

        let stored_device = registry.get_device(&device_id).await?;
        assert!(stored_device.is_some());
        let stored_device = stored_device.unwrap();
        assert_eq!(stored_device.device_type, "sensor");
        assert_eq!(stored_device.status, DeviceStatus::Online);

        Ok(())
    }
}

fn create_test_packet() -> DiscoveryPacket {
    let device_info = DeviceInfo {
        device_id: Uuid::new_v4().to_string(),
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

    DiscoveryPacket {
        device_info,
        timestamp: Utc::now(),
        nonce: [0u8; 32],
        signature: None,
    }
}

// Reuse create_test_device_info from announcer_tests.rs 