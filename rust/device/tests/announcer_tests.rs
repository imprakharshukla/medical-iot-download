use common::{DeviceInfo, DiscoveryConfig, NetworkInfo};
use device::discovery::DeviceAnnouncer;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use chrono::Utc;

#[tokio::test]
async fn test_device_announcer_creation() {
    let device_info = create_test_device_info();
    let config = DiscoveryConfig::default();
    
    let announcer = DeviceAnnouncer::new(device_info, config).await;
    assert!(announcer.is_ok());
}

#[tokio::test]
async fn test_announcement_sending() {
    let device_info = create_test_device_info();
    let config = DiscoveryConfig::default();
    
    // Create a test listener
    let listener = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    listener.join_multicast_v4(
        &config.multicast_addr.parse().unwrap(),
        &"0.0.0.0".parse().unwrap(),
    ).unwrap();

    // Create and start announcer
    let announcer = DeviceAnnouncer::new(device_info, config).await.unwrap();
    let announcement_handle = tokio::spawn(async move {
        announcer.send_announcement().await
    });

    // Listen for announcement
    let mut buf = vec![0; 1024];
    let recv_future = listener.recv_from(&mut buf);
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(1));

    tokio::select! {
        result = recv_future => {
            let (len, _) = result.unwrap();
            let packet: common::DiscoveryPacket = serde_json::from_slice(&buf[..len]).unwrap();
            assert_eq!(packet.device_info.device_id, "TEST_DEVICE_001");
        }
        _ = timeout => {
            panic!("Timeout waiting for announcement");
        }
    }

    announcement_handle.await.unwrap().unwrap();
}

fn create_test_device_info() -> DeviceInfo {
    DeviceInfo {
        device_id: "TEST_DEVICE_001".to_string(),
        device_type: "TEST".to_string(),
        capabilities: vec!["test_capability".to_string()],
        firmware_version: "1.0.0".to_string(),
        protocol_version: "1.0".to_string(),
        last_seen: Utc::now(),
        network_info: NetworkInfo {
            ip_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            hostname: Some("test-device".to_string()),
        },
    }
} 