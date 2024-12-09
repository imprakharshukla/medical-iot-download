use common::{DeviceInfo, DiscoveryConfig};
use device::discovery::DeviceAnnouncer;
use mec::discovery::{DiscoveryListener, DeviceRegistry};
use tokio::time::Duration;

#[tokio::test]
async fn test_end_to_end_discovery() {
    // Start MEC discovery service
    let config = DiscoveryConfig::default();
    let listener = DiscoveryListener::new(config.clone()).await.unwrap();
    let registry = DeviceRegistry::new();
    
    // Start device announcer
    let device_info = create_test_device_info();
    let announcer = DeviceAnnouncer::new(device_info.clone(), config).await.unwrap();
    
    // Run both components
    let listener_handle = tokio::spawn(async move {
        listener.start_listening().await
    });
    
    let announcer_handle = tokio::spawn(async move {
        announcer.start_announcing().await
    });
    
    // Wait for some announcements
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    // Cleanup
    listener_handle.abort();
    announcer_handle.abort();
}

// Helper functions from previous test files 