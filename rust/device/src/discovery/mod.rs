mod announcer;
mod security;

pub use announcer::DeviceAnnouncer;
pub use security::SecurityManager;

use common::{DeviceInfo, DiscoveryConfig, Result};

pub async fn start_discovery(device_info: DeviceInfo, config: DiscoveryConfig) -> Result<()> {
    let announcer = DeviceAnnouncer::new(device_info, config).await?;
    announcer.start().await
} 