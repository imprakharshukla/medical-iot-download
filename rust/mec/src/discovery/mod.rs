mod listener;
mod validator;
mod registry;

use std::sync::Arc;
use common::{DiscoveryConfig, Result};

pub use listener::DiscoveryListener;
pub use validator::PacketValidator;
pub use registry::DeviceRegistry;

pub async fn start_discovery(config: DiscoveryConfig, registry: Arc<DeviceRegistry>) -> Result<()> {
    let listener = DiscoveryListener::new(config.clone(), registry).await?;
    listener.start_listening().await
} 