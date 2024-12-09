use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod error;
pub mod types;
pub mod config;
pub mod encryption;

pub use error::{DiscoveryError, Result};
pub use types::*;
pub use config::*;

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub multicast_addr: String,
    pub port: u16,
    pub announcement_interval: std::time::Duration,
    pub security: SecurityConfig,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub key_rotation_interval: std::time::Duration,
    pub signature_algorithm: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            key_rotation_interval: std::time::Duration::from_secs(3600),
            signature_algorithm: "Ed25519".to_string(),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            multicast_addr: "239.255.255.250".to_string(),
            port: 1234,
            announcement_interval: std::time::Duration::from_secs(5),
            security: SecurityConfig::default(),
            max_packet_size: 1024,
        }
    }
}

pub trait Discovery {
    fn get_device_info(&self) -> &DeviceInfo;
    fn is_active(&self) -> bool;
    fn last_seen(&self) -> DateTime<Utc>;
} 