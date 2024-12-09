use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceStatus {
    Online,
    Offline,
    Maintenance,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_type: String,
    pub capabilities: Vec<String>,
    pub last_seen: DateTime<Utc>,
    pub status: DeviceStatus,
    pub network_info: NetworkInfo,
    pub firmware_version: String,
    pub protocol_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub ip_address: String,
    pub port: u16,
    pub mac_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryPacket {
    pub device_info: DeviceInfo,
    pub timestamp: DateTime<Utc>,
    pub nonce: [u8; 32],
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub status: DeviceStatus,
    pub message: Option<String>,
    pub registration_required: bool,
    pub timestamp: DateTime<Utc>,
    pub signature: Option<Vec<u8>>,
} 