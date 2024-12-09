use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityChallenge {
    pub challenge_id: String,
    pub device_id: String,
    pub nonce: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub device_id: String,
    pub response: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub certificate: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
} 