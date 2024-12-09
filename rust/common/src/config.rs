use serde::{Deserialize, Serialize};
use std::result::Result as StdResult;
use crate::error::DiscoveryError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub redis_url: String,
    pub bind_address: String,
    pub encryption_key: String,
    pub signing_key: String,
}

impl Config {
    pub fn load() -> StdResult<Self, DiscoveryError> {
        // Load from config file or environment
        Ok(Self {
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            bind_address: std::env::var("BIND_ADDRESS")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            encryption_key: std::env::var("ENCRYPTION_KEY")
                .unwrap_or_else(|_| "default_encryption_key".to_string()),
            signing_key: std::env::var("SIGNING_KEY")
                .unwrap_or_else(|_| "default_signing_key".to_string()),
        })
    }
} 