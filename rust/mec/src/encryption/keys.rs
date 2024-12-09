//! Encryption key management module
//! 
//! Provides functionality for managing encryption keys used in securing medical data.

use common::encryption::wbaes::WbAES;
use std::sync::Arc;
use parking_lot::RwLock;
use chrono::{DateTime, Utc, Duration};
use rand::Rng;
use log::info;
use common::{Result, DiscoveryError};

#[derive(Clone)]
pub struct KeyVersion {
    pub key: Arc<WbAES>,
    pub version: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct KeyPair {
    pub metadata_key: Arc<WbAES>,
    pub payload_key: Arc<WbAES>,
    active_keys: Arc<RwLock<Vec<KeyVersion>>>,
    rotation_interval: Duration,
}

impl KeyPair {
    pub fn new(initial_key: WbAES) -> Self {
        let key_version = KeyVersion {
            key: Arc::new(initial_key.clone()),
            version: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(30),
        };

        Self {
            metadata_key: Arc::new(initial_key.clone()),
            payload_key: Arc::new(initial_key),
            active_keys: Arc::new(RwLock::new(vec![key_version])),
            rotation_interval: Duration::seconds(30),
        }
    }

    pub fn get_active_key(&self) -> KeyVersion {
        let keys = self.active_keys.read();
        keys.last().unwrap().clone()
    }

    pub async fn rotate_keys(&self) -> Result<()> {
        info!("Starting key rotation process...");
        let mut keys = self.active_keys.write();
        info!("Acquired write lock on active keys");
        
        let new_key = WbAES::generate_key()
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;
        info!("Generated new key");
        
        let old_version = keys.last().map(|k| k.version).unwrap_or(0);
        let new_version = old_version + 1;
        let now = Utc::now();
        
        info!("Rotating keys: old_version={}, new_version={}", old_version, new_version);
        
        let new_version_key = KeyVersion {
            key: Arc::new(new_key),
            version: new_version,
            created_at: now,
            expires_at: now + self.rotation_interval,
        };

        // Keep last 2 versions for graceful rotation
        if keys.len() >= 2 {
            let removed = keys.remove(0);
            info!("Removed old key version {} (created at {})", 
                removed.version, 
                removed.created_at.to_rfc3339()
            );
        }
        
        keys.push(new_version_key.clone());
        info!("Added new key version {} (expires at {})", 
            new_version_key.version, 
            new_version_key.expires_at.to_rfc3339()
        );

        info!("Key rotation completed successfully");
        Ok(())
    }

    pub fn get_key_by_version(&self, version: u64) -> Option<Arc<WbAES>> {
        let keys = self.active_keys.read();
        keys.iter()
            .find(|k| k.version == version)
            .map(|k| k.key.clone())
    }
}

pub trait KeyGeneration {
    fn get_key(&self) -> Option<Vec<u8>>;
} 