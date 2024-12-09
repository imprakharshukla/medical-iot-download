use common::{DiscoveryPacket, DiscoveryError, Result, SecurityConfig};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use std::collections::HashMap;
use std::sync::RwLock;

pub struct PacketValidator {
    trusted_keys: RwLock<HashMap<String, PublicKey>>,
    config: SecurityConfig,
}

impl PacketValidator {
    pub fn new(config: SecurityConfig) -> Result<Self> {
        let trusted_keys = RwLock::new(HashMap::new());
        // Load trusted keys from config
        Ok(Self { trusted_keys, config })
    }

    pub fn validate(&self, packet: &DiscoveryPacket) -> Result<bool> {
        if let Some(signature) = &packet.signature {
            let public_key = self.get_public_key(&packet.device_info.device_id)?;
            let data = serde_json::to_vec(&packet)
                .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;
            let signature = Signature::from_bytes(signature)
                .map_err(|_| DiscoveryError::SecurityError("Invalid signature format".to_string()))?;
            public_key.verify(&data, &signature)
                .map_err(|_| DiscoveryError::SecurityError("Signature verification failed".to_string()))?;
        }
        Ok(true)
    }

    fn get_public_key(&self, device_id: &str) -> Result<PublicKey> {
        let keys = self.trusted_keys.read()
            .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;
        keys.get(device_id)
            .cloned()
            .ok_or_else(|| DiscoveryError::SecurityError("Public key not found".to_string()))
    }
} 