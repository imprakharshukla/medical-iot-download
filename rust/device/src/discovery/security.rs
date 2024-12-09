use common::{SecurityConfig, DiscoveryError, Result};
use ed25519_dalek::{Keypair, Signer};
use rand::rngs::OsRng;
use std::sync::RwLock;

pub struct SecurityManager {
    keypair: RwLock<Keypair>,
    config: SecurityConfig,
}

impl SecurityManager {
    pub fn new(config: &SecurityConfig) -> Result<Self> {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

        Ok(Self {
            keypair: RwLock::new(keypair),
            config: config.clone(),
        })
    }

    pub fn sign_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let keypair = self.keypair.read()
            .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;

        Ok(keypair.sign(packet).to_bytes().to_vec())
    }

    pub fn verify_signature(&self, packet: &[u8], signature: &[u8]) -> Result<bool> {
        let keypair = self.keypair.read()
            .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;

        let signature_bytes = ed25519_dalek::Signature::from_bytes(signature)
            .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;

        Ok(keypair.verify(packet, &signature_bytes).is_ok())
    }

    pub fn rotate_keys(&self) -> Result<()> {
        let mut keypair = self.keypair.write()
            .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;
        
        let mut csprng = OsRng;
        *keypair = Keypair::generate(&mut csprng);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sign_and_verify() {
        let config = SecurityConfig {
            key_rotation_interval: Duration::from_secs(3600),
            signature_algorithm: "Ed25519".to_string(),
        };

        let manager = SecurityManager::new(&config).unwrap();
        let test_data = b"test message";
        
        let signature = manager.sign_packet(test_data).unwrap();
        assert!(manager.verify_signature(test_data, &signature).unwrap());
    }

    #[test]
    fn test_key_rotation() {
        let config = SecurityConfig {
            key_rotation_interval: Duration::from_secs(3600),
            signature_algorithm: "Ed25519".to_string(),
        };

        let manager = SecurityManager::new(&config).unwrap();
        let test_data = b"test message";
        
        let signature1 = manager.sign_packet(test_data).unwrap();
        manager.rotate_keys().unwrap();
        let signature2 = manager.sign_packet(test_data).unwrap();
        
        assert_ne!(signature1, signature2);
    }
} 