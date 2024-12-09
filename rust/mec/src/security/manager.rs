use common::{SecurityConfig, DiscoveryError, Result, SecurityChallenge, ChallengeResponse};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::{rngs::OsRng, random};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use chrono::Utc;

pub struct SecurityManager {
    keypair: Keypair,
    trusted_devices: RwLock<HashMap<String, DeviceCredentials>>,
    active_challenges: RwLock<HashMap<String, SecurityChallenge>>,
    config: SecurityConfig,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Result<Self> {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);

        Ok(Self {
            keypair,
            trusted_devices: RwLock::new(HashMap::new()),
            active_challenges: RwLock::new(HashMap::new()),
            config,
        })
    }

    pub fn create_challenge(&self, device_id: &str) -> Result<SecurityChallenge> {
        let challenge = SecurityChallenge {
            challenge_id: Uuid::new_v4().to_string(),
            device_id: device_id.to_string(),
            nonce: random(),
            timestamp: Utc::now(),
            signature: None,
        };

        let mut challenges = self.active_challenges.write()
            .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;
        challenges.insert(challenge.challenge_id.clone(), challenge.clone());

        Ok(challenge)
    }

    pub fn verify_challenge_response(&self, response: &ChallengeResponse) -> Result<bool> {
        let challenges = self.active_challenges.read()
            .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;
        
        let challenge = challenges.get(&response.challenge_id)
            .ok_or_else(|| DiscoveryError::SecurityError("Challenge not found".to_string()))?;

        // Verify the response signature
        if let Some(signature) = &response.signature {
            let devices = self.trusted_devices.read()
                .map_err(|_| DiscoveryError::SecurityError("Failed to acquire lock".to_string()))?;
            
            let device = devices.get(&response.device_id)
                .ok_or_else(|| DiscoveryError::SecurityError("Device not found".to_string()))?;

            let public_key = PublicKey::from_bytes(&device.public_key)
                .map_err(|e| DiscoveryError::SecurityError(format!("Failed to parse public key: {}", e)))?;

            if let Ok(signature) = Signature::from_bytes(signature) {
                if let Ok(verified) = signature.verify(&response.response, &public_key) {
                    return Ok(verified);
                }
            }
        }

        Ok(false)
    }
} 