use common::{Result, DiscoveryError};
use ed25519_dalek::{Signature, PublicKey, Verifier};
use sha2::{Sha256, Digest};

pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8]
) -> Result<bool> {
    let public_key = PublicKey::from_bytes(public_key)
        .map_err(|_| DiscoveryError::SecurityError("Invalid public key".to_string()))?;
    
    let signature = Signature::from_bytes(signature)
        .map_err(|_| DiscoveryError::SecurityError("Invalid signature".to_string()))?;

    public_key.verify(data, &signature)
        .map_err(|_| DiscoveryError::SecurityError("Signature verification failed".to_string()))?;

    Ok(true)
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
} 