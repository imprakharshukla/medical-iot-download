use serde::{Serialize, Deserialize};
use rand::Rng;
use sha2::{Sha256, Digest};

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub client_random: Vec<u8>,
    pub supported_versions: Vec<u64>,
    pub client_public_key: Vec<u8>,
    pub timestamp: i64,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub server_random: Vec<u8>,
    pub selected_version: u64,
    pub encrypted_key: Vec<u8>,
    pub key_version: u64,
    pub signature: Vec<u8>,
    pub timestamp: i64,
}

pub fn generate_session_key(
    client_random: &[u8],
    server_random: &[u8],
    shared_secret: &[u8]
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.update(shared_secret);
    hasher.finalize().to_vec()
} 