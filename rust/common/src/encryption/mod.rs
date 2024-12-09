pub mod error;
pub mod wbaes;
pub mod handshake;

pub use error::EncryptionError;
pub use wbaes::WbAES;
pub use handshake::{HandshakeRequest, HandshakeResponse, generate_session_key};

use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub device_id: String,
    pub encrypted_payload: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub payload_nonce: Vec<u8>,
    pub metadata_nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    pub timestamp: String,
    pub data_type: String,
    pub reading_count: usize,
    pub device_id: String,
} 