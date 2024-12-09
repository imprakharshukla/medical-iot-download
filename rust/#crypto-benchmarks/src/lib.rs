pub mod algorithms;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

// Common traits for all encryption algorithms
pub trait Encryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait KeyGeneration {
    fn generate_key(&self) -> Result<Vec<u8>>;
}