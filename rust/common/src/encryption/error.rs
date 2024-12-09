use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
} 